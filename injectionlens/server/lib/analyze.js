// Orchestration: run the four ingestion pipelines on one URL, group segments
// across profiles, attach signals, and produce findings with tiered impact.
const { fetchHtml, renderPage, AI_CRAWLER_UAS } = require('./ingest');
const { buildRawProfile, buildReaderProfile, normText } = require('./profiles');
const { detectInstruction, analyzeInstruction, primaryInstruction, computeImpact, CAPABILITY_TEMPLATES } = require('./risk');

const EXCERPT_LEN = 200;

function excerpt(text) {
  const t = normText(text);
  return t.length > EXCERPT_LEN ? t.slice(0, EXCERPT_LEN) + '…' : t;
}

function tokenSet(text) {
  return new Set(normText(text).toLowerCase().split(/\W+/).filter((w) => w.length > 2));
}

function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const w of a) if (b.has(w)) inter++;
  return inter / (a.size + b.size - inter);
}

async function analyze(url, capabilityKey = 'summary-only') {
  const started = Date.now();
  if (!CAPABILITY_TEMPLATES[capabilityKey]) capabilityKey = 'summary-only';

  // --- run the four pipelines ---
  const http = await fetchHtml(url); // Pipeline A input
  const rendered = await renderPage(url); // Pipeline B + D
  const raw = buildRawProfile(http.html); // Pipeline A: raw HTTP source
  const reader = buildReaderProfile(rendered.html); // Pipeline C: Reader/Markdown
  const a11y = rendered.a11yNodes || []; // Pipeline D: accessibility tree (flat from CDP)

  // --- group segments across profiles ---
  const groups = new Map(); // key: normalized text

  function getGroup(text) {
    const key = normText(text);
    if (!key) return null;
    if (!groups.has(key)) {
      groups.set(key, {
        key,
        text: key,
        httpSource: null,
        renderedDom: null,
        readerMarkdown: null,
        accessibilityTree: null,
      });
    }
    return groups.get(key);
  }

  // fuzzy attach for reader segments (Readability may merge/split text)
  function attachFuzzy(profile, seg, extra = {}) {
    const key = normText(seg.text);
    if (groups.has(key)) { groups.get(key)[profile] = { ...seg, ...extra }; return; }
    const toks = tokenSet(key);
    let best = null; let bestScore = 0.6;
    for (const [gkey, g] of groups) {
      if (g[profile]) continue;
      const s = jaccard(toks, tokenSet(gkey));
      if (s > bestScore) { bestScore = s; best = g; }
    }
    if (best) best[profile] = { ...seg, ...extra, fuzzyMatched: true };
    else {
      const g = getGroup(key);
      if (g) g[profile] = { ...seg, ...extra };
    }
  }

  for (const item of raw.items) {
    const g = getGroup(item.text);
    if (g && !g.httpSource) g.httpSource = item;
  }
  for (const item of rendered.items) {
    const g = getGroup(item.text);
    if (g && !g.renderedDom) g.renderedDom = item;
  }
  for (const c of rendered.comments) {
    const g = getGroup(c.text);
    if (g) { g.commentInRendered = true; }
  }
  for (const seg of reader.segments || []) attachFuzzy('readerMarkdown', seg, { inReader: true });
  for (const node of a11y) {
    if (node.name.length < 4) continue;
    attachFuzzy('accessibilityTree', { role: node.role, name: node.name }, {});
  }

  // --- cloaking probe: same URL, AI-crawler UA ---
  let cloak = null;
  try {
    const baseText = new Set();
    for (const g of groups.values()) baseText.add(g.key);
    for (const bot of AI_CRAWLER_UAS.slice(0, 2)) {
      const aiFetch = await fetchHtml(url, bot.ua);
      const aiRaw = buildRawProfile(aiFetch.html);
      const aiOnly = aiRaw.items
        .map((i) => normText(i.text))
        .filter((t) => t.length > 12 && !baseText.has(t) && !Array.from(baseText).some((b) => jaccard(tokenSet(b), tokenSet(t)) > 0.7));
      if (aiOnly.length) {
        cloak = {
          bot: bot.ua.match(/compatible; (\w+)/)?.[1] || bot.bot,
          humanBytes: http.html.length,
          aiBytes: aiFetch.html.length,
          aiOnlySegments: aiOnly.slice(0, 8).map(excerpt),
          aiOnlyFull: aiOnly.slice(0, 8),
        };
        break;
      }
    }
  } catch { /* cloaking probe is best-effort */ }

  // --- signals + findings ---
  const findings = [];
  const matrix = [];
  let fid = 0;

  for (const g of groups.values()) {
    const signals = [];
    const occ = g;
    const humanVisible = !!(occ.renderedDom && occ.renderedDom.visible);
    const aiProfiles = [];
    if (occ.httpSource) aiProfiles.push('http-source');
    if (occ.renderedDom) aiProfiles.push('rendered-dom');
    if (occ.readerMarkdown) aiProfiles.push('reader-markdown');
    if (occ.accessibilityTree) aiProfiles.push('accessibility-tree');

    if (occ.httpSource) {
      if (occ.httpSource.kind === 'comment') signals.push({ type: 'html-comment', severity: 'high', detail: 'Only exists as an HTML comment in the raw source — invisible to human readers.' });
      if (occ.httpSource.kind === 'meta') signals.push({ type: 'meta-tag', severity: 'info', detail: 'Inside a <meta> tag — some agents ingest page metadata.' });
      if (occ.httpSource.zeroWidth) signals.push({ type: 'zero-width-chars', severity: 'high', detail: 'Contains zero-width/invisible Unicode characters.' });
      if (occ.httpSource.hiddenHints && occ.httpSource.hiddenHints.length && occ.httpSource.kind === 'element') {
        signals.push({ type: 'hidden-in-source', severity: 'medium', detail: `Hidden hints in raw markup: ${occ.httpSource.hiddenHints.join(', ')}` });
      }
    }
    if (occ.renderedDom) {
      if (!occ.renderedDom.visible) {
        signals.push({ type: 'render-hidden', severity: 'high', detail: `Invisible after rendering: ${occ.renderedDom.hiddenReasons.join('; ')}` });
      }
      if (occ.renderedDom.zeroWidth) signals.push({ type: 'zero-width-chars', severity: 'high', detail: 'Contains zero-width/invisible Unicode characters.' });
    }
    if (occ.httpSource && occ.renderedDom && !occ.renderedDom.visible && (occ.readerMarkdown || occ.accessibilityTree)) {
      signals.push({ type: 'ai-visible-human-invisible', severity: 'high', detail: 'Invisible to humans, but picked up by reader/a11y pipelines an agent may use.' });
    }
    if (occ.httpSource && !occ.renderedDom) {
      signals.push({ type: 'raw-only', severity: 'medium', detail: 'Present in HTTP source but dropped from the rendered DOM (parser/JS removed it).' });
    }
    if (occ.renderedDom && occ.renderedDom.visible && !occ.readerMarkdown) {
      signals.push({ type: 'reader-excludes', severity: 'info', detail: 'Visible to humans, excluded by Readability (nav/ads boilerplate).' });
    }

    const inQuotedMarkup = !!(occ.renderedDom && occ.renderedDom.inCodeOrQuote) || !!(occ.httpSource && occ.httpSource.inCodeOrQuote);
    const matches = analyzeInstruction(g.text, inQuotedMarkup);
    const primary = primaryInstruction(matches);
    const instruction = primary ? { type: primary.type } : null;
    const quotedContext = matches.length ? matches.every((m) => m.quotedContext) : inQuotedMarkup;
    if (instruction && quotedContext) {
      signals.push({ type: 'quoted-context', severity: 'info', detail: 'Matches an injection pattern but sits inside code/quote or clearly defensive prose — possibly educational material (hard negative).' });
    }

    // evidence tier: hidden/comment/zero-width delivery + pattern match = strong
    const hasStrongDelivery = signals.some((s) => ['html-comment', 'zero-width-chars', 'render-hidden', 'ai-visible-human-invisible'].includes(s.type));
    const hasWeakDelivery = signals.some((s) => ['hidden-in-source', 'raw-only', 'meta-tag'].includes(s.type));
    let evidenceTier = 0;
    if (instruction) evidenceTier = 1;
    if (instruction && (hasStrongDelivery || hasWeakDelivery)) evidenceTier = 3;
    else if (instruction && (occ.httpSource || occ.renderedDom)) evidenceTier = 2;
    else if (!instruction && hasStrongDelivery) evidenceTier = 2;
    else if (!instruction && hasWeakDelivery) evidenceTier = 1;

    const interesting = !!instruction || signals.some((s) => s.severity !== 'info');
    const impact = computeImpact(instruction ? instruction.type : null, evidenceTier, capabilityKey, { quotedContext, cloaked: !!cloak && (occ.httpSource || occ.renderedDom) });

    if (interesting) {
      findings.push({
        id: 'F' + ++fid,
        excerpt: excerpt(g.text),
        fullText: g.text.length <= 600 ? g.text : g.text.slice(0, 600) + '…',
        humanVisible,
        aiProfiles,
        signals,
        instruction: instruction ? instruction.type : null,
        instructionTypes: matches.map((m) => m.type),
        evidenceTier,
        quotedContext,
        impact,
        nodeRef: occ.renderedDom ? occ.renderedDom.id : null,
      });
    }

    if (interesting || aiProfiles.length >= 2 || (occ.httpSource && occ.renderedDom)) {
      matrix.push({
        key: g.key.slice(0, 60),
        excerpt: excerpt(g.text),
        humanVisible,
        httpSource: !!occ.httpSource,
        renderedDom: occ.renderedDom ? (occ.renderedDom.visible ? 'visible' : 'hidden') : 'absent',
        readerMarkdown: !!occ.readerMarkdown,
        accessibilityTree: !!occ.accessibilityTree,
        findingId: interesting ? 'F' + fid : null,
        instruction: instruction ? instruction.type : null,
      });
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.impact.level] - order[b.impact.level]);

  if (cloak) {
    const cloakMatches = analyzeInstruction((cloak.aiOnlyFull || []).join('\n'), false);
    const cloakPrimary = primaryInstruction(cloakMatches);
    findings.unshift({
      id: 'F' + ++fid,
      excerpt: `Server returned ${cloak.aiOnlySegments.length}+ AI-only segment(s) to ${cloak.bot}`,
      fullText: cloak.aiOnlySegments.join('\n---\n'),
      humanVisible: false,
      aiProfiles: ['http-source (AI-crawler UA)'],
      signals: [{ type: 'ua-cloaking', severity: 'critical', detail: `Same URL serves different content to ${cloak.bot} vs a browser UA (${cloak.humanBytes} B human vs ${cloak.aiBytes} B bot response).` }],
      instruction: cloakPrimary ? cloakPrimary.type : null,
      instructionTypes: cloakMatches.map((m) => m.type),
      evidenceTier: 3,
      quotedContext: cloakMatches.length ? cloakMatches.every((m) => m.quotedContext) : false,
      impact: computeImpact(cloakPrimary ? cloakPrimary.type : null, 3, capabilityKey, { cloaked: true, quotedContext: cloakMatches.length ? cloakMatches.every((m) => m.quotedContext) : false }),
      nodeRef: null,
    });
  }

  const levelCount = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) levelCount[f.impact.level]++;

  return {
    url,
    finalUrl: url,
    analyzedAt: new Date().toISOString(),
    elapsedMs: Date.now() - started,
    capability: capabilityKey,
    capabilityLabel: CAPABILITY_TEMPLATES[capabilityKey].label,
    pageTitle: rendered.title,
    stats: {
      httpSourceItems: raw.items.length,
      renderedItems: rendered.items.length,
      readerSegments: (reader.segments || []).length,
      a11yNodes: a11y.length,
      cloakingDetected: !!cloak,
    },
    cloak,
    findings,
    levelCount,
    matrix,
    humanHtml: rendered.html,
    readerMarkdown: reader.markdown || '',
  };
}

module.exports = { analyze };
