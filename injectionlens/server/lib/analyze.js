// Orchestration: run the four ingestion pipelines on one URL, group segments
// across profiles, attach signals, and produce findings with tiered impact.
const { fetchHtml, renderPage, AI_CRAWLER_UAS, uaProbePermission } = require('./ingest');
const { buildRawProfile, buildReaderProfile, normText } = require('./profiles');
const { analyzeInstruction, assessSegment, CAPABILITY_TEMPLATES } = require('./risk');
const { defaultPolicy } = require('./net-guard');
const inspect = require('./inspect');

const EXCERPT_LEN = 200;

function excerpt(text) {
  const t = normText(text);
  return t.length > EXCERPT_LEN ? t.slice(0, EXCERPT_LEN) + '…' : t;
}

// Which delivery channel did this segment arrive through? The answer decides
// how much weight the text carries: a hidden delivery is evidence of intent.
const ATTRIBUTE_KINDS = new Set(['attribute', 'data-attribute', 'hidden-input-value', 'meta', 'jsonld', 'jsonld-malformed']);

function detectDelivery(group, humanVisible) {
  const raw = group.httpSource;
  if (raw) {
    const kind = raw.extractionKind || raw.kind;
    if (kind === 'comment') return 'comment';
    if (kind === 'meta') return 'meta';
    if (kind === 'jsonld' || kind === 'jsonld-malformed') return 'jsonld';
    if (ATTRIBUTE_KINDS.has(kind)) return 'attribute';
  }
  if (group.renderedDom) {
    if (!group.renderedDom.visible) return 'css-hidden';
    if (group.renderedDom.nearInvisibleReasons && group.renderedDom.nearInvisibleReasons.length) return 'near-invisible';
    return 'visible';
  }
  if (humanVisible) return 'visible';
  // Present in the raw source but the renderer dropped it (parser/JS removed it).
  return 'css-hidden';
}

function detectInCodeOrQuote(group) {
  return !!(group.renderedDom && group.renderedDom.inCodeOrQuote)
    || !!(group.httpSource && group.httpSource.inCodeOrQuote)
    || !!(group.readerMarkdown && group.readerMarkdown.inCodeOrQuote);
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

async function analyze(url, capabilityKey = 'summary-only', { policy = defaultPolicy } = {}) {
  const started = Date.now();
  // Fail loudly instead of silently falling back: a capability template the
  // model does not know would produce levels nobody can reproduce.
  if (!CAPABILITY_TEMPLATES[capabilityKey]) {
    throw new Error(`Unknown capability template "${capabilityKey}". Known templates: ${Object.keys(CAPABILITY_TEMPLATES).join(', ')}`);
  }

  // One network policy per scan: DNS answers are reused inside it, every hop and
  // every browser subresource is checked against it.
  const guard = await policy.checkTarget(url, { purpose: 'analyze-target' });
  if (!guard.allowed) {
    const err = new Error(guard.reason);
    err.code = guard.code;
    throw err;
  }

  // --- run the four pipelines ---
  const http = await fetchHtml(url, undefined, undefined, policy); // Pipeline A input
  const rendered = await renderPage(url, { policy }); // Pipeline B + D
  const raw = buildRawProfile(http.html); // Pipeline A: raw HTTP source
  const reader = buildReaderProfile(rendered.html); // Pipeline C: Reader/Markdown
  const a11y = rendered.a11yNodes || []; // Pipeline D: accessibility tree (flat from CDP)

  // --- group segments across profiles ---
  // The normalized text is a COMPARISON KEY only: it decides which observations
  // describe the same content. It is never used as the text we analyse, because
  // normalization strips exactly the invisible characters a payload may hide in.
  // Each group keeps the original evidence of every observation, and the text
  // handed to the risk model is the longest original preserved for that key.
  const groups = new Map(); // key: normalized text

  function getGroup(originalText, normalizedText) {
    const key = normText(normalizedText !== undefined ? normalizedText : originalText);
    if (!key) return null;
    if (!groups.has(key)) {
      groups.set(key, {
        key,
        originalText: typeof originalText === 'string' ? originalText : key,
        normalizedText: key,
        occurrences: [],
        httpSource: null,
        renderedDom: null,
        readerMarkdown: null,
        accessibilityTree: null,
      });
    }
    const group = groups.get(key);
    // Prefer the longest preserved original: it is the one most likely to still
    // carry an invisible/decoded channel the normalizer can inspect.
    if (typeof originalText === 'string' && originalText.length > group.originalText.length) {
      group.originalText = originalText;
    }
    return group;
  }

  function recordOccurrence(group, item, pipeline) {
    if (!group || !item) return;
    group.occurrences.push({
      pipeline,
      extractionKind: item.extractionKind || item.kind || 'unknown',
      path: item.path || null,
      originalText: item.originalText !== undefined ? item.originalText : (item.text || ''),
      normalizedText: item.normalizedText !== undefined ? item.normalizedText : normText(item.text || ''),
      invisibleClasses: item.invisibleClasses || [],
      decodedText: item.decodedText || null,
    });
  }

  // fuzzy attach for reader segments (Readability may merge/split text)
  function attachFuzzy(profile, seg, extra = {}) {
    const key = normText(seg.normalizedText !== undefined ? seg.normalizedText : seg.text);
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
      const g = getGroup(seg.originalText !== undefined ? seg.originalText : seg.text, key);
      if (g) g[profile] = { ...seg, ...extra };
    }
  }

  for (const item of raw.items) {
    const g = getGroup(item.originalText, item.normalizedText);
    if (g && !g.httpSource) g.httpSource = item;
    recordOccurrence(g, item, 'http-source');
  }
  for (const item of rendered.items) {
    const g = getGroup(item.originalText, item.normalizedText);
    if (g && !g.renderedDom) g.renderedDom = item;
    recordOccurrence(g, item, 'rendered-dom');
  }
  for (const c of rendered.comments) {
    const g = getGroup(c.originalText, normText(c.originalText));
    if (g) { g.commentInRendered = true; }
    recordOccurrence(g, { originalText: c.originalText, normalizedText: normText(c.originalText), extractionKind: 'comment', path: '(rendered DOM comment)' }, 'rendered-dom');
  }
  for (const seg of reader.segments || []) {
    attachFuzzy('readerMarkdown', seg, { inReader: true });
    recordOccurrence(getGroup(seg.originalText, seg.normalizedText), seg, 'reader-markdown');
  }
  for (const node of a11y) {
    if (node.name.length < 4) continue;
    attachFuzzy('accessibilityTree', { role: node.role, name: node.name, originalText: node.name, normalizedText: normText(node.name), extractionKind: 'a11y-node', path: `accessibility tree (role=${node.role})` }, {});
    recordOccurrence(getGroup(node.name, normText(node.name)), { originalText: node.name, normalizedText: normText(node.name), extractionKind: 'a11y-node', path: `accessibility tree (role=${node.role})` }, 'accessibility-tree');
  }

  // --- cloaking probe: same URL, each configured AI-agent UA ---
  // The probe is authorised only against the local fixture origin (or an
  // explicitly allowlisted host). Every configured entry is probed, and the
  // per-entry result is recorded — including "skipped" — so the report can name
  // the actual UA token responsible instead of guessing.
  const uaProbe = [];
  let cloak = null;
  {
    const permission = uaProbePermission(url, policy);
    const baseText = new Set();
    for (const g of groups.values()) baseText.add(g.key);
    for (const bot of AI_CRAWLER_UAS) {
      const record = {
        token: bot.token,
        vendor: bot.vendor,
        category: bot.category,
        status: 'pending',
        bytes: null,
        differs: false,
        aiOnlyCount: 0,
      };
      if (!permission.allowed) {
        record.status = permission.reason;
        uaProbe.push(record);
        continue;
      }
      try {
        // The probe must validate against the SAME policy as the scan, otherwise a
        // run bound to another port silently has every probe refused.
        const aiFetch = await fetchHtml(url, bot.ua, undefined, policy);
        const aiRaw = buildRawProfile(aiFetch.html);
        const aiOnly = aiRaw.items
          .map((i) => normText(i.text))
          .filter((t) => t.length > 12 && !baseText.has(t) && !Array.from(baseText).some((b) => jaccard(tokenSet(b), tokenSet(t)) > 0.7));
        record.bytes = aiFetch.html.length;
        record.differs = aiFetch.html !== http.html;
        record.aiOnlyCount = aiOnly.length;
        record.status = 'probed';
        if (aiOnly.length && !cloak) {
          cloak = {
            bot: bot.token,
            vendor: bot.vendor,
            category: bot.category,
            uaUsed: bot.ua,
            triggerToken: bot.token,
            humanBytes: http.html.length,
            aiBytes: aiFetch.html.length,
            aiOnlySegments: aiOnly.slice(0, 8).map(excerpt),
            aiOnlyFull: aiOnly.slice(0, 8),
          };
        }
      } catch (err) {
        record.status = `probe failed: ${err.message}`;
      }
      uaProbe.push(record);
    }
    if (!permission.allowed && uaProbe.length) {
      uaProbe.push({
        token: null,
        status: permission.reason,
        scope: permission.scope,
        note: 'Sending crawler/fetcher User-Agents to third-party hosts needs explicit permission; ordinary page analysis does not imply it.',
      });
    }
  }

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

    const attrKind = occ.httpSource && ['data-attribute', 'attribute', 'hidden-input-value'].includes(occ.httpSource.extractionKind);
    if (occ.httpSource) {
      const srcKind = occ.httpSource.extractionKind || occ.httpSource.kind;
      if (srcKind === 'comment') signals.push({ type: 'html-comment', severity: 'high', detail: 'Only exists as an HTML comment in the raw source — invisible to human readers.' });
      if (srcKind === 'meta') signals.push({ type: 'meta-tag', severity: 'info', detail: 'Inside a <meta> tag — some agents ingest page metadata.' });
      if (srcKind === 'title') signals.push({ type: 'document-title', severity: 'info', detail: 'From the document <title> in <head>, which agents read before the body.' });
      if (srcKind === 'template') signals.push({ type: 'inert-template', severity: 'medium', detail: 'Inside a <template> element: never rendered for a human, but present in the source an agent may read.' });
      if (srcKind === 'noscript') signals.push({ type: 'noscript-content', severity: 'medium', detail: 'Inside <noscript>: shown only when scripting is off, but present in the source.' });
      if (srcKind === 'jsonld' || srcKind === 'jsonld-malformed') signals.push({ type: 'jsonld', severity: srcKind === 'jsonld-malformed' ? 'medium' : 'info', detail: srcKind === 'jsonld-malformed' ? 'Malformed JSON-LD kept as raw evidence (it could not be parsed and was not executed).' : 'A string value inside JSON-LD structured data.' });
      if (srcKind === 'cdata') signals.push({ type: 'cdata', severity: 'info', detail: 'Inside a CDATA section.' });
      if (attrKind) signals.push({ type: 'attribute-value', severity: 'high', detail: `Page-authored attribute value (${occ.httpSource.path}) — present in the source, but not rendered as text for a human.` });
      if (occ.httpSource.hasInvisible && occ.httpSource.invisibleClasses && occ.httpSource.invisibleClasses.length) {
        signals.push({ type: 'invisible-unicode', severity: 'high', detail: `Contains invisible Unicode: ${occ.httpSource.invisibleClasses.join(', ')}.` });
        if (occ.httpSource.decodedText) {
          signals.push({ type: 'decoded-invisible-text', severity: 'high', detail: `Invisible characters decode to: ${occ.httpSource.decodedText}` });
        }
      }
      if (occ.httpSource.hiddenHints && occ.httpSource.hiddenHints.length && (occ.httpSource.extractionKind || occ.httpSource.kind) === 'element') {
        signals.push({ type: 'hidden-in-source', severity: 'medium', detail: `Hidden hints in raw markup: ${occ.httpSource.hiddenHints.join(', ')}` });
      }
    }
    if (occ.renderedDom) {
      if (!occ.renderedDom.visible) {
        signals.push({ type: 'render-hidden', severity: 'high', detail: `Invisible after rendering: ${occ.renderedDom.hiddenReasons.join('; ')}` });
      }
      if (occ.renderedDom.zeroWidth) signals.push({ type: 'invisible-unicode', severity: 'high', detail: 'Contains invisible Unicode characters in the rendered DOM.' });
      if (occ.renderedDom.nearInvisibleReasons && occ.renderedDom.nearInvisibleReasons.length) {
        signals.push({ type: 'near-invisible', severity: 'high', detail: `Barely visible to a human: ${occ.renderedDom.nearInvisibleReasons.map((r) => `near-invisible: ${r}`).join('; ')}.` });
      }
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
    const delivery = detectDelivery(occ, humanVisible);
    // The segment-level impact model owns the decision: level, intents,
    // addressed-to-AI, discount, and the explanation the UI shows.
    //
    // We hand it the PRESERVED ORIGINAL evidence, never the deduplication key:
    // the group key is normalized (invisible characters already stripped), and
    // passing that would destroy the very evidence the normalizer must decode.
    const evidenceText = g.originalText;
    const assessment = assessSegment(
      {
        text: evidenceText,
        humanVisible,
        delivery,
        inCodeOrQuote: detectInCodeOrQuote(occ),
      },
      capabilityKey,
    );
    const legacyMatches = analyzeInstruction(evidenceText, inQuotedMarkup);
    const intents = assessment.intents.length ? assessment.intents : legacyMatches.map((m) => m.type);
    const primaryIntent = assessment.primaryIntent || (intents.length ? intents[0] : null);
    const quotedContext = assessment.intents.length
      ? assessment.discounted
      : (legacyMatches.length ? legacyMatches.every((m) => m.quotedContext) : inQuotedMarkup);
    const instruction = primaryIntent ? { type: primaryIntent } : null;
    const impact = { level: assessment.level, explanation: assessment.explanation };
    if (assessment.discounted) {
      signals.push({ type: 'quoted-context', severity: 'info', detail: 'Matches an injection pattern but sits in visible code/quote text, so it is likely quoted attack material rather than an instruction to follow.' });
    }
    if (assessment.decoded.length) {
      signals.push({ type: 'decoded-invisible-text', severity: 'high', detail: `Hidden Unicode tag characters decoded to: ${assessment.decoded.join(' | ')}` });
    }
    if (assessment.addressedToAI) {
      signals.push({ type: 'addressed-to-ai', severity: 'info', detail: 'The text talks to an AI/agent rather than to a human reader.' });
    }

    // evidence tier: kept for the UI and for the cloaking finding
    const hasStrongDelivery = signals.some((s) => ['html-comment', 'invisible-unicode', 'render-hidden', 'near-invisible', 'attribute-value', 'ai-visible-human-invisible'].includes(s.type));
    const hasWeakDelivery = signals.some((s) => ['hidden-in-source', 'raw-only', 'meta-tag', 'inert-template', 'noscript-content'].includes(s.type));
    let evidenceTier = 0;
    if (instruction) evidenceTier = 1;
    if (instruction && (hasStrongDelivery || hasWeakDelivery)) evidenceTier = 3;
    else if (instruction && (occ.httpSource || occ.renderedDom)) evidenceTier = 2;
    else if (!instruction && hasStrongDelivery) evidenceTier = 2;
    else if (!instruction && hasWeakDelivery) evidenceTier = 1;

    const interesting = !!instruction || signals.some((s) => s.severity !== 'info');

    if (interesting) {
      findings.push({
        id: 'F' + ++fid,
        excerpt: excerpt(evidenceText),
        fullText: evidenceText.length <= 600 ? evidenceText : evidenceText.slice(0, 600) + '…',
        // Original evidence and the normalized comparison key are both kept, so
        // the UI can show what the page actually contains.
        originalText: evidenceText,
        normalizedText: g.normalizedText,
        occurrences: occ.occurrences,
        humanVisible,
        delivery,
        aiProfiles,
        signals,
        instruction: instruction ? instruction.type : null,
        instructionTypes: intents,
        intents: assessment.intents,
        addressedToAI: assessment.addressedToAI,
        discounted: assessment.discounted,
        evidenceTier,
        quotedContext,
        impact,
        nodeRef: occ.renderedDom ? occ.renderedDom.id : null,
      });
    }

    if (interesting || aiProfiles.length >= 2 || (occ.httpSource && occ.renderedDom)) {
      matrix.push({
        key: g.key.slice(0, 60),
        excerpt: excerpt(evidenceText),
        humanVisible,
        delivery,
        httpSource: !!occ.httpSource,
        renderedDom: occ.renderedDom ? (occ.renderedDom.visible ? 'visible' : 'hidden') : 'absent',
        readerMarkdown: !!occ.readerMarkdown,
        accessibilityTree: !!occ.accessibilityTree,
        findingId: interesting ? 'F' + fid : null,
        instruction: instruction ? instruction.type : null,
        extractionKinds: Array.from(new Set(occ.occurrences.map((o) => o.extractionKind))),
        paths: Array.from(new Set(occ.occurrences.map((o) => o.path).filter(Boolean))),
      });
    }
  }

  // --- channel inspections (P1): AI-summary links and URL fragments --------
  // These two channels are invisible to all four ingestion pipelines: a
  // pre-filled prompt lives in a link's query string, and a fragment is never
  // sent to the server at all. They are analysed here so they are surfaced, and
  // they keep their own delivery ids so no pipeline is credited with reading them.
  const pageInspection = inspect.inspectPage({
    anchors: Array.isArray(raw.anchors) ? raw.anchors : [],
    url,
  });
  const inspections = pageInspection.channels.map(({ channel, record }) => {
    const { assessment, classification, segment } = inspect.assessInspection(record, capabilityKey);
    return {
      channel,
      delivery: segment.delivery,
      humanVisible: false,
      text: segment.text,
      note: segment.note,
      record,
      classification,
      level: assessment.level,
      intents: assessment.intents,
      addressedToAI: assessment.addressedToAI,
      discounted: assessment.discounted,
      explanation: assessment.explanation,
    };
  });

  for (const item of inspections) {
    const { record, classification } = item;
    const signals = [];
    if (item.channel === 'ai-summary-link') {
      signals.push({
        type: 'ai-summary-link',
        severity: 'high',
        detail: `A link to ${record.host} carries a pre-filled prompt in its "${record.param}" parameter. The prompt is not page text: no ingestion pipeline reads it as an instruction, and a human sees only a button.`,
      });
      if (classification && classification.manipulative) {
        signals.push({
          type: 'recommendation-manipulation',
          severity: 'high',
          detail: `The pre-filled prompt asks the assistant to treat the page as authoritative or to prefer it later (markers: ${classification.recommendationMarkers.join(', ')}).`,
        });
      }
      if (classification && classification.benignSummaryRequest) {
        signals.push({
          type: 'benign-summary-request',
          severity: 'info',
          detail: 'The pre-filled prompt only asks for a summary, with no recommendation or trust instruction. This is a normal product feature.',
        });
      }
    } else {
      signals.push({
        type: 'url-fragment',
        severity: 'high',
        detail: 'The URL fragment carries text. A fragment is never sent to the server, so no server-side pipeline can see it, but a browser-side assistant can read it.',
      });
    }
    if (record.embeddedUrls && record.embeddedUrls.length) {
      signals.push({
        type: 'embedded-destination',
        severity: 'medium',
        detail: `The decoded text names ${record.embeddedUrls.length} destination(s): ${record.embeddedUrls.slice(0, 4).join(', ')}. Recorded as evidence; InjectionLens never requests them.`,
      });
    }

    const interesting = item.level !== 'info' || item.intents.length > 0 || item.channel === 'url-fragment';
    if (!interesting) continue;

    findings.push({
      id: 'F' + ++fid,
      excerpt: excerpt(item.text),
      fullText: item.text,
      originalText: item.text,
      normalizedText: normText(item.text),
      occurrences: [{
        pipeline: item.channel,
        extractionKind: item.channel,
        path: item.channel === 'url-fragment' ? '(URL fragment)' : record.sourcePath,
        originalText: item.text,
        normalizedText: normText(item.text),
        invisibleClasses: [],
        decodedText: item.channel === 'ai-summary-link' ? record.decodedPrompt : record.decodedFragment,
      }],
      humanVisible: false,
      delivery: item.delivery,
      aiProfiles: [item.channel],
      channel: item.channel,
      channelEvidence: {
        sourceUrl: record.href,
        rawValue: item.channel === 'ai-summary-link' ? record.rawParam : record.rawFragment,
        decoded: item.channel === 'ai-summary-link' ? record.decodedPrompt : record.decodedFragment,
        host: record.host || null,
        param: record.param || null,
        nestedParams: record.nestedParams || null,
        linkText: record.linkText || null,
        embeddedUrls: record.embeddedUrls || [],
        sentToServer: item.channel === 'url-fragment' ? false : null,
      },
      classification: item.classification,
      signals,
      instruction: item.intents.length ? item.intents[0] : null,
      instructionTypes: item.intents,
      intents: item.intents,
      addressedToAI: item.addressedToAI,
      discounted: item.discounted,
      evidenceTier: 3,
      quotedContext: item.discounted,
      impact: { level: item.level, explanation: item.explanation },
      nodeRef: null,
    });
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.impact.level] - order[b.impact.level]);

  if (cloak) {
    const cloakText = (cloak.aiOnlyFull || []).join('\n');
    const cloakAssessment = assessSegment(
      { text: cloakText, humanVisible: false, delivery: 'ai-only', inCodeOrQuote: false },
      capabilityKey,
    );
    findings.unshift({
      id: 'F' + ++fid,
      excerpt: `Server returned ${cloak.aiOnlySegments.length}+ AI-only segment(s) to ${cloak.bot}`,
      fullText: cloak.aiOnlySegments.join('\n---\n'),
      humanVisible: false,
      delivery: 'ai-only',
      aiProfiles: ['http-source (AI-crawler UA)'],
      signals: [{ type: 'ua-cloaking', severity: 'critical', detail: `Same URL serves different content to ${cloak.bot} vs a browser UA (${cloak.humanBytes} B human vs ${cloak.aiBytes} B bot response).` }],
      instruction: cloakAssessment.primaryIntent,
      instructionTypes: cloakAssessment.intents,
      intents: cloakAssessment.intents,
      addressedToAI: cloakAssessment.addressedToAI,
      discounted: cloakAssessment.discounted,
      evidenceTier: 3,
      quotedContext: cloakAssessment.discounted,
      impact: { level: cloakAssessment.level, explanation: cloakAssessment.explanation },
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
      blockedSubrequests: policy.blockedRequests.length,
      assistantLinks: pageInspection.aiSummaryLinks.length,
      fragmentInspected: !!pageInspection.fragment,
    },
    cloak,
    uaProbe,
    blockedRequests: policy.blockedRequests.slice(),
    inspections,
    findings,
    levelCount,
    matrix,
    humanHtml: rendered.html,
    readerMarkdown: reader.markdown || '',
  };
}

module.exports = { analyze };
