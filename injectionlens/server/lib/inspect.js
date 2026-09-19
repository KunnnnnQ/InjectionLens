// P1 inspection: AI-summary links and URL fragments.
//
// Two channel-level checks that the four ingestion pipelines cannot see:
//
//   AI-summary links ("summarize with AI" / "ask AI" links)
//     A page can offer a link to an AI assistant with the question pre-filled
//     in the query string. The prompt is not page text, so no ingestion pipeline
//     reads it as an instruction; the human sees only a button. This module
//     decodes the pre-filled prompt and analyses it LOCALLY, exactly like any
//     other candidate instruction.
//
//   URL fragments (#...)
//     A fragment is never sent to the server, so it is absent from the HTTP
//     source and from anything the server returns, yet a browser-side assistant
//     can read it. HashJack (Cato CTRL, 2025-11) is the published case.
//
// Both are reported as their own delivery channels ('ai-link-prompt' and
// 'url-fragment') so they are never attributed to the HTTP-source pipeline.
//
// Safety rules this module implements rather than documents:
//   - nothing here performs network I/O; it only reads strings already fetched;
//   - a decoded prompt is analysed as text and never submitted anywhere;
//   - a URL found inside a decoded prompt is recorded as evidence and NEVER
//     followed, requested or resolved.
'use strict';

const { assessSegment } = require('./risk');

// ---------------------------------------------------------------------------
// Recognised assistant links
// ---------------------------------------------------------------------------

/**
 * Pre-filled prompt parameter names. `q` is what the published cases used
 * (chatgpt.com/?q=..., claude.ai/new?q=...), plus the obvious variants.
 */
const PROMPT_PARAM_NAMES = ['q', 'query', 'prompt', 'text'];

/**
 * Hosts whose links are treated as assistant links.
 *
 * Two groups, and the distinction matters:
 *   - reserved test hosts (.example/.invalid/.test) so the evaluation fixtures
 *     can exercise the recogniser without pointing at anything real;
 *   - the assistant hosts named in the published reports, recognised by string
 *     match only. InjectionLens never requests them.
 */
const ASSISTANT_HOST_PATTERNS = [
  /(^|\.)example$/i,
  /(^|\.)invalid$/i,
  /(^|\.)test$/i,
  /(^|\.)chatgpt\.com$/i,
  /(^|\.)chat\.openai\.com$/i,
  /(^|\.)claude\.ai$/i,
  /(^|\.)gemini\.google\.com$/i,
  /(^|\.)perplexity\.ai$/i,
  /(^|\.)copilot\.microsoft\.com$/i,
];

/**
 * Paths that mark a link as an assistant conversation starter. `/?q=` on a bare
 * assistant host counts, which is the documented "Summarize with AI" shape.
 */
const ASSISTANT_PATH_HINTS = [/^\/$/, /^\/new\/?$/i, /^\/search\/?$/i, /^\/chat\/?$/i, /^\/ask\/?$/i];

function isAssistantHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.+$/, '');
  if (!host) return false;
  return ASSISTANT_HOST_PATTERNS.some((re) => re.test(host));
}

function promptParamOf(url) {
  for (const name of PROMPT_PARAM_NAMES) {
    const value = url.searchParams.get(name);
    if (value && value.trim() !== '') return { name, value };
  }
  return null;
}

/**
 * Find assistant links carrying a pre-filled prompt.
 *
 * @param {Array<{href: string, text?: string, path?: string}>} anchors
 * @returns {Array<object>} inspection records, one per decoded prompt
 */
function inspectAssistantLinks(anchors = []) {
  const found = [];
  for (const anchor of anchors) {
    const href = String(anchor && anchor.href ? anchor.href : '');
    if (!href) continue;
    let url;
    try {
      url = new URL(href);
    } catch {
      continue; // relative or malformed: not an assistant link
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
    if (!isAssistantHost(url.hostname)) continue;
    const param = promptParamOf(url);
    if (!param) continue;
    if (!ASSISTANT_PATH_HINTS.some((re) => re.test(url.pathname))) continue;

    // Decoded by URLSearchParams; kept beside the raw value so a reviewer can
    // see exactly what the page carried.
    const decoded = param.value;
    found.push({
      kind: 'ai-summary-link',
      host: url.hostname.toLowerCase(),
      path: url.pathname,
      param: param.name,
      href,
      // The raw parameter as it appeared in the query string.
      rawParam: rawParamOf(href, param.name),
      decodedPrompt: decoded,
      // A prompt that names a destination is evidence, never a target.
      embeddedUrls: extractUrls(decoded),
      linkText: String((anchor && anchor.text) || '').trim(),
      sourcePath: anchor && anchor.path ? anchor.path : null,
    });
  }
  return found;
}

function rawParamOf(href, name) {
  const match = new RegExp(`[?&]${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=([^&#]*)`).exec(href);
  return match ? match[1] : null;
}

/**
 * URLs mentioned inside a prompt. Recorded so the report can say "this prompt
 * also names an address"; nothing here is contacted.
 */
function extractUrls(text) {
  const out = [];
  for (const match of String(text || '').matchAll(/https?:\/\/[^\s"'<>)\]]+/gi)) out.push(match[0]);
  for (const match of String(text || '').matchAll(/[\w.+-]+@[\w-]+\.[\w.]+/g)) {
    if (!out.includes(match[0])) out.push(match[0]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Prompt classification
//
// The distinction the reports draw: asking an assistant to summarise a page is a
// normal product feature; asking it to REMEMBER the page as authoritative, or to
// prefer it later, is recommendation manipulation.
// ---------------------------------------------------------------------------

const SUMMARY_REQUEST = /\b(summar(?:y|ise|ize)|tldr|tl;dr|overview|key\s+points?|explain\s+this)\b/i;
const RECOMMENDATION_MARKERS = [
  { id: 'trusted-source', re: /\b(trusted|authoritative|reliable|official)\s+(source|reference|site|page)\b/i },
  { id: 'remember', re: /\b(remember|memorize|memorise|note|store|keep\s+in\s+mind|save)\b[\s\S]{0,60}?\b(as|that|this|for\s+(all\s+)?(later|future|subsequent))/i },
  { id: 'prefer', re: /\b(prefer|prioriti[sz]e|recommend|rank|choose|pick|favour|favor)\b[\s\S]{0,40}?\b(this|us|our|first|above|over|instead)\b/i },
  { id: 'always-mention', re: /\b(always|whenever|every\s+time|from\s+now\s+on)\b[\s\S]{0,40}?\b(mention|cite|recommend|suggest|include|say|state)\b/i },
  { id: 'citation', re: /\b(cite|quote|reference|link\s+to)\s+(this|us|our|the\s+page)\b/i },
];

function classifyPrompt(promptText) {
  const text = String(promptText || '');
  const markers = RECOMMENDATION_MARKERS.filter((marker) => marker.re.test(text)).map((marker) => marker.id);
  const asksForSummary = SUMMARY_REQUEST.test(text);
  return {
    asksForSummary,
    recommendationMarkers: markers,
    manipulative: markers.length > 0,
    // A summary request with no recommendation markers is the benign shape.
    benignSummaryRequest: asksForSummary && markers.length === 0,
  };
}

// ---------------------------------------------------------------------------
// URL fragments
// ---------------------------------------------------------------------------

/**
 * Decode a URL fragment, including the common nested form where the fragment
 * itself looks like a query string (`#q=...`, `#prompt=...`).
 */
function inspectFragment(rawUrl) {
  let url;
  try {
    url = new URL(String(rawUrl));
  } catch {
    return null;
  }
  const hash = url.hash || '';
  if (hash === '' || hash === '#') return null;

  const rawFragment = hash.slice(1);
  let decoded = rawFragment;
  try {
    decoded = decodeURIComponent(rawFragment);
  } catch {
    decoded = rawFragment; // malformed escapes are kept as-is, not dropped
  }

  // A fragment shaped like "q=..." or "?q=..." carries a named parameter.
  const nested = {};
  const paramText = decoded.replace(/^\?/, '');
  if (/^[^=&\s]+=[\s\S]*$/.test(paramText)) {
    for (const pair of paramText.split('&')) {
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const key = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      let valueDecoded = value;
      try {
        valueDecoded = decodeURIComponent(value.replace(/\+/g, ' '));
      } catch {
        valueDecoded = value;
      }
      nested[key] = valueDecoded;
    }
  }

  return {
    kind: 'url-fragment',
    href: String(rawUrl),
    rawFragment,
    decodedFragment: decoded,
    nestedParams: Object.keys(nested).length ? nested : null,
    embeddedUrls: extractUrls(decoded),
    // Stated in the record so the report cannot imply server-side visibility.
    sentToServer: false,
  };
}

// ---------------------------------------------------------------------------
// Turning an inspection into an assessable segment
// ---------------------------------------------------------------------------

/**
 * The text a record contributes to the risk model, and the delivery it arrived
 * through. Both are explicit so nothing is ever attributed to the wrong channel.
 */
function segmentFor(record) {
  if (!record) return null;
  if (record.kind === 'ai-summary-link') {
    return {
      text: record.decodedPrompt,
      delivery: 'ai-link-prompt',
      humanVisible: false,
      inCodeOrQuote: false,
      note: `pre-filled prompt in the ${record.param} parameter of a link to ${record.host}`,
    };
  }
  if (record.kind === 'url-fragment') {
    // The decoded fragment, and the nested parameter values when present: those
    // are the parts an assistant would actually read as an instruction.
    const text = record.nestedParams
      ? Object.values(record.nestedParams).join('\n')
      : record.decodedFragment;
    return {
      text,
      delivery: 'url-fragment',
      humanVisible: false,
      inCodeOrQuote: false,
      note: 'URL fragment; never sent to the server, so no server-side pipeline can see it',
    };
  }
  return null;
}

/**
 * Assess one inspection record under one capability template.
 *
 * @returns {{record: object, assessment: object|null, classification: object|null}}
 */
function assessInspection(record, capabilityKey) {
  const segment = segmentFor(record);
  if (!segment) return { record, assessment: null, classification: null };
  const assessment = assessSegment(
    {
      text: segment.text,
      humanVisible: segment.humanVisible,
      delivery: segment.delivery,
      inCodeOrQuote: segment.inCodeOrQuote,
    },
    capabilityKey,
  );
  const classification = record.kind === 'ai-summary-link' ? classifyPrompt(record.decodedPrompt) : null;
  return { record, assessment, classification, segment };
}

/**
 * Run every inspection channel over one already-fetched page.
 *
 * @param {{anchors?: Array, url?: string}} input anchors are the page's <a>
 *        hrefs; no network access happens here.
 */
function inspectPage({ anchors = [], url = null } = {}) {
  const links = inspectAssistantLinks(anchors);
  const fragment = url ? inspectFragment(url) : null;
  return {
    aiSummaryLinks: links,
    fragment,
    channels: [
      ...links.map((record) => ({ channel: 'ai-summary-link', record })),
      ...(fragment ? [{ channel: 'url-fragment', record: fragment }] : []),
    ],
  };
}

module.exports = {
  PROMPT_PARAM_NAMES,
  ASSISTANT_HOST_PATTERNS,
  ASSISTANT_PATH_HINTS,
  RECOMMENDATION_MARKERS,
  isAssistantHost,
  promptParamOf,
  extractUrls,
  classifyPrompt,
  inspectAssistantLinks,
  inspectFragment,
  segmentFor,
  assessInspection,
  inspectPage,
};
