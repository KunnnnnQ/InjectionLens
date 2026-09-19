// Pipeline A (HTTP source): parse raw HTML with jsdom — what a raw-fetch agent ingests
// Pipeline C (Reader/Markdown): Readability + Turndown — what a clean-read agent ingests
//
// Every extracted item preserves its original text alongside a normalized copy.
// The normalized copy is only a comparison key for grouping; the original is what
// reaches the risk normalizer, so an invisible-character payload is never lost
// before it has been inspected and decoded.
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const TurndownService = require('turndown');
const { decodeTagChars } = require('./risk');

const ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u2060]/;

// Characters that can hide a whole instruction. Grouped so the evidence can say
// which class was used instead of just "something invisible".
const INVISIBLE_CLASSES = [
  ['soft-hyphen', /[\u00AD]/g],
  ['arabic-letter-mark', /[\u061C]/g],
  ['mongolian-vowel-separator', /[\u180E]/g],
  ['zero-width', /[\u200B-\u200F]/g],
  ['bidi-control', /[\u202A-\u202E]/g],
  ['word-joiner', /[\u2060-\u2064]/g],
  ['bidi-isolate', /[\u2066-\u2069]/g],
  ['byte-order-mark', /[\uFEFF]/g],
  ['unicode-tag', /[\u{E0000}-\u{E007F}]/gu],
];

function normText(s) {
  return (s || '').replace(/[\u200B-\u200D\uFEFF\u2060]/g, '').replace(/\s+/g, ' ').trim();
}

/** Which invisible-character classes does this string use? */
function invisibleClasses(raw) {
  const text = typeof raw === 'string' ? raw : '';
  const found = [];
  for (const [name, re] of INVISIBLE_CLASSES) {
    re.lastIndex = 0;
    if (re.test(text)) found.push(name);
  }
  return found;
}

function hasInvisible(raw) {
  return invisibleClasses(raw).length > 0;
}

/**
 * Build the shared evidence fields for one extracted value.
 * @param {string} originalText the value exactly as authored
 * @param {{kind: string, path: string, pipeline: string, extra?: object}} meta
 */
function makeItem(originalText, meta) {
  const original = typeof originalText === 'string' ? originalText : '';
  const classes = invisibleClasses(original);
  return {
    originalText: original,
    normalizedText: normText(original),
    // Decoded payload for the channels that carry one; null when nothing was hidden.
    decodedText: classes.includes('unicode-tag') ? decodeTagChars(original) || null : null,
    invisibleClasses: classes,
    hasInvisible: classes.length > 0,
    extractionKind: meta.kind,
    path: meta.path,
    pipeline: meta.pipeline,
    // kept for existing callers/UI
    text: normText(original),
    zeroWidth: classes.length > 0,
    ...(meta.extra || {}),
  };
}

// ---------------------------------------------------------------------------
// Page-authored attribute extraction
// ---------------------------------------------------------------------------

// Attributes whose value is usually a URL, an ID, a token or styling rather than
// page-authored prose. Excluded so the report is not buried in noise.
const NON_TEXT_ATTRIBUTES = new Set([
  'href', 'src', 'srcset', 'action', 'formaction', 'poster', 'cite', 'ping',
  'style', 'class', 'id', 'name', 'for', 'rel', 'type', 'method', 'target',
  'integrity', 'crossorigin', 'referrerpolicy', 'srcset', 'sizes', 'media',
  'http-equiv', 'charset', 'content', 'role', 'tabindex', 'width', 'height',
  'viewbox', 'd', 'fill', 'stroke', 'points', 'transform', 'xmlns', 'lang',
]);

// InjectionLens instrumentation attributes. These are written by our own
// renderer, so they must never be reported as page evidence.
const INSTRUMENTATION_ATTRIBUTES = new Set(['data-ilid']);

const SENTENCE_ATTRIBUTES = [
  'alt', 'title', 'aria-label', 'aria-description', 'aria-placeholder',
  'placeholder', 'aria-roledescription', 'aria-valuetext', 'longdesc',
  'summary', 'abbr', 'label', 'download',
];

function looksLikeProse(value) {
  const v = (value || '').trim();
  if (v.length < 3) return false;
  if (!/\s/.test(v)) return false; // a single token is usually an identifier
  return /[A-Za-z\u4e00-\u9fff]/.test(v);
}

/**
 * Text-bearing attributes on one element. Each attribute becomes its own item —
 * unrelated attributes are never merged into one anonymous string.
 */
function collectAttributes(el, pathOf) {
  const out = [];
  const push = (attr, value, kind) => {
    if (!value) return;
    out.push(makeItem(value, { kind, path: `${pathOf(el)}@${attr}`, pipeline: 'http-source' }));
  };

  for (const attr of SENTENCE_ATTRIBUTES) {
    if (!el.hasAttribute(attr)) continue;
    const value = el.getAttribute(attr) || '';
    // title/alt on a non-text element can be an ID; prefer prose, but keep short
    // human-readable titles such as an SVG <title> handled elsewhere.
    if (attr === 'summary' || attr === 'abbr' || attr === 'label' || attr === 'download') {
      if (value.trim().length >= 3) push(attr, value, 'attribute');
      continue;
    }
    if (looksLikeProse(value) || value.trim().length >= 12) push(attr, value, 'attribute');
  }

  // Hidden form values are read by agents that submit or parse forms.
  if (el.tagName.toLowerCase() === 'input' && (el.getAttribute('type') || '').toLowerCase() === 'hidden') {
    const value = el.getAttribute('value') || '';
    if (value.trim()) push('value', value, 'hidden-input-value');
  }

  for (const attr of Array.from(el.attributes || [])) {
    const name = attr.name.toLowerCase();
    if (!name.startsWith('data-')) continue;
    if (INSTRUMENTATION_ATTRIBUTES.has(name)) continue; // never our own data-ilid
    const value = attr.value || '';
    if (!value.trim()) continue;
    if (NON_TEXT_ATTRIBUTES.has(name)) continue;
    // data-* is where real-world payloads hide, so keep anything prose-like and
    // anything long enough to carry an instruction.
    if (looksLikeProse(value) || value.trim().length >= 8) push(name, value, 'data-attribute');
  }
  return out;
}

// ---------------------------------------------------------------------------
// Non-body / structured content
// ---------------------------------------------------------------------------

/** JSON-LD: parse safely, walk nested arrays/objects, keep readable paths. */
function collectJsonLd(rawJson, sourceLabel) {
  const out = [];
  let parsed;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    // Malformed JSON-LD must not abort the scan; keep it as raw evidence.
    return [makeItem(rawJson, {
      kind: 'jsonld-malformed',
      path: sourceLabel,
      pipeline: 'http-source',
      extra: { parseError: true },
    })];
  }
  const walk = (node, path) => {
    if (typeof node === 'string') {
      const value = node.trim();
      if (value.length >= 8) out.push(makeItem(node, { kind: 'jsonld', path, pipeline: 'http-source' }));
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child, i) => walk(child, `${path}[${i}]`));
      return;
    }
    if (node && typeof node === 'object') {
      for (const [key, value] of Object.entries(node)) walk(value, path ? `${path}.${key}` : key);
    }
  };
  walk(parsed, '');
  return out;
}

function buildPath(el) {
  const parts = [];
  let cur = el;
  while (cur && cur.nodeType === 1 && cur.tagName.toLowerCase() !== 'body') {
    const parent = cur.parentElement;
    let idx = 1;
    let sameCount = 1;
    if (parent) {
      const same = Array.from(parent.children).filter((c) => c.tagName === cur.tagName);
      idx = same.indexOf(cur) + 1;
      sameCount = same.length;
    }
    parts.unshift(`${cur.tagName.toLowerCase()}${sameTagIndex(sameCount, idx)}`);
    cur = cur.parentElement;
  }
  return 'body > ' + parts.join(' > ');
}

function sameTagIndex(total, idx) {
  return total > 1 ? `:nth-of-type(${idx})` : '';
}

// Readable path for elements outside <body>: never depends on our own injected
// instrumentation attribute.
function documentPath(el) {
  const tag = el.tagName.toLowerCase();
  const parent = el.parentElement;
  if (!parent) return tag;
  const same = Array.from(parent.children).filter((c) => c.tagName === el.tagName);
  const idx = same.indexOf(el) + 1;
  return `${documentPath(parent)} > ${tag}${sameTagIndex(same.length, idx)}`;
}

// ---------------------------------------------------------------------------
// Pipeline A: raw HTTP source
// ---------------------------------------------------------------------------
function buildRawProfile(html) {
  const dom = new JSDOM(html);
  const doc = dom.window.document;
  const items = [];

  // --- body elements: own text + attributes ---
  doc.querySelectorAll('body *').forEach((el) => {
    if (el.closest('script, style, noscript, template')) return;
    let own = '';
    for (const n of el.childNodes) if (n.nodeType === 3) own += n.nodeValue;
    const text = normText(own);
    if (text) {
      const styleAttr = (el.getAttribute('style') || '').replace(/\s+/g, '').toLowerCase();
      const cls = (el.getAttribute('class') || '').toLowerCase();
      const hiddenHints = [];
      if (el.hasAttribute('hidden')) hiddenHints.push('hidden attribute');
      if (styleAttr.includes('display:none')) hiddenHints.push('inline display:none');
      if (styleAttr.includes('visibility:hidden')) hiddenHints.push('inline visibility:hidden');
      if (/(^|\s)(sr-only|visually-hidden|screen-reader-only)(\s|$)/.test(cls)) hiddenHints.push('sr-only class');
      if (el.getAttribute('aria-hidden') === 'true') hiddenHints.push('aria-hidden');
      items.push(makeItem(own, {
        kind: 'element',
        path: buildPath(el),
        pipeline: 'http-source',
        extra: { tag: el.tagName.toLowerCase(), inCodeOrQuote: !!el.closest('pre, code, blockquote, kbd, samp'), hiddenHints },
      }));
    }
    items.push(...collectAttributes(el, buildPath));
  });

  // --- comments ---
  const walker = doc.createTreeWalker(doc.documentElement, dom.window.NodeFilter.SHOW_COMMENT);
  let c = walker.nextNode();
  while (c) {
    const raw = c.nodeValue || '';
    if (normText(raw)) {
      items.push(makeItem(raw, {
        kind: 'comment',
        path: '(HTML comment)',
        pipeline: 'http-source',
        extra: { tag: '#comment', hiddenHints: ['HTML comment'], inCodeOrQuote: false },
      }));
    }
    c = walker.nextNode();
  }

  // --- meta tags ---
  doc.querySelectorAll('meta').forEach((m) => {
    const content = m.getAttribute('content') || '';
    if (normText(content)) {
      items.push(makeItem(content, {
        kind: 'meta',
        path: `meta[name="${m.getAttribute('name') || m.getAttribute('property') || ''}"]`,
        pipeline: 'http-source',
        extra: { tag: 'meta', hiddenHints: ['meta tag'], inCodeOrQuote: false, metaName: m.getAttribute('name') || m.getAttribute('property') || '' },
      }));
    }
  });

  // --- document title (head content an agent reads before the body) ---
  if (doc.title && normText(doc.title)) {
    items.push(makeItem(doc.title, {
      kind: 'title',
      path: 'head > title',
      pipeline: 'http-source',
      extra: { tag: 'title', hiddenHints: ['document title'], inCodeOrQuote: false },
    }));
  }

  // --- head attributes, noscript, template, SVG text, JSON-LD, CDATA ---
  // Attributes in <head> (meta/title/link, and any data-* an author added) are
  // ingested by raw-fetch agents even though a human never sees them.
  doc.querySelectorAll('head *').forEach((el) => {
    items.push(...collectAttributes(el, documentPath));
  });

  doc.querySelectorAll('noscript').forEach((el) => {
    const text = el.textContent || '';
    if (!normText(text)) return;
    // A <noscript> body is markup when scripting is off; the text is what an
    // agent that does not execute scripts would read.
    const inner = new JSDOM(text).window.document.body;
    if (inner && normText(inner.textContent)) {
      items.push(makeItem(inner.textContent, {
        kind: 'noscript',
        path: `${documentPath(el)} (parsed content)`,
        pipeline: 'http-source',
        extra: { tag: 'noscript', hiddenHints: ['noscript'], inCodeOrQuote: false },
      }));
    } else {
      items.push(makeItem(text, {
        kind: 'noscript',
        path: documentPath(el),
        pipeline: 'http-source',
        extra: { tag: 'noscript', hiddenHints: ['noscript'], inCodeOrQuote: false },
      }));
    }
  });

  doc.querySelectorAll('template').forEach((el) => {
    // A <template> never renders, so its markup is INERT: it lives in
    // el.content (a DocumentFragment), not in the element's rendered children.
    const content = el.content ? el.content.textContent : '';
    const text = content || el.textContent || '';
    if (!normText(text)) return;
    items.push(makeItem(text, {
      kind: 'template',
      path: `${documentPath(el)} (inert content)`,
      pipeline: 'http-source',
      extra: { tag: 'template', hiddenHints: ['template (not rendered)'], inCodeOrQuote: false },
    }));
  });

  // SVG <title>/<desc>/<text> carry page-authored text. The element walk above
  // already records their text as element items, so only their attributes are
  // added here — nothing is extracted twice.
  doc.querySelectorAll('svg title, svg desc, svg text').forEach((el) => {
    items.push(...collectAttributes(el, documentPath));
  });

  doc.querySelectorAll('script[type="application/ld+json"]').forEach((el, i) => {
    const raw = el.textContent || '';
    if (!raw.trim()) return;
    const label = doc.querySelectorAll('script[type="application/ld+json"]').length > 1
      ? `script[type="application/ld+json"]:nth-of-type(${i + 1})`
      : 'script[type="application/ld+json"]';
    // Never executed: only parsed as data.
    items.push(...collectJsonLd(raw, label));
  });

  // --- CDATA sections (only meaningful in XML-ish content, kept for completeness) ---
  const cdataRe = /<!\[CDATA\[([\s\S]*?)\]\]>/g;
  let cd;
  let cdi = 0;
  while ((cd = cdataRe.exec(html)) !== null) {
    cdi++;
    if (!normText(cd[1])) continue;
    items.push(makeItem(cd[1], {
      kind: 'cdata',
      path: `CDATA section #${cdi}`,
      pipeline: 'http-source',
      extra: { hiddenHints: ['CDATA section'], inCodeOrQuote: false },
    }));
  }

  return { items };
}

// ---------------------------------------------------------------------------
// Pipeline C: Reader / Markdown
// ---------------------------------------------------------------------------
function buildReaderProfile(renderedHtml) {
  const dom = new JSDOM(renderedHtml, { url: 'https://injectionlens.local/' });
  let article = null;
  try {
    article = new Readability(dom.window.document).parse();
  } catch {
    article = null;
  }
  if (!article) return { ok: false, segments: [], markdown: '' };

  const turndown = new TurndownService({ headingStyle: 'atx', codeBlockStyle: 'fenced' });
  const markdown = turndown.turndown(article.content || '');
  const adom = new JSDOM(article.content || '<div></div>').window.document;
  const segments = [];
  adom.querySelectorAll('p, li, h1, h2, h3, h4, h5, h6, blockquote, td, figcaption').forEach((el) => {
    let own = '';
    for (const n of el.childNodes) if (n.nodeType === 3) own += n.nodeValue;
    const raw = own || el.textContent || '';
    if (normText(raw)) {
      segments.push(makeItem(raw, {
        kind: 'reader-segment',
        path: `reader > ${el.tagName.toLowerCase()}`,
        pipeline: 'reader-markdown',
        extra: { tag: el.tagName.toLowerCase(), inCodeOrQuote: !!el.closest('pre, code, blockquote') },
      }));
    }
  });
  return { ok: true, title: article.title, segments, markdown };
}

module.exports = {
  buildRawProfile,
  buildReaderProfile,
  normText,
  invisibleClasses,
  hasInvisible,
  makeItem,
  collectJsonLd,
  collectAttributes,
  INVISIBLE_CLASSES,
  INSTRUMENTATION_ATTRIBUTES,
};
