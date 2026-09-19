// Pipeline A (HTTP source): parse raw HTML with jsdom — what a raw-fetch agent ingests
// Pipeline C (Reader/Markdown): Readability + Turndown — what a clean-read agent ingests
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');
const TurndownService = require('turndown');

const ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u2060]/;

function normText(s) {
  return (s || '').replace(/[\u200B-\u200D\uFEFF\u2060]/g, '').replace(/\s+/g, ' ').trim();
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

// ---------- Pipeline A: raw HTTP source ----------
function buildRawProfile(html) {
  const dom = new JSDOM(html);
  const doc = dom.window.document;
  const items = [];

  doc.querySelectorAll('body *').forEach((el) => {
    if (el.closest('script, style, noscript, template')) return;
    let own = '';
    for (const n of el.childNodes) if (n.nodeType === 3) own += n.nodeValue;
    const text = normText(own);
    if (!text) return;
    const styleAttr = (el.getAttribute('style') || '').replace(/\s+/g, '').toLowerCase();
    const cls = (el.getAttribute('class') || '').toLowerCase();
    const hiddenHints = [];
    if (el.hasAttribute('hidden')) hiddenHints.push('hidden attribute');
    if (styleAttr.includes('display:none')) hiddenHints.push('inline display:none');
    if (styleAttr.includes('visibility:hidden')) hiddenHints.push('inline visibility:hidden');
    if (/(^|\s)(sr-only|visually-hidden|screen-reader-only)(\s|$)/.test(cls)) hiddenHints.push('sr-only class');
    if (el.getAttribute('aria-hidden') === 'true') hiddenHints.push('aria-hidden');
    items.push({
      kind: 'element',
      tag: el.tagName.toLowerCase(),
      path: buildPath(el),
      text,
      zeroWidth: ZERO_WIDTH.test(own),
      hiddenHints,
      inCodeOrQuote: !!el.closest('pre, code, blockquote, kbd, samp'),
    });
  });

  const comments = [];
  const walker = dom.window.document.createTreeWalker(doc.documentElement, dom.window.NodeFilter.SHOW_COMMENT);
  let c = walker.nextNode();
  while (c) {
    const text = normText(c.nodeValue || '');
    if (text) comments.push({ kind: 'comment', tag: '#comment', path: '(HTML comment)', text, zeroWidth: ZERO_WIDTH.test(c.nodeValue || ''), hiddenHints: ['HTML comment'], inCodeOrQuote: false });
    c = walker.nextNode();
  }

  const metas = [];
  doc.querySelectorAll('meta').forEach((m) => {
    const content = normText(m.getAttribute('content') || '');
    if (content) metas.push({ kind: 'meta', tag: 'meta', path: `meta[name="${m.getAttribute('name') || m.getAttribute('property') || ''}"]`, text: content, zeroWidth: ZERO_WIDTH.test(content), hiddenHints: ['meta tag'], inCodeOrQuote: false });
  });

  return { items: [...items, ...comments, ...metas] };
}

// ---------- Pipeline C: Reader / Markdown ----------
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
    const text = normText(own || el.textContent);
    if (text) segments.push({ tag: el.tagName.toLowerCase(), text, inCodeOrQuote: !!el.closest('pre, code, blockquote') });
  });
  return { ok: true, title: article.title, segments, markdown };
}

module.exports = { buildRawProfile, buildReaderProfile, normText };
