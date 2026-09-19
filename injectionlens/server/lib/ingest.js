// Ingestion: HTTP fetch (with UA variants) + headless render (DOM + accessibility tree)
const { withPage } = require('./browser');

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

const AI_CRAWLER_UAS = [
  { bot: 'GPTBot', ua: 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' },
  { bot: 'ClaudeBot', ua: 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +anthropic.com/claudebot)' },
  { bot: 'PerplexityBot', ua: 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' },
];

async function fetchHtml(url, ua = BROWSER_UA, timeoutMs = 15000) {
  const res = await fetch(url, {
    headers: { 'User-Agent': ua, Accept: 'text/html,application/xhtml+xml' },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
  });
  const html = await res.text();
  return {
    html,
    status: res.status,
    finalUrl: res.url,
    headers: { 'content-type': res.headers.get('content-type'), 'server': res.headers.get('server') },
  };
}

// Render the page in headless Chrome: full serialized DOM (tagged with data-ilid),
// per-element visibility forensics, comments, meta tags, and the accessibility tree.
async function renderPage(url) {
  return withPage(async (page) => {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    await page.waitForTimeout(600);

    const rendered = await page.evaluate(() => {
      const items = [];
      let counter = 0;
      const ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u2060]/;

      const ownText = (el) => {
        let t = '';
        for (const n of el.childNodes) if (n.nodeType === Node.TEXT_NODE) t += n.nodeValue;
        return t;
      };

      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
      let el = walker.currentNode;
      while (el) {
        const text = ownText(el).replace(/\s+/g, ' ').trim();
        if (text) {
          const id = 'il' + counter++;
          el.setAttribute('data-ilid', id);
          const cs = getComputedStyle(el);
          const r = el.getBoundingClientRect();
          const hiddenReasons = [];
          if (cs.display === 'none') hiddenReasons.push('display:none');
          if (cs.visibility === 'hidden' || cs.visibility === 'collapse') hiddenReasons.push(`visibility:${cs.visibility}`);
          if (parseFloat(cs.opacity) === 0) hiddenReasons.push('opacity:0');
          if (parseFloat(cs.fontSize) === 0) hiddenReasons.push('font-size:0');
          if (cs.color === cs.backgroundColor && cs.color !== 'rgba(0, 0, 0, 0)') hiddenReasons.push(`text matches background (${cs.color})`);
          if (r.width === 0 || r.height === 0) hiddenReasons.push('zero-size box');
          else if (r.x + r.width < 0 || r.y + r.height < 0) hiddenReasons.push('off-screen');
          const inCodeOrQuote = !!(el.closest('pre, code, blockquote, kbd, samp'));
          items.push({
            id,
            tag: el.tagName.toLowerCase(),
            cls: typeof el.className === 'string' ? el.className.slice(0, 80) : '',
            text,
            zeroWidth: ZERO_WIDTH.test(ownText(el)),
            hiddenReasons,
            visible: hiddenReasons.length === 0,
            inCodeOrQuote,
            rect: { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) },
          });
        }
        el = walker.nextNode();
      }

      const comments = [];
      const cwalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
      let c = cwalker.nextNode();
      while (c) {
        const text = (c.nodeValue || '').replace(/\s+/g, ' ').trim();
        if (text) comments.push({ text });
        c = cwalker.nextNode();
      }

      const metas = [];
      document.querySelectorAll('meta').forEach((m) => {
        const content = (m.getAttribute('content') || '').trim();
        if (content) metas.push({ name: m.getAttribute('name') || m.getAttribute('property') || '(unnamed)', content });
      });

      return {
        html: document.documentElement.outerHTML,
        items,
        comments,
        metas,
        title: document.title,
      };
    });

    // playwright-core >=1.57 removed page.accessibility — use the CDP AX tree directly
    let a11yNodes = [];
    try {
      const cdp = await page.context().newCDPSession(page);
      const { nodes } = await cdp.send('Accessibility.getFullAXTree');
      a11yNodes = (nodes || [])
        .filter((n) => n.role && n.role.value && !['none', 'presentation', 'generic', 'InlineTextBox'].includes(n.role.value))
        .map((n) => ({
          role: n.role.value,
          name: typeof n.name?.value === 'string' ? n.name.value : '',
        }));
      await cdp.detach().catch(() => {});
    } catch { /* a11y pipeline is best-effort */ }

    return { ...rendered, a11yNodes };
  });
}

function flattenA11y(node, out = []) {
  if (!node) return out;
  if (node.name && typeof node.name === 'string') {
    const name = node.name.replace(/\s+/g, ' ').trim();
    if (name) out.push({ role: node.role || '?', name });
  }
  (node.children || []).forEach((c) => flattenA11y(c, out));
  return out;
}

module.exports = { fetchHtml, renderPage, flattenA11y, BROWSER_UA, AI_CRAWLER_UAS };
