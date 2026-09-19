// Ingestion: HTTP fetch (with UA variants) + headless render (DOM + accessibility tree)
const { withPage } = require('./browser');
const { defaultPolicy, fetchWithRedirects, createBrowserRequestGuard } = require('./net-guard');

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

/**
 * Verified AI-agent User-Agent inventory.
 *
 * Only the TOKEN is recorded here, because that is all the vendors document —
 * inventing a full "Mozilla/5.0 (compatible; ...)" string would be dressing up a
 * guess as a citation. `token` is the exact string used in the User-Agent header
 * for probes; a real client usually embeds the token in a longer UA, which is
 * why detection elsewhere matches the token as a substring rather than equality.
 *
 * sourceStatus records how far the token was actually verified in this run:
 *   'vendor-primary'  the exact token and category were read from an accessible
 *                     official vendor page during the run;
 *   'secondary'       the token was corroborated only by third-party
 *                     documentation (Cloudflare's bot reference), because the
 *                     vendor's own page was unreachable.
 * The full record, including the exact URLs and HTTP results, is in
 * eval/results/stage4-ua-sources.txt.
 */
const AI_CRAWLER_UAS = [
  // --- training crawlers: collect page content for model development ---
  { token: 'GPTBot', vendor: 'OpenAI', category: 'training', sourceStatus: 'secondary', doc: 'https://developers.openai.com/api/docs/bots' },
  { token: 'ClaudeBot', vendor: 'Anthropic', category: 'training', sourceStatus: 'vendor-primary', doc: 'https://privacy.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler' },
  // --- search crawlers: build a search index ---
  { token: 'PerplexityBot', vendor: 'Perplexity', category: 'search', sourceStatus: 'secondary', doc: 'https://docs.perplexity.ai/docs/resources/perplexity-crawlers' },
  { token: 'OAI-SearchBot', vendor: 'OpenAI', category: 'search', sourceStatus: 'secondary', doc: 'https://developers.openai.com/api/docs/bots' },
  { token: 'Claude-SearchBot', vendor: 'Anthropic', category: 'search', sourceStatus: 'vendor-primary', doc: 'https://privacy.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler' },
  // --- user-triggered fetchers: fetch a page because a person asked ---
  { token: 'ChatGPT-User', vendor: 'OpenAI', category: 'user-triggered', sourceStatus: 'secondary', doc: 'https://developers.openai.com/api/docs/bots' },
  { token: 'Claude-User', vendor: 'Anthropic', category: 'user-triggered', sourceStatus: 'vendor-primary', doc: 'https://privacy.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler' },
  { token: 'Perplexity-User', vendor: 'Perplexity', category: 'user-triggered', sourceStatus: 'secondary', doc: 'https://docs.perplexity.ai/docs/resources/perplexity-crawlers' },
].map((b) => ({ ...b, ua: b.token }));

// Detection tokens for the fixture server. Google-Extended is deliberately NOT
// here: it is a robots.txt product token, not an HTTP User-Agent (plan §3 item 9).
const CRAWLER_UA_TOKENS = AI_CRAWLER_UAS.map((b) => b.token);

function detectCrawlerToken(userAgent) {
  if (!userAgent) return null;
  const hit = AI_CRAWLER_UAS.find((b) => userAgent.includes(b.token));
  return hit ? hit.token : null;
}

/**
 * UA probing permission boundary.
 *
 * Sending a crawler or AI-fetcher User-Agent is a different act from reading a
 * page as a browser: it tells the server "an AI agent is here". Permission to
 * analyse a page does NOT imply permission to send those UAs, so probing is
 * limited to the local fixture origin and to hosts named explicitly in
 * INJECTIONLENS_UA_PROBE_ALLOWLIST.
 */
function uaProbePermission(targetUrl, policy = defaultPolicy) {
  let url;
  try {
    url = new URL(String(targetUrl));
  } catch {
    return { allowed: false, reason: 'UA probe skipped: malformed URL' };
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);
  // The fixture boundary comes from the SAME policy that authorises the fetch.
  // Comparing against a process-global default would misjudge any run that
  // binds a different port (the smoke runner uses an ephemeral one).
  const local = policy.isFixtureOrigin
    ? policy.isFixtureOrigin(host, port)
    : defaultPolicy.isFixtureOrigin(host, port);
  if (local) {
    return { allowed: true, scope: 'local-fixture', reason: null };
  }
  const extra = (process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (extra.includes(host)) return { allowed: true, scope: 'explicit-allowlist', reason: null };
  return {
    allowed: false,
    scope: 'third-party',
    reason: 'UA probe skipped: third-party host (crawler/fetcher UA probing is limited to the local fixture server unless the host is in INJECTIONLENS_UA_PROBE_ALLOWLIST)',
  };
}

async function fetchHtml(url, ua = BROWSER_UA, timeoutMs = 15000, policy = defaultPolicy) {
  const { response, html } = await fetchWithRedirects(url, {
    headers: { 'User-Agent': ua, Accept: 'text/html,application/xhtml+xml' },
    timeoutMs,
    policy,
  });
  return {
    html,
    status: response.status,
    finalUrl: response.url,
    headers: { 'content-type': response.headers.get('content-type'), 'server': response.headers.get('server') },
  };
}

// Render the page in headless Chrome: full serialized DOM (tagged with data-ilid),
// per-element visibility forensics, comments, meta tags, and the accessibility tree.
// Every navigation and subresource request is filtered by the network boundary.
async function renderPage(url, { policy = defaultPolicy, blockedRequests } = {}) {
  return withPage(async (page) => {
    await page.context().route('**/*', createBrowserRequestGuard(policy, (entry) => {
      if (blockedRequests) blockedRequests.push(entry);
    }));
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    await page.waitForTimeout(600);

    const rendered = await page.evaluate(() => {
      const items = [];
      let counter = 0;
      const ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u2060]/;

      // Thresholds for "a human would not notice this". Near-invisible content is
      // reported as evidence, never as proof of malice.
      const NEAR_INVISIBLE = {
        maxFontSizePx: 4,      // below this the text is not readable
        maxOpacity: 0.1,       // effective opacity, ancestors multiplied
        maxTextAlpha: 0.1,     // alpha channel of the text colour
        minContrast: 1.2,      // WCAG-style contrast ratio against the effective background
        tinyBoxPx: 2,          // a box this small with overflow hidden clips the text
        offScreenPx: -9999,    // text-indent / absolute positioning trick
      };

      const ownText = (el) => {
        let t = '';
        for (const n of el.childNodes) if (n.nodeType === Node.TEXT_NODE) t += n.nodeValue;
        return t;
      };

      const round2 = (n) => Math.round(n * 100) / 100;

      const parseColor = (value) => {
        const m = String(value || '').match(/rgba?\(([^)]+)\)/);
        if (!m) return null;
        const parts = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
        if (parts.length < 3 || parts.some((n) => !Number.isFinite(n))) return null;
        return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
      };
      const alphaOf = (value) => {
        const c = parseColor(value);
        return c ? c.a : null;
      };
      const luminance = (c) => {
        const ch = [c.r, c.g, c.b].map((v) => {
          const s = v / 255;
          return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
        });
        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
      };
      const round = (n) => Math.round(n);
      const sameTagIndex = (total, idx) => (total > 1 ? `:nth-of-type(${idx})` : '');
      const domPath = (el) => {
        const parts = [];
        let cur = el;
        while (cur && cur.nodeType === 1) {
          const parent = cur.parentElement;
          let idx = 1;
          let total = 1;
          if (parent) {
            const same = Array.from(parent.children).filter((c) => c.tagName === cur.tagName);
            idx = same.indexOf(cur) + 1;
            total = same.length;
          }
          parts.unshift(`${cur.tagName.toLowerCase()}${sameTagIndex(total, idx)}`);
          cur = parent;
        }
        return parts.join(' > ');
      };
      // Effective background walks ancestors until a non-transparent colour is
      // found, falling back to white (the browser default canvas).
      const effectiveBackground = (el) => {
        for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
          const c = parseColor(getComputedStyle(node).backgroundColor);
          if (c && c.a > 0) return c;
        }
        return { r: 255, g: 255, b: 255, a: 1 };
      };
      const contrastRatio = (fgValue, bg) => {
        const fg = parseColor(fgValue);
        if (!fg) return null;
        const fl = luminance(fg);
        const bl = luminance(bg);
        const lighter = Math.max(fl, bl);
        const darker = Math.min(fl, bl);
        return (lighter + 0.05) / (darker + 0.05);
      };

      // Attributes are separate evidence items — never merged into the element text.
      const INSTRUMENTATION_ATTRIBUTES = new Set(['data-ilid']);
      const SENTENCE_ATTRIBUTES = ['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'aria-placeholder', 'aria-valuetext'];
      const renderedAttributes = (el, id) => {
        const out = [];
        const push = (attr, value, kind) => {
          if (!value || !value.trim()) return;
          out.push({
            id: `${id}:${attr}`,
            kind,
            tag: el.tagName.toLowerCase(),
            attr,
            path: `${domPath(el)}@${attr}`,
            originalText: value,
            normalizedText: value.replace(/\s+/g, ' ').trim(),
            text: value.replace(/\s+/g, ' ').trim(),
            zeroWidth: ZERO_WIDTH.test(value),
            hiddenReasons: ['attribute value (not rendered as text)'],
            nearInvisibleReasons: [],
            visible: false,
            inCodeOrQuote: false,
            rect: null,
          });
        };
        for (const attr of SENTENCE_ATTRIBUTES) {
          if (!el.hasAttribute(attr)) continue;
          const value = el.getAttribute(attr) || '';
          if (value.trim().length >= 8 || /\s/.test(value.trim())) push(attr, value, 'attribute');
        }
        if (el.tagName.toLowerCase() === 'input' && (el.getAttribute('type') || '').toLowerCase() === 'hidden') {
          push('value', el.getAttribute('value') || '', 'hidden-input-value');
        }
        for (const attr of Array.from(el.attributes || [])) {
          const name = attr.name.toLowerCase();
          if (!name.startsWith('data-')) continue;
          if (INSTRUMENTATION_ATTRIBUTES.has(name)) continue;
          const value = attr.value || '';
          if (!value.trim()) continue;
          if (value.trim().length >= 8 || /\s/.test(value.trim())) push(name, value, 'data-attribute');
        }
        return out;
      };

      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
      let el = walker.currentNode;
      while (el) {
        const raw = ownText(el);
        const text = raw.replace(/\s+/g, ' ').trim();
        if (text) {
          const id = 'il' + counter++;
          // NOTE: data-ilid is InjectionLens instrumentation, written here so the
          // UI can highlight a node. It is never read back as page evidence.
          el.setAttribute('data-ilid', id);
          const cs = getComputedStyle(el);
          const r = el.getBoundingClientRect();
          const hiddenReasons = [];
          const nearInvisibleReasons = [];

          if (cs.display === 'none') hiddenReasons.push('display:none');
          if (cs.visibility === 'hidden' || cs.visibility === 'collapse') hiddenReasons.push(`visibility:${cs.visibility}`);

          // Effective opacity multiplies through the ancestor chain.
          let effectiveOpacity = 1;
          for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
            const own = parseFloat(getComputedStyle(node).opacity);
            if (Number.isFinite(own)) effectiveOpacity *= own;
          }
          const fontSize = parseFloat(cs.fontSize);
          const colorAlpha = alphaOf(cs.color);
          const bg = effectiveBackground(el);
          const contrast = contrastRatio(cs.color, bg);

          if (effectiveOpacity === 0) hiddenReasons.push('effective opacity:0');
          else if (effectiveOpacity < NEAR_INVISIBLE.maxOpacity) {
            nearInvisibleReasons.push(`effective opacity ${round2(effectiveOpacity)}`);
          }
          if (parseFloat(cs.fontSize) === 0) hiddenReasons.push('font-size:0');
          else if (Number.isFinite(fontSize) && fontSize > 0 && fontSize < NEAR_INVISIBLE.maxFontSizePx) {
            nearInvisibleReasons.push(`font-size ${round2(fontSize)}px`);
          }
          if (colorAlpha === 0) hiddenReasons.push('text alpha 0 (fully transparent)');
          else if (colorAlpha !== null && colorAlpha < NEAR_INVISIBLE.maxTextAlpha) {
            nearInvisibleReasons.push(`text alpha ${round2(colorAlpha)}`);
          }
          if (contrast !== null && contrast < NEAR_INVISIBLE.minContrast) {
            nearInvisibleReasons.push(`contrast ratio ${round2(contrast)}`);
          }
          if (cs.clip && cs.clip !== 'auto' && /rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)/.test(cs.clip)) {
            hiddenReasons.push(`clip:${cs.clip}`);
          }
          if (cs.clipPath && cs.clipPath !== 'none' && /inset\(\s*(100%|50%)/.test(cs.clipPath)) {
            hiddenReasons.push(`clip-path:${cs.clipPath}`);
          }
          const textIndent = parseFloat(cs.textIndent);
          if (Number.isFinite(textIndent) && textIndent <= -999) {
            nearInvisibleReasons.push(`text-indent ${round2(textIndent)}px`);
          }
          const overflowHidden = cs.overflow === 'hidden' || cs.overflowX === 'hidden' || cs.overflowY === 'hidden';
          if (overflowHidden && (r.width < NEAR_INVISIBLE.tinyBoxPx || r.height < NEAR_INVISIBLE.tinyBoxPx)) {
            nearInvisibleReasons.push(`box ${Math.round(r.width)}x${Math.round(r.height)} with overflow hidden`);
          }
          if (r.width === 0 || r.height === 0) hiddenReasons.push('zero-size box');
          else if (r.x + r.width <= 0 || r.y + r.height <= 0) hiddenReasons.push('off-screen box');
          else if (r.x <= NEAR_INVISIBLE.offScreenPx || r.y <= NEAR_INVISIBLE.offScreenPx) nearInvisibleReasons.push(`positioned off-screen at x=${Math.round(r.x)}, y=${Math.round(r.y)}`);

          const inCodeOrQuote = !!(el.closest('pre, code, blockquote, kbd, samp'));
          items.push({
            id,
            tag: el.tagName.toLowerCase(),
            cls: typeof el.className === 'string' ? el.className.slice(0, 80) : '',
            // Raw text is preserved: the risk normalizer must see the original,
            // including any invisible characters, before anything strips them.
            originalText: raw,
            normalizedText: text,
            text,
            zeroWidth: ZERO_WIDTH.test(raw),
            hiddenReasons,
            nearInvisibleReasons,
            // A human cannot read this text if it is hidden OR only technically
            // on the page: 1px type or 2% opacity is not human-readable content.
            visible: hiddenReasons.length === 0 && nearInvisibleReasons.length === 0,
            inCodeOrQuote,
            rect: { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) },
          });
          items.push(...renderedAttributes(el, id));
        }
        el = walker.nextNode();
      }

      const comments = [];
      const cwalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
      let c = cwalker.nextNode();
      while (c) {
        const text = (c.nodeValue || '').replace(/\s+/g, ' ').trim();
        if (text) comments.push({ text, originalText: c.nodeValue || '' });
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

module.exports = { fetchHtml, renderPage, flattenA11y, BROWSER_UA, AI_CRAWLER_UAS, CRAWLER_UA_TOKENS, detectCrawlerToken, uaProbePermission };
