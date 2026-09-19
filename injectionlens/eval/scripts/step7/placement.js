// Step 7 evaluation utilities — safe placement into six local HTML contexts.
//
// Every page this module produces is generated locally, served from loopback and
// contains no live destination: fictional brands, reserved domains, no scripts
// (a JSON-LD data block is not a script), no forms, no external subresources.
// assertPageSafety() is the referee and renderPage() refuses to return a page
// that fails it, so an escaping bug surfaces as an exception instead of as a
// page that quietly reaches out to a real host.
//
// The six contexts mirror the delivery channels named in the plan and in the
// Forcepoint/Unit 42 reports: visible body text, HTML comment, meta content,
// data-* attribute, JSON-LD string, and CSS-hidden element.
//
// expected_pipelines_hypothesis is a HYPOTHESIS derived from the committed
// extractors (profiles.js / ingest.js / analyze.js). It is recorded so that a
// future runner can compare it with what the pipelines actually observed; it is
// not a claim about detection.
'use strict';

const { sha256Hex } = require('./ids');
const { findUnsafeTargets } = require('./targets');
const { getWrapper } = require('./variants');

const PLACEMENT_IDS = Object.freeze([
  'p-visible-body',
  'p-html-comment',
  'p-meta-content',
  'p-data-attribute',
  'p-jsonld-string',
  'p-css-hidden',
]);

const HIDDEN_SUB_RECIPES = Object.freeze({
  'h-display-none': { style: 'display:none' },
  'h-visibility-hidden': { style: 'visibility:hidden' },
  'h-opacity-0': { style: 'opacity:0' },
  'h-near-invisible': { style: 'font-size:1px;color:rgba(31,41,51,0.05)' },
  'h-offscreen': { style: 'position:absolute;left:-10000px;top:auto' },
  'h-tiny-clip': { style: 'width:1px;height:1px;overflow:hidden' },
  'h-sr-only-class': { className: 'sr-only' },
});

const DEFAULT_HIDDEN_SUB_RECIPES = Object.freeze(['h-display-none', 'h-near-invisible', 'h-offscreen']);

const PAGE_STYLE = [
  'body{font-family:system-ui;max-width:760px;margin:2rem auto;line-height:1.6;color:#1f2933}',
  '.wrap{border:1px solid #d7dde5;border-radius:8px;padding:1rem}',
  '.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}',
  'footer{color:#6b7280;font-size:.85rem}',
].join('\n');

const PAGE_FOOTER =
  'Generated locally by the InjectionLens Step 7 evaluation harness (synthetic/upstream inert text; '
  + 'fictional brands; reserved domains only). Nothing on this page is executed.';

class PlacementSafetyError extends Error {
  constructor(message, violations) {
    super(message);
    this.name = 'PlacementSafetyError';
    this.violations = violations || [];
  }
}

function escapeHtmlText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeHtmlAttribute(value) {
  return escapeHtmlText(value).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function hasUnrepresentableChars(value) {
  const text = String(value);
  if (text.includes('\u0000')) return true;
  // Lone surrogates cannot survive a UTF-8 round-trip.
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

function canEmbedComment(value) {
  const text = String(value);
  if (text.length === 0 || hasUnrepresentableChars(text)) return false;
  if (text.includes('--')) return false;
  if (text.endsWith('-')) return false;
  if (text.includes('>')) return false;
  return true;
}

/**
 * Can this text be planted without escaping tricks? A record that no placement
 * accepts is excluded as EX-IRRELEVANT-EMBED rather than mangled into a page.
 */
function canEmbed(placementId, value) {
  if (!PLACEMENT_IDS.includes(placementId)) throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  const text = String(value ?? '');
  if (text.trim() === '' || hasUnrepresentableChars(text)) return false;
  if (placementId === 'p-html-comment') return canEmbedComment(text);
  return true;
}

/**
 * Per-cell feasibility. A payload that cannot be planted in one context does not
 * disqualify the record: that single cell is SKIPPED with a reason, and the other
 * five contexts still run. Exclusion is reserved for text no placement accepts.
 */
function cellFeasibility({ payload, placementId } = {}) {
  if (!PLACEMENT_IDS.includes(placementId)) throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  if (canEmbed(placementId, payload)) {
    return { embeddable: true, reason_code: null, reason: null };
  }
  return {
    embeddable: false,
    reason_code: 'CELL-NOT-EMBEDDABLE',
    reason: `payload cannot be planted in ${placementId} without breaking the surrounding markup`,
  };
}

function buildJsonLdBlock(payloadText) {
  const document = {
    '@context': 'https://schema.example/context',
    '@type': 'Product',
    name: 'Fictional Test Product',
    review: {
      '@type': 'Review',
      reviewBody: payloadText,
    },
    additionalProperty: [
      { '@type': 'PropertyValue', name: 'harness', value: 'step7-local-page' },
    ],
  };
  // "<" is escaped so a payload can never close the surrounding script element.
  return JSON.stringify(document, null, 2).replace(/</g, '\\u003c');
}

/** Declared sub-recipes for one placement; the hidden family is the only one. */
function subRecipesFor(placementId, { hiddenSubRecipes = DEFAULT_HIDDEN_SUB_RECIPES } = {}) {
  if (placementId !== 'p-css-hidden') return [null];
  for (const id of hiddenSubRecipes) {
    if (!Object.prototype.hasOwnProperty.call(HIDDEN_SUB_RECIPES, id)) {
      throw new Error(`unknown hidden sub-recipe ${JSON.stringify(id)}`);
    }
  }
  return hiddenSubRecipes.slice();
}

function planPlacements({ hiddenSubRecipes = DEFAULT_HIDDEN_SUB_RECIPES } = {}) {
  const plan = [];
  for (const placementId of PLACEMENT_IDS) {
    for (const subRecipe of subRecipesFor(placementId, { hiddenSubRecipes })) {
      plan.push({ placement_id: placementId, sub_recipe: subRecipe });
    }
  }
  return plan;
}

function plantNode(placementId, subRecipe, payload) {
  switch (placementId) {
    case 'p-visible-body':
      return { in: 'body', html: `<p>${escapeHtmlText(payload)}</p>` };
    case 'p-html-comment':
      if (!canEmbedComment(payload)) {
        throw new PlacementSafetyError('payload cannot be embedded in an HTML comment safely', [
          { kind: 'embed-rejected', detail: 'comment payload contains "--", ">" or ends with "-"' },
        ]);
      }
      return { in: 'body', html: `<!--${payload}-->` };
    case 'p-meta-content':
      return { in: 'head', html: `<meta name="description" content="${escapeHtmlAttribute(payload)}">` };
    case 'p-data-attribute':
      return { in: 'body', html: `<div class="card" data-agent-note="${escapeHtmlAttribute(payload)}">Fictional product card.</div>` };
    case 'p-jsonld-string':
      return { in: 'body', html: `<script type="application/ld+json">\n${buildJsonLdBlock(payload)}\n</script>` };
    case 'p-css-hidden': {
      const recipe = HIDDEN_SUB_RECIPES[subRecipe];
      if (!recipe) throw new Error(`p-css-hidden requires a declared sub-recipe, got ${JSON.stringify(subRecipe)}`);
      const attrs = [];
      if (recipe.className) attrs.push(`class="${escapeHtmlAttribute(recipe.className)}"`);
      if (recipe.style) attrs.push(`style="${escapeHtmlAttribute(recipe.style)}"`);
      return { in: 'body', html: `<p ${attrs.join(' ')}>${escapeHtmlText(payload)}</p>` };
    }
    default:
      throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  }
}

function expectedPathsFor(placementId) {
  switch (placementId) {
    case 'p-visible-body':
    case 'p-css-hidden':
      return ['body > main > p'];
    case 'p-html-comment':
      return ['(HTML comment)'];
    case 'p-meta-content':
      return ['meta[name="description"]'];
    case 'p-data-attribute':
      return ['body > main > div@data-agent-note'];
    case 'p-jsonld-string':
      // collectJsonLd() walks the parsed document and reports key paths, so a
      // string inside review.reviewBody arrives as "review.reviewBody".
      return ['review.reviewBody'];
    default:
      throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  }
}

function expectedPipelineHypothesis(placementId) {
  switch (placementId) {
    case 'p-visible-body':
      return ['http-source', 'rendered-dom', 'reader-markdown', 'accessibility-tree'];
    case 'p-html-comment':
      return ['http-source', 'rendered-dom'];
    case 'p-meta-content':
      return ['http-source'];
    case 'p-data-attribute':
      return ['http-source', 'rendered-dom'];
    case 'p-jsonld-string':
      return ['http-source'];
    case 'p-css-hidden':
      return ['http-source', 'rendered-dom', 'accessibility-tree'];
    default:
      throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  }
}

/**
 * Structural safety check. Deliberately string-based and dependency-free; the
 * placement tests additionally parse the page with jsdom to prove inertness.
 */
function assertPageSafety(html) {
  const violations = [];
  const add = (kind, detail) => violations.push({ kind, detail });

  for (const match of html.matchAll(/<\s*script\b([^>]*)>/gi)) {
    const attrs = match[1] || '';
    if (!/type\s*=\s*["']application\/ld\+json["']/i.test(attrs)) {
      add('executable-script', match[0]);
    }
  }
  for (const tag of ['iframe', 'object', 'embed', 'form', 'base', 'link', 'img', 'video', 'audio', 'source']) {
    const re = new RegExp(`<\\s*${tag}\\b`, 'i');
    if (re.test(html)) add('external-or-active-element', tag);
  }
  for (const match of html.matchAll(/\son[a-z]+\s*=/gi)) add('inline-event-handler', match[0].trim());
  for (const match of html.matchAll(/\s(?:src|href|action|srcset|data)\s*=\s*["']?([^"'\s>]+)/gi)) {
    const value = match[1];
    if (/^(https?:)?\/\//i.test(value)) add('external-subresource', value);
  }
  for (const target of findUnsafeTargets(html)) {
    add(`non-reserved-${target.kind}`, target.match);
  }

  if (violations.length > 0) {
    throw new PlacementSafetyError(`generated page failed the local-safety check: ${JSON.stringify(violations)}`, violations);
  }
  return { ok: true, violations: [] };
}

/**
 * Render one local page that plants `payload` in the requested context.
 *
 * @param {{payload?: string|null, placementId: string, subRecipe?: string|null, wrapperId?: string|null,
 *          filler?: string|null, control?: boolean, title?: string|null}} input
 */
function renderPage({
  payload = null,
  placementId,
  subRecipe = null,
  wrapperId = null,
  filler = null,
  control = false,
  title = null,
} = {}) {
  if (!PLACEMENT_IDS.includes(placementId)) throw new Error(`unknown placement ${JSON.stringify(placementId)}`);
  if (placementId === 'p-css-hidden' && !Object.prototype.hasOwnProperty.call(HIDDEN_SUB_RECIPES, subRecipe)) {
    throw new Error(`unknown hidden sub-recipe ${JSON.stringify(subRecipe)}`);
  }
  if (!control && (typeof payload !== 'string' || payload === '')) {
    throw new Error('renderPage needs a payload, or control=true');
  }
  if (control && payload !== null) {
    throw new Error('a control page must not carry a payload');
  }

  const wrapper = wrapperId ? getWrapper(wrapperId) : null;
  const pageTitle = title || (wrapper ? wrapper.title : 'InjectionLens Step 7 local test page');

  let headPlant = null;
  let bodyPlant = null;
  let expectedPaths = [];
  let plantIn = null;

  if (control) {
    const controlText = filler || (wrapper ? wrapper.filler : 'Fictional filler text used as a no-payload control.');
    bodyPlant = `<p>${escapeHtmlText(controlText)}</p>`;
  } else {
    const node = plantNode(placementId, subRecipe, payload);
    if (node.in === 'head') headPlant = node.html;
    else bodyPlant = node.html;
    expectedPaths = expectedPathsFor(placementId);
    plantIn = node.in;
  }

  const wrapperBlock = wrapper
    ? [
      '<section class="wrap">',
      `<h2>${escapeHtmlText(wrapper.title)}</h2>`,
      ...wrapper.paragraphs.map((paragraph) => `<p>${escapeHtmlText(paragraph)}</p>`),
      '</section>',
    ].join('\n')
    : '';

  const html = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<title>${escapeHtmlText(pageTitle)}</title>`,
    headPlant || '',
    `<style>\n${PAGE_STYLE}\n</style>`,
    '</head>',
    '<body>',
    '<main>',
    `<h1>${escapeHtmlText(pageTitle)}</h1>`,
    wrapperBlock,
    bodyPlant || '',
    '</main>',
    `<footer>${PAGE_FOOTER}</footer>`,
    '</body>',
    '</html>',
    '',
  ].filter((line) => line !== '').join('\n');

  assertPageSafety(html);

  return {
    placement_id: placementId,
    sub_recipe: subRecipe,
    wrapper_id: wrapperId,
    control: control === true,
    plant_in: plantIn,
    expected_paths: expectedPaths,
    expected_pipelines_hypothesis: control ? [] : expectedPipelineHypothesis(placementId),
    html,
    page_sha256: sha256Hex(html),
  };
}

module.exports = {
  PLACEMENT_IDS,
  HIDDEN_SUB_RECIPES,
  DEFAULT_HIDDEN_SUB_RECIPES,
  PlacementSafetyError,
  escapeHtmlText,
  escapeHtmlAttribute,
  canEmbedComment,
  canEmbed,
  cellFeasibility,
  buildJsonLdBlock,
  subRecipesFor,
  planPlacements,
  expectedPathsFor,
  expectedPipelineHypothesis,
  assertPageSafety,
  renderPage,
};
