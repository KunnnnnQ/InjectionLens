// Replica fixture manifest: schema, safety lint, and validation.
//
// This is the Lane 2 half of Human Step 6. Lane 1 owns the replica HTML and the
// manifest; this module owns everything that can be checked about them
// mechanically, and nothing about how a page is scored.
//
// Three rules shape the code:
//   1. Validation never guesses. A missing, malformed, duplicated or unsafe
//      entry is an error that stops the run before any browser is launched.
//   2. The vocabulary is imported from the product, never copied. Intent names
//      come from risk.js, capability keys from CAPABILITY_TEMPLATES, and UA
//      tokens from ingest.js, so a rename in the product breaks the manifest
//      loudly instead of silently matching nothing.
//   3. A fixture is inert test data. It may name a real service in its text,
//      but every URL it carries must point at a reserved domain, and it may
//      not contain anything a browser would execute.
//
// Evidence: Step 6 contract sections 1-2 (manifest schema, per-case
//   expectations) and 3.2 (validation rules); AGENTS.md rule 7 (inert domains,
//   fictional brands, no executable payloads).

'use strict';

const crypto = require('node:crypto');

const PIPELINES = Object.freeze([
  'http-source',
  'rendered-dom',
  'reader-markdown',
  'accessibility-tree',
]);

const LEVELS = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

// A case that was not adjudicated must say why, and only these reasons exist.
const SKIP_CODES = Object.freeze(['known-gap', 'no-headless-browser', 'filtered-out']);

const SERVE_MODES = Object.freeze(['static', 'ua-conditional']);

const LEVEL_RANK = new Map(LEVELS.map((level, index) => [level, index]));

/** Ordinal position of a level; -1 for anything that is not a level. */
function levelRank(level) {
  const rank = LEVEL_RANK.get(level);
  return rank === undefined ? -1 : rank;
}

/** Highest level actually present in an analyze() levelCount object. */
function maxLevelOf(levelCount) {
  let best = null;
  for (const level of LEVELS) {
    if (levelCount && levelCount[level] > 0) best = level;
  }
  return best;
}

const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function sha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Path safety
//
// The manifest names files and routes that the runner will read and serve. A
// manifest is data, not code, so it must not be able to point the runner at a
// file outside the fixture root.
// ---------------------------------------------------------------------------

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

/** A relative path inside the fixture root: no absolute path, no "..", no "//". */
function isSafeRelativePath(value) {
  if (!isNonEmptyString(value)) return false;
  const normalized = toPosix(value);
  if (normalized.startsWith('/')) return false;
  if (/^[a-zA-Z]:/.test(normalized)) return false;
  const segments = normalized.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) return false;
  return true;
}

/** A fixture file name: one directory level only, .html, not hidden. */
function isFixtureBasename(value) {
  if (!isNonEmptyString(value)) return false;
  const normalized = toPosix(value);
  if (normalized.includes('/')) return false;
  if (normalized.startsWith('.')) return false;
  return normalized.toLowerCase().endsWith('.html');
}

/** A path-only route the runner will prefix with its own ephemeral origin. */
function isRoutePath(value) {
  if (!isNonEmptyString(value)) return false;
  if (!value.startsWith('/')) return false;
  if (value.includes('://')) return false;
  return !toPosix(value).split('/').some((segment) => segment === '..');
}

/** The route a case is served at: explicit, or /fixtures/<file>. */
function routeFor(spec) {
  const serve = isPlainObject(spec.serve) ? spec.serve : {};
  if (isNonEmptyString(serve.route)) return serve.route;
  return `/fixtures/${spec.file}`;
}

/** Every fixture file a case depends on. */
function referencedFiles(spec) {
  const files = [];
  if (isNonEmptyString(spec.file)) files.push(spec.file);
  if (isPlainObject(spec.serve) && spec.serve.mode === 'ua-conditional') {
    if (isNonEmptyString(spec.serve.human)) files.push(spec.serve.human);
    if (isNonEmptyString(spec.serve.ai)) files.push(spec.serve.ai);
  }
  return files;
}

// ---------------------------------------------------------------------------
// Safety lint
//
// Only reserved domains and the loopback fixture origin may appear as a URL in
// a fixture: the pattern is reproduced locally, never linked to. Nothing in a
// fixture may execute either - the runner reads these pages, and a fixture that
// runs script would turn test data into code.
// ---------------------------------------------------------------------------

const INERT_HOST_SUFFIXES = Object.freeze(['.example', '.invalid', '.test']);
const LOOPBACK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '::1']);

function isInertHost(host) {
  const normalized = String(host || '').toLowerCase().replace(/\.+$/, '');
  if (!normalized) return false;
  if (LOOPBACK_HOSTS.includes(normalized)) return true;
  return INERT_HOST_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

const ABSOLUTE_URL_RE = /(?:https?|ftp|file):\/\/([^\s"'<>()\\]+)/gi;
const PROTOCOL_RELATIVE_RE = /(?:^|[\s"'(=,])\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/gi;
const MAILTO_RE = /mailto:([^\s"'<>?]+)/gi;
const SCRIPT_TAG_RE = /<script\b([^>]*)>/gi;
const TAG_RE = /<[a-zA-Z][^>]*>/g;
const EMBEDDED_RE = /<(iframe|object|embed|base|frame|frameset|applet)\b/gi;
const UNSAFE_SCHEME_RE = /(?:javascript|vbscript)\s*:|data:text\/html/gi;
const META_REFRESH_RE = /<meta\b[^>]*http-equiv\s*=\s*["']?refresh/gi;

/** Strip credentials and port from the part of a URL after "//". */
function hostOf(urlRemainder) {
  let rest = String(urlRemainder).split(/[/?#]/)[0];
  const at = rest.lastIndexOf('@');
  if (at !== -1) rest = rest.slice(at + 1);
  const colon = rest.lastIndexOf(':');
  if (colon !== -1 && /^\d*$/.test(rest.slice(colon + 1))) rest = rest.slice(0, colon);
  return rest.toLowerCase();
}

/**
 * Everything unsafe about one fixture file.
 *
 * @param {string} html
 * @param {string} label where the content came from, e.g. "replica-01.html"
 * @returns {Array<{rule: string, message: string, sample: string}>}
 */
function lintFixtureHtml(html, label) {
  const source = typeof html === 'string' ? html : '';
  const violations = [];
  const push = (rule, message, sample) => {
    violations.push({ rule, message, sample: String(sample || '').slice(0, 120) });
  };

  for (const match of source.matchAll(ABSOLUTE_URL_RE)) {
    const host = hostOf(match[1]);
    if (!isInertHost(host)) {
      push('url-host', `${label}: absolute URL to non-inert host "${host}"`, match[0]);
    }
  }

  for (const match of source.matchAll(PROTOCOL_RELATIVE_RE)) {
    const host = hostOf(match[1]);
    if (!isInertHost(host)) {
      push('url-host', `${label}: protocol-relative URL to non-inert host "${host}"`, match[0]);
    }
  }

  for (const match of source.matchAll(MAILTO_RE)) {
    const address = match[1];
    const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase();
    if (!domain || !isInertHost(domain)) {
      push('mailto-host', `${label}: mailto address outside a reserved domain ("${domain || address}")`, match[0]);
    }
  }

  for (const match of source.matchAll(SCRIPT_TAG_RE)) {
    const typeMatch = /type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(match[1]);
    const type = (typeMatch ? (typeMatch[1] ?? typeMatch[2] ?? typeMatch[3]) : '') || '';
    if (type.trim().toLowerCase() !== 'application/ld+json') {
      push('script', `${label}: <script> is not type="application/ld+json" (fixtures must not execute)`, match[0]);
    }
  }

  for (const match of source.matchAll(EMBEDDED_RE)) {
    push('embedded', `${label}: <${match[1].toLowerCase()}> can load or run external content`, match[0]);
  }

  for (const match of source.matchAll(UNSAFE_SCHEME_RE)) {
    push('scheme', `${label}: unsafe URL scheme "${match[0]}"`, match[0]);
  }

  for (const match of source.matchAll(META_REFRESH_RE)) {
    push('meta-refresh', `${label}: <meta http-equiv="refresh"> navigates the reader away`, match[0]);
  }

  for (const tag of source.matchAll(TAG_RE)) {
    const handler = /\son[a-z]+\s*=/i.exec(tag[0]);
    if (handler) {
      push('event-handler', `${label}: inline event handler "${handler[0].trim()}"`, tag[0]);
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function createReport() {
  const errors = [];
  const warnings = [];
  return {
    errors,
    warnings,
    error(path, message) {
      errors.push({ path, message });
    },
    warn(path, message) {
      warnings.push({ path, message });
    },
  };
}

function validateProvenance(report, where, provenance) {
  if (!isPlainObject(provenance)) {
    report.error(`${where}.provenance`, 'provenance is required: { label, date, url }');
    return;
  }
  for (const field of ['label', 'date', 'url']) {
    if (!isNonEmptyString(provenance[field])) {
      report.error(`${where}.provenance.${field}`, `provenance.${field} is required and must be a non-empty string`);
    }
  }
  if (isNonEmptyString(provenance.url) && !/^https:\/\//i.test(provenance.url)) {
    report.error(`${where}.provenance.url`, 'provenance.url must be an https URL to the source report');
  }
  if (!isNonEmptyString(provenance.planRef)) {
    report.warn(`${where}.provenance.planRef`, 'no planRef: the results table cannot point back at the plan');
  }
}

function validateServe(report, where, spec, options) {
  if (spec.serve === undefined) return;
  if (!isPlainObject(spec.serve)) {
    report.error(`${where}.serve`, 'serve must be an object when present');
    return;
  }
  const serve = spec.serve;
  const mode = serve.mode === undefined ? 'static' : serve.mode;
  if (!SERVE_MODES.includes(mode)) {
    report.error(`${where}.serve.mode`, `serve.mode must be one of ${SERVE_MODES.join(' | ')}, got ${JSON.stringify(serve.mode)}`);
    return;
  }
  if (serve.route !== undefined && !isRoutePath(serve.route)) {
    report.error(`${where}.serve.route`, `serve.route must be a path starting with "/" and containing no host or "..": ${JSON.stringify(serve.route)}`);
  }
  if (mode === 'static') {
    for (const field of ['human', 'ai', 'triggerTokens']) {
      if (serve[field] !== undefined) {
        report.error(`${where}.serve.${field}`, `serve.${field} only applies when serve.mode is "ua-conditional"`);
      }
    }
    return;
  }

  if (isNonEmptyString(serve.route) && !serve.route.startsWith('/fixtures/')) {
    report.error(`${where}.serve.route`, 'a ua-conditional route must live under /fixtures/');
  }
  for (const field of ['human', 'ai']) {
    const value = serve[field];
    if (!isSafeRelativePath(value)) {
      report.error(`${where}.serve.${field}`, `serve.${field} must be a relative path inside the fixture root`);
      continue;
    }
    if (!toPosix(value).toLowerCase().endsWith('.html')) {
      report.error(`${where}.serve.${field}`, `serve.${field} must reference an .html file`);
      continue;
    }
    const read = options.readFixture(value);
    if (!read.ok) report.error(`${where}.serve.${field}`, `fixture file not readable: ${read.reason}`);
  }
  if (!isStringArray(serve.triggerTokens) || serve.triggerTokens.length === 0) {
    report.error(`${where}.serve.triggerTokens`, 'serve.triggerTokens must be a non-empty array of UA tokens');
    return;
  }
  const known = new Set(options.taxonomy.crawlerTokens || []);
  if (known.size === 0) {
    report.warn(`${where}.serve.triggerTokens`, 'the UA inventory was empty, so the trigger tokens could not be checked');
  }
  for (const token of serve.triggerTokens) {
    if (!known.has(token)) {
      report.error(`${where}.serve.triggerTokens`, `"${token}" is not in the verified AI-agent UA inventory (server/lib/ingest.js)`);
    }
  }
}

function validateExpect(report, where, expect, spec, options) {
  if (!isPlainObject(expect)) {
    report.error(`${where}.expect`, 'expect is required');
    return;
  }
  const knownIntents = new Set(options.taxonomy.intentKeys || []);
  const knownCapabilities = new Set(options.taxonomy.capabilityKeys || []);
  const knownTokens = new Set(options.taxonomy.crawlerTokens || []);
  if (knownIntents.size === 0) report.warn(`${where}.expect`, 'the intent vocabulary was empty, so intents could not be checked');
  if (knownCapabilities.size === 0) report.warn(`${where}.expect`, 'the capability vocabulary was empty, so capability keys could not be checked');

  // --- pipelines ---------------------------------------------------------
  if (!isStringArray(expect.pipelines) || expect.pipelines.length === 0) {
    report.error(`${where}.expect.pipelines`, 'expect.pipelines must be a non-empty array of pipeline ids');
  } else {
    for (const pipeline of expect.pipelines) {
      if (!PIPELINES.includes(pipeline)) {
        report.error(`${where}.expect.pipelines`, `unknown pipeline "${pipeline}"; known: ${PIPELINES.join(', ')}`);
      }
    }
    if (new Set(expect.pipelines).size !== expect.pipelines.length) {
      report.error(`${where}.expect.pipelines`, 'expect.pipelines contains duplicates');
    }
  }
  const pipelines = isStringArray(expect.pipelines) ? expect.pipelines : [];

  if (expect.absentFrom !== undefined) {
    if (!isStringArray(expect.absentFrom)) {
      report.error(`${where}.expect.absentFrom`, 'expect.absentFrom must be an array of pipeline ids when present');
    } else {
      for (const pipeline of expect.absentFrom) {
        if (!PIPELINES.includes(pipeline)) {
          report.error(`${where}.expect.absentFrom`, `unknown pipeline "${pipeline}"; known: ${PIPELINES.join(', ')}`);
        }
        if (pipelines.includes(pipeline)) {
          report.error(`${where}.expect.absentFrom`, `"${pipeline}" is declared both as expected and as absent`);
        }
      }
    }
  }

  // --- intents -----------------------------------------------------------
  const benign = expect.benign === true;
  if (!isStringArray(expect.intents)) {
    report.error(`${where}.expect.intents`, 'expect.intents must be an array of intent ids');
  } else {
    if (expect.intents.length === 0 && !benign) {
      report.error(`${where}.expect.intents`, 'expect.intents may only be empty when expect.benign is true');
    }
    for (const intent of expect.intents) {
      if (!knownIntents.has(intent)) {
        report.error(`${where}.expect.intents`, `unknown intent "${intent}"; known: ${[...knownIntents].join(', ')}`);
      }
    }
  }
  if (expect.forbiddenIntents !== undefined) {
    if (!isStringArray(expect.forbiddenIntents)) {
      report.error(`${where}.expect.forbiddenIntents`, 'expect.forbiddenIntents must be an array of intent ids when present');
    } else {
      for (const intent of expect.forbiddenIntents) {
        if (!knownIntents.has(intent)) {
          report.error(`${where}.expect.forbiddenIntents`, `unknown intent "${intent}"; known: ${[...knownIntents].join(', ')}`);
        }
        if (isStringArray(expect.intents) && expect.intents.includes(intent)) {
          report.error(`${where}.expect.forbiddenIntents`, `"${intent}" is both expected and forbidden`);
        }
      }
    }
  }

  // --- evidence ----------------------------------------------------------
  if (!Array.isArray(expect.evidence) || expect.evidence.length === 0) {
    report.error(`${where}.expect.evidence`, 'expect.evidence must be a non-empty array of { pipeline, contains } checks');
  } else {
    expect.evidence.forEach((entry, index) => {
      const at = `${where}.expect.evidence[${index}]`;
      if (!isPlainObject(entry)) {
        report.error(at, 'evidence entries must be objects');
        return;
      }
      if (!PIPELINES.includes(entry.pipeline)) {
        report.error(`${at}.pipeline`, `unknown pipeline ${JSON.stringify(entry.pipeline)}; known: ${PIPELINES.join(', ')}`);
      }
      if (!isNonEmptyString(entry.contains)) {
        report.error(`${at}.contains`, 'contains must be a non-empty substring of the evidence text');
      }
      for (const field of ['kind', 'pathContains']) {
        if (entry[field] !== undefined && !isNonEmptyString(entry[field])) {
          report.error(`${at}.${field}`, `${field} must be a non-empty string when present`);
        }
      }
      if (entry.note !== undefined && !isNonEmptyString(entry.note)) {
        report.error(`${at}.note`, 'note must be a non-empty string when present');
      }
      if (entry.forbidIntents !== undefined) {
        if (!isStringArray(entry.forbidIntents)) {
          report.error(`${at}.forbidIntents`, 'forbidIntents must be an array of intent ids when present');
        } else {
          for (const intent of entry.forbidIntents) {
            if (!knownIntents.has(intent)) {
              report.error(`${at}.forbidIntents`, `unknown intent "${intent}"`);
            }
          }
        }
      }
    });
    const evidencePipelines = new Set(
      expect.evidence.filter(isPlainObject).map((entry) => entry.pipeline).filter((p) => PIPELINES.includes(p)),
    );
    const declared = new Set(pipelines);
    const onlyInPipelines = [...declared].filter((p) => !evidencePipelines.has(p));
    const onlyInEvidence = [...evidencePipelines].filter((p) => !declared.has(p));
    if (onlyInPipelines.length || onlyInEvidence.length) {
      report.error(
        `${where}.expect.pipelines`,
        `pipelines and evidence must describe the same set; only in pipelines: [${onlyInPipelines.join(', ')}], only in evidence: [${onlyInEvidence.join(', ')}]`,
      );
    }
  }

  // --- capabilities ------------------------------------------------------
  if (!isPlainObject(expect.capabilities) || Object.keys(expect.capabilities).length === 0) {
    report.error(`${where}.expect.capabilities`, 'expect.capabilities must declare at least one capability template');
  } else {
    for (const [key, value] of Object.entries(expect.capabilities)) {
      const at = `${where}.expect.capabilities.${key}`;
      if (knownCapabilities.size > 0 && !knownCapabilities.has(key)) {
        report.error(at, `unknown capability template "${key}"; known: ${[...knownCapabilities].join(', ')}`);
      }
      if (!isPlainObject(value)) {
        report.error(at, 'each capability must declare { minLevel } and/or { maxLevel }');
        continue;
      }
      const hasMin = value.minLevel !== undefined;
      const hasMax = value.maxLevel !== undefined;
      if (!hasMin && !hasMax) {
        report.error(at, 'declare minLevel, maxLevel, or both');
      }
      for (const field of ['minLevel', 'maxLevel']) {
        if (value[field] !== undefined && !LEVELS.includes(value[field])) {
          report.error(`${at}.${field}`, `unknown level ${JSON.stringify(value[field])}; known: ${LEVELS.join(' < ')}`);
        }
      }
      if (hasMin && hasMax && LEVELS.includes(value.minLevel) && LEVELS.includes(value.maxLevel)
        && levelRank(value.minLevel) > levelRank(value.maxLevel)) {
        report.error(at, `minLevel "${value.minLevel}" is above maxLevel "${value.maxLevel}"`);
      }
    }
  }

  const capabilityKeys = isPlainObject(expect.capabilities) ? Object.keys(expect.capabilities) : [];
  if (!isNonEmptyString(expect.primaryCapability)) {
    report.error(`${where}.expect.primaryCapability`, 'expect.primaryCapability is required: it names the capability the case floor is stated for');
  } else if (!capabilityKeys.includes(expect.primaryCapability)) {
    report.error(`${where}.expect.primaryCapability`, `"${expect.primaryCapability}" is not declared in expect.capabilities`);
  }

  // --- cloaking ----------------------------------------------------------
  if (expect.cloak !== undefined) {
    const serveMode = isPlainObject(spec.serve) && spec.serve.mode ? spec.serve.mode : 'static';
    if (serveMode !== 'ua-conditional') {
      report.error(`${where}.expect.cloak`, 'expect.cloak only applies to a case served with serve.mode "ua-conditional"');
    }
    if (!isPlainObject(expect.cloak) || expect.cloak.required !== true || !isNonEmptyString(expect.cloak.triggerToken)) {
      report.error(`${where}.expect.cloak`, 'expect.cloak must be { required: true, triggerToken }');
    } else if (knownTokens.size > 0 && !knownTokens.has(expect.cloak.triggerToken)) {
      report.error(`${where}.expect.cloak.triggerToken`, `"${expect.cloak.triggerToken}" is not in the verified AI-agent UA inventory`);
    }
  }

  // --- known gaps --------------------------------------------------------
  if (expect.knownGap !== undefined) {
    const gap = expect.knownGap;
    const at = `${where}.expect.knownGap`;
    if (!isPlainObject(gap)) {
      report.error(at, 'expect.knownGap must be an object');
      return;
    }
    for (const field of ['code', 'reason', 'payloadContains']) {
      if (!isNonEmptyString(gap[field])) report.error(`${at}.${field}`, `${field} is required and must be a non-empty string`);
    }
    if (gap.expectNoDetection !== true) {
      report.error(`${at}.expectNoDetection`, 'only expectNoDetection: true is supported: a known gap asserts the payload is still missed');
    }
    for (const [key, value] of Object.entries(isPlainObject(expect.capabilities) ? expect.capabilities : {})) {
      if (isPlainObject(value) && isNonEmptyString(value.minLevel) && value.minLevel !== 'info') {
        report.error(`${at}`, `a known-gap case cannot demand ${key}.minLevel "${value.minLevel}": nothing is detected, so the floor is info`);
      }
    }
  }
}

function validateCase(report, spec, index, options, seen) {
  const where = isPlainObject(spec) && isNonEmptyString(spec.id) ? spec.id : `cases[${index}]`;
  if (!isPlainObject(spec)) {
    report.error(where, 'each case must be an object');
    return;
  }

  // --- identity ----------------------------------------------------------
  if (!isNonEmptyString(spec.id)) {
    report.error(`${where}.id`, 'id is required');
  } else if (!ID_PATTERN.test(spec.id)) {
    report.error(`${where}.id`, `id must match ${ID_PATTERN} (lower-case kebab-case), got ${JSON.stringify(spec.id)}`);
  } else if (seen.ids.has(spec.id)) {
    report.error(`${where}.id`, `duplicate case id "${spec.id}"`);
  } else {
    seen.ids.add(spec.id);
  }

  if (!isFixtureBasename(spec.file)) {
    report.error(`${where}.file`, `file must be a plain .html file name inside the fixture root, got ${JSON.stringify(spec.file)}`);
  } else {
    if (seen.files.has(spec.file)) {
      report.error(`${where}.file`, `"${spec.file}" is already used by case "${seen.files.get(spec.file)}"`);
    } else {
      seen.files.set(spec.file, where);
    }
    const read = options.readFixture(spec.file);
    if (!read.ok) report.error(`${where}.file`, `fixture file not readable: ${read.reason}`);
    else for (const violation of lintFixtureHtml(read.content, spec.file)) {
      report.error(`${where}.file`, `unsafe fixture: ${violation.message}`);
    }
  }

  if (!isNonEmptyString(spec.title)) report.error(`${where}.title`, 'title is required');
  if (!isNonEmptyString(spec.pattern)) report.error(`${where}.pattern`, 'pattern is required: state the inert local pattern this page reproduces');
  if (spec.reproducedFrom !== undefined && !isNonEmptyString(spec.reproducedFrom)) {
    report.error(`${where}.reproducedFrom`, 'reproducedFrom must be a non-empty string when present');
  }

  validateProvenance(report, where, spec.provenance);
  validateServe(report, where, spec, options);
  validateExpect(report, where, spec.expect, spec, options);
}

/**
 * Validate a parsed manifest.
 *
 * @param {object} manifest parsed manifest document
 * @param {object} options
 * @param {{intentKeys?: string[], capabilityKeys?: string[], crawlerTokens?: string[]}} options.taxonomy
 *   the live vocabularies from the product; pass real ones, never a copy
 * @param {(relPath: string) => ({ok: true, content: string} | {ok: false, reason: string})} options.readFixture
 * @param {string[]} [options.fixtureFiles] file names present under the fixture root
 * @returns {{ok: boolean, errors: Array, warnings: Array}}
 */
function validateManifest(manifest, options = {}) {
  const report = createReport();
  const resolved = {
    taxonomy: {
      intentKeys: options.taxonomy?.intentKeys || [],
      capabilityKeys: options.taxonomy?.capabilityKeys || [],
      crawlerTokens: options.taxonomy?.crawlerTokens || [],
    },
    readFixture: typeof options.readFixture === 'function'
      ? options.readFixture
      : () => ({ ok: false, reason: 'no fixture reader was provided' }),
  };

  if (!isPlainObject(manifest)) {
    report.error('manifest', 'manifest must be a JSON object');
    return { ok: false, errors: report.errors, warnings: report.warnings };
  }
  if (manifest.schemaVersion !== 1) {
    report.error('schemaVersion', `schemaVersion must be 1, got ${JSON.stringify(manifest.schemaVersion)}`);
  }
  if (manifest.set !== undefined && !isPlainObject(manifest.set)) {
    report.error('set', 'set must be an object when present');
  }
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) {
    report.error('cases', 'cases must be a non-empty array: an empty manifest must never be reported as a pass');
    return { ok: false, errors: report.errors, warnings: report.warnings };
  }

  const seen = { ids: new Set(), files: new Map() };
  manifest.cases.forEach((spec, index) => validateCase(report, spec, index, resolved, seen));

  // A replica file nobody references is usually work in progress, not a defect,
  // so it is reported without failing the run.
  if (Array.isArray(options.fixtureFiles)) {
    const referenced = new Set();
    for (const spec of manifest.cases) {
      if (isPlainObject(spec)) for (const file of referencedFiles(spec)) referenced.add(toPosix(file));
    }
    for (const file of options.fixtureFiles) {
      const normalized = toPosix(file);
      if (/^replica-.*\.html$/i.test(normalized) && !referenced.has(normalized)) {
        report.warn('cases', `fixture "${normalized}" looks like a replica page but no case references it`);
      }
    }
  }

  const adjudicable = manifest.cases.filter((spec) => isPlainObject(spec) && !(isPlainObject(spec.expect) && spec.expect.knownGap));
  if (adjudicable.length === 0) {
    report.warn('cases', 'every case is declared as a known gap: the run cannot prove any positive detection');
  }

  return { ok: report.errors.length === 0, errors: report.errors, warnings: report.warnings };
}

module.exports = {
  PIPELINES,
  LEVELS,
  SKIP_CODES,
  SERVE_MODES,
  levelRank,
  maxLevelOf,
  sha256,
  isSafeRelativePath,
  isFixtureBasename,
  isRoutePath,
  isInertHost,
  lintFixtureHtml,
  routeFor,
  referencedFiles,
  validateManifest,
};
