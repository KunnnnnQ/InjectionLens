// Observation and adjudication for one replica case.
//
// The runner must be able to say, for every declared expectation, what was
// expected and what was actually observed — and must never turn "not checked"
// into a pass. This module is the part of the runner that can be reasoned about
// without a browser: it consumes the plain object that analyze() returns and
// produces checks, failures and a status.
//
// Two kinds of information are kept strictly apart, because conflating them was
// a real defect:
//
//   * Finding evidence (source "finding") — a segment that analyze() turned into
//     a security finding. Only this kind carries an intent, a risk level, a
//     delivery classification and an extraction kind/path, because those are
//     things the product decided.
//   * Pipeline-presence evidence (source "rendered-html" | "reader-markdown" |
//     "matrix-row") — text that is genuinely present in an output analyze()
//     already returned, but that never became a finding. It proves a pipeline
//     CARRIED the text; it asserts nothing about intent or risk. A page whose
//     payload sits below the finding threshold still has its text in the
//     rendered HTML and the Reader/Markdown output, and the runner has to be
//     able to verify that without inventing a classification.
//
// A non-zero pipeline item count is never treated as proof that a particular
// substring was read: the substring itself has to appear in that pipeline's
// returned output.
//
// Two more semantics are worth stating because the rest of the code depends on
// them:
//
//   * An `expect.evidence` entry names the payload carrier: a substring that a
//     named pipeline must have carried, at an optional extraction kind or path.
//     A kind or a path can only be satisfied by finding evidence, since those
//     attributes come from the product. `expect.pipelines` is the summary view
//     of those entries (which is why validation requires the two sets to be
//     identical).
//   * `expect.absentFrom` asserts that none of those declared payload
//     substrings reaches the named pipeline. It is a positive observation about
//     an absence ("this pipeline genuinely did not read it"), not a gap.
//
// Evidence: Step 6 contract sections 3.4 (per-case result schema) and 3.5
//   (PASS/FAIL/SKIPPED/ERROR semantics); plan §2 (the pipeline differences the
//   replica set exists to measure).

'use strict';

const { PIPELINES, LEVELS, levelRank, maxLevelOf } = require('./replica-manifest');

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/** Does this text contain the needle, in original or normalized form? */
function textContains(haystack, needle) {
  if (typeof needle !== 'string' || needle === '') return false;
  return typeof haystack === 'string' && haystack.includes(needle);
}

/** Normalize the way the ingestion profiles do, for presence comparisons. */
function normalizeForPresence(value) {
  return String(value === undefined || value === null ? '' : value).replace(/\s+/g, ' ').trim();
}

/** The rendered HTML analyze() returned, if any. */
function renderedOutputOf(analysis) {
  const result = analysis || {};
  return typeof result.humanHtml === 'string' ? result.humanHtml : '';
}

/** The Reader/Markdown output analyze() returned, if any. */
function readerOutputOf(analysis) {
  const result = analysis || {};
  return typeof result.readerMarkdown === 'string' ? result.readerMarkdown : '';
}

/**
 * Pipeline-presence evidence: text that is in what analyze() returned, without a
 * finding attached to it. Nothing here carries an intent, a level or a
 * fabricated finding id.
 */
function collectPipelinePresence(analysis) {
  const result = analysis || {};
  const presence = [];
  const stats = result.stats || {};
  const counts = {
    'http-source': Number(stats.httpSourceItems) || 0,
    'rendered-dom': Number(stats.renderedItems) || 0,
    'reader-markdown': Number(stats.readerSegments) || 0,
    'accessibility-tree': Number(stats.a11yNodes) || 0,
  };

  const addText = (pipeline, text, source, path) => {
    if (typeof text !== 'string' || text.trim() === '') return;
    presence.push({
      source,
      pipeline,
      extractionKind: null,
      path: path || null,
      originalText: text,
      normalizedText: normalizeForPresence(text),
    });
  };

  // The full rendered DOM output. Every element the renderer kept is in here, so
  // a substring match is a real observation rather than an inference.
  addText('rendered-dom', renderedOutputOf(result), 'rendered-html', '(rendered HTML output)');

  // The Reader/Markdown output.
  addText('reader-markdown', readerOutputOf(result), 'reader-markdown', '(Reader/Markdown output)');

  // The ingestion matrix: one row per segment, naming the pipelines that carried
  // it. The excerpt is truncated, so a match here is real but a miss proves
  // nothing; the full profile outputs above are the authoritative carrier.
  const matrix = Array.isArray(result.matrix) ? result.matrix : [];
  for (const row of matrix) {
    if (!row || typeof row !== 'object') continue;
    const text = typeof row.excerpt === 'string' ? row.excerpt : '';
    if (row.httpSource === true) addText('http-source', text, 'matrix-row', row.key ? `matrix:${row.key}` : 'matrix');
    if (row.renderedDom === 'visible' || row.renderedDom === 'hidden') addText('rendered-dom', text, 'matrix-row', row.key ? `matrix:${row.key}` : 'matrix');
    if (row.readerMarkdown === true) addText('reader-markdown', text, 'matrix-row', row.key ? `matrix:${row.key}` : 'matrix');
    if (row.accessibilityTree === true) addText('accessibility-tree', text, 'matrix-row', row.key ? `matrix:${row.key}` : 'matrix');
  }

  return { presence, counts };
}

/**
 * Flatten one analyze() result into what the checks need.
 *
 * Occurrences are the authoritative record of "which pipeline read this text":
 * every finding occurrence is recorded with its extraction kind and node path,
 * and pipeline-presence evidence is recorded beside it without any security
 * classification. Levels and intents are read per capability run, because the
 * same page is rated differently under different templates.
 */
function collectObservations(analysis) {
  const result = analysis || {};
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const occurrences = [];

  for (const finding of findings) {
    const level = finding.impact && finding.impact.level ? finding.impact.level : 'info';
    const entry = {
      findingId: finding.id || null,
      level,
      intents: Array.isArray(finding.intents) ? finding.intents.slice() : [],
      humanVisible: finding.humanVisible === true,
      delivery: finding.delivery || null,
      excerpt: typeof finding.excerpt === 'string' ? finding.excerpt : '',
    };
    const own = Array.isArray(finding.occurrences) ? finding.occurrences : [];
    if (own.length === 0) {
      // Synthetic findings (cloaking) carry text without an occurrence.
      occurrences.push({
        ...entry,
        source: 'finding',
        pipeline: '(finding)',
        extractionKind: 'finding',
        path: null,
        originalText: typeof finding.originalText === 'string' ? finding.originalText : '',
        normalizedText: typeof finding.normalizedText === 'string' ? finding.normalizedText : '',
      });
      continue;
    }
    for (const occurrence of own) {
      occurrences.push({
        ...entry,
        source: 'finding',
        pipeline: occurrence.pipeline || '(unknown)',
        extractionKind: occurrence.extractionKind || 'unknown',
        path: occurrence.path || null,
        originalText: typeof occurrence.originalText === 'string' ? occurrence.originalText : '',
        normalizedText: typeof occurrence.normalizedText === 'string' ? occurrence.normalizedText : '',
      });
    }
  }

  const { presence, counts: pipelineItems } = collectPipelinePresence(result);

  // Presence evidence that duplicates a finding occurrence on the same pipeline
  // adds nothing but noise, so it is dropped. Comparison is on the normalized
  // text, which is the same comparison the ingestion pipeline uses for grouping.
  const seen = new Set(occurrences
    .filter((occurrence) => occurrence.source === 'finding')
    .map((occurrence) => `${occurrence.pipeline}\u0000${normalizeForPresence(occurrence.originalText)}`));
  const pipelinePresence = [];
  for (const item of presence) {
    const key = `${item.pipeline}\u0000${normalizeForPresence(item.originalText)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    pipelinePresence.push(item);
  }

  const levelCount = {};
  for (const level of LEVELS) levelCount[level] = Number((result.levelCount || {})[level]) || 0;

  const intents = [...new Set(findings.flatMap((finding) => (Array.isArray(finding.intents) ? finding.intents : [])))].sort();

  return {
    findings: findings.map((finding) => ({
      id: finding.id || null,
      level: finding.impact && finding.impact.level ? finding.impact.level : 'info',
      intents: Array.isArray(finding.intents) ? finding.intents.slice() : [],
      humanVisible: finding.humanVisible === true,
      delivery: finding.delivery || null,
      aiProfiles: Array.isArray(finding.aiProfiles) ? finding.aiProfiles.slice() : [],
    })),
    occurrences,
    pipelinePresence,
    pipelineItems,
    levelCount,
    maxLevel: maxLevelOf(levelCount),
    intents,
    cloak: result.cloak || null,
    uaProbe: Array.isArray(result.uaProbe) ? result.uaProbe : [],
    blockedRequests: Array.isArray(result.blockedRequests) ? result.blockedRequests.length : 0,
    // Extraction kinds describe how the RISK MODEL classified text, so only
    // finding occurrences contribute. Presence evidence has no kind to report.
    extractionKinds: [...new Set(occurrences.map((occurrence) => occurrence.extractionKind))].sort(),
  };
}

/**
 * Occurrences that satisfy one expect.evidence entry.
 *
 * A kind or a path can only be asserted by finding evidence, because those
 * attributes are produced by the risk model, not by the ingestion profiles. When
 * an entry names neither, pipeline-presence evidence may satisfy it: the text
 * being in that pipeline's returned output is the observation.
 */
function matchEvidence(observations, entry) {
  const pipeline = entry.pipeline;
  const findingMatches = observations.occurrences.filter((occurrence) => occurrence.pipeline === pipeline
    && (entry.kind === undefined || occurrence.extractionKind === entry.kind)
    && (entry.pathContains === undefined || (occurrence.path && occurrence.path.includes(entry.pathContains)))
    && (textContains(occurrence.originalText, entry.contains)
      || textContains(occurrence.normalizedText, entry.contains)));

  const requiresClassification = entry.kind !== undefined || entry.pathContains !== undefined;
  const presenceMatches = requiresClassification
    ? []
    : observations.pipelinePresence.filter((item) => item.pipeline === pipeline
      && (textContains(item.originalText, entry.contains)
        || textContains(item.normalizedText, entry.contains)
        || textContains(normalizeForPresence(item.originalText), entry.contains)));

  return [...findingMatches, ...presenceMatches];
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

function check(key, expectation, kind, status, expected, observed, detail) {
  return { key, expectation, kind, status, expected, observed, detail: detail || null };
}

function pass(key, expectation, kind, expected, observed, detail) {
  return check(key, expectation, kind, 'pass', expected, observed, detail);
}

function fail(key, expectation, kind, expected, observed, detail) {
  return check(key, expectation, kind, 'fail', expected, observed, detail);
}

/**
 * Every check for one case under one capability template.
 *
 * @param {object} spec one manifest case
 * @param {object} observations result of collectObservations()
 * @param {string} capabilityKey the template this analysis ran under
 */
function evaluateChecks(spec, observations, capabilityKey) {
  const expect = spec.expect || {};
  const checks = [];
  const evidence = Array.isArray(expect.evidence) ? expect.evidence : [];

  // --- payload carriers --------------------------------------------------
  evidence.forEach((entry, index) => {
    const key = `evidence[${index}]`;
    const expectation = `expect.evidence[${index}]`;
    const expected = {
      pipeline: entry.pipeline,
      kind: entry.kind === undefined ? null : entry.kind,
      pathContains: entry.pathContains === undefined ? null : entry.pathContains,
      contains: entry.contains,
    };
    const matches = matchEvidence(observations, entry);
    if (matches.length > 0) {
      const first = matches[0];
      checks.push(pass(key, expectation, 'evidence', expected, {
        matches: matches.length,
        path: first.path,
        extractionKind: first.extractionKind,
        findingId: first.findingId !== undefined ? first.findingId : null,
        source: first.source,
      }, first.source === 'finding'
        ? `${entry.pipeline} read "${entry.contains}" (${first.extractionKind}${first.path ? ` at ${first.path}` : ''})`
        : `${entry.pipeline} output contains "${entry.contains}" (${first.source}; not a security finding)`));
    } else {
      const seenKinds = [...new Set(observations.occurrences
        .filter((occurrence) => occurrence.pipeline === entry.pipeline)
        .map((occurrence) => occurrence.extractionKind))].sort();
      const presenceSources = [...new Set(observations.pipelinePresence
        .filter((item) => item.pipeline === entry.pipeline)
        .map((item) => item.source))].sort();
      checks.push(fail(key, expectation, 'evidence', expected, {
        matches: 0,
        pipelineItems: observations.pipelineItems[entry.pipeline] || 0,
        extractionKinds: seenKinds,
        presenceSources,
      }, `${entry.pipeline} did not carry "${entry.contains}"`
        + (seenKinds.length ? ` (finding kinds seen on that pipeline: ${seenKinds.join(', ')})` : ' (no finding occurrence on that pipeline)')
        + (presenceSources.length ? ` (outputs checked for presence: ${presenceSources.join(', ')})` : ' (no output available for presence checking)')));
    }

    if (Array.isArray(entry.forbidIntents) && entry.forbidIntents.length > 0) {
      const forbidden = new Set(entry.forbidIntents);
      // Only finding occurrences can "offend": presence evidence carries no
      // intent, so it can neither violate nor satisfy an intent expectation.
      const offenders = matches.filter((occurrence) => occurrence.source === 'finding'
        && occurrence.intents.some((intent) => forbidden.has(intent)));
      const keyName = `${key}.forbidIntents`;
      if (offenders.length === 0) {
        checks.push(pass(keyName, `${expectation}.forbidIntents`, 'forbidden-intent', entry.forbidIntents, { offenders: 0 },
          `no finding carrying "${entry.contains}" reported ${entry.forbidIntents.join(', ')}`));
      } else {
        const observed = [...new Set(offenders.flatMap((occurrence) => occurrence.intents).filter((intent) => forbidden.has(intent)))].sort();
        checks.push(fail(keyName, `${expectation}.forbidIntents`, 'forbidden-intent', entry.forbidIntents, { offenders: offenders.length, intents: observed },
          `the carrier for "${entry.contains}" was rated ${observed.join(', ')} (finding ${offenders[0].findingId}, level ${offenders[0].level})`));
      }
    }
  });

  // --- pipeline summary view --------------------------------------------
  for (const pipeline of Array.isArray(expect.pipelines) ? expect.pipelines : []) {
    const entryIndexes = evidence.map((entry, index) => (entry.pipeline === pipeline ? index : -1)).filter((index) => index >= 0);
    const failed = entryIndexes.filter((index) => checks.find((candidate) => candidate.key === `evidence[${index}]`)?.status === 'fail');
    const observed = {
      items: observations.pipelineItems[pipeline] || 0,
      evidenceMatched: entryIndexes.length - failed.length,
      evidenceExpected: entryIndexes.length,
    };
    if (failed.length === 0) {
      checks.push(pass(`pipeline:${pipeline}`, `expect.pipelines (${pipeline})`, 'pipeline', 'carries every declared payload', observed,
        `${pipeline} read ${observed.items} item(s) and carried ${observed.evidenceMatched}/${observed.evidenceExpected} declared payload(s)`));
    } else {
      checks.push(fail(`pipeline:${pipeline}`, `expect.pipelines (${pipeline})`, 'pipeline',
        'carries every declared payload', observed, `${pipeline} missed ${failed.length} declared payload(s)`));
    }
  }

  // --- absence -----------------------------------------------------------
  for (const pipeline of Array.isArray(expect.absentFrom) ? expect.absentFrom : []) {
    const key = `absentFrom:${pipeline}`;
    const violated = [];
    for (const entry of evidence) {
      const matches = matchEvidence(observations, { ...entry, pipeline });
      if (matches.length > 0) violated.push({ contains: entry.contains, path: matches[0].path, source: matches[0].source });
    }
    if (violated.length === 0) {
      checks.push(pass(key, `expect.absentFrom (${pipeline})`, 'absent', 'carries no declared payload',
        { matches: 0, items: observations.pipelineItems[pipeline] || 0 },
        `${pipeline} read ${observations.pipelineItems[pipeline] || 0} item(s) but none of the declared payloads`));
    } else {
      checks.push(fail(key, `expect.absentFrom (${pipeline})`, 'absent', 'carries no declared payload',
        { matches: violated.length, first: violated[0] },
        `${pipeline} carried ${violated.length} declared payload(s), first at ${violated[0].path || '(no path)'}`));
    }
  }

  // --- intents -----------------------------------------------------------
  for (const intent of Array.isArray(expect.intents) ? expect.intents : []) {
    const key = `intent:${intent}`;
    if (observations.intents.includes(intent)) {
      checks.push(pass(key, `expect.intents (${intent})`, 'intent', intent, { observed: true, all: observations.intents },
        `the page was rated with intent "${intent}"`));
    } else {
      checks.push(fail(key, `expect.intents (${intent})`, 'intent', intent, { observed: false, all: observations.intents },
        `intent "${intent}" was not observed (observed: ${observations.intents.length ? observations.intents.join(', ') : 'none'})`));
    }
  }
  for (const intent of Array.isArray(expect.forbiddenIntents) ? expect.forbiddenIntents : []) {
    const key = `forbiddenIntent:${intent}`;
    if (observations.intents.includes(intent)) {
      checks.push(fail(key, `expect.forbiddenIntents (${intent})`, 'forbidden-intent', intent, { observed: true, all: observations.intents },
        `intent "${intent}" must not appear on this page, but it was observed`));
    } else {
      checks.push(pass(key, `expect.forbiddenIntents (${intent})`, 'forbidden-intent', intent, { observed: false },
        `intent "${intent}" was not observed`));
    }
  }

  // --- capability level --------------------------------------------------
  const declared = (expect.capabilities && expect.capabilities[capabilityKey]) || null;
  if (declared) {
    const observedMax = observations.maxLevel;
    const base = {
      capability: capabilityKey,
      levelCount: observations.levelCount,
      maxLevel: observedMax,
      evaluated: true,
    };
    if (declared.minLevel !== undefined) {
      const key = `capability:${capabilityKey}:minLevel`;
      const ok = observedMax !== null && levelRank(observedMax) >= levelRank(declared.minLevel);
      checks.push(ok
        ? pass(key, `expect.capabilities.${capabilityKey}.minLevel`, 'capability', declared.minLevel, base,
          `strongest rating under "${capabilityKey}" is ${observedMax}`)
        : fail(key, `expect.capabilities.${capabilityKey}.minLevel`, 'capability', declared.minLevel, base,
          observedMax === null
            ? `no finding was produced, so the page never reached "${declared.minLevel}" under "${capabilityKey}"`
            : `strongest rating under "${capabilityKey}" is ${observedMax}, below the expected floor "${declared.minLevel}"`));
    }
    if (declared.maxLevel !== undefined) {
      const key = `capability:${capabilityKey}:maxLevel`;
      const ok = observedMax === null || levelRank(observedMax) <= levelRank(declared.maxLevel);
      checks.push(ok
        ? pass(key, `expect.capabilities.${capabilityKey}.maxLevel`, 'capability', declared.maxLevel, base,
          observedMax === null ? 'no finding was produced' : `strongest rating under "${capabilityKey}" is ${observedMax}`)
        : fail(key, `expect.capabilities.${capabilityKey}.maxLevel`, 'capability', declared.maxLevel, base,
          `strongest rating under "${capabilityKey}" is ${observedMax}, above the expected ceiling "${declared.maxLevel}"`));
    }
  }

  // --- cloaking ----------------------------------------------------------
  if (expect.cloak) {
    const key = 'cloak';
    const cloak = observations.cloak;
    const probed = observations.uaProbe.filter((entry) => entry.status === 'probed');
    const expected = { required: true, triggerToken: expect.cloak.triggerToken };
    if (cloak && cloak.triggerToken === expect.cloak.triggerToken) {
      checks.push(pass(key, 'expect.cloak', 'cloak', expected,
        { triggerToken: cloak.triggerToken, aiOnly: (cloak.aiOnlyFull || []).length, humanBytes: cloak.humanBytes, aiBytes: cloak.aiBytes },
        `the server served AI-only content to ${cloak.triggerToken}`));
    } else {
      checks.push(fail(key, 'expect.cloak', 'cloak', expected,
        { triggerToken: cloak ? cloak.triggerToken : null, probed: probed.map((entry) => entry.token) },
        cloak
          ? `cloaking was detected, but the trigger was ${cloak.triggerToken}, not ${expect.cloak.triggerToken}`
          : `no cloaking was detected (probed tokens: ${probed.map((entry) => entry.token).join(', ') || 'none'})`));
    }
  }

  return checks;
}

// ---------------------------------------------------------------------------
// Aggregation across capability runs
// ---------------------------------------------------------------------------

/**
 * Merge the check lists of every capability run.
 *
 * A capability-independent expectation (pipelines, intents, absence) is
 * satisfied only when it holds in EVERY run, and the merged check names the
 * capabilities where it did not. Capability level checks are naturally
 * per-run. The first failing observation is kept as the reported detail.
 */
function aggregateChecks(runs) {
  const merged = new Map();
  for (const run of runs) {
    for (const item of run.checks) {
      if (!merged.has(item.key)) {
        merged.set(item.key, { ...item, capabilities: [run.capability], failedIn: item.status === 'fail' ? [run.capability] : [] });
        continue;
      }
      const existing = merged.get(item.key);
      existing.capabilities.push(run.capability);
      if (item.status === 'fail') {
        existing.failedIn.push(run.capability);
        if (existing.status === 'pass') {
          existing.status = 'fail';
          existing.expected = item.expected;
          existing.observed = item.observed;
          existing.detail = item.detail;
        }
      }
    }
  }
  const checks = [...merged.values()];
  const failures = checks.filter((item) => item.status === 'fail').map((item) => ({
    expectation: item.expectation,
    expected: item.expected,
    observed: item.observed,
    capabilities: item.failedIn,
    message: item.detail,
  }));
  return { checks, failures };
}

/**
 * Case status from what actually happened.
 *
 * ERROR and SKIPPED are decided by the runner (they are about whether the case
 * could be exercised at all); this function only distinguishes a violated
 * expectation from a satisfied one.
 */
function statusFor({ error, skipReason, failures }) {
  if (error) return 'error';
  if (skipReason) return 'skipped';
  return failures && failures.length > 0 ? 'fail' : 'pass';
}

/** Exit code for a finished run. ERROR dominates FAIL; --strict makes skips fail. */
function exitCodeFor(summary, options = {}) {
  const total = Number(summary && summary.total) || 0;
  if (total === 0) return 2;
  if (Number(summary.error) > 0) return 2;
  if (Number(summary.fail) > 0) return 1;
  if (options.strict === true && Number(summary.skippedExcludingFiltered) > 0) return 1;
  return 0;
}

module.exports = {
  textContains,
  collectObservations,
  matchEvidence,
  evaluateChecks,
  aggregateChecks,
  statusFor,
  exitCodeFor,
  PIPELINES,
};
