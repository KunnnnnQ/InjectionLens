#!/usr/bin/env node
// Step 6 replica fixture runner (Lane 2 half).
//
// Runs the replica fixture manifest against the four ingestion pipelines and
// reports, per case, what was expected and what was actually observed.
//
// Design points that matter when reading the output:
//
//   * The runner serves the fixtures itself, from an ephemeral loopback port.
//     It never needs a development server to be running, and it never analyses
//     anything except the origin it bound for this run.
//   * Every case gets its own network policy, because analyze() reports
//     blockedRequests from the policy it was handed; sharing one policy would
//     make the second case's blocked-request count include the first case's.
//   * A case is never silently skipped. SKIPPED always carries a reason code,
//     and "the manifest says this is a known gap" is a reason that is itself
//     checked: if the payload ever starts being detected, the case FAILS as a
//     stale gap instead of quietly passing.
//
// Usage:
//   node scripts/run-fixtures.js [--manifest <path>] [--fixtures-root <dir>]
//        [--only <id[,id...]>] [--capability <key>]... [--json <path|->|--no-json]
//        [--strict] [--list] [--timeout-ms <n>] [--verbose]
//
// Exit codes: 0 pass, 1 fail (or a non-filtered skip under --strict),
//             2 usage error, invalid/unreadable manifest, bind failure,
//               no case selected, case ERROR, or unwritable report.
//
// Evidence: Step 6 contract sections 3.1-3.6; plan section 5 (the replica set and the
//   results table it feeds); AGENTS.md rules 7 (test only against the local
//   fixture origin) and 8 (use ephemeral ports, never a busy one).

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');
const express = require('express');

const { analyze } = require('../server/lib/analyze');
const { CAPABILITY_TEMPLATES, INTENT_RULES } = require('../server/lib/risk');
const {
  BROWSER_UA,
  CRAWLER_UA_TOKENS,
  detectCrawlerToken,
} = require('../server/lib/ingest');
const { createPolicy } = require('../server/lib/net-guard');
const { executablePath } = require('../server/lib/browser');

const manifestLib = require('./lib/replica-manifest');
const verdict = require('./lib/fixture-verdict');

const REPO_ROOT = path.join(__dirname, '..');
const DEFAULT_MANIFEST = path.join(REPO_ROOT, 'server', 'fixtures', 'replicas.manifest.json');
const DEFAULT_FIXTURES_ROOT = path.join(REPO_ROOT, 'server', 'fixtures');
const DEFAULT_JSON_PATH = path.join(REPO_ROOT, 'eval', 'results', 'stage6-fixtures.json');

// The development app owns these ports; an ephemeral bind must never take one.
const RESERVED_PORTS = [7100, 7101];
const HOST = '127.0.0.1';
const DEFAULT_TIMEOUT_MS = 120000;
const ROUTE_PROBE_TIMEOUT_MS = 10000;

class UsageError extends Error {}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const PARSE_OPTIONS = {
  manifest: { type: 'string' },
  'fixtures-root': { type: 'string' },
  only: { type: 'string', multiple: true },
  capability: { type: 'string', multiple: true },
  json: { type: 'string' },
  'no-json': { type: 'boolean' },
  strict: { type: 'boolean' },
  list: { type: 'boolean' },
  'timeout-ms': { type: 'string' },
  verbose: { type: 'boolean' },
  help: { type: 'boolean' },
};

const USAGE = [
  'Usage: node scripts/run-fixtures.js [options]',
  '',
  '  --manifest <path>       manifest to run (default: server/fixtures/replicas.manifest.json)',
  '  --fixtures-root <dir>   directory the manifest resolves against (default: server/fixtures)',
  '  --only <id[,id...]>     run only these case ids (repeatable); others are reported as filtered-out',
  '  --capability <key>      restrict every case to this capability template (repeatable)',
  '  --json <path|->         write the machine-readable report (default: eval/results/stage6-fixtures.json;',
  '                          "-" prints only the JSON, on stdout, with the human report on stderr)',
  '  --no-json               do not write a report file',
  '  --strict                a SKIPPED case that is not filtered-out fails the run',
  '  --list                  validate the manifest, print the case ids, run nothing',
  '  --timeout-ms <n>        per-analysis timeout (default: 120000)',
  '  --verbose               include error stacks in the report',
  '  --help                  show this message',
].join('\n');

function parseCli(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: PARSE_OPTIONS, allowPositionals: false });
  } catch (error) {
    throw new UsageError(`${error.message}\n\n${USAGE}`);
  }
  const values = parsed.values;
  if (values.help) return { help: true };
  if (values.json !== undefined && values['no-json']) {
    throw new UsageError('--json and --no-json cannot be combined');
  }
  const timeoutMs = values['timeout-ms'] === undefined ? DEFAULT_TIMEOUT_MS : Number(values['timeout-ms']);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new UsageError(`--timeout-ms must be a positive number, got ${JSON.stringify(values['timeout-ms'])}`);
  }
  const only = (values.only || []).flatMap((value) => value.split(',')).map((value) => value.trim()).filter(Boolean);
  return {
    help: false,
    manifestPath: values.manifest ? path.resolve(values.manifest) : DEFAULT_MANIFEST,
    fixturesRoot: values['fixtures-root'] ? path.resolve(values['fixtures-root']) : DEFAULT_FIXTURES_ROOT,
    only,
    capabilities: values.capability || [],
    jsonPath: values['no-json'] ? null : (values.json === undefined ? DEFAULT_JSON_PATH : values.json),
    strict: values.strict === true,
    list: values.list === true,
    verbose: values.verbose === true,
    timeoutMs,
  };
}

// ---------------------------------------------------------------------------
// Manifest loading and validation
// ---------------------------------------------------------------------------

function makeFixtureReader(fixturesRoot) {
  const root = path.resolve(fixturesRoot);
  return (relPath) => {
    const resolved = path.resolve(root, relPath);
    const relative = path.relative(root, resolved);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      return { ok: false, reason: `"${relPath}" escapes the fixture root` };
    }
    try {
      return { ok: true, content: fs.readFileSync(resolved, 'utf8') };
    } catch (error) {
      return { ok: false, reason: `${relPath}: ${error.code || error.message}` };
    }
  };
}

function listFixtureFiles(fixturesRoot) {
  try {
    return fs.readdirSync(fixturesRoot).filter((name) => name.toLowerCase().endsWith('.html'));
  } catch {
    return [];
  }
}

function loadManifest(manifestPath) {
  let raw;
  try {
    raw = fs.readFileSync(manifestPath, 'utf8');
  } catch (error) {
    return { ok: false, reason: `cannot read manifest ${manifestPath}: ${error.code || error.message}` };
  }
  try {
    return { ok: true, manifest: JSON.parse(raw), raw };
  } catch (error) {
    return { ok: false, reason: `manifest is not valid JSON: ${error.message}` };
  }
}

/** The live vocabularies, read from the product rather than restated here. */
function liveTaxonomy() {
  return {
    intentKeys: Object.keys(INTENT_RULES),
    capabilityKeys: Object.keys(CAPABILITY_TEMPLATES),
    crawlerTokens: CRAWLER_UA_TOKENS.slice(),
  };
}

/**
 * Which capability templates this case runs under.
 *
 * Without --capability: every declared template, primary first, so the case's
 * headline number is the first run. With --capability: exactly the requested
 * templates, so a restricted run costs only what it asks for.
 */
function selectCapabilities(spec, requested) {
  const declared = Object.keys(spec.expect.capabilities);
  if (!requested || requested.length === 0) {
    const primary = spec.expect.primaryCapability;
    return [primary, ...declared.filter((key) => key !== primary)];
  }
  const wanted = [...new Set(requested)];
  const missing = wanted.filter((key) => !declared.includes(key));
  if (missing.length > 0) {
    throw new UsageError(`--capability ${missing.join(', ')} is not declared by case "${spec.id}" (declared: ${declared.join(', ')})`);
  }
  return wanted;
}

// ---------------------------------------------------------------------------
// Fixture server
// ---------------------------------------------------------------------------

function listenOnEphemeralPort(app, attempts = 5) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const candidate = app.listen(0, HOST, async () => {
      settled = true;
      const address = candidate.address();
      if (!address || address.address !== HOST) {
        await closeServer(candidate);
        reject(new Error(`fixture server bound ${address ? address.address : 'an unknown address'}, expected ${HOST}`));
        return;
      }
      if (RESERVED_PORTS.includes(address.port)) {
        // The OS handed us a port the development app uses; take another one.
        await closeServer(candidate);
        if (attempts <= 1) {
          reject(new Error(`could not bind an ephemeral port outside ${RESERVED_PORTS.join('/')}`));
          return;
        }
        listenOnEphemeralPort(app, attempts - 1).then(resolve, reject);
        return;
      }
      resolve({ server: candidate, port: address.port, origin: `http://${HOST}:${address.port}` });
    });
    candidate.once('error', (error) => {
      if (!settled) reject(new Error(`fixture server could not bind ${HOST}:0: ${error.code || error.message}`));
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server || !server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });
}

/**
 * Start a fixture server for this run.
 *
 * The static mount is the same express.static the app uses, and a
 * ua-conditional case is dispatched by the same detectCrawlerToken() the app
 * uses, so the bytes served here are the bytes the demo serves - without the
 * runner depending on a running development server or on server/index.js.
 */
async function createFixtureServer({ fixturesRoot, cases, readFixture }) {
  const app = express();
  const uaConditional = [];

  for (const spec of cases) {
    if (!spec.serve || spec.serve.mode !== 'ua-conditional') continue;
    const route = manifestLib.routeFor(spec);
    const tokens = spec.serve.triggerTokens.slice();
    const human = readFixture(spec.serve.human);
    const ai = readFixture(spec.serve.ai);
    uaConditional.push({ id: spec.id, route, tokens, human, ai });
    app.get(route, (req, res) => {
      const token = detectCrawlerToken(req.get('user-agent') || '');
      const serveAi = !!token && tokens.includes(token);
      res.type('html').send(serveAi ? ai.content : human.content);
    });
  }

  app.use('/fixtures', express.static(fixturesRoot));

  const { server, port, origin } = await listenOnEphemeralPort(app);
  return { app, server, port, origin, uaConditional };
}

// ---------------------------------------------------------------------------
// Per-case execution
// ---------------------------------------------------------------------------

async function fetchRoute(url, userAgent) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ROUTE_PROBE_TIMEOUT_MS);
  try {
    const headers = userAgent ? { 'User-Agent': userAgent } : undefined;
    const response = await fetch(url, { headers, signal: controller.signal, redirect: 'error' });
    const body = await response.text();
    return { status: response.status, contentType: response.headers.get('content-type') || '', body };
  } finally {
    clearTimeout(timer);
  }
}

async function analyzeWithin(url, capability, policy, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`analysis of ${url} under "${capability}" exceeded ${timeoutMs} ms`)), timeoutMs);
  });
  try {
    return await Promise.race([analyze(url, capability, { policy }), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function errorInfo(error, verbose) {
  const info = {
    name: error && error.name ? error.name : 'Error',
    message: error && error.message ? error.message : String(error),
    code: error && error.code ? error.code : null,
  };
  // A stack is attached only when it is actually wanted. Carrying the key with
  // an undefined value would make the report change shape when it is serialised
  // to JSON, which the report has to survive unchanged.
  if (verbose && error && error.stack) info.stack = String(error.stack);
  return info;
}

function countChecks(checks, kind) {
  const of = checks.filter((item) => item.kind === kind);
  return { passed: of.filter((item) => item.status === 'pass').length, total: of.length };
}

/**
 * Run one case: serve it, analyse it under every declared capability, then
 * adjudicate the aggregated checks.
 */
async function runCase(spec, context) {
  const started = Date.now();
  const route = manifestLib.routeFor(spec);
  const url = `${context.origin}${route}`;
  const capabilities = context.capabilities(spec);
  const expect = spec.expect;
  const gap = expect.knownGap || null;

  const record = {
    id: spec.id,
    file: spec.file,
    fileSha256: context.fileHashes.get(spec.file) || null,
    title: spec.title,
    source: {
      label: spec.provenance.label,
      date: spec.provenance.date,
      url: spec.provenance.url,
    },
    route,
    url,
    serve: spec.serve
      ? { mode: spec.serve.mode, triggerTokens: (spec.serve.triggerTokens || []).slice() }
      : { mode: 'static' },
    primaryCapability: expect.primaryCapability,
    capabilities,
    expectation: {
      pipelines: (expect.pipelines || []).slice(),
      absentFrom: (expect.absentFrom || []).slice(),
      intents: (expect.intents || []).slice(),
      forbiddenIntents: (expect.forbiddenIntents || []).slice(),
      capabilities: expect.capabilities,
      entity: gap ? 'known-gap' : 'adjudicated',
    },
    status: 'error',
    capabilityResults: [],
    checks: [],
    failures: [],
    pipelineChecks: [],
    intentChecks: [],
    evidenceChecks: [],
    absenceChecks: [],
    cloakCheck: null,
    serveCheck: null,
    observed: null,
    knownGap: gap ? { code: gap.code, reason: gap.reason, payloadContains: gap.payloadContains, detected: null } : null,
    skipReason: null,
    error: null,
    elapsedMs: 0,
  };

  const finish = (status) => {
    record.status = status;
    record.elapsedMs = Date.now() - started;
    return record;
  };

  if (context.globalSkip) {
    record.skipReason = { code: context.globalSkip.code, message: context.globalSkip.message };
    return finish('skipped');
  }

  // --- the route must exist before anything is analysed ------------------
  let probe;
  try {
    probe = await fetchRoute(url, BROWSER_UA);
  } catch (error) {
    record.error = errorInfo(error, context.verbose);
    return finish('error');
  }
  if (probe.status !== 200) {
    record.error = { name: 'FixtureRouteError', code: null, message: `${route} answered HTTP ${probe.status} (expected 200)` };
    return finish('error');
  }
  if (!/^text\/html/i.test(probe.contentType)) {
    record.error = { name: 'FixtureRouteError', code: null, message: `${route} answered content-type ${probe.contentType || '(none)'} (expected text/html)` };
    return finish('error');
  }

  // --- ua-conditional serving is an expectation of its own ---------------
  const serveChecks = [];
  if (spec.serve && spec.serve.mode === 'ua-conditional') {
    const tokens = spec.serve.triggerTokens;
    const trigger = tokens[0];
    const otherToken = CRAWLER_UA_TOKENS.find((token) => !tokens.includes(token)) || null;
    const readHuman = context.readFixture(spec.serve.human).content;
    const readAi = context.readFixture(spec.serve.ai).content;
    const cases = [
      { label: 'browser UA gets the human page', ua: BROWSER_UA, expected: readHuman },
      { label: `${trigger} gets the AI-only page`, ua: trigger, expected: readAi },
    ];
    if (otherToken) {
      cases.push({ label: `${otherToken} still gets the human page`, ua: otherToken, expected: readHuman });
    }
    for (const item of cases) {
      let response;
      try {
        response = await fetchRoute(url, item.ua);
      } catch (error) {
        serveChecks.push({
          key: `serve:${item.ua}`,
          expectation: 'serve.uaConditional',
          kind: 'serve',
          status: 'fail',
          expected: item.label,
          observed: { error: error.message },
          detail: `could not fetch ${url} as ${item.ua}: ${error.message}`,
        });
        continue;
      }
      const matches = response.body === item.expected;
      serveChecks.push({
        key: `serve:${item.ua}`,
        expectation: 'serve.uaConditional',
        kind: 'serve',
        status: matches ? 'pass' : 'fail',
        expected: item.label,
        observed: { bytes: response.body.length, expectedBytes: item.expected.length },
        detail: matches ? item.label : `${item.label}: served ${response.body.length} B, expected ${item.expected.length} B`,
      });
    }
    record.serveCheck = serveChecks;
  }

  // --- one analysis per capability, each with its own network policy -----
  const runs = [];
  for (const capability of capabilities) {
    // A fresh policy per run: analyze() reports blockedRequests from it.
    const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: context.port }] });
    let analysis;
    try {
      analysis = await analyzeWithin(url, capability, policy, context.timeoutMs);
    } catch (error) {
      record.error = { ...errorInfo(error, context.verbose), capability };
      return finish('error');
    }
    const observations = verdict.collectObservations(analysis);
    const checks = verdict.evaluateChecks(spec, observations, capability);
    runs.push({ capability, observations, checks, policy });
    record.capabilityResults.push({
      capability,
      evaluated: !gap,
      levels: observations.levelCount,
      maxLevel: observations.maxLevel,
      observedIntents: observations.intents,
      pipelines: observations.pipelineItems,
      extractionKinds: observations.extractionKinds,
      pipelinePresence: {
        total: observations.pipelinePresence.length,
        bySource: observations.pipelinePresence.reduce((acc, item) => {
          acc[item.source] = (acc[item.source] || 0) + 1;
          return acc;
        }, {}),
      },
      cloak: observations.cloak
        ? { triggerToken: observations.cloak.triggerToken, aiOnly: (observations.cloak.aiOnlyFull || []).length }
        : null,
      uaProbe: {
        probed: observations.uaProbe.filter((entry) => entry.status === 'probed').length,
        skipped: observations.uaProbe.filter((entry) => entry.status !== 'probed').length,
        triggerToken: observations.cloak ? observations.cloak.triggerToken : null,
      },
      blockedRequests: observations.blockedRequests,
    });
  }

  // --- what the primary capability actually saw --------------------------
  const primaryRun = record.capabilityResults.find((item) => item.capability === expect.primaryCapability)
    || record.capabilityResults[0]
    || null;
  record.observed = primaryRun
    ? {
      primaryCapability: primaryRun.capability,
      maxLevel: primaryRun.maxLevel,
      levels: primaryRun.levels,
      intents: primaryRun.observedIntents,
      pipelines: primaryRun.pipelines,
      cloaking: primaryRun.cloak,
      uaProbe: primaryRun.uaProbe,
      blockedRequests: primaryRun.blockedRequests,
    }
    : null;

  // --- a declared known gap is checked, not believed ---------------------
  if (gap) {
    // Staleness is about DETECTION, not presence. Pipeline-presence evidence
    // records that a pipeline read some text; it carries no intent and no level,
    // so it cannot close a gap. A gap closes only when the payload reaches a
    // FINDING occurrence, which is what "the detector now reads this" means.
    const detected = runs.some((run) => run.observations.occurrences
      .some((occurrence) => verdict.textContains(occurrence.originalText, gap.payloadContains)
        || verdict.textContains(occurrence.normalizedText, gap.payloadContains)));
    record.knownGap.detected = detected;
    if (detected) {
      record.failures.push({
        expectation: 'expect.knownGap.expectNoDetection',
        expected: 'payload still not ingested by any pipeline',
        observed: 'payload detected',
        capabilities: runs.map((run) => run.capability),
        message: `the declared known gap is stale: "${gap.payloadContains}" is now read by a pipeline, so case "${spec.id}" should be adjudicated`,
      });
      record.checks.push({
        key: 'knownGap:detected', expectation: 'expect.knownGap.expectNoDetection', kind: 'known-gap',
        status: 'fail', expected: 'not detected', observed: 'detected',
        detail: `"${gap.payloadContains}" is now read by a pipeline: update the manifest`,
      });
      return finish('fail');
    }
    record.checks.push({
      key: 'knownGap:notDetected', expectation: 'expect.knownGap.expectNoDetection', kind: 'known-gap',
      status: 'pass', expected: 'not detected', observed: 'not detected',
      detail: `"${gap.payloadContains}" is still not read by any pipeline (gap code "${gap.code}")`,
    });
    record.skipReason = { code: 'known-gap', message: `${gap.code}: ${gap.reason}` };
    record.failures = [];
    return finish('skipped');
  }

  // --- aggregate and adjudicate -----------------------------------------
  const aggregated = verdict.aggregateChecks(runs);
  record.checks = [...aggregated.checks, ...serveChecks];
  record.failures = [
    ...aggregated.failures,
    ...serveChecks.filter((item) => item.status === 'fail').map((item) => ({
      expectation: item.expectation,
      expected: item.expected,
      observed: item.observed,
      capabilities,
      message: item.detail,
    })),
  ];
  record.pipelineChecks = record.checks.filter((item) => item.kind === 'pipeline');
  record.intentChecks = record.checks.filter((item) => item.kind === 'intent' || item.kind === 'forbidden-intent');
  record.evidenceChecks = record.checks.filter((item) => item.kind === 'evidence' || item.kind === 'forbidden-intent');
  record.absenceChecks = record.checks.filter((item) => item.kind === 'absent');
  record.cloakCheck = record.checks.find((item) => item.kind === 'cloak') || null;
  if (record.observed) {
    record.observed.checks = {
      evidence: countChecks(record.checks, 'evidence'),
      pipelines: countChecks(record.checks, 'pipeline'),
      intents: countChecks(record.checks, 'intent'),
      capabilities: countChecks(record.checks, 'capability'),
    };
  }

  return finish(verdict.statusFor({ error: null, skipReason: null, failures: record.failures }));
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

function gitHead() {
  try {
    const { execFileSync } = require('node:child_process');
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/**
 * Run the manifest. Pure with respect to the process: it prints nothing, exits
 * nothing, and returns the report - which is what the tests exercise.
 */
async function runFixtures(options) {
  const manifestPath = options.manifestPath;
  const fixturesRoot = options.fixturesRoot;
  const readFixture = makeFixtureReader(fixturesRoot);
  const warnings = [];
  const startedAt = new Date().toISOString();

  const loaded = loadManifest(manifestPath);
  if (!loaded.ok) {
    const error = new UsageError(loaded.reason);
    error.exitCode = 2;
    throw error;
  }

  const validation = manifestLib.validateManifest(loaded.manifest, {
    taxonomy: liveTaxonomy(),
    readFixture,
    fixtureFiles: listFixtureFiles(fixturesRoot),
  });
  if (!validation.ok) {
    const error = new UsageError(`manifest ${manifestPath} is invalid:\n${validation.errors.map((item) => `  - ${item.path}: ${item.message}`).join('\n')}`);
    error.errors = validation.errors;
    error.exitCode = 2;
    throw error;
  }
  warnings.push(...validation.warnings);

  const allCases = loaded.manifest.cases;
  const knownIds = allCases.map((spec) => spec.id);
  if (options.only.length > 0) {
    const unknown = options.only.filter((id) => !knownIds.includes(id));
    if (unknown.length > 0) {
      const error = new UsageError(`--only lists unknown case id(s): ${unknown.join(', ')}\nknown ids: ${knownIds.join(', ')}`);
      error.exitCode = 2;
      throw error;
    }
  }
  const selected = options.only.length > 0 ? allCases.filter((spec) => options.only.includes(spec.id)) : allCases;
  if (selected.length === 0) {
    const error = new UsageError('no case was selected: an empty run must never be reported as a pass');
    error.exitCode = 2;
    throw error;
  }

  const fileHashes = new Map();
  for (const spec of selected) {
    for (const file of manifestLib.referencedFiles(spec)) {
      const read = readFixture(file);
      if (read.ok) fileHashes.set(file, manifestLib.sha256(read.content));
    }
  }

  if (process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST) {
    warnings.push({
      path: 'environment',
      message: 'INJECTIONLENS_UA_PROBE_ALLOWLIST is set, but this run only ever probes the fixture origin it bound',
    });
  }

  const globalSkip = executablePath
    ? null
    : {
      code: 'no-headless-browser',
      message: 'no system Chrome/Edge was found, and analyze() renders every page: rendered-dom and accessibility-tree cannot run',
    };
  if (globalSkip) warnings.push({ path: 'environment', message: globalSkip.message });

  const cases = selected;
  const filteredOut = allCases.filter((spec) => !selected.includes(spec));

  // Resolve the capability set for every selected case before binding a port,
  // so a bad --capability is a usage error rather than a half-finished run.
  const capabilityPlan = new Map();
  for (const spec of cases) capabilityPlan.set(spec.id, selectCapabilities(spec, options.capabilities));

  const server = await createFixtureServer({ fixturesRoot, cases, readFixture });
  const context = {
    origin: server.origin,
    port: server.port,
    timeoutMs: options.timeoutMs,
    verbose: options.verbose === true,
    globalSkip,
    readFixture,
    fileHashes,
    capabilities: (spec) => capabilityPlan.get(spec.id),
  };

  const results = [];
  try {
    for (const spec of cases) {
      results.push(await runCase(spec, context));
    }
    for (const spec of filteredOut) {
      results.push({
        id: spec.id,
        file: spec.file,
        fileSha256: null,
        title: spec.title,
        source: { label: spec.provenance.label, date: spec.provenance.date, url: spec.provenance.url },
        route: manifestLib.routeFor(spec),
        url: null,
        serve: spec.serve ? { mode: spec.serve.mode, triggerTokens: (spec.serve.triggerTokens || []).slice() } : { mode: 'static' },
        primaryCapability: spec.expect.primaryCapability,
        capabilities: [],
        expectation: { entity: spec.expect.knownGap ? 'known-gap' : 'adjudicated' },
        status: 'skipped',
        capabilityResults: [],
        checks: [],
        failures: [],
        skipReason: { code: 'filtered-out', message: 'not selected by --only in this run' },
        error: null,
        elapsedMs: 0,
      });
    }
  } finally {
    await closeServer(server.server);
  }

  // Manifest order, whatever order the runs finished in.
  const order = new Map(allCases.map((spec, index) => [spec.id, index]));
  results.sort((a, b) => order.get(a.id) - order.get(b.id));

  const summary = {
    total: results.length,
    executed: results.filter((item) => item.status === 'pass' || item.status === 'fail').length,
    pass: results.filter((item) => item.status === 'pass').length,
    fail: results.filter((item) => item.status === 'fail').length,
    skipped: results.filter((item) => item.status === 'skipped').length,
    error: results.filter((item) => item.status === 'error').length,
    skippedExcludingFiltered: results.filter((item) => item.status === 'skipped' && item.skipReason.code !== 'filtered-out').length,
    bySkipCode: results
      .filter((item) => item.status === 'skipped')
      .reduce((accumulator, item) => {
        accumulator[item.skipReason.code] = (accumulator[item.skipReason.code] || 0) + 1;
        return accumulator;
      }, {}),
  };

  return {
    schemaVersion: 1,
    runner: 'scripts/run-fixtures.js',
    runnerVersion: 1,
    generatedAt: startedAt,
    gitHead: gitHead(),
    manifest: { path: manifestPath, sha256: manifestLib.sha256(loaded.raw) },
    fixturesRoot,
    server: { origin: server.origin, port: server.port, host: HOST, ephemeral: true, closed: server.server.listening === false },
    environment: {
      node: process.version,
      platform: process.platform,
      chrome: executablePath || null,
      INJECTIONLENS_ALLOWED_HOSTS: process.env.INJECTIONLENS_ALLOWED_HOSTS || null,
      INJECTIONLENS_UA_PROBE_ALLOWLIST: process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST || null,
      externalAnalysis: 'disabled (allowedHosts = [])',
      uaProbeScope: 'the ephemeral fixture origin of this run only',
    },
    warnings,
    cases: results,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function renderHuman(report, { strict }) {
  const lines = [];
  lines.push('InjectionLens - Step 6 replica fixture runner');
  lines.push(`manifest: ${report.manifest.path} (sha256 ${report.manifest.sha256.slice(0, 16)}...)`);
  lines.push(`fixtures root: ${report.fixturesRoot}`);
  lines.push(`fixture server: ${report.server.origin} (ephemeral, loopback only, closed=${report.server.closed})`);
  lines.push(`chrome: ${report.environment.chrome || 'not found - every case will be SKIPPED'}`);
  lines.push(`external analysis: ${report.environment.externalAnalysis}`);
  lines.push('');

  for (const item of report.cases) {
    const primary = (item.capabilityResults || []).find((entry) => entry.capability === item.primaryCapability)
      || (item.capabilityResults || [])[0];
    const parts = [`${item.status.toUpperCase()} ${item.id}`];
    parts.push(`[${item.primaryCapability}]`);
    if (primary) {
      const declared = (item.expectation && item.expectation.capabilities && item.expectation.capabilities[item.primaryCapability]) || {};
      const floor = declared.minLevel ? `>=${declared.minLevel}` : '';
      const ceiling = declared.maxLevel ? `<=${declared.maxLevel}` : '';
      parts.push(`expected ${[floor, ceiling].filter(Boolean).join(' ') || '(no level bound)'} observed=${primary.maxLevel || 'none'}`);
      parts.push(`evidence ${countChecks(item.checks, 'evidence').passed}/${countChecks(item.checks, 'evidence').total}`);
      parts.push(`intents ${countChecks(item.checks, 'intent').passed}/${countChecks(item.checks, 'intent').total}`);
      parts.push(`pipelines ${countChecks(item.checks, 'pipeline').passed}/${countChecks(item.checks, 'pipeline').total}`);
    }
    parts.push(`${item.elapsedMs}ms`);
    lines.push(parts.join(' '));
    if (item.skipReason) lines.push(`     skipped: ${item.skipReason.code} - ${item.skipReason.message}`);
    if (item.error) lines.push(`     error: ${item.error.name}: ${item.error.message}`);
    for (const failure of item.failures.slice(0, 6)) {
      lines.push(`     FAIL ${failure.expectation}: expected ${JSON.stringify(failure.expected)} - ${failure.message}`);
    }
    if (item.failures.length > 6) lines.push(`     ... ${item.failures.length - 6} more failure(s)`);
  }

  if (report.warnings.length > 0) {
    lines.push('');
    lines.push(`warnings (${report.warnings.length}):`);
    for (const warning of report.warnings) lines.push(`  - ${warning.path}: ${warning.message}`);
  }

  const summary = report.summary;
  lines.push('');
  lines.push(`summary: total=${summary.total} pass=${summary.pass} fail=${summary.fail} skipped=${summary.skipped} error=${summary.error}`
    + ` (skipped excluding filtered-out: ${summary.skippedExcludingFiltered}${strict ? ', --strict makes those fail the run' : ''})`);
  lines.push(`SUMMARY ${JSON.stringify(summary)}`);
  return lines.join('\n');
}

async function main(argv) {
  let options;
  try {
    options = parseCli(argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  let report;
  try {
    if (options.list) {
      // Validation only: prove the manifest can be run without running it.
      const loaded = loadManifest(options.manifestPath);
      if (!loaded.ok) {
        process.stderr.write(`${loaded.reason}\n`);
        return 2;
      }
      const validation = manifestLib.validateManifest(loaded.manifest, {
        taxonomy: liveTaxonomy(),
        readFixture: makeFixtureReader(options.fixturesRoot),
        fixtureFiles: listFixtureFiles(options.fixturesRoot),
      });
      if (!validation.ok) {
        process.stderr.write(`manifest ${options.manifestPath} is invalid:\n${validation.errors.map((item) => `  - ${item.path}: ${item.message}`).join('\n')}\n`);
        return 2;
      }
      for (const spec of loaded.manifest.cases) process.stdout.write(`${spec.id}\t${spec.file}\t${spec.expect.primaryCapability}\n`);
      for (const warning of validation.warnings) process.stderr.write(`warning: ${warning.path}: ${warning.message}\n`);
      return 0;
    }
    report = await runFixtures(options);
  } catch (error) {
    if (error instanceof UsageError || error.exitCode === 2) {
      process.stderr.write(`${error.message}\n`);
      return 2;
    }
    process.stderr.write(`runner error: ${error && error.stack ? error.stack : error}\n`);
    return 2;
  }

  const exitCode = verdict.exitCodeFor(report.summary, { strict: options.strict });
  const human = renderHuman(report, { strict: options.strict });

  if (options.jsonPath === '-') {
    process.stderr.write(`${human}\n`);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`${human}\n`);
    if (options.jsonPath) {
      try {
        fs.mkdirSync(path.dirname(options.jsonPath), { recursive: true });
        fs.writeFileSync(options.jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
        process.stdout.write(`report written: ${options.jsonPath}\n`);
      } catch (error) {
        process.stderr.write(`could not write ${options.jsonPath}: ${error.message}\n`);
        return 2;
      }
    }
  }
  return exitCode;
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => {
      // The headless browser and the listeners are closed by now; exiting
      // explicitly keeps a stray handle from holding the process open.
      process.exit(code);
    })
    .catch((error) => {
      process.stderr.write(`runner error: ${error && error.stack ? error.stack : error}\n`);
      process.exit(2);
    });
}

module.exports = {
  main,
  runFixtures,
  parseCli,
  createFixtureServer,
  closeServer,
  listenOnEphemeralPort,
  makeFixtureReader,
  loadManifest,
  liveTaxonomy,
  selectCapabilities,
  renderHuman,
  UsageError,
  DEFAULT_MANIFEST,
  DEFAULT_FIXTURES_ROOT,
  DEFAULT_JSON_PATH,
};
