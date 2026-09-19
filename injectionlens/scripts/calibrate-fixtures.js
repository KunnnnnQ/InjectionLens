// Calibration probe for the Step 6 replica set.
//
// Purpose: print what the four ingestion pipelines and the risk model ACTUALLY
// report for each replica page, so the manifest expectations are written from
// measured behaviour instead of guessed behaviour. It is a diagnostic, not part
// of the runner: it asserts nothing, exits 0, and writes no artifact.
//
// It serves the fixtures from an ephemeral loopback port with the same
// ua-conditional dispatch the runner uses, analyses each page under every
// capability template, and prints, per case:
//   - the level count and strongest level,
//   - the observed intents,
//   - one line per occurrence (pipeline / extraction kind / path / text),
//   - the cloaking probe result when one exists.
//
// Usage: node scripts/calibrate-fixtures.js [--only <id>] [--text <max chars>]
//
// Evidence: Step 6 contract section 2 (per-case expectations, calibrated).

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { analyze } = require('../server/lib/analyze');
const { CAPABILITY_TEMPLATES } = require('../server/lib/risk');
const { createPolicy } = require('../server/lib/net-guard');
const { getBrowser, executablePath } = require('../server/lib/browser');
const { createFixtureServer, makeFixtureReader, DEFAULT_FIXTURES_ROOT } = require('./run-fixtures');

const HOST = '127.0.0.1';
const CAPABILITIES = Object.keys(CAPABILITY_TEMPLATES);

// The replica set under calibration: manifest-shaped specs, minimal on purpose.
const CASES = [
  { id: 'unit42-scam-ad-review', file: 'replica-scam-ad-review.html' },
  { id: 'forcepoint-5000-payment', file: 'replica-payment-5000.html' },
  { id: 'forcepoint-rm-rf', file: 'replica-rm-rf.html' },
  { id: 'unit42-offscreen-hiring', file: 'replica-hiring-offscreen.html' },
  { id: 'brave-comet-spoiler', file: 'replica-forum-spoiler.html' },
  {
    id: 'splx-chatgpt-user-cloaking',
    file: 'replica-cloaking-human.html',
    serve: {
      mode: 'ua-conditional',
      route: '/fixtures/replica-cloaking.html',
      triggerTokens: ['ChatGPT-User'],
      human: 'replica-cloaking-human.html',
      ai: 'replica-cloaking-ai.html',
    },
  },
  { id: 'msft-ai-summary-link', file: 'replica-ai-summary-link.html' },
  { id: 'arxiv-content-protection', file: 'replica-content-protection.html' },
];

function parseArgs(argv) {
  const options = { only: null, textMax: 120, jsonPath: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--only') options.only = argv[++i];
    else if (argv[i] === '--text') options.textMax = Number(argv[++i]);
    else if (argv[i] === '--json') options.jsonPath = argv[++i];
  }
  return options;
}

function clip(value, max) {
  const text = String(value === undefined || value === null ? '' : value).replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

/** Machine-readable form: unique payload carriers per case, across capabilities. */
function collectJson(cases, perCapability) {
  return cases.map((spec) => {
    const runs = perCapability.get(spec.id) || [];
    const carriers = new Map();
    const intents = new Set();
    const levels = {};
    let cloak = null;
    for (const run of runs) {
      for (const level of Object.keys(run.analysis.levelCount)) {
        levels[level] = (levels[level] || 0) + run.analysis.levelCount[level];
      }
      if (run.analysis.cloak && !cloak) {
        cloak = {
          triggerToken: run.analysis.cloak.triggerToken,
          humanBytes: run.analysis.cloak.humanBytes,
          aiBytes: run.analysis.cloak.aiBytes,
        };
      }
      for (const finding of run.analysis.findings) {
        for (const intent of finding.intents || []) intents.add(intent);
        for (const occurrence of finding.occurrences || []) {
          const key = `${occurrence.pipeline}|${occurrence.extractionKind}|${occurrence.path || ''}|${occurrence.originalText}`;
          if (!carriers.has(key)) {
            carriers.set(key, {
              pipeline: occurrence.pipeline,
              extractionKind: occurrence.extractionKind,
              path: occurrence.path,
              originalText: occurrence.originalText,
              normalizedText: occurrence.normalizedText,
              level: finding.impact.level,
              intents: finding.intents || [],
              humanVisible: finding.humanVisible === true,
            });
          }
        }
      }
    }
    return {
      id: spec.id,
      file: spec.file,
      capabilities: runs.map((run) => run.capability),
      levels,
      maxLevel: maxLevel(levels),
      intents: [...intents].sort(),
      cloak,
      carriers: [...carriers.values()],
    };
  });
}

(async () => {
  const options = parseArgs(process.argv.slice(2));
  const fixturesRoot = DEFAULT_FIXTURES_ROOT;
  const readFixture = makeFixtureReader(fixturesRoot);
  const cases = options.only ? CASES.filter((spec) => spec.id === options.only) : CASES;

  console.log(`fixtures root: ${fixturesRoot}`);
  console.log(`system browser: ${executablePath || 'NOT FOUND (rendered pipelines will fail)'}`);
  console.log(`capabilities: ${CAPABILITIES.join(', ')}\n`);

  const server = await createFixtureServer({ fixturesRoot, cases, readFixture });
  console.log(`fixture server: ${server.origin} (ephemeral)\n`);

  const perCapability = new Map();
  for (const spec of cases) perCapability.set(spec.id, []);

  try {
    for (const spec of cases) {
      const route = spec.serve && spec.serve.route ? spec.serve.route : `/fixtures/${spec.file}`;
      const url = `${server.origin}${route}`;
      console.log('='.repeat(100));
      console.log(`CASE ${spec.id}`);
      console.log(`  route: ${route}`);
      if (spec.serve) console.log(`  serve: ${spec.serve.mode}, trigger=${spec.serve.triggerTokens.join(',')}`);
      console.log('='.repeat(100));

      for (const capability of CAPABILITIES) {
        const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: server.port }] });
        let analysis;
        try {
          analysis = await analyze(url, capability, { policy });
        } catch (error) {
          console.log(`  [${capability}] ANALYSIS ERROR: ${error.message}`);
          continue;
        }
        perCapability.get(spec.id).push({ capability, analysis });
        const levels = Object.entries(analysis.levelCount)
          .filter(([, count]) => count > 0)
          .map(([level, count]) => `${level}:${count}`)
          .join(' ') || 'none';
        const intents = [...new Set(analysis.findings.flatMap((finding) => finding.intents || []))].sort();
        console.log(`  [${capability}] levels={${levels}} max=${maxLevel(analysis.levelCount)}`);
        console.log(`      intents: ${intents.length ? intents.join(', ') : '(none)'}`);
        if (analysis.cloak) {
          console.log(`      cloak: trigger=${analysis.cloak.triggerToken} human=${analysis.cloak.humanBytes}B ai=${analysis.cloak.aiBytes}B`);
        }
        for (const finding of analysis.findings) {
          console.log(`      ${finding.id} level=${finding.impact.level} delivery=${finding.delivery} visible=${finding.humanVisible} intents=[${(finding.intents || []).join(',')}]`);
          const occurrences = Array.isArray(finding.occurrences) ? finding.occurrences : [];
          for (const occurrence of occurrences) {
            console.log(`         - ${occurrence.pipeline} / ${occurrence.extractionKind} / ${occurrence.path || '(no path)'}`);
            console.log(`           ${clip(occurrence.originalText, options.textMax)}`);
          }
        }
      }
      console.log('');
    }
  } finally {
    await new Promise((resolve) => server.server.close(resolve));
  }

  if (options.jsonPath) {
    // Written from node, in UTF-8, on purpose: a shell redirection on Windows
    // can re-encode the bytes (PowerShell 5.1 writes UTF-16 for ">"), which then
    // fails to parse as JSON.
    const jsonPath = path.resolve(options.jsonPath);
    fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
    fs.writeFileSync(jsonPath, `${JSON.stringify(collectJson(cases, perCapability), null, 2)}\n`, 'utf8');
    console.log(`calibration report written: ${jsonPath}`);
  }

  const browser = await getBrowser().catch(() => null);
  if (browser) await browser.close().catch(() => {});

  console.log('calibration complete');
  process.exit(0);
})();

function maxLevel(levelCount) {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  let best = 'none';
  for (const level of order) if (levelCount && levelCount[level] > 0) best = level;
  return best;
}
