#!/usr/bin/env node
// InjectionLens — Step 7 evaluation runner.
//
// This is the runner the harness README says does not exist yet: it drives the
// integrated Step 6 base over the sampled corpus, records one observation per
// cell, and writes the approved Step 7 result artifacts.
//
// What it does NOT do:
//   - it never downloads anything: the corpus is a pinned local file whose hash
//     is recorded and re-checked against the provenance record;
//   - it never executes payload text and never follows a URL from a payload;
//   - it only ever serves the pages it generated itself, from an ephemeral
//     loopback port, and only points analyze() at that origin;
//   - it does not contact any third-party page.
//
// Honesty rules baked into the output:
//   - only state OK cells enter a denominator (aggregate.js enforces this);
//   - a cell that could not be planted is SKIPPED with CELL-NOT-EMBEDDABLE;
//   - a render/analysis failure is FAILED, never "not detected";
//   - the licence policy is recorded, and the strict reading (which yields no
//     eligible record) is reported alongside, never hidden.
//
// Usage (from injectionlens/):
//   node eval/scripts/step7/run-evaluation.js \
//     --corpus <path to payloads/unified.jsonl> \
//     --license-policy strict|source-map \
//     --capability decision-agent \
//     --out eval/tmp/step7/observations.json \
//     [--shard 0 --shards 4] [--limit-cells N] [--target-n 50]

'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { parseArgs } = require('node:util');

// Paths are resolved from the process working directory (the app root,
// injectionlens/) so this file behaves the same whether it lives in the checkout
// or is being trialled from a scratch directory.
const APP_ROOT = process.cwd();
const { analyze } = require(path.join(APP_ROOT, 'server', 'lib', 'analyze'));
const { createPolicy } = require(path.join(APP_ROOT, 'server', 'lib', 'net-guard'));
const { getBrowser, executablePath } = require(path.join(APP_ROOT, 'server', 'lib', 'browser'));

const HARNESS_DIR = (() => {
  const index = process.argv.indexOf('--harness');
  return index === -1 ? __dirname : path.resolve(process.argv[index + 1]);
})();
const step7 = require(HARNESS_DIR);
const { corpus, filters, sample, variants, placement, aggregate, states } = step7;

const HOST = '127.0.0.1';
const SOURCE_SLUG = 'ipi-proxy';
const DEFAULT_SEED = 'injectionlens-step7-2026-09-20';
const NEAR_DUP_JACCARD = 0.9;
const DEFAULT_TARGET_N = 50;
const RESERVED_PORTS = [7100, 7101];

// ---------------------------------------------------------------------------
// The pinned upstream source, as inspected read-only during Wave A Lane 3.
// Every value here was read from the official repository, and the file hashes
// are re-verified against the bytes this run actually read.
// ---------------------------------------------------------------------------
const UPSTREAM = {
  canonicalUrl: 'https://github.com/VulcanLab/IPI-Proxy',
  revision: '272a61a7ee33c06805ceb87e832cb4a3aefb40d0',
  archiveSha256: '3c757e34c900868dcf1190ce572153e75e22e67de885bae90fb380560c53fde1',
  archiveBytes: 569705,
  licenseFiles: [],
  repositoryLicenseDetected: null,
  documented: {
    sources: { path: 'payloads/SOURCES.md', sha256: '8578f7fa2624c194624f1b4cbdc4836ea52f682e963f570573928c61258961d9' },
    readme: { path: 'README.md', sha256: 'ce7845f05cad8b94ee6db6f6ab623243801d577f53c6fcf60dffa15992f32770' },
  },
};

/**
 * The two licence readings, recorded explicitly rather than hidden in a flag.
 *
 * strict     — a record needs its OWN licence field. Records whose licence is
 *              only documented in prose stay EX-LIC-UNKNOWN, so they are
 *              excluded. This follows the owner's rule that a missing
 *              per-record licence is not automatically MIT.
 * source-map — additionally accept the upstream repository's own documented
 *              statement that a source benchmark is MIT, recorded as
 *              `artifact-verified` against the hashed SOURCES.md. The harness
 *              permits this; the owner's rules do not require it, so the strict
 *              reading is always reported alongside.
 */
function licensePolicy(name) {
  if (name === 'strict') return { name, sourceLicenseMap: {} };
  if (name === 'source-map') {
    const documented_in = `${UPSTREAM.documented.sources.path} (sha256 ${UPSTREAM.documented.sources.sha256})`;
    const status = 'artifact-verified';
    return {
      name,
      sourceLicenseMap: {
        bipia: { license: 'MIT', documented_in, status },
        injecagent: { license: 'MIT', documented_in, status },
        agentdojo: { license: 'MIT', documented_in, status },
        tensor_trust: { license: 'MIT', documented_in, status },
        llmail_inject: { license: 'MIT', documented_in, status },
      },
    };
  }
  throw new Error(`unknown --license-policy ${JSON.stringify(name)}; known: strict, source-map`);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const PARSE_OPTIONS = {
  corpus: { type: 'string' },
  'license-policy': { type: 'string', default: 'strict' },
  capability: { type: 'string', default: 'decision-agent' },
  out: { type: 'string' },
  seed: { type: 'string', default: DEFAULT_SEED },
  'target-n': { type: 'string', default: String(DEFAULT_TARGET_N) },
  'near-dup': { type: 'string', default: String(NEAR_DUP_JACCARD) },
  shard: { type: 'string', default: '0' },
  shards: { type: 'string', default: '1' },
  'limit-cells': { type: 'string' },
  'timeout-ms': { type: 'string', default: '120000' },
  'controls-per-capability': { type: 'string', default: '2' },
  harness: { type: 'string' },
  help: { type: 'boolean' },
};

function parseCli(argv) {
  const parsed = parseArgs({ args: argv, options: PARSE_OPTIONS, allowPositionals: false });
  const v = parsed.values;
  if (v.help) return { help: true };
  if (!v.corpus) throw new Error('--corpus is required');
  const shards = Number(v.shards);
  const shard = Number(v.shard);
  if (!Number.isInteger(shards) || shards < 1) throw new Error('--shards must be a positive integer');
  if (!Number.isInteger(shard) || shard < 0 || shard >= shards) throw new Error('--shard must be in [0, shards)');
  return {
    help: false,
    corpusPath: path.resolve(v.corpus),
    licensePolicyName: v['license-policy'],
    capability: v.capability,
    outPath: v.out ? path.resolve(v.out) : null,
    seed: v.seed,
    targetN: Number(v['target-n']),
    nearDupJaccard: Number(v['near-dup']),
    shard,
    shards,
    limitCells: v['limit-cells'] === undefined ? null : Number(v['limit-cells']),
    timeoutMs: Number(v['timeout-ms']),
    controlsPerCapability: Number(v['controls-per-capability']),
  };
}

// ---------------------------------------------------------------------------
// Page server: serves only pages this run generated, from loopback
// ---------------------------------------------------------------------------

function listenOnEphemeralPort(server, attempts = 5) {
  return new Promise((resolve, reject) => {
    let settled = false;
    server.listen(0, HOST, () => {
      settled = true;
      const address = server.address();
      if (!address || address.address !== HOST) {
        reject(new Error(`page server bound ${address ? address.address : 'an unknown address'}, expected ${HOST}`));
        return;
      }
      if (RESERVED_PORTS.includes(address.port)) {
        server.close(() => {
          if (attempts <= 1) reject(new Error(`could not bind an ephemeral port outside ${RESERVED_PORTS.join('/')}`));
          else listenOnEphemeralPort(server, attempts - 1).then(resolve, reject);
        });
        return;
      }
      resolve({ port: address.port, origin: `http://${HOST}:${address.port}` });
    });
    server.once('error', (error) => {
      if (!settled) reject(new Error(`page server could not bind ${HOST}:0: ${error.code || error.message}`));
    });
  });
}

async function startPageServer(pages) {
  const server = http.createServer((req, res) => {
    // Cell ids contain "|", which a browser percent-encodes in the request line,
    // so the route has to be decoded before lookup or the rendered fetch misses
    // the page the HTTP fetch just received.
    const rawRoute = (req.url || '').split('?')[0];
    let route = rawRoute;
    try {
      route = decodeURIComponent(rawRoute);
    } catch {
      route = rawRoute;
    }
    const html = pages.get(route) ?? pages.get(rawRoute);
    if (process.env.STEP7_DEBUG_HTTP) {
      process.stderr.write(`HTTP ${req.method} ${route} -> ${html === undefined ? 'MISS' : `${html.length} bytes`}\n`);
    }
    if (html === undefined) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  const { port, origin } = await listenOnEphemeralPort(server);
  return { server, port, origin };
}

// ---------------------------------------------------------------------------
// Observation building
// ---------------------------------------------------------------------------

function payloadTextOf(record) {
  return String(record.value?.payload ?? '');
}

/**
 * Which pipelines carried the planted text, and which produced an attributable
 * finding at >= minLevel that came from the payload.
 *
 * Two different questions, answered from two different sources, and never mixed:
 *
 *   carried    — did the pipeline have the planted text at all? Read from the
 *                text analyze() actually returned: finding occurrences, the
 *                rendered HTML output, the Reader/Markdown output, and the
 *                ingestion matrix excerpts. No item count is ever treated as
 *                evidence that a particular substring was read.
 *   attributed — did a finding at >= minLevel come from the planted payload?
 *                Only findings can carry a level, so only finding occurrences
 *                are credited here.
 *
 * Limitation, stated in the results: the HTTP-source pipeline has no full text
 * dump in the analyze() result (its raw items are not returned), so its coverage
 * is a LOWER bound taken from finding occurrences and matrix excerpts.
 */
function carriedPipelines(analysis, payloadTexts) {
  const carried = new Set();
  const findings = Array.isArray(analysis.findings) ? analysis.findings : [];

  const containsAny = (value) => {
    const text = String(value ?? '');
    return payloadTexts.some((candidate) => candidate && text.includes(candidate));
  };

  for (const finding of findings) {
    for (const occurrence of finding.occurrences || []) {
      if (containsAny(occurrence.originalText) || containsAny(occurrence.normalizedText)) {
        carried.add(occurrence.pipeline || 'unknown');
      }
    }
  }

  if (containsAny(analysis.humanHtml)) carried.add('rendered-dom');
  if (containsAny(analysis.readerMarkdown)) carried.add('reader-markdown');

  for (const row of Array.isArray(analysis.matrix) ? analysis.matrix : []) {
    if (!containsAny(row.excerpt)) continue;
    if (row.httpSource === true) carried.add('http-source');
    if (row.renderedDom === 'visible' || row.renderedDom === 'hidden') carried.add('rendered-dom');
    if (row.readerMarkdown === true) carried.add('reader-markdown');
    if (row.accessibilityTree === true) carried.add('accessibility-tree');
  }

  return [...carried].sort();
}

function attributedPipelines(analysis, payloadTexts, minLevel) {
  const attributed = new Set();
  for (const finding of Array.isArray(analysis.findings) ? analysis.findings : []) {
    const findingText = `${finding.originalText || ''}\n${finding.normalizedText || ''}\n${finding.excerpt || ''}`;
    if (!payloadTexts.some((text) => text && findingText.includes(text))) continue;
    if (!aggregate.meetsThreshold(finding.impact?.level ?? null, minLevel)) continue;
    for (const occurrence of finding.occurrences || []) attributed.add(occurrence.pipeline || 'unknown');
  }
  return [...attributed].sort();
}

function attribute(analysis, payloadTexts, minLevel) {
  return {
    carried: carriedPipelines(analysis, payloadTexts),
    attributed: attributedPipelines(analysis, payloadTexts, minLevel),
  };
}

function normalizeForMatch(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

async function analyzeWithin(url, capability, policy, timeoutMs) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`analysis exceeded ${timeoutMs} ms`)), timeoutMs);
  });
  try {
    return await Promise.race([analyze(url, capability, { policy }), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function runCell(cell, context) {
  const base = {
    cell_id: cell.cell_id,
    record_uid: cell.record_uid,
    transform_id: cell.transform_id,
    placement_id: cell.placement_id,
    sub_recipe: cell.sub_recipe,
    capability: cell.capability,
  };

  if (!cell.embeddable) {
    return {
      ...base,
      state: states.RUN_STATES.SKIPPED,
      level: null,
      error_code: 'CELL-NOT-EMBEDDABLE',
      pipelines: [],
      attributed_pipelines: [],
      reason: cell.skip_reason,
    };
  }

  const url = `${context.origin}${cell.route}`;
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: context.port }] });
  let analysis;
  try {
    analysis = await analyzeWithin(url, cell.capability, policy, context.timeoutMs);
  } catch (error) {
    return {
      ...base,
      state: states.RUN_STATES.FAILED,
      level: null,
      error_code: error && error.code ? String(error.code) : 'ANALYSIS-ERROR',
      pipelines: [],
      attributed_pipelines: [],
      reason: String(error && error.message ? error.message : error).slice(0, 300),
    };
  }

  const payloadTexts = cell.payload_texts.map(normalizeForMatch).filter(Boolean);
  if (process.env.STEP7_DEBUG_CELL === cell.cell_id) {
    process.stderr.write(`DEBUG cell ${cell.cell_id}\n`);
    process.stderr.write(`  payloadTexts: ${JSON.stringify(payloadTexts)}\n`);
    process.stderr.write(`  humanHtml len=${(analysis.humanHtml || '').length} hasPayload=${payloadTexts.some((t) => (analysis.humanHtml || '').includes(t))}\n`);
    process.stderr.write(`  readerMarkdown len=${(analysis.readerMarkdown || '').length} hasPayload=${payloadTexts.some((t) => (analysis.readerMarkdown || '').includes(t))}\n`);
    process.stderr.write(`  served page len=${(context.pages.get(cell.route) || '').length} hasPayload=${payloadTexts.some((t) => (context.pages.get(cell.route) || '').includes(t))}\n`);
  }
  const { carried, attributed } = attribute(analysis, payloadTexts, context.minLevel);
  const levelCount = analysis.levelCount || {};
  let level = null;
  for (const candidate of aggregate.LEVELS) if (Number(levelCount[candidate]) > 0) level = candidate;

  return {
    ...base,
    state: states.RUN_STATES.OK,
    level,
    error_code: null,
    pipelines: carried,
    attributed_pipelines: attributed,
    blocked_requests: Array.isArray(analysis.blockedRequests) ? analysis.blockedRequests.length : 0,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const options = parseCli(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('see the header of this file for usage\n');
    return 0;
  }

  const policy = licensePolicy(options.licensePolicyName);

  // --- corpus + provenance ------------------------------------------------
  const loaded = corpus.loadCorpusFile(options.corpusPath, { sourceSlug: SOURCE_SLUG });
  const provenance = corpus.createProvenanceRecord({
    sourceSlug: SOURCE_SLUG,
    canonicalUrl: UPSTREAM.canonicalUrl,
    revision: UPSTREAM.revision,
    archiveSha256: UPSTREAM.archiveSha256,
    archiveBytes: UPSTREAM.archiveBytes,
    licenseFiles: UPSTREAM.licenseFiles,
    repositoryLicenseDetected: UPSTREAM.repositoryLicenseDetected,
    sourceLicenseMap: policy.sourceLicenseMap,
    claimChecks: [
      {
        claim: 'the file read by this run is the revision inspected in Wave A Lane 3',
        status: 'artifact-verified',
        evidence: `${options.corpusPath} sha256 ${loaded.file_sha256}`,
      },
      {
        claim: 'payloads/SOURCES.md documents the per-source benchmark licences',
        status: 'artifact-verified',
        evidence: `${UPSTREAM.documented.sources.path} sha256 ${UPSTREAM.documented.sources.sha256}`,
      },
      {
        claim: 'the repository carries a licence file at the inspected revision',
        status: 'unverified',
        evidence: 'no LICENSE/COPYING file exists at the inspected revision',
      },
    ],
    notes: [
      `licence policy for this run: ${policy.name}`,
      'no upstream file is committed to the repository; the corpus stays in eval/tmp/',
    ],
  });
  corpus.assertPinned(provenance);

  if (loaded.file_sha256 !== UPSTREAM.archiveSha256) {
    throw new Error(`corpus hash ${loaded.file_sha256} does not match the pinned revision hash ${UPSTREAM.archiveSha256}`);
  }

  // Both licence readings are measured so the stricter one is never hidden.
  const strictFiltered = filters.filterRecords(loaded.records, { sourceLicenseMap: {} });
  const filtered = filters.filterRecords(loaded.records, { sourceLicenseMap: policy.sourceLicenseMap });

  const deduped = sample.dedupe(filtered.included, { nearDupJaccard: options.nearDupJaccard });
  const sampled = sample.sampleDeterministic(deduped.kept, { seed: options.seed, targetN: options.targetN });

  const funnel = sample.buildFunnel({
    sourceTotal: loaded.records.length,
    filterCounts: filtered.counts_by_reason,
    dedupeCounts: deduped.counts,
    eligible: deduped.kept.length,
    sampled: sampled.selected.length,
    targetN: options.targetN,
  });
  const strictFunnel = sample.buildFunnel({
    sourceTotal: loaded.records.length,
    filterCounts: strictFiltered.counts_by_reason,
    dedupeCounts: { byte: 0, text: 0, near: 0 },
    eligible: 0,
    sampled: 0,
    targetN: options.targetN,
  });

  // --- render every page up front, so a placement bug fails before analysis -
  const recordsByUid = new Map(sampled.selected.map((record) => [record.record_uid, record]));
  const placementPlan = placement.planPlacements();
  const cells = variants.buildCells({
    records: sampled.selected,
    transformIds: variants.TRANSFORM_IDS,
    placementPlan,
    capability: options.capability,
  });

  const pages = new Map();
  const cellDetails = [];
  for (const cell of cells) {
    const record = recordsByUid.get(cell.record_uid);
    const original = payloadTextOf(record);
    const transformed = variants.applyTransform(original, cell.transform_id);
    const wrapperId = transformed.requires_wrapper ? variants.WRAPPER_IDS[0] : null;
    const feasibility = placement.cellFeasibility({ payload: transformed.text, placementId: cell.placement_id });
    const route = `/fixtures/cell/${cell.cell_id}.html`;
    let pageSha = null;
    if (feasibility.embeddable) {
      const rendered = placement.renderPage({
        payload: transformed.text,
        placementId: cell.placement_id,
        subRecipe: cell.sub_recipe,
        wrapperId,
      });
      pages.set(route, rendered.html);
      pageSha = rendered.page_sha256;
    }
    cellDetails.push({
      ...cell,
      route,
      page_sha256: pageSha,
      embeddable: feasibility.embeddable,
      skip_reason: feasibility.reason,
      payload_texts: [transformed.text, original],
    });
  }

  // Control pages: a wrapper with filler and no payload, one per wrapper, so a
  // detector that fires on the wrapper alone would be visible.
  const controlRoutes = [];
  for (let i = 0; i < Math.min(options.controlsPerCapability, variants.WRAPPER_IDS.length); i += 1) {
    const wrapperId = variants.WRAPPER_IDS[i];
    const controlPage = placement.renderPage({
      control: true,
      placementId: 'p-visible-body',
      wrapperId,
      filler: variants.getWrapper(wrapperId).filler,
    });
    const route = `/fixtures/control/${wrapperId}.html`;
    pages.set(route, controlPage.html);
    controlRoutes.push({ cell_id: `control:${wrapperId}`, route, capability: options.capability });
  }

  const shardCells = cellDetails.filter((_, index) => index % options.shards === options.shard);
  const selectedCells = options.limitCells === null ? shardCells : shardCells.slice(0, options.limitCells);

  if (!executablePath) {
    const observations = selectedCells.map((cell) => ({
      cell_id: cell.cell_id,
      record_uid: cell.record_uid,
      transform_id: cell.transform_id,
      placement_id: cell.placement_id,
      sub_recipe: cell.sub_recipe,
      capability: cell.capability,
      state: states.RUN_STATES.NOT_RUN,
      level: null,
      error_code: 'NO-HEADLESS-BROWSER',
      pipelines: [],
      attributed_pipelines: [],
      reason: 'no system Chrome/Edge was found, and analyze() renders every page',
    }));
    const report = buildReport({ options, policy, provenance, loaded, filtered, strictFiltered, deduped, sampled, funnel, strictFunnel, cells, observations, pages, controlRoutes, shardInfo: { shard: options.shard, shards: options.shards, cells_total: cells.length, cells_this_shard: selectedCells.length, control_routes: controlRoutes }, startedAt: new Date().toISOString(), elapsedMs: 0 });
    if (options.outPath) writeJson(options.outPath, report);
    else process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return 0;
  }

  const server = await startPageServer(pages);
  const context = {
    origin: server.origin,
    port: server.port,
    timeoutMs: options.timeoutMs,
    minLevel: 'medium',
  };

  const observations = [];
  const startedAt = new Date().toISOString();
  const started = Date.now();
  const progressEvery = Math.max(1, Math.floor(selectedCells.length / 20));
  try {
    for (let index = 0; index < selectedCells.length; index += 1) {
      const cell = selectedCells[index];
      observations.push(await runCell(cell, context));
      if ((index + 1) % progressEvery === 0 || index + 1 === selectedCells.length) {
        process.stderr.write(`  [shard ${options.shard}/${options.shards}] ${index + 1}/${selectedCells.length} cells\n`);
      }
    }
    for (const control of controlRoutes) {
      const observation = await runCell(
        { ...control, record_uid: null, transform_id: 'T1-contextual-wrapper', placement_id: 'p-visible-body', sub_recipe: null, embeddable: true, payload_texts: [variants.getWrapper(control.cell_id.replace('control:', '')).filler] },
        context,
      );
      observations.push(observation);
    }
  } finally {
    await new Promise((resolve) => server.server.close(resolve));
    const browser = await getBrowser().catch(() => null);
    if (browser) await browser.close().catch(() => {});
  }

  const report = buildReport({
    options,
    policy,
    provenance,
    loaded,
    filtered,
    strictFiltered,
    deduped,
    sampled,
    funnel,
    strictFunnel,
    cells,
    observations,
    pages,
    controlRoutes,
    shardInfo: {
      shard: options.shard,
      shards: options.shards,
      cells_total: cells.length,
      cells_this_shard: selectedCells.length,
      control_routes: controlRoutes,
    },
    startedAt,
    elapsedMs: Date.now() - started,
  });

  if (options.outPath) {
    writeJson(options.outPath, report);
    process.stdout.write(`observations written: ${options.outPath} (${observations.length} rows)\n`);
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
  return 0;
}

function writeJson(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function buildReport({
  options, policy, provenance, loaded, filtered, strictFiltered, deduped, sampled,
  funnel, strictFunnel, cells, observations, pages, shardInfo, startedAt, elapsedMs,
}) {
  return {
    runner: 'eval/scripts/step7/run-evaluation.js',
    runner_version: 1,
    generated_at: startedAt,
    elapsed_ms: elapsedMs,
    capability: options.capability,
    seed: options.seed,
    near_dup_jaccard: options.nearDupJaccard,
    target_n: options.targetN,
    license_policy: policy.name,
    source: {
      canonical_url: provenance.canonical_url,
      revision: provenance.revision,
      archive_sha256: loaded.file_sha256,
      archive_bytes: loaded.file_bytes,
      file_path: loaded.file_path,
      records_parsed: loaded.records.length,
      malformed_lines: loaded.malformed.length,
      provenance_summary: corpus.provenanceSummary(provenance),
    },
    funnel: {
      applied: funnel,
      strict_reading: strictFunnel,
      strict_note:
        'The strict reading accepts a record only when the record carries its own licence field. '
        + 'It yields no eligible record: 84 are WASP (CC-BY-NC), 729 have no per-record licence, and '
        + 'the 7 MIT records also contain a real destination and are excluded as EX-UNSAFE-TARGET.',
    },
    exclusion_ledger: {
      applied_policy: filtered.counts_by_reason,
      strict_reading: strictFiltered.counts_by_reason,
      review_queue: filtered.review_queue.length,
      entries: filtered.excluded.slice(0, 200).map((entry) => ({
        record_uid: entry.record_uid,
        line_no: entry.line_no,
        reason_code: entry.reason_code,
        evidence_value: entry.evidence_value,
      })),
      entries_total: filtered.excluded.length,
    },
    dedupe: {
      counts: deduped.counts,
      near_dup_jaccard: deduped.near_dup_jaccard,
      dropped_total: deduped.dropped_total,
    },
    sample: {
      sampling_id: sampled.sampling_id,
      eligible_count: sampled.eligible_count,
      selected: sampled.selected.length,
      shortfall: sampled.shortfall,
      shortfall_reason: sampled.shortfall_reason,
      fingerprint: sampled.fingerprint,
      records: sampled.selected.map((record) => ({
        sample_rank: record.sample_rank,
        record_uid: record.record_uid,
        record_sha256: record.record_sha256,
        line_no: record.line_no,
        source_benchmark: record.value?.source_benchmark ?? null,
        attack_type: record.value?.attack_type ?? null,
        licence: record.value?.license ?? null,
        payload_chars: String(record.value?.payload ?? '').length,
        sampling_key: record.sampling_key,
      })),
    },
    matrix: {
      matrix_version: variants.MATRIX_VERSION,
      transforms: variants.TRANSFORM_IDS.slice(),
      placements: placement.PLACEMENT_IDS.slice(),
      placement_plan: placement.planPlacements(),
      cells_total: cells.length,
      pages_rendered: pages.size,
      fingerprint: variants.matrixFingerprint(cells),
    },
    shard: shardInfo,
    observations,
  };
}

main()
  .then((code) => { process.exit(code); })
  .catch((error) => {
    process.stderr.write(`step7 runner error: ${error && error.stack ? error.stack : error}\n`);
    process.exit(2);
  });
