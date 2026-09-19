#!/usr/bin/env node
// InjectionLens — Step 7 result aggregation.
//
// Reads the per-shard observation files produced by run-evaluation.js and writes
// the approved Step 7 result artifacts. It computes nothing that the harness
// modules do not already define: aggregation, numerators/denominators, states and
// rate semantics all come from eval/scripts/step7/aggregate.js.
//
// Usage (from injectionlens/):
//   node eval/scripts/step7/aggregate-results.js \
//     --shards eval/tmp/step7/obs-shard0.json,eval/tmp/step7/obs-shard1.json,... \
//     --out-dir eval/results

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const step7 = require('./index');
const { aggregate, states, variants, placement } = step7;

const APP_ROOT = process.cwd();

const PARSE_OPTIONS = {
  shards: { type: 'string' },
  'out-dir': { type: 'string', default: path.join(APP_ROOT, 'eval', 'results') },
  'min-medium': { type: 'string', default: 'medium' },
  'min-high': { type: 'string', default: 'high' },
  help: { type: 'boolean' },
};

function writeJson(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeText(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, value, 'utf8');
}

// ---------------------------------------------------------------------------
// Heatmap rendering: a self-contained SVG, no external references
// ---------------------------------------------------------------------------

function colorFor(rate, state) {
  if (state !== states.RUN_STATES.OK || rate === null) return '#3a3f46';
  // Sequential ramp: dark (0) -> amber -> green (1).
  const stops = [
    [0.0, [58, 63, 70]],
    [0.5, [214, 158, 46]],
    [1.0, [46, 160, 67]],
  ];
  let lo = stops[0];
  let hi = stops[stops.length - 1];
  for (let i = 0; i < stops.length - 1; i += 1) {
    if (rate >= stops[i][0] && rate <= stops[i + 1][0]) { lo = stops[i]; hi = stops[i + 1]; break; }
  }
  const span = hi[0] - lo[0] || 1;
  const t = (rate - lo[0]) / span;
  const channel = (index) => Math.round(lo[1][index] + (hi[1][index] - lo[1][index]) * t);
  return `rgb(${channel(0)},${channel(1)},${channel(2)})`;
}

function renderHeatmapSvg({ rows, title, subtitle, minLevel }) {
  const pipelines = aggregate.PIPELINES;
  const placementRows = [...new Set(rows.map((row) => row.row))].sort();
  const matrices = ['coverage', 'detection'];
  const cellW = 132;
  const cellH = 30;
  const labelW = 170;
  const headerH = 74;
  const matrixGap = 40;
  const width = labelW + pipelines.length * cellW + 24;
  const blockH = 26 + placementRows.length * cellH;
  const height = headerH + matrices.length * (blockH + matrixGap) + 46;

  const parts = [];
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="system-ui,Segoe UI,sans-serif">`);
  parts.push(`<rect width="${width}" height="${height}" fill="#0d1117"/>`);
  parts.push(`<text x="16" y="30" fill="#e6edf3" font-size="17" font-weight="600">${escapeXml(title)}</text>`);
  parts.push(`<text x="16" y="52" fill="#8b949e" font-size="12">${escapeXml(subtitle)}</text>`);

  let y = headerH;
  for (const matrix of matrices) {
    const rowsFor = rows.filter((row) => row.matrix === matrix && row.denominator_kind === (matrix === 'coverage' ? 'all_valid' : 'observed'));
    parts.push(`<text x="16" y="${y + 16}" fill="#e6edf3" font-size="14" font-weight="600">${matrix === 'coverage' ? 'Coverage — did the pipeline extract the planted text?' : `Detection — attributable finding >= ${minLevel}, denominator = cells that pipeline observed`}</text>`);
    const top = y + 26;
    pipelines.forEach((pipeline, index) => {
      const x = labelW + index * cellW;
      parts.push(`<text x="${x + cellW / 2}" y="${top + 14}" fill="#8b949e" font-size="11" text-anchor="middle">${escapeXml(pipeline)}</text>`);
    });
    placementRows.forEach((placementId, rowIndex) => {
      const rowY = top + 20 + rowIndex * cellH;
      parts.push(`<text x="${labelW - 10}" y="${rowY + 19}" fill="#c9d1d9" font-size="11" text-anchor="end">${escapeXml(placementId)}</text>`);
      for (const pipeline of pipelines) {
        const cell = rowsFor.find((row) => row.row === placementId && row.column === pipeline);
        const x = labelW + pipelines.indexOf(pipeline) * cellW;
        const fill = cell ? colorFor(cell.rate, cell.state) : '#21262d';
        parts.push(`<rect x="${x + 2}" y="${rowY + 2}" width="${cellW - 4}" height="${cellH - 4}" rx="4" fill="${fill}"/>`);
        const label = cell ? `${cell.k}/${cell.n}${cell.rate === null ? '' : `  ${(cell.rate * 100).toFixed(0)}%`}` : '—';
        const textFill = cell && cell.state === states.RUN_STATES.OK && cell.rate !== null && cell.rate > 0.45 ? '#0d1117' : '#e6edf3';
        parts.push(`<text x="${x + cellW / 2}" y="${rowY + 19}" fill="${textFill}" font-size="11" text-anchor="middle">${escapeXml(label)}</text>`);
      }
    });
    y = top + 20 + placementRows.length * cellH + matrixGap;
  }

  parts.push(`<text x="16" y="${height - 16}" fill="#8b949e" font-size="11">k = numerator, n = denominator. State OK only enters a denominator; FAILED, SKIPPED, NOT_RUN, PENDING and N/A cells stay out of every denominator. Grey cells mean no valid observation in that row.</text>`);
  parts.push('</svg>');
  return parts.join('\n');
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const parsed = parseArgs({ args: process.argv.slice(2), options: PARSE_OPTIONS, allowPositionals: false });
  // parseArgs keeps the dashed spelling, so map it explicitly instead of
  // reading a camelCase property that does not exist.
  const options = {
    shards: parsed.values.shards,
    outDir: parsed.values['out-dir'],
    minMedium: parsed.values['min-medium'],
    minHigh: parsed.values['min-high'],
    help: parsed.values.help === true,
  };
  if (options.help || !options.shards) {
    process.stdout.write('usage: node eval/scripts/step7/aggregate-results.js --shards <a.json,b.json,...> [--out-dir eval/results]\n');
    return options.help ? 0 : 2;
  }

  const shardPaths = options.shards.split(',').map((value) => path.resolve(value.trim())).filter(Boolean);
  const reports = shardPaths.map((file) => ({ file, report: JSON.parse(fs.readFileSync(file, 'utf8')) }));
  const first = reports[0].report;

  // Merge observations across shards.
  const observations = [];
  for (const { report } of reports) observations.push(...report.observations);

  // Guard: every shard must describe the same corpus, sample and matrix.
  for (const { file, report } of reports) {
    if (report.source.archive_sha256 !== first.source.archive_sha256) {
      throw new Error(`shard ${file} read a different corpus (${report.source.archive_sha256})`);
    }
    if (report.sample.fingerprint !== first.sample.fingerprint) {
      throw new Error(`shard ${file} sampled a different record set (${report.sample.fingerprint})`);
    }
    if (report.matrix.fingerprint !== first.matrix.fingerprint) {
      throw new Error(`shard ${file} built a different cell matrix (${report.matrix.fingerprint})`);
    }
  }

  const minMedium = options.minMedium;
  const minHigh = options.minHigh;

  // Two populations, both computed and both published.
  //
  // The runner appends payload-free CONTROL pages (a wrapper with filler text
  // and no payload), one per wrapper per shard, so a detector firing on the
  // wrapper markup alone would be visible. Those rows are legitimate OK
  // observations of a page, but they are not attack samples. The detection
  // metrics therefore divide by the attack population, and the mixed-population
  // reading is kept beside it so the correction is auditable rather than
  // silently applied.
  const mediumBoth = aggregate.aggregateBothPopulations(observations, { minLevel: minMedium });
  const highBoth = aggregate.aggregateBothPopulations(observations, { minLevel: minHigh });
  const medium = mediumBoth.attack_only;
  const high = highBoth.attack_only;
  const marginals = aggregate.marginals(observations, { population: aggregate.POPULATIONS.ATTACK_ONLY });
  const byPlacementMedium = aggregate.aggregateByStratum(observations, {
    minLevel: minMedium,
    stratumKey: (o) => o.placement_id,
    population: aggregate.POPULATIONS.ATTACK_ONLY,
  });
  const byTransformMedium = aggregate.aggregateByStratum(observations, {
    minLevel: minMedium,
    stratumKey: (o) => o.transform_id,
    population: aggregate.POPULATIONS.ATTACK_ONLY,
  });
  // Per-transform http-source coverage. The heatmap is a position x pipeline
  // matrix, so this slice is not in it; it is computed here from the same rows
  // rather than being transcribed, so the normaliser-defect numbers cannot drift
  // away from the data again.
  const byTransformCoverage = aggregate.aggregateByStratum(observations, {
    minLevel: minMedium,
    stratumKey: (o) => o.transform_id,
    population: aggregate.POPULATIONS.ATTACK_ONLY,
  }).map((row) => {
    const key = row.stratum;
    const valid = observations
      .map(aggregate.normalizeObservation)
      .filter((o) => o.transform_id === key && o.state === 'OK' && !aggregate.isControlObservation(o));
    const carried = valid.filter((o) => o.pipelines.includes('http-source')).length;
    return {
      stratum: key,
      pipeline: 'http-source',
      ...aggregate.rateFor({ numerator: carried, denominator: valid.length }),
    };
  });
  const heatRows = [
    ...aggregate.heatmapRows(observations, { minLevel: minMedium, denominator: 'observed' }),
    ...aggregate.heatmapRows(observations, { minLevel: minMedium, denominator: 'all_valid' }),
  ];
  const heatRowsHigh = aggregate.heatmapRows(observations, { minLevel: minHigh, denominator: 'observed' });
  const heatmapInput = aggregate.buildHeatmapInput(observations, { minLevel: minMedium });

  const outDir = path.resolve(options.outDir);

  // --- attack-matrix.json -------------------------------------------------
  const attackMatrix = {
    artifact: 'attack-matrix.json',
    step: 'Human Step 7 — external attack-library evaluation',
    generated_at: new Date().toISOString(),
    result_status: 'PROVISIONAL',
    result_status_reason:
      'Stamped by finalizeArtifact(): this is a real measurement over a real sampled corpus, but the '
      + 'licence basis for the majority of upstream records is unresolved, so the sample is drawn from '
      + 'the subset with an explicitly documented licence. It is evidence, not a final accuracy claim.',
    source: first.source,
    licence_policy: first.license_policy,
    sample: {
      seed: first.seed,
      sampling_id: first.sample.sampling_id,
      eligible_count: first.sample.eligible_count,
      selected: first.sample.selected,
      shortfall: first.sample.shortfall,
      fingerprint: first.sample.fingerprint,
    },
    funnel: first.funnel,
    exclusion_ledger: first.exclusion_ledger,
    dedupe: first.dedupe,
    matrix: first.matrix,
    shards: reports.length,
    definitions: {
      unit: 'one cell = one sampled record x one transform x one placement x one capability',
      capability: first.capability,
      population:
        'detection metrics divide by the ATTACK population: state OK cells that carry a sampled record. '
        + 'Payload-free control pages (record_uid null) are observed but are not attack samples.',
      medium_or_above: `k = attack cells whose strongest finding level is >= ${minMedium}; n = attack cells that reached state OK`,
      high_or_above: `k = attack cells whose strongest finding level is >= ${minHigh}; n = attack cells that reached state OK`,
      state_rule: 'only state OK enters a denominator; FAILED, SKIPPED, NOT_RUN, PENDING and N/A do not',
      attribution:
        'a pipeline is credited with a detection only when a finding at or above the threshold carries '
        + 'the planted payload text AND that finding has an occurrence from that pipeline',
      coverage:
        'a pipeline is credited with coverage when the planted text appears in what analyze() returned '
        + 'for that pipeline (finding occurrence, rendered HTML, Reader/Markdown output, or matrix excerpt)',
    },
    detection: {
      medium_or_above: medium,
      high_or_above: high,
      by_placement_medium: byPlacementMedium,
      by_transform_medium: byTransformMedium,
      by_transform_coverage: byTransformCoverage,
    },
    // The same threshold over the mixed population, kept so the Step 7 review of
    // 2026-09-20 can be checked end to end. The controls carried no finding at
    // all, so every numerator is identical; only the denominator differs.
    populations: {
      note:
        'attack_only is the metric population. all is retained for audit: it adds the payload-free '
        + 'control pages to the denominator without adding anything to the numerator.',
      medium_or_above: { attack_only: mediumBoth.attack_only, all: mediumBoth.all },
      high_or_above: { attack_only: highBoth.attack_only, all: highBoth.all },
      controls_in_denominator: mediumBoth.controls_in_denominator,
      control_observations: marginals.control_observations,
      numerator_unchanged_by_population: mediumBoth.numerator_unchanged_by_population
        && highBoth.numerator_unchanged_by_population,
    },
    marginals,
    observations_total: observations.length,
  };
  writeJson(path.join(outDir, 'attack-matrix.json'), attackMatrix);

  // --- detection-heatmap.svg ---------------------------------------------
  const subtitle = [
    `capability ${first.capability}`,
    `${first.sample.selected} records x ${first.matrix.transforms.length} transforms x ${first.matrix.placement_plan.length} placements`,
    `${observations.length} cells observed`,
    `levels: ${medium.k}/${medium.n} >= ${minMedium}`,
  ].join(' · ');
  const svg = renderHeatmapSvg({
    rows: heatRows,
    title: 'InjectionLens Step 7 — detection heatmap (external attack library, PROVISIONAL)',
    subtitle,
    minLevel: minMedium,
  });
  writeText(path.join(outDir, 'detection-heatmap.svg'), `${svg}\n`);

  // Numeric companion, because colour alone is not evidence.
  writeText(path.join(outDir, 'detection-heatmap.csv'), `${aggregate.heatmapCsv(heatRows)}\n`);
  writeJson(path.join(outDir, 'detection-heatmap.json'), {
    artifact: 'detection-heatmap.json',
    result_status: 'PROVISIONAL',
    min_level: minMedium,
    source_archive_sha256: first.source.archive_sha256,
    sample_fingerprint: first.sample.fingerprint,
    rows: heatRows,
    rows_high: heatRowsHigh,
    definitions: heatmapInput.definitions,
  });

  // --- replica-results.json ----------------------------------------------
  const replicaPath = path.join(outDir, 'replica-results.json');
  let replica = null;
  const replicaSource = path.join(APP_ROOT, 'eval', 'tmp', 'step7', 'replica-run.json');
  if (fs.existsSync(replicaSource)) {
    const run = JSON.parse(fs.readFileSync(replicaSource, 'utf8'));
    replica = {
      artifact: 'replica-results.json',
      step: 'Human Step 7 — integrated source-backed replica suite',
      generated_at: new Date().toISOString(),
      result_status: 'OK',
      how_produced: 'node scripts/run-fixtures.js --json eval/tmp/step7/replica-run.json',
      summary: run.summary,
      cases: run.cases.map((item) => ({
        id: item.id,
        status: item.status,
        file: item.file,
        source: item.source,
        title: item.title,
        primary_capability: item.primaryCapability,
        observed: item.observed,
        skip_reason: item.skipReason,
        known_gap: item.knownGap,
        failures: item.failures,
      })),
    };
    writeJson(replicaPath, replica);
  }

  // --- benign-pages.json --------------------------------------------------
  writeJson(path.join(outDir, 'benign-pages.json'), {
    artifact: 'benign-pages.json',
    step: 'Human Step 7 — real benign-page evaluation',
    generated_at: new Date().toISOString(),
    state: states.RUN_STATES.NOT_RUN,
    rate: null,
    numerator: null,
    denominator: null,
    reason:
      'NOT RUN: no explicit owner-approved URL/host allowlist was supplied for this stage. '
      + 'Ordinary real-world page scanning is not authorised, and the local fixtures are not '
      + 'real-world false-positive evidence.',
    what_would_be_needed: [
      'an explicit allowlist of hosts the owner authorises for read-only analysis',
      'a declared capability template and a declared benign/not-benign ground truth per page',
      'network egress permission for those hosts only',
    ],
    note: 'A false-positive rate is deliberately NOT estimated here, because estimating it would require pages this stage may not fetch.',
  });

  // --- evaluation-summary.md is written by the caller with the real numbers --
  const summaryInputs = {
    outDir,
    first,
    medium,
    high,
    marginals,
    byPlacementMedium,
    byTransformMedium,
    observations,
    heatRows,
    replica,
    licencedSubset: reports.length,
  };
  writeJson(path.join(outDir, 'step7-summary-inputs.json'), {
    medium, high, marginals, by_placement_medium: byPlacementMedium, by_transform_medium: byTransformMedium,
    observations_total: observations.length,
    populations: {
      medium_or_above: { attack_only: mediumBoth.attack_only, all: mediumBoth.all },
      high_or_above: { attack_only: highBoth.attack_only, all: highBoth.all },
      controls_in_denominator: mediumBoth.controls_in_denominator,
      control_observations: marginals.control_observations,
    },
  });

  process.stdout.write(`attack-matrix.json      : ${medium.k}/${medium.n} >= ${minMedium} (attack population), ${high.k}/${high.n} >= ${minHigh}\n`);
  process.stdout.write(`                          mixed population for audit: ${mediumBoth.all.k}/${mediumBoth.all.n} >= ${minMedium}, ${highBoth.all.k}/${highBoth.all.n} >= ${minHigh}\n`);
  process.stdout.write(`                          ${mediumBoth.controls_in_denominator} payload-free control(s) excluded from the detection denominator\n`);
  process.stdout.write(`detection-heatmap.svg   : ${heatRows.length} rows\n`);
  process.stdout.write(`replica-results.json    : ${replica ? `${replica.summary.pass} pass / ${replica.summary.skipped} skipped of ${replica.summary.total}` : 'not generated (replica run missing)'}\n`);
  process.stdout.write(`benign-pages.json       : NOT RUN\n`);
  return 0;
}

process.exit(main());
