// Tests for Step 7 aggregation, states and machine-readable heatmap input.
//
// Evidence: Wave A Lane 3 scope ("medium-or-above and high-or-above aggregation",
// "explicit numerators and denominators", "N/A, NOT RUN, SKIPPED, PENDING and
// FAILED states", "machine-readable heatmap input", "proof that provisional data
// cannot be labeled as final results").
//
// The central invariant: "we did not measure it" and "we measured zero" are
// different facts, and only one of them is a number.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  RUN_STATES,
  RESULT_STATUS,
  rate,
  formatRate,
  dominantState,
  finalizeArtifact,
  assertFinal,
} = require('../eval/scripts/step7/states');
const {
  LEVELS,
  PIPELINES,
  POPULATIONS,
  normalizeObservation,
  isControlObservation,
  aggregate,
  aggregateBothPopulations,
  aggregateByStratum,
  heatmapRows,
  heatmapCsv,
  marginals,
  buildHeatmapInput,
} = require('../eval/scripts/step7/aggregate');
const productRisk = require('../server/lib/risk');

const cell = (overrides = {}) => {
  const state = overrides.state || RUN_STATES.OK;
  const measured = state === RUN_STATES.OK;
  return {
    cell_id: overrides.cell_id || 'demo:L000001:aaaaaaaaaaaa|T0-original|p-visible-body|summary-only',
    // An attack cell carries a sampled record. The runner writes record_uid null
    // for the payload-free control pages, and the detection population is
    // defined by exactly that difference, so the default fixture here must be an
    // attack cell for the denominator assertions below to mean what they say.
    record_uid: overrides.record_uid === undefined ? 'demo:L000001:aaaaaaaaaaaa' : overrides.record_uid,
    placement_id: 'p-visible-body',
    transform_id: 'T0-original',
    capability: 'summary-only',
    state,
    level: 'high',
    pipelines: ['http-source', 'rendered-dom'],
    attributed_pipelines: ['http-source'],
    ...overrides,
    // An unmeasured cell cannot carry a level or an attributed pipeline; keep the
    // helper honest so the fixtures used below are themselves valid observations.
    level: measured ? (overrides.level === undefined ? 'high' : overrides.level) : null,
    attributed_pipelines: measured ? (overrides.attributed_pipelines || ['http-source']) : [],
  };
};

/** A payload-free control page, exactly as run-evaluation.js records it. */
const control = (overrides = {}) => ({
  cell_id: overrides.cell_id || 'control:w-product-listing',
  record_uid: null,
  transform_id: 'T1-contextual-wrapper',
  placement_id: 'p-visible-body',
  sub_recipe: null,
  capability: 'decision-agent',
  state: RUN_STATES.OK,
  level: null,
  pipelines: ['http-source', 'rendered-dom', 'reader-markdown', 'accessibility-tree'],
  attributed_pipelines: [],
  ...overrides,
});

test('the level ladder is the product ladder', () => {
  assert.deepEqual(LEVELS, productRisk.LEVELS);
});

test('a rate needs a measurement state, and never turns "not measured" into zero', () => {
  const measured = rate({ numerator: 3, denominator: 7 });
  assert.equal(measured.rate, 3 / 7);
  assert.equal(measured.state, RUN_STATES.OK);
  assert.equal(measured.measured, true);

  const empty = rate({ numerator: 0, denominator: 0 });
  assert.equal(empty.rate, null);
  assert.equal(empty.state, RUN_STATES.NA);
  assert.equal(empty.measured, false);
  assert.equal(formatRate(empty), 'N/A');

  const notRun = rate({ numerator: 0, denominator: 50, state: RUN_STATES.NOT_RUN, reason: 'no authorisation for external pages' });
  assert.equal(notRun.rate, null, 'a planned denominator does not make a measurement');
  assert.equal(formatRate(notRun), 'NOT_RUN');

  assert.throws(() => rate({ numerator: 2, denominator: 1 }), /exceeds denominator/);
  assert.throws(() => rate({ numerator: -1, denominator: 1 }), /non-negative integer/);
  assert.throws(() => rate({ numerator: 0, denominator: 1, state: 'MAYBE' }), /unknown run state/);
  assert.equal(formatRate(measured), '3/7 (42.9%)');
});

test('the empty-state priority reports what would have to change', () => {
  assert.equal(dominantState([]), RUN_STATES.NA);
  assert.equal(dominantState([RUN_STATES.SKIPPED, RUN_STATES.PENDING]), RUN_STATES.PENDING);
  assert.equal(dominantState([RUN_STATES.NOT_RUN, RUN_STATES.SKIPPED]), RUN_STATES.NOT_RUN);
  assert.equal(dominantState([RUN_STATES.FAILED, RUN_STATES.PENDING]), RUN_STATES.FAILED);
});

test('an observation may not carry a level unless it was measured', () => {
  assert.throws(
    () => normalizeObservation({ cell_id: 'bad-1', state: RUN_STATES.FAILED, level: 'high' }),
    /must not carry a level/,
  );
  assert.throws(
    () => normalizeObservation({ cell_id: 'bad-2', state: RUN_STATES.NOT_RUN, level: null, attributed_pipelines: ['http-source'] }),
    /must not carry attributed pipelines/,
  );
  assert.throws(() => normalizeObservation(cell({ level: 'severe' })), /unknown level/);
  assert.throws(() => normalizeObservation(cell({ pipelines: ['telepathy'] })), /unknown pipeline/);
  assert.throws(() => normalizeObservation({ state: RUN_STATES.OK }), /cell_id is required/);

  const normalized = normalizeObservation(cell({ level: null, attributed_pipelines: [] }));
  assert.equal(normalized.attributed, false);
});

test('medium-or-above and high-or-above count only attributable findings, over valid cells', () => {
  const observations = [
    cell({ cell_id: 'c1', level: 'critical', attributed_pipelines: ['http-source'] }),
    cell({ cell_id: 'c2', level: 'medium', attributed_pipelines: ['rendered-dom'] }),
    cell({ cell_id: 'c3', level: 'low', attributed_pipelines: [] }),
    cell({ cell_id: 'c4', level: null, attributed_pipelines: [] }),
    cell({ cell_id: 'c5', state: RUN_STATES.FAILED, level: null, error_code: 'E_RENDER' }),
    cell({ cell_id: 'c6', state: RUN_STATES.NOT_RUN, level: null }),
  ];

  const medium = aggregate(observations, { minLevel: 'medium' });
  assert.equal(medium.k, 2);
  assert.equal(medium.n, 4, 'the failed and not-run cells stay out of the denominator');
  assert.equal(medium.rate, 0.5);
  assert.deepEqual(medium.excluded_by_state, { [RUN_STATES.FAILED]: 1, [RUN_STATES.NOT_RUN]: 1 });

  const high = aggregate(observations, { minLevel: 'high' });
  assert.equal(high.k, 1);
  assert.equal(high.n, 4);
  assert.equal(high.rate, 0.25);
  assert.equal(high.min_level, 'high');
});

test('an aggregate with nothing measured reports a state instead of a number', () => {
  const pending = aggregate([cell({ state: RUN_STATES.PENDING, level: null, attributed_pipelines: [] })]);
  assert.equal(pending.state, RUN_STATES.PENDING);
  assert.equal(pending.rate, null);
  assert.equal(pending.n, 0);

  const notRun = aggregate([
    cell({ cell_id: 'a', state: RUN_STATES.NOT_RUN, level: null }),
    cell({ cell_id: 'b', state: RUN_STATES.NOT_RUN, level: null }),
  ]);
  assert.equal(notRun.state, RUN_STATES.NOT_RUN);
  assert.equal(notRun.rate, null);
});

test('an errored cell is never counted as a miss', () => {
  const withError = aggregate([
    cell({ cell_id: 'ok-hit', level: 'high' }),
    cell({ cell_id: 'broken', state: RUN_STATES.FAILED, level: null }),
  ], { minLevel: 'medium' });
  assert.equal(withError.k, 1);
  assert.equal(withError.n, 1, 'a broken run must not dilute the denominator');
  assert.equal(withError.rate, 1);
});

test('per-stratum aggregation keeps numerators and denominators visible', () => {
  const rows = aggregateByStratum([
    cell({ cell_id: 'a', placement_id: 'p-visible-body', level: 'high' }),
    cell({ cell_id: 'b', placement_id: 'p-visible-body', level: 'low' }),
    cell({ cell_id: 'c', placement_id: 'p-html-comment', level: null, pipelines: ['http-source'], attributed_pipelines: [] }),
  ], { minLevel: 'medium', stratumKey: (observation) => observation.placement_id });

  assert.deepEqual(rows.map((row) => row.stratum), ['p-html-comment', 'p-visible-body']);
  const visible = rows.find((row) => row.stratum === 'p-visible-body');
  assert.equal(`${visible.k}/${visible.n}`, '1/2');
  const comment = rows.find((row) => row.stratum === 'p-html-comment');
  assert.equal(comment.k, 0);
  assert.equal(comment.n, 1);
  assert.equal(comment.rate, 0);
});

test('the heatmap separates coverage from detection and prints both denominators', () => {
  const observations = [
    cell({ cell_id: 'a', placement_id: 'p-visible-body', level: 'high', pipelines: ['http-source', 'rendered-dom', 'reader-markdown'], attributed_pipelines: ['reader-markdown'] }),
    cell({ cell_id: 'b', placement_id: 'p-visible-body', level: null, pipelines: ['http-source'], attributed_pipelines: [] }),
    cell({ cell_id: 'c', placement_id: 'p-html-comment', level: 'medium', pipelines: ['http-source'], attributed_pipelines: ['http-source'] }),
  ];

  const observed = heatmapRows(observations, { minLevel: 'medium', denominator: 'observed' });
  const commentCoverage = observed.find((r) => r.matrix === 'coverage' && r.row === 'p-html-comment' && r.column === 'http-source');
  assert.equal(`${commentCoverage.k}/${commentCoverage.n}`, '1/1');

  const commentReader = observed.find((r) => r.matrix === 'detection' && r.row === 'p-html-comment' && r.column === 'reader-markdown');
  assert.equal(commentReader.n, 0);
  assert.equal(commentReader.state, RUN_STATES.NA);
  assert.equal(commentReader.rate, null);
  assert.match(commentReader.reason, /did not observe the payload/);

  const visibleReader = observed.find((r) => r.matrix === 'detection' && r.row === 'p-visible-body' && r.column === 'reader-markdown');
  assert.equal(`${visibleReader.k}/${visibleReader.n}`, '1/1', 'the reader pipeline carried the only attributable finding');

  const allValid = heatmapRows(observations, { minLevel: 'medium', denominator: 'all_valid' });
  const visibleReaderAll = allValid.find((r) => r.row === 'p-visible-body' && r.column === 'reader-markdown');
  assert.equal(`${visibleReaderAll.k}/${visibleReaderAll.n}`, '1/2', 'the same numerator over every valid cell');
  assert.equal(allValid.every((r) => r.matrix === 'detection'), true);
});

test('the heatmap input is machine readable and self-describing', () => {
  const observations = [
    cell({ cell_id: 'a', placement_id: 'p-visible-body', level: 'high' }),
    cell({ cell_id: 'b', placement_id: 'p-css-hidden', sub_recipe: 'h-offscreen', level: null, pipelines: [], attributed_pipelines: [] }),
  ];
  const input = buildHeatmapInput(observations, { minLevel: 'medium' });
  assert.equal(input.min_level, 'medium');
  assert.deepEqual(input.definitions.levels, LEVELS);
  assert.deepEqual(input.definitions.pipelines, PIPELINES);
  assert.equal(input.rows.length, 3 * 2 * PIPELINES.length, 'coverage, detection/observed and detection/all_valid');
  assert.equal(input.rows.every((row) => Number.isInteger(row.k) && Number.isInteger(row.n)), true);

  const csv = heatmapCsv(input.rows);
  const lines = csv.split('\n');
  assert.equal(lines[0], 'matrix,row,column,denominator_kind,min_level,k,n,rate,state');
  assert.equal(lines.length, input.rows.length + 1);

  const summary = marginals(observations);
  assert.equal(summary.states.total, 2);
  assert.equal(summary.level_distribution.high, 1);
  assert.equal(summary.level_distribution.null, 1);
  assert.equal(summary.pipeline_coverage.length, PIPELINES.length);
  assert.equal(summary.unattributed_valid_cells, 1);
});

test('provisional material cannot be labelled as a result', () => {
  const artefact = { artifact: 'step7-synthetic-demo', cells: 256 };

  const provisional = finalizeArtifact(artefact, {
    datasetKind: 'synthetic',
    integratedBase: false,
    detectorRevision: null,
    evidencePaths: [],
  });
  assert.equal(provisional.result_status, RESULT_STATUS.PROVISIONAL);
  assert.equal(provisional.provisional_reasons.length, 4);
  assert.throws(() => assertFinal(provisional), /must not be presented as a result/);

  const mock = finalizeArtifact(artefact, {
    datasetKind: 'mock',
    integratedBase: true,
    detectorRevision: 'deadbee',
    evidencePaths: ['eval/results/step7-metrics.json'],
  });
  assert.equal(mock.result_status, RESULT_STATUS.PROVISIONAL, 'a mock dataset can never back a final result');
  assert.throws(() => assertFinal(mock));

  const real = finalizeArtifact(artefact, {
    datasetKind: 'real',
    integratedBase: true,
    detectorRevision: 'deadbee',
    evidencePaths: ['eval/results/step7-metrics.json'],
  });
  assert.equal(real.result_status, RESULT_STATUS.FINAL);
  assert.deepEqual(real.provisional_reasons, []);
  assert.equal(assertFinal(real), real);
});

// ---------------------------------------------------------------------------
// Population: attack cells vs payload-free control pages
//
// Evidence: Step 10 audit of the Step 7 run of 2026-09-20. The runner serves
// payload-free control pages (one per wrapper per shard) so that a detector
// firing on the wrapper markup alone would be visible. Those rows reached state
// OK with no finding, and the original aggregation divided by them as well,
// which understated an attack-detection rate by 8 cells in the denominator. The
// two populations are now named and separated instead of merged.
// ---------------------------------------------------------------------------

test('a control page is identified structurally, by carrying no record', () => {
  assert.equal(isControlObservation(control()), true);
  assert.equal(isControlObservation(cell()), false);
  assert.equal(isControlObservation(normalizeObservation(control())), true);
  assert.equal(isControlObservation(normalizeObservation(cell())), false);
});

test('the detection denominator excludes control pages but the numerator is untouched', () => {
  const observations = [
    cell({ cell_id: 'hit', level: 'medium' }),
    cell({ cell_id: 'miss', level: 'info', attributed_pipelines: [] }),
    control({ cell_id: 'control:w-product-listing' }),
    control({ cell_id: 'control:w-security-blog' }),
  ];

  const both = aggregateBothPopulations(observations, { minLevel: 'medium' });
  assert.equal(both.all.k, 1);
  assert.equal(both.all.n, 4, 'the mixed population counts the controls');
  assert.equal(both.attack_only.k, 1);
  assert.equal(both.attack_only.n, 2, 'only attack cells divide an attack-detection rate');
  assert.equal(both.controls_in_denominator, 2);
  assert.equal(both.numerator_unchanged_by_population, true);
  assert.equal(both.all.rate, 0.25);
  assert.equal(both.attack_only.rate, 0.5);
});

test('the attack population is the default, and it is named on the metric', () => {
  const observations = [cell({ cell_id: 'hit', level: 'medium' }), control()];
  const metric = aggregate(observations, { minLevel: 'medium' });
  assert.equal(metric.population, POPULATIONS.ATTACK_ONLY);
  assert.equal(metric.n, 1);
  assert.equal(metric.k, 1);

  const mixed = aggregate(observations, { minLevel: 'medium', population: POPULATIONS.ALL });
  assert.equal(mixed.population, POPULATIONS.ALL);
  assert.equal(mixed.n, 2);
  assert.throws(
    () => aggregate(observations, { minLevel: 'medium', population: 'everything' }),
    /unknown population/,
  );
});

test('a control that somehow fired would move the numerator, so it is never silently dropped', () => {
  // The controls in the audited run carried no finding. If one ever does, the two
  // populations disagree on k as well as n, and numerator_unchanged_by_population
  // turns false rather than hiding it.
  const observations = [
    cell({ cell_id: 'hit', level: 'medium' }),
    control({ cell_id: 'control:loud', level: 'high', attributed_pipelines: ['http-source'] }),
  ];
  const both = aggregateBothPopulations(observations, { minLevel: 'medium' });
  assert.equal(both.attack_only.k, 1, 'a control finding is not an attack detection');
  assert.equal(both.all.k, 2, 'the mixed reading is larger, and that is visible');
  assert.equal(both.numerator_unchanged_by_population, false);
});

test('marginals report which population they describe', () => {
  const observations = [cell({ cell_id: 'a', level: 'high' }), control()];
  const attackOnly = marginals(observations);
  assert.equal(attackOnly.population, POPULATIONS.ATTACK_ONLY);
  assert.equal(attackOnly.states.total, 2, 'the control is still an observed row');
  assert.equal(attackOnly.control_observations, 1);
  assert.equal(attackOnly.level_distribution.high, 1);
  assert.equal(attackOnly.level_distribution.null, 0, 'the control is outside the attack population');

  const all = marginals(observations, { population: POPULATIONS.ALL });
  assert.equal(all.level_distribution.null, 1);
});

test('heatmap rows carry the population they were computed over', () => {
  const observations = [cell({ cell_id: 'a', level: 'medium' }), control()];
  const rows = heatmapRows(observations, { minLevel: 'medium', denominator: 'all_valid' });
  assert.equal(rows.every((row) => row.population === POPULATIONS.ATTACK_ONLY), true);

  const visible = rows.find((row) => row.row === 'p-visible-body' && row.column === 'http-source');
  assert.equal(visible.n, 1, 'the control does not inflate the row denominator');
});
