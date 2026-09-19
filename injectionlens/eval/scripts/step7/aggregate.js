// Step 7 evaluation utilities — detection aggregation and heatmap input.
//
// Two questions are easy to conflate, so they are computed separately:
//
//   coverage   did this pipeline extract the planted text at all?
//   detection  did an attributable finding at >= medium / >= high come from it?
//
// A pipeline that never saw the payload cannot be credited with missing it, so
// the detection matrix is emitted twice: once with the denominator restricted to
// cells that pipeline observed, and once over all valid cells. Neither reading is
// hidden, and every cell carries its own k and n.
//
// State handling: only state OK observations enter a denominator. A render
// failure is recorded as an error, never as "not detected" — otherwise a broken
// browser would look like a robust detector.
'use strict';

const { RUN_STATES, isRunState, rate, dominantState } = require('./states');

// Mirrors server/lib/risk.js LEVELS; a test asserts the two ladders are equal.
const LEVELS = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

// Mirrors the pipeline ids used by analyze.js recordOccurrence().
const PIPELINES = Object.freeze(['http-source', 'rendered-dom', 'reader-markdown', 'accessibility-tree']);

const HEATMAP_MATRICES = Object.freeze(['coverage', 'detection']);
const DENOMINATOR_KINDS = Object.freeze(['observed', 'all_valid']);

// Which observations belong in a denominator.
//
// The runner appends payload-free CONTROL pages (a wrapper with filler text) so
// that a detector firing on the wrapper alone would be visible. A control is a
// legitimate OK observation of the page, but it is not an attack sample, and an
// attack-detection rate must not be diluted by it. The two populations are
// therefore named explicitly instead of being merged:
//
//   all         every OK observation, attack cells plus controls
//   attack_only attack cells only — the population a detection rate is about
//
// Both are computed and both are published; neither is hidden. The `population`
// field is carried on every metric so a k/n pair can never be read without
// knowing which denominator it came from.
const POPULATIONS = Object.freeze({ ALL: 'all', ATTACK_ONLY: 'attack_only' });

class EvaluationObservationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EvaluationObservationError';
  }
}

/**
 * Is this observation a payload-free control page?
 *
 * The definition is structural, not a naming convention: a control is planted
 * with no record behind it, and the runner writes `record_uid: null` for exactly
 * those rows. A regression test checks that this holds for every control row.
 */
function isControlObservation(observation) {
  return observation.record_uid === null || observation.record_uid === undefined;
}

function assertPopulation(population) {
  if (!Object.values(POPULATIONS).includes(population)) {
    throw new EvaluationObservationError(
      `unknown population ${JSON.stringify(population)}; expected one of ${Object.values(POPULATIONS).join(', ')}`,
    );
  }
  return population;
}

/** The valid (state OK) observations a metric with this population divides by. */
function populationValid(normalized, population) {
  assertPopulation(population);
  return normalized.filter(
    (observation) => observation.state === RUN_STATES.OK
      && (population === POPULATIONS.ALL || !isControlObservation(observation)),
  );
}

function levelIndex(level) {
  const index = LEVELS.indexOf(level);
  if (index === -1) throw new EvaluationObservationError(`unknown level ${JSON.stringify(level)}`);
  return index;
}

function meetsThreshold(level, minLevel) {
  if (level === null || level === undefined) return false;
  return levelIndex(level) >= levelIndex(minLevel);
}

/**
 * Validate one observation. The invariants are the point: an unmeasured cell may
 * not carry a level, and a level implies an attributable finding.
 */
function normalizeObservation(observation = {}) {
  const {
    cell_id: cellId,
    state,
    level = null,
    attributed_pipelines = [],
    pipelines = [],
    error_code = null,
  } = observation;

  if (typeof cellId !== 'string' || cellId === '') {
    throw new EvaluationObservationError('observation.cell_id is required');
  }
  if (!isRunState(state)) {
    throw new EvaluationObservationError(`observation ${cellId}: unknown state ${JSON.stringify(state)}`);
  }
  if (level !== null && !LEVELS.includes(level)) {
    throw new EvaluationObservationError(`observation ${cellId}: unknown level ${JSON.stringify(level)}`);
  }
  if (state !== RUN_STATES.OK && level !== null) {
    throw new EvaluationObservationError(
      `observation ${cellId}: state ${state} must not carry a level (a failed or skipped cell is not a measurement)`,
    );
  }
  for (const pipeline of [...pipelines, ...attributed_pipelines]) {
    if (!PIPELINES.includes(pipeline)) {
      throw new EvaluationObservationError(`observation ${cellId}: unknown pipeline ${JSON.stringify(pipeline)}`);
    }
  }
  if (state !== RUN_STATES.OK && attributed_pipelines.length > 0) {
    throw new EvaluationObservationError(`observation ${cellId}: state ${state} must not carry attributed pipelines`);
  }

  return {
    cell_id: cellId,
    record_uid: observation.record_uid ?? null,
    transform_id: observation.transform_id ?? null,
    placement_id: observation.placement_id ?? null,
    sub_recipe: observation.sub_recipe ?? null,
    capability: observation.capability ?? null,
    state,
    level,
    attributed: level !== null,
    pipelines: pipelines.slice(),
    attributed_pipelines: attributed_pipelines.slice(),
    error_code,
  };
}

function summarizeStates(observations) {
  const counts = {};
  for (const state of Object.values(RUN_STATES)) counts[state] = 0;
  for (const observation of observations) counts[observation.state] += 1;
  return { total: observations.length, by_state: counts };
}

function excludedByState(observations) {
  const counts = {};
  for (const observation of observations) {
    if (observation.state === RUN_STATES.OK) continue;
    counts[observation.state] = (counts[observation.state] || 0) + 1;
  }
  return counts;
}

/**
 * medium-or-above / high-or-above aggregation with explicit k and n.
 *
 * @param {Array} observations normalized or raw observations
 * @param {{minLevel?: 'medium'|'high', population?: 'all'|'attack_only'}} options
 */
function aggregate(observations, { minLevel = 'medium', population = POPULATIONS.ATTACK_ONLY } = {}) {
  if (!Array.isArray(observations)) throw new EvaluationObservationError('aggregate expects an array');
  levelIndex(minLevel);
  assertPopulation(population);
  const normalized = observations.map(normalizeObservation);
  const valid = populationValid(normalized, population);
  const hits = valid.filter((observation) => meetsThreshold(observation.level, minLevel));

  const state = valid.length > 0
    ? RUN_STATES.OK
    : dominantState(normalized.map((observation) => observation.state));

  const result = rate({
    numerator: hits.length,
    denominator: valid.length,
    state,
    reason: valid.length === 0 ? 'no observation reached state OK' : null,
  });

  return {
    min_level: minLevel,
    population,
    ...result,
    excluded_by_state: excludedByState(normalized),
    n_observations: normalized.length,
  };
}

/**
 * The same threshold over both populations, with the control rows accounted for
 * explicitly. This is what lets one reading be compared with the other later,
 * including after the controls change.
 */
function aggregateBothPopulations(observations, { minLevel = 'medium' } = {}) {
  const all = aggregate(observations, { minLevel, population: POPULATIONS.ALL });
  const attackOnly = aggregate(observations, { minLevel, population: POPULATIONS.ATTACK_ONLY });
  return {
    all,
    attack_only: attackOnly,
    controls_in_denominator: all.n - attackOnly.n,
    numerator_unchanged_by_population: all.k === attackOnly.k,
  };
}

function aggregateByStratum(
  observations,
  { minLevel = 'medium', stratumKey, population = POPULATIONS.ATTACK_ONLY } = {},
) {
  if (typeof stratumKey !== 'function') throw new EvaluationObservationError('stratumKey must be a function');
  assertPopulation(population);
  const buckets = new Map();
  for (const observation of observations.map(normalizeObservation)) {
    const key = stratumKey(observation);
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(observation);
  }
  return Array.from(buckets.keys()).sort().map((key) => ({
    stratum: key,
    ...aggregate(buckets.get(key), { minLevel, population }),
  }));
}

function orderedValues(observations, field, order) {
  const present = Array.from(new Set(observations.map((observation) => observation[field]).filter((value) => value !== null)));
  const known = order.filter((value) => present.includes(value));
  const unknown = present.filter((value) => !order.includes(value)).sort();
  return [...known, ...unknown];
}

/**
 * Machine-readable heatmap input: one row per (matrix, placement, pipeline).
 *
 * @param {Array} observations
 * @param {{minLevel?: string, denominator?: 'observed'|'all_valid'}} options
 */
function heatmapRows(
  observations,
  { minLevel = 'medium', denominator = 'observed', population = POPULATIONS.ATTACK_ONLY } = {},
) {
  if (!DENOMINATOR_KINDS.includes(denominator)) {
    throw new EvaluationObservationError(`denominator must be one of ${DENOMINATOR_KINDS.join(', ')}`);
  }
  assertPopulation(population);
  const normalized = observations.map(normalizeObservation);
  // A control carries no placement of its own beyond the visible body, so the
  // row set is read from the attack population: a row that exists only because a
  // control sat in it would be a row about nothing.
  const placementIds = orderedValues(
    normalized.filter((observation) => !isControlObservation(observation)),
    'placement_id',
    [],
  );
  const matrixKinds = denominator === 'observed' ? HEATMAP_MATRICES : ['detection'];
  const out = [];

  for (const matrix of matrixKinds) {
    for (const placement of placementIds) {
      const inRow = normalized.filter((observation) => observation.placement_id === placement);
      const valid = populationValid(inRow, population);
      const rowState = valid.length > 0 ? RUN_STATES.OK : dominantState(inRow.map((observation) => observation.state));
      for (const pipeline of PIPELINES) {
        const observed = valid.filter((observation) => observation.pipelines.includes(pipeline));
        let numerator;
        let cellDenominator;
        let reason = null;

        if (matrix === 'coverage') {
          numerator = observed.length;
          cellDenominator = valid.length;
          if (valid.length === 0) reason = 'no observation reached state OK in this row';
        } else if (denominator === 'observed') {
          numerator = observed.filter((observation) => meetsThreshold(observation.level, minLevel)
            && observation.attributed_pipelines.includes(pipeline)).length;
          cellDenominator = observed.length;
          if (observed.length === 0) reason = 'this pipeline did not observe the payload in this row';
        } else {
          numerator = valid.filter((observation) => meetsThreshold(observation.level, minLevel)
            && observation.attributed_pipelines.includes(pipeline)).length;
          cellDenominator = valid.length;
          if (valid.length === 0) reason = 'no observation reached state OK in this row';
        }

        const cell = rate({ numerator, denominator: cellDenominator, state: rowState, reason });
        out.push({
          matrix,
          row: placement,
          column: pipeline,
          denominator_kind: matrix === 'coverage' ? 'all_valid' : denominator,
          min_level: minLevel,
          population: matrix === 'coverage' ? POPULATIONS.ATTACK_ONLY : population,
          ...cell,
        });
      }
    }
  }
  return out;
}

function heatmapCsv(rows) {
  const header = 'matrix,row,column,denominator_kind,min_level,k,n,rate,state';
  const lines = rows.map((row) => [
    row.matrix,
    row.row,
    row.column,
    row.denominator_kind,
    row.min_level,
    row.k,
    row.n,
    row.rate === null ? '' : row.rate.toFixed(6),
    row.state,
  ].join(','));
  return [header, ...lines].join('\n');
}

function marginals(observations, { population = POPULATIONS.ATTACK_ONLY } = {}) {
  assertPopulation(population);
  const normalized = observations.map(normalizeObservation);
  const valid = populationValid(normalized, population);
  const levelDistribution = {};
  for (const level of [...LEVELS, null]) levelDistribution[String(level)] = 0;
  for (const observation of valid) levelDistribution[String(observation.level)] += 1;

  const pipelineCoverage = PIPELINES.map((pipeline) => ({
    pipeline,
    ...rate({
      numerator: valid.filter((observation) => observation.pipelines.includes(pipeline)).length,
      denominator: valid.length,
      state: valid.length ? RUN_STATES.OK : dominantState(normalized.map((observation) => observation.state)),
      reason: valid.length ? null : 'no observation reached state OK',
    }),
  }));

  return {
    population,
    states: summarizeStates(normalized),
    control_observations: normalized.filter(isControlObservation).length,
    level_distribution: levelDistribution,
    pipeline_coverage: pipelineCoverage,
    placements: orderedValues(normalized.filter((observation) => !isControlObservation(observation)), 'placement_id', []),
    transforms: orderedValues(normalized.filter((observation) => !isControlObservation(observation)), 'transform_id', []),
    capabilities: orderedValues(normalized, 'capability', []),
    unattributed_valid_cells: valid.filter((observation) => observation.level === null).length,
  };
}

function buildHeatmapInput(observations, { minLevel = 'medium', population = POPULATIONS.ATTACK_ONLY } = {}) {
  assertPopulation(population);
  const normalized = observations.map(normalizeObservation);
  return {
    min_level: minLevel,
    population,
    definitions: {
      coverage: 'k = valid cells in which the pipeline extracted the planted text; n = all valid cells in the row',
      detection_observed: 'k = valid cells with an attributable finding at >= min_level carried by that pipeline; n = valid cells that pipeline observed',
      detection_all_valid: 'k = the same numerator; n = all valid cells in the row',
      valid: 'state OK only; FAILED, SKIPPED, NOT_RUN, PENDING and N/A cells stay out of every denominator',
      population: 'attack_only excludes the payload-free control pages, which have record_uid null; all includes them',
      levels: LEVELS.slice(),
      pipelines: PIPELINES.slice(),
    },
    rows: [
      ...heatmapRows(normalized, { minLevel, denominator: 'observed', population }),
      ...heatmapRows(normalized, { minLevel, denominator: 'all_valid', population }),
    ],
    marginals: marginals(normalized, { population }),
  };
}

module.exports = {
  LEVELS,
  PIPELINES,
  POPULATIONS,
  HEATMAP_MATRICES,
  DENOMINATOR_KINDS,
  EvaluationObservationError,
  levelIndex,
  meetsThreshold,
  normalizeObservation,
  rateFor: rate,
  isControlObservation,
  populationValid,
  summarizeStates,
  aggregate,
  aggregateBothPopulations,
  aggregateByStratum,
  heatmapRows,
  heatmapCsv,
  marginals,
  buildHeatmapInput,
};
