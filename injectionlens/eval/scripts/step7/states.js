// Step 7 evaluation utilities — status vocabulary and aggregate construction.
//
// Why this module exists: an evaluation harness can mislead without inventing a
// single number. It can print "0%" for something that was never measured, and it
// can print a confident percentage for a denominator of one. Every aggregate
// produced under eval/scripts/step7 goes through rate(), which keeps the
// numerator, the denominator and the measurement state as three separate facts.
//
// Nothing here claims Human Step 7 has been run. A measurement is only ever
// recorded by a caller that actually observed something; the utilities in this
// folder produce plans, filters, pages and aggregation rules.
'use strict';

const RUN_STATES = Object.freeze({
  OK: 'OK',
  NOT_RUN: 'NOT_RUN',
  SKIPPED: 'SKIPPED',
  PENDING: 'PENDING',
  FAILED: 'FAILED',
  NA: 'N/A',
});

const RESULT_STATUS = Object.freeze({
  PROVISIONAL: 'PROVISIONAL',
  FINAL: 'FINAL',
});

const DATASET_KINDS = Object.freeze(['synthetic', 'mock', 'real']);

// Priority used only when an aggregate has nothing measured in it.
//   FAILED  — we tried and it broke; the most actionable empty state.
//   PENDING — work remains, so neither "not run" nor "skipped" is the truth yet.
//   NOT_RUN — deliberately not started (for example, no authorisation).
//   SKIPPED — deliberately passed over.
//   N/A     — nothing to say.
const EMPTY_STATE_PRIORITY = Object.freeze([
  RUN_STATES.FAILED,
  RUN_STATES.PENDING,
  RUN_STATES.NOT_RUN,
  RUN_STATES.SKIPPED,
  RUN_STATES.NA,
]);

class EvaluationStateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EvaluationStateError';
  }
}

function isRunState(value) {
  return Object.values(RUN_STATES).includes(value);
}

function assertCount(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new EvaluationStateError(`${label} must be a non-negative integer, got ${JSON.stringify(value)}`);
  }
}

/**
 * Build one aggregate with an explicit numerator and denominator.
 *
 * Contract:
 *   - a rate is a number ONLY when state is OK and the denominator is non-zero;
 *   - state OK with denominator 0 becomes N/A (never 0 and never a division);
 *   - any other state keeps rate === null, so "not measured" can never be read
 *     as "measured zero".
 *
 * @param {{numerator?: number, denominator?: number, state?: string, reason?: string|null}} input
 */
function rate({ numerator = 0, denominator = 0, state = RUN_STATES.OK, reason = null } = {}) {
  assertCount(numerator, 'numerator');
  assertCount(denominator, 'denominator');
  if (!isRunState(state)) {
    throw new EvaluationStateError(`unknown run state ${JSON.stringify(state)}`);
  }
  if (numerator > denominator) {
    throw new EvaluationStateError(`numerator ${numerator} exceeds denominator ${denominator}`);
  }

  let effectiveState = state;
  let effectiveReason = reason;
  if (effectiveState === RUN_STATES.OK && denominator === 0) {
    effectiveState = RUN_STATES.NA;
    effectiveReason = reason || 'denominator is zero';
  }

  const measured = effectiveState === RUN_STATES.OK;
  return {
    k: numerator,
    n: denominator,
    rate: measured ? numerator / denominator : null,
    state: effectiveState,
    measured,
    reason: effectiveReason,
  };
}

/** Human-readable one-liner for reports: "3/7 (42.9%)", "N/A", "NOT RUN". */
function formatRate(result, digits = 1) {
  if (!result || typeof result !== 'object') {
    throw new EvaluationStateError('formatRate expects a rate() result');
  }
  if (!result.measured) {
    return result.state === RUN_STATES.NA ? RUN_STATES.NA : result.state;
  }
  return `${result.k}/${result.n} (${(result.rate * 100).toFixed(digits)}%)`;
}

/** Which empty state best describes a set of observations that contains no OK. */
function dominantState(states) {
  const list = Array.isArray(states) ? states : Array.from(states || []);
  if (list.length === 0) return RUN_STATES.NA;
  for (const state of EMPTY_STATE_PRIORITY) {
    if (list.includes(state)) return state;
  }
  return RUN_STATES.NA;
}

/**
 * Stamp an artifact PROVISIONAL or FINAL.
 *
 * The rule is deliberately hard to satisfy: a FINAL label requires a real
 * dataset, a confirmed integrated base, a detector revision and at least one
 * evidence path. Anything else — a synthetic dataset, a mock license table, an
 * un-integrated base — is stamped PROVISIONAL and the reasons are recorded, so
 * provisional material cannot be relabelled as a result by editing a string.
 *
 * @param {object} artifact
 * @param {{datasetKind?: string, integratedBase?: boolean, detectorRevision?: string|null, evidencePaths?: string[]}} basis
 */
function finalizeArtifact(artifact, basis = {}) {
  if (!artifact || typeof artifact !== 'object') {
    throw new EvaluationStateError('finalizeArtifact expects an artifact object');
  }
  const datasetKind = basis.datasetKind;
  const reasons = [];
  if (!DATASET_KINDS.includes(datasetKind)) {
    reasons.push(`dataset kind ${JSON.stringify(datasetKind ?? null)} is not one of ${DATASET_KINDS.join(', ')}`);
  } else if (datasetKind !== 'real') {
    reasons.push(`dataset kind is "${datasetKind}"; only a real dataset can back a final result`);
  }
  if (basis.integratedBase !== true) {
    reasons.push('the integrated Step 6 base is not confirmed');
  }
  if (typeof basis.detectorRevision !== 'string' || basis.detectorRevision.trim() === '') {
    reasons.push('no detector revision was recorded');
  }
  if (!Array.isArray(basis.evidencePaths) || basis.evidencePaths.length === 0) {
    reasons.push('no evidence file paths were recorded');
  }

  const result_status = reasons.length ? RESULT_STATUS.PROVISIONAL : RESULT_STATUS.FINAL;
  return {
    ...artifact,
    result_status,
    provisional_reasons: reasons,
    basis: {
      dataset_kind: datasetKind ?? null,
      integrated_base: basis.integratedBase === true,
      detector_revision: basis.detectorRevision ?? null,
      evidence_paths: Array.isArray(basis.evidencePaths) ? basis.evidencePaths.slice() : [],
    },
  };
}

/** Refuse to treat anything that is not FINAL as a result. */
function assertFinal(artifact) {
  if (!artifact || artifact.result_status !== RESULT_STATUS.FINAL) {
    const status = artifact ? artifact.result_status : undefined;
    throw new EvaluationStateError(
      `artifact is ${JSON.stringify(status ?? null)}, not ${RESULT_STATUS.FINAL}; it must not be presented as a result`,
    );
  }
  return artifact;
}

module.exports = {
  RUN_STATES,
  RESULT_STATUS,
  DATASET_KINDS,
  EvaluationStateError,
  isRunState,
  rate,
  formatRate,
  dominantState,
  finalizeArtifact,
  assertFinal,
};
