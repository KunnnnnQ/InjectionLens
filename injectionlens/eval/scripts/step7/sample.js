// Step 7 evaluation utilities — deduplication, deterministic sampling, funnel.
//
// Sampling must be reproducible by someone who does not trust this code:
//
//   1. de-duplicate (byte, normalised text, near-duplicate);
//   2. sort the survivors by SHA-256(seed || record hash) and take the first N.
//
// Step 2 has no random number generator in it at all. The same seed and the same
// record bytes give the same selection regardless of file order, of how the JSON
// was re-serialised, or of which machine runs it.
//
// The de-duplication key is the product's own comparison key
// (server/lib/profiles.js normText). That function is exported, so a test pins
// the equality directly. tokenSet/jaccard are copies of the private helpers in
// analyze.js and are documented as such rather than claimed to be verified.
'use strict';

const { samplingKey, compareHexKeys, canonicalSha256, SAMPLING_ID } = require('./ids');

const DEFAULT_PAYLOAD_FIELD = 'payload';

/** Mirror of server/lib/profiles.js normText — the product's comparison key. */
function normText(value) {
  return (value || '').replace(/[\u200B-\u200D\uFEFF\u2060]/g, '').replace(/\s+/g, ' ').trim();
}

/** Mirror of analyze.js tokenSet. */
function tokenSet(text) {
  return new Set(normText(text).toLowerCase().split(/\W+/).filter((w) => w.length > 2));
}

/** Mirror of analyze.js jaccard. */
function jaccard(a, b) {
  if (!a.size || !b.size) return 0;
  let intersection = 0;
  for (const word of a) if (b.has(word)) intersection += 1;
  return intersection / (a.size + b.size - intersection);
}

function payloadOf(record, payloadField) {
  return String(record?.value?.[payloadField] ?? '');
}

function sortDeterministically(records) {
  return records.slice().sort((a, b) => {
    if (a.record_sha256 !== b.record_sha256) return a.record_sha256 < b.record_sha256 ? -1 : 1;
    if (a.line_no !== b.line_no) return a.line_no - b.line_no;
    return a.record_uid < b.record_uid ? -1 : 1;
  });
}

/**
 * Three-level deduplication.
 *
 * @param {Array} records
 * @param {{nearDupJaccard: number, payloadField?: string}} options
 *        nearDupJaccard is required and recorded: the harness has no default,
 *        because the threshold changes the sampling frame.
 */
function dedupe(records, { nearDupJaccard, payloadField = DEFAULT_PAYLOAD_FIELD } = {}) {
  if (!Array.isArray(records)) throw new Error('dedupe expects an array of records');
  if (typeof nearDupJaccard !== 'number' || !(nearDupJaccard > 0 && nearDupJaccard <= 1)) {
    throw new Error('nearDupJaccard is required and must be in (0, 1]');
  }

  const kept = [];
  const dropped = [];
  const counts = { byte: 0, text: 0, near: 0 };
  const byHash = new Map();
  const byText = new Map();

  for (const record of sortDeterministically(records)) {
    const hash = record.record_sha256;
    const text = normText(payloadOf(record, payloadField));

    if (byHash.has(hash)) {
      counts.byte += 1;
      dropped.push({ record_uid: record.record_uid, record_sha256: hash, duplicate_of: byHash.get(hash), level: 'byte' });
      continue;
    }
    if (byText.has(text)) {
      counts.text += 1;
      dropped.push({ record_uid: record.record_uid, record_sha256: hash, duplicate_of: byText.get(text), level: 'text' });
      byHash.set(hash, record.record_uid);
      continue;
    }

    const tokens = tokenSet(text);
    let near = null;
    for (const candidate of kept) {
      if (jaccard(tokens, candidate.tokens) >= nearDupJaccard) {
        near = candidate;
        break;
      }
    }
    if (near) {
      counts.near += 1;
      dropped.push({ record_uid: record.record_uid, record_sha256: hash, duplicate_of: near.record.record_uid, level: 'near' });
      byHash.set(hash, record.record_uid);
      byText.set(text, record.record_uid);
      continue;
    }

    byHash.set(hash, record.record_uid);
    byText.set(text, record.record_uid);
    kept.push({ record, text, tokens });
  }

  return {
    kept: kept.map((entry) => entry.record),
    dropped,
    counts,
    near_dup_jaccard: nearDupJaccard,
    dropped_total: dropped.length,
  };
}

/**
 * Keyed-hash sampling without replacement.
 *
 * @param {Array} records eligible records (already filtered and de-duplicated)
 * @param {{seed: string, targetN: number, samplingId?: string}} options
 */
function sampleDeterministic(records, { seed, targetN, samplingId = SAMPLING_ID } = {}) {
  if (!Array.isArray(records)) throw new Error('sampleDeterministic expects an array of records');
  if (typeof seed !== 'string' || seed.trim() === '') {
    throw new Error('sampleDeterministic requires a non-empty seed; the harness deliberately has no default seed');
  }
  if (!Number.isInteger(targetN) || targetN < 1) {
    throw new Error('targetN must be a positive integer');
  }

  const keyed = records.map((record) => ({
    key: samplingKey({ seed, recordSha256: record.record_sha256, samplingId }),
    recordSha256: record.record_sha256,
    recordUid: record.record_uid,
    record,
  })).sort(compareHexKeys);

  const selected = keyed.slice(0, targetN).map((entry, index) => ({
    ...entry.record,
    sample_rank: index + 1,
    sampling_key: entry.key,
  }));

  return {
    sampling_id: samplingId,
    seed,
    target_n: targetN,
    eligible_count: records.length,
    selected,
    shortfall: selected.length < targetN,
    shortfall_reason: selected.length < targetN
      ? `only ${records.length} eligible record(s) for a target of ${targetN}`
      : null,
    fingerprint: canonicalSha256(selected.map((record) => record.record_uid)),
  };
}

/**
 * The corpus funnel. Every stage is reported, so a reader can re-derive N
 * instead of trusting a single "50 records were used".
 */
function buildFunnel({
  sourceTotal,
  filterCounts = {},
  dedupeCounts = {},
  eligible,
  sampled,
  targetN,
} = {}) {
  const excludedTotal = Object.values(filterCounts).reduce((sum, value) => sum + value, 0);
  const dedupedTotal = Object.values(dedupeCounts).reduce((sum, value) => sum + value, 0);
  return {
    n_source_records_total: sourceTotal ?? null,
    n_excluded_by_reason: { ...filterCounts },
    n_excluded_total: excludedTotal,
    n_deduped_by_level: { ...dedupeCounts },
    n_deduped_total: dedupedTotal,
    n_eligible: eligible ?? null,
    n_sampled: sampled ?? null,
    target_n: targetN ?? null,
    sample_shortfall: typeof sampled === 'number' && typeof targetN === 'number' ? sampled < targetN : null,
  };
}

module.exports = {
  DEFAULT_PAYLOAD_FIELD,
  normText,
  tokenSet,
  jaccard,
  payloadOf,
  sortDeterministically,
  dedupe,
  sampleDeterministic,
  buildFunnel,
};
