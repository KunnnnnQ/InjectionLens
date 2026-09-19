// Step 7 evaluation utilities — stable identifiers and deterministic hashing.
//
// Every identifier in this harness is derived from bytes that are pinned by a
// hash, never from a position in a file that could be re-serialised:
//
//   record_sha256  the SHA-256 of the raw JSONL line (without its terminator).
//                  This is the identity of a record. Any reformatting of the
//                  corpus changes it, and that is the point: it makes a silent
//                  corpus swap visible.
//   record_uid     a human-readable pointer: "<source>:L<line>:<hash12>".
//   cell_id        one observation unit: record x transform x placement x
//                  capability. Two runs that produce the same cell_id really are
//                  describing the same experiment.
//
// Selection never uses Math.random. Ordering by a keyed SHA-256 makes the sample
// independent of input order and reproducible by anyone with a SHA-256 tool.
'use strict';

const crypto = require('node:crypto');

class EvaluationIdError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EvaluationIdError';
  }
}

const SAMPLING_ID = 'keyed-sha256-sort-v1';

function sha256Hex(input) {
  if (typeof input !== 'string' && !Buffer.isBuffer(input)) {
    throw new EvaluationIdError('sha256Hex expects a string or Buffer');
  }
  return crypto.createHash('sha256').update(input, typeof input === 'string' ? 'utf8' : undefined).digest('hex');
}

function assertSha256Hex(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new EvaluationIdError(`${label} must be a 64-character lowercase hex SHA-256, got ${JSON.stringify(value)}`);
  }
  return value;
}

/** Remove exactly one trailing line terminator; leave every other byte alone. */
function stripOneLineTerminator(rawLine) {
  if (typeof rawLine !== 'string') throw new EvaluationIdError('stripOneLineTerminator expects a string');
  return rawLine.replace(/\r?\n$/, '');
}

/** Identity of one corpus record: the hash of its raw line bytes. */
function recordSha256(rawLine) {
  return sha256Hex(Buffer.from(stripOneLineTerminator(rawLine), 'utf8'));
}

function padLineNumber(lineNo) {
  if (!Number.isInteger(lineNo) || lineNo < 1) {
    throw new EvaluationIdError(`line number must be a positive integer, got ${JSON.stringify(lineNo)}`);
  }
  return String(lineNo).padStart(6, '0');
}

function makeRecordUid({ sourceSlug, lineNo, recordSha256: hash }) {
  if (typeof sourceSlug !== 'string' || sourceSlug.trim() === '') {
    throw new EvaluationIdError('sourceSlug is required');
  }
  assertSha256Hex(hash, 'recordSha256');
  return `${sourceSlug}:L${padLineNumber(lineNo)}:${hash.slice(0, 12)}`;
}

/**
 * One observation unit. subRecipe is only used by placements that have declared
 * sub-recipes (currently the CSS-hidden family); it stays out of the id when a
 * placement has none, so ids stay stable if the family grows later.
 */
function makeCellId({ recordUid, transformId, placementId, subRecipe = null, capability }) {
  const parts = [recordUid, transformId, placementId];
  if (subRecipe) parts.push(subRecipe);
  parts.push(capability);
  for (const part of parts) {
    if (typeof part !== 'string' || part.trim() === '') {
      throw new EvaluationIdError(`cell id component is empty: ${JSON.stringify(part)}`);
    }
    if (part.includes('|')) {
      throw new EvaluationIdError(`cell id components must not contain "|": ${JSON.stringify(part)}`);
    }
  }
  return parts.join('|');
}

/** Deterministic selection key. Same seed + same record bytes => same key. */
function samplingKey({ seed, recordSha256: hash, samplingId = SAMPLING_ID }) {
  if (typeof seed !== 'string' || seed.trim() === '') {
    throw new EvaluationIdError('a non-empty seed string is required; the harness has no default seed');
  }
  assertSha256Hex(hash, 'recordSha256');
  return sha256Hex(`${samplingId}\u001f${seed}\u001f${hash}`);
}

function compareHexKeys(a, b) {
  if (a.key !== b.key) return a.key < b.key ? -1 : 1;
  // Tie-break on the record hash, then the uid, so the order is total.
  if (a.recordSha256 !== b.recordSha256) return a.recordSha256 < b.recordSha256 ? -1 : 1;
  return a.recordUid < b.recordUid ? -1 : 1;
}

/**
 * Canonical JSON: object keys sorted, arrays in order, no undefined.
 *
 * Used to hash our own artifacts and configuration. It is deliberately NOT used
 * for corpus records — those are hashed as raw bytes so that a re-serialisation
 * with different key order cannot masquerade as the same record.
 */
function canonicalJson(value) {
  const encode = (node, path) => {
    if (node === null) return 'null';
    const type = typeof node;
    if (type === 'string') return JSON.stringify(node);
    if (type === 'boolean') return node ? 'true' : 'false';
    if (type === 'number') {
      if (!Number.isFinite(node)) throw new EvaluationIdError(`non-finite number at ${path}`);
      return JSON.stringify(node);
    }
    if (type === 'undefined') throw new EvaluationIdError(`undefined value at ${path}`);
    if (type === 'function' || type === 'symbol' || type === 'bigint') {
      throw new EvaluationIdError(`unsupported ${type} value at ${path}`);
    }
    if (Array.isArray(node)) {
      return `[${node.map((item, i) => encode(item, `${path}[${i}]`)).join(',')}]`;
    }
    const keys = Object.keys(node).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(node[key], `${path}.${key}`)}`).join(',')}}`;
  };
  return encode(value, '$');
}

function canonicalSha256(value) {
  return sha256Hex(canonicalJson(value));
}

module.exports = {
  SAMPLING_ID,
  EvaluationIdError,
  sha256Hex,
  assertSha256Hex,
  stripOneLineTerminator,
  recordSha256,
  makeRecordUid,
  makeCellId,
  samplingKey,
  compareHexKeys,
  canonicalJson,
  canonicalSha256,
};
