// Step 7 evaluation utilities — corpus loading and provenance recording.
//
// Two rules shape this module:
//
//   1. The harness reads a local file and nothing else. loadCorpusFile() refuses
//      anything that looks like a network location, so a run cannot silently
//      depend on the network. Retrieval is a separate, human-recorded act.
//   2. A provenance record carries claims with an explicit verification status.
//      A claim may not be marked "verified" without evidence, and an unpinned
//      source (no revision, no archive hash) is refused by assertPinned().
//
// The upstream licence facts for VulcanLab/IPI-Proxy that were inspected for
// this lane are recorded in injectionlens/eval/README.md; they live there as
// prose on purpose, because a licence fact is only useful with its evidence.
'use strict';

const fs = require('node:fs');
const { sha256Hex, recordSha256, makeRecordUid, assertSha256Hex } = require('./ids');

// The vocabulary from the Step 5 evidence record (eval/results/stage4-ua-sources.txt).
const CLAIM_STATUS = Object.freeze([
  'artifact-verified',
  'upstream-verified',
  'claimed-only',
  'unverified',
]);

const VERIFIED_STATUSES = Object.freeze(['artifact-verified', 'upstream-verified']);

class EvaluationInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EvaluationInputError';
  }
}

function isNetworkLocation(target) {
  if (typeof target !== 'string') return false;
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(target)
    || /^git@/i.test(target)
    || /^\\\\/.test(target);
}

/**
 * Parse a JSONL corpus into records addressed by their own bytes.
 * Malformed lines are kept as evidence instead of being dropped silently.
 */
function parseJsonl(text, { sourceSlug } = {}) {
  if (typeof text !== 'string') throw new EvaluationInputError('parseJsonl expects the file contents as a string');
  if (typeof sourceSlug !== 'string' || sourceSlug.trim() === '') {
    throw new EvaluationInputError('sourceSlug is required');
  }

  // Split on CRLF or LF so the record hash never depends on the line ending.
  const lines = text.split(/\r?\n/);
  const records = [];
  const malformed = [];

  lines.forEach((raw, index) => {
    const lineNo = index + 1;
    if (raw.trim() === '') return;
    const hash = recordSha256(raw);
    let value = null;
    let parseError = null;
    try {
      value = JSON.parse(raw);
    } catch (err) {
      parseError = String(err.message || err);
    }
    const entry = {
      line_no: lineNo,
      raw,
      record_sha256: hash,
      record_uid: makeRecordUid({ sourceSlug, lineNo, recordSha256: hash }),
      value,
    };
    if (parseError) {
      malformed.push({ ...entry, parse_error: parseError });
    } else {
      records.push(entry);
    }
  });

  return { records, malformed, line_count: lines.length };
}

/** Read a pinned local corpus file. Never a URL, never a UNC path. */
function loadCorpusFile(filePath, { sourceSlug } = {}) {
  if (isNetworkLocation(filePath)) {
    throw new EvaluationInputError(
      `refusing to read ${JSON.stringify(filePath)}: the harness reads pinned local files only `
      + '(retrieve upstream material separately, into injectionlens/eval/tmp/, and record its hash)',
    );
  }
  const buffer = fs.readFileSync(filePath);
  const text = buffer.toString('utf8');
  return {
    source_slug: sourceSlug,
    file_path: filePath,
    file_sha256: sha256Hex(buffer),
    file_bytes: buffer.length,
    ...parseJsonl(text, { sourceSlug }),
  };
}

function assertClaimShape(claim, index) {
  const at = `claim_checks[${index}]`;
  if (!claim || typeof claim !== 'object') throw new EvaluationInputError(`${at} must be an object`);
  if (typeof claim.claim !== 'string' || claim.claim.trim() === '') {
    throw new EvaluationInputError(`${at}.claim is required`);
  }
  if (!CLAIM_STATUS.includes(claim.status)) {
    throw new EvaluationInputError(`${at}.status must be one of ${CLAIM_STATUS.join(', ')}`);
  }
  if (VERIFIED_STATUSES.includes(claim.status) && (typeof claim.evidence !== 'string' || claim.evidence.trim() === '')) {
    throw new EvaluationInputError(
      `${at} is marked "${claim.status}" without evidence; a verified claim must name the artifact or upstream file it was read from`,
    );
  }
}

/**
 * Build a provenance record. Every optional claim defaults to "unverified":
 * silence is never treated as confirmation.
 *
 * @param {object} input
 * @param {string} input.sourceSlug
 * @param {string} input.canonicalUrl       repository or dataset URL
 * @param {string} input.revision           exact inspected revision (commit SHA or release id)
 * @param {string} input.archiveSha256      SHA-256 of the exact file the harness reads
 * @param {number} [input.archiveBytes]
 * @param {string} [input.retrievedAtUtc]
 * @param {string} [input.retrievedBy]
 * @param {Array<{path: string, sha256?: string, first_line?: string}>} [input.licenseFiles]
 * @param {string|null} [input.repositoryLicenseDetected]
 * @param {Record<string, {license: string, documented_in: string, status?: string}>} [input.sourceLicenseMap]
 * @param {Array<{claim: string, status?: string, evidence?: string}>} [input.claimChecks]
 */
function createProvenanceRecord(input = {}) {
  const {
    sourceSlug,
    canonicalUrl,
    revision,
    archiveSha256,
    archiveBytes,
    retrievedAtUtc = null,
    retrievedBy = null,
    licenseFiles = [],
    repositoryLicenseDetected = null,
    sourceLicenseMap = {},
    claimChecks = [],
    notes = [],
  } = input;

  if (typeof sourceSlug !== 'string' || sourceSlug.trim() === '') {
    throw new EvaluationInputError('sourceSlug is required');
  }
  if (typeof canonicalUrl !== 'string' || canonicalUrl.trim() === '') {
    throw new EvaluationInputError('canonicalUrl is required');
  }
  assertSha256Hex(archiveSha256, 'archiveSha256');

  const map = {};
  for (const [key, entry] of Object.entries(sourceLicenseMap)) {
    if (!entry || typeof entry.license !== 'string' || entry.license.trim() === '') {
      throw new EvaluationInputError(`sourceLicenseMap["${key}"].license is required`);
    }
    if (typeof entry.documented_in !== 'string' || entry.documented_in.trim() === '') {
      throw new EvaluationInputError(`sourceLicenseMap["${key}"].documented_in is required`);
    }
    const status = entry.status ?? 'unverified';
    if (!CLAIM_STATUS.includes(status)) {
      throw new EvaluationInputError(`sourceLicenseMap["${key}"].status must be one of ${CLAIM_STATUS.join(', ')}`);
    }
    map[key] = { license: entry.license, documented_in: entry.documented_in, status };
  }

  const claims = claimChecks.map((claim, index) => {
    const normalized = { claim: claim.claim, status: claim.status ?? 'unverified', evidence: claim.evidence ?? null };
    assertClaimShape(normalized, index);
    return normalized;
  });

  return {
    source_slug: sourceSlug,
    canonical_url: canonicalUrl,
    revision: revision ?? null,
    archive_sha256: archiveSha256,
    archive_bytes: Number.isInteger(archiveBytes) ? archiveBytes : null,
    retrieved_at_utc: retrievedAtUtc,
    retrieved_by: retrievedBy,
    license_files: licenseFiles.map((file) => ({
      path: file.path,
      sha256: file.sha256 ?? null,
      first_line: file.first_line ?? null,
    })),
    repository_license_detected: repositoryLicenseDetected,
    source_license_map: map,
    claim_checks: claims,
    notes: notes.slice(),
  };
}

/** Refuse to sample from a source that is not pinned to a revision and a hash. */
function assertPinned(provenance) {
  if (!provenance || typeof provenance !== 'object') {
    throw new EvaluationInputError('a provenance record is required before sampling');
  }
  if (typeof provenance.revision !== 'string' || provenance.revision.trim() === '') {
    throw new EvaluationInputError('provenance.revision is required: record the exact inspected revision');
  }
  assertSha256Hex(provenance.archive_sha256, 'provenance.archive_sha256');
  return provenance;
}

function provenanceSummary(provenance) {
  assertPinned(provenance);
  const unresolved = [];
  for (const claim of provenance.claim_checks) {
    if (!VERIFIED_STATUSES.includes(claim.status)) unresolved.push({ kind: 'claim', claim: claim.claim, status: claim.status });
  }
  for (const [key, entry] of Object.entries(provenance.source_license_map)) {
    if (!VERIFIED_STATUSES.includes(entry.status)) {
      unresolved.push({ kind: 'source_license', source: key, license: entry.license, status: entry.status });
    }
  }
  if (!provenance.repository_license_detected) {
    unresolved.push({ kind: 'repository_license', detail: 'no repository-level licence was detected at the inspected revision' });
  }
  return {
    source_slug: provenance.source_slug,
    canonical_url: provenance.canonical_url,
    revision: provenance.revision,
    archive_sha256: provenance.archive_sha256,
    verified_claims: provenance.claim_checks.filter((c) => VERIFIED_STATUSES.includes(c.status)).length,
    total_claims: provenance.claim_checks.length,
    unresolved,
  };
}

module.exports = {
  CLAIM_STATUS,
  VERIFIED_STATUSES,
  EvaluationInputError,
  isNetworkLocation,
  parseJsonl,
  loadCorpusFile,
  createProvenanceRecord,
  assertPinned,
  provenanceSummary,
};
