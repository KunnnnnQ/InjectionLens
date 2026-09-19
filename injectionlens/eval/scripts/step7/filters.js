// Step 7 evaluation utilities — filtering, with an explicit reason for every
// record that is dropped.
//
// Three passes run in a fixed order (licence, then safety, then relevance) and
// each excluded record gets exactly one primary reason code plus the list of
// other rules that would also have excluded it. Nothing is ever dropped
// silently: filterRecords() returns the ledger.
//
// Two design decisions worth stating out loud:
//
//   - A licence may be established either per record or per source, but a
//     source-level mapping only counts when its status is "artifact-verified" or
//     "upstream-verified". A mapping that is merely claimed is treated as
//     unclear, which is a deliberate fail-closed choice (AGENTS.md rule 7:
//     exclude non-commercial data; attribute external data).
//   - The safety pass is a declared-flag and string classifier. It does not run
//     anything and it does not judge intent. Destructive command *text* is
//     allowed by design (AGENTS.md rule 7 allows inert destructive strings in
//     fixtures); only real destinations, real personal data, declared malware
//     and declared abusive content are excluded.
'use strict';

const { findUnsafeTargets } = require('./targets');
const { canEmbed, PLACEMENT_IDS } = require('./placement');

const EXCLUSION_REASONS = Object.freeze({
  'EX-LIC-NC': 'non-commercial licence (CC-BY-NC family or any NonCommercial term)',
  'EX-LIC-ND': 'NoDerivatives term; the transformation matrix produces derived text',
  'EX-LIC-SA': 'ShareAlike term; policy excludes it by default so downstream artefacts keep their licence',
  'EX-LIC-UNKNOWN': 'no per-record licence and no verified source-level licence mapping',
  'EX-WASP': 'record originates from the WASP dataset, which the upstream repository documents as CC-BY-NC 4.0',
  'EX-IRRELEVANT-EMPTY': 'payload text is too short to plant',
  'EX-IRRELEVANT-PLACEHOLDER': 'payload contains template placeholders rather than text',
  'EX-IRRELEVANT-EMBED': 'payload cannot be embedded in any of the six declared placements without breaking the markup',
  'EX-IRRELEVANT-DUP': 'duplicate of an earlier record (assigned by the deduplication pass, not here)',
  'EX-UNSAFE-TARGET': 'payload contains a real destination (non-reserved URL, IP, mail address or wallet address)',
  'EX-UNSAFE-EXFIL': 'record metadata declares that an outbound callback is required',
  'EX-UNSAFE-CONTENT': 'record metadata declares abusive or real-person-targeted content',
  'EX-UNSAFE-CODE': 'record metadata declares executable malicious code rather than inert text',
});

const DEFAULT_POLICY = Object.freeze({
  payloadField: 'payload',
  licenseField: 'license',
  sourceField: 'source_benchmark',
  excludeShareAlike: true,
  waspSourceKeys: Object.freeze(['wasp']),
  contentFlagDenylist: Object.freeze([
    'csam',
    'sexual-minors',
    'harassment-target',
    'real-person-target',
    'weapons-acquisition',
    'drug-acquisition',
  ]),
  minPayloadChars: 8,
});

function resolvePolicy(policy = {}) {
  return { ...DEFAULT_POLICY, ...policy };
}

// ---------------------------------------------------------------------------
// Licence classification
// ---------------------------------------------------------------------------

const LICENSE_RULES = Object.freeze([
  { spdx: 'MIT', re: /^mit$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'Apache-2.0', re: /^apache(-2(\.0)?)?$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'BSD-3-Clause', re: /^bsd-3-clause$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'BSD-2-Clause', re: /^bsd-2-clause$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'ISC', re: /^isc$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'CC0-1.0', re: /^cc0(-1\.0)?$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'CC-BY-4.0', re: /^cc-by(-4\.0)?$/, commercial: true, derivatives: true, shareAlike: false },
  { spdx: 'CC-BY-SA-4.0', re: /^cc-by-sa(-4\.0)?$/, commercial: true, derivatives: true, shareAlike: true },
  { spdx: 'CC-BY-ND-4.0', re: /^cc-by-nd(-4\.0)?$/, commercial: true, derivatives: false, shareAlike: false },
  { spdx: 'CC-BY-NC-4.0', re: /^cc-by-nc(-4\.0)?$/, commercial: false, derivatives: true, shareAlike: false },
  { spdx: 'CC-BY-NC-SA-4.0', re: /^cc-by-nc-sa(-4\.0)?$/, commercial: false, derivatives: true, shareAlike: true },
  { spdx: 'CC-BY-NC-ND-4.0', re: /^cc-by-nc-nd(-4\.0)?$/, commercial: false, derivatives: false, shareAlike: false },
]);

function normalizeLicenseString(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/^the[\s-]+/, '')
    .replace(/[\s_]+/g, '-')
    .replace(/-?licen[cs]e$/, '')
    .replace(/^creativecommons\.org\/licen[cs]es\//, '')
    .replace(/\/$/, '');
}

/**
 * Classify one licence string. Unknown input is "unclear" and therefore
 * excluded: this harness never guesses that an unrecognised string means MIT.
 */
function classifyLicense(value) {
  const raw = value === null || value === undefined ? null : String(value);
  const normalized = normalizeLicenseString(raw);
  if (normalized === '') {
    return {
      raw,
      spdx: null,
      known: false,
      unclear: true,
      commercial: 'unknown',
      derivatives: 'unknown',
      shareAlike: 'unknown',
    };
  }
  for (const rule of LICENSE_RULES) {
    if (rule.re.test(normalized)) {
      return {
        raw,
        spdx: rule.spdx,
        known: true,
        unclear: false,
        commercial: rule.commercial,
        derivatives: rule.derivatives,
        shareAlike: rule.shareAlike,
      };
    }
  }
  return {
    raw,
    spdx: null,
    known: false,
    unclear: true,
    commercial: 'unknown',
    derivatives: 'unknown',
    shareAlike: 'unknown',
  };
}

// ---------------------------------------------------------------------------
// Licence pass
// ---------------------------------------------------------------------------

function isWaspRecord(value, policy) {
  const source = String(value?.[policy.sourceField] ?? '').toLowerCase();
  return policy.waspSourceKeys.some((key) => source === String(key).toLowerCase());
}

/**
 * Where does this record's licence come from?
 * order: per-record field, then a VERIFIED source-level mapping, then nothing.
 */
function resolveLicense(record, { policy = DEFAULT_POLICY, sourceLicenseMap = {} } = {}) {
  policy = resolvePolicy(policy);
  const value = record?.value ?? {};
  const perRecord = value[policy.licenseField];
  if (perRecord !== undefined && perRecord !== null && String(perRecord).trim() !== '') {
    return { origin: 'record', value: String(perRecord), documented_in: null, status: 'artifact-verified' };
  }
  const sourceKey = String(value[policy.sourceField] ?? '');
  const mapped = sourceLicenseMap[sourceKey];
  if (mapped) {
    return {
      origin: 'source-map',
      value: mapped.license,
      documented_in: mapped.documented_in,
      status: mapped.status ?? 'unverified',
    };
  }
  return { origin: 'absent', value: null, documented_in: null, status: 'unverified' };
}

function licenseDecision(record, { policy = DEFAULT_POLICY, sourceLicenseMap = {} } = {}) {
  policy = resolvePolicy(policy);
  const value = record?.value ?? {};
  const resolved = resolveLicense(record, { policy, sourceLicenseMap });
  const classification = classifyLicense(resolved.value);
  const verifiedMapping = resolved.origin === 'record'
    || ['artifact-verified', 'upstream-verified'].includes(resolved.status);
  const matched = [];

  if (isWaspRecord(value, policy)) {
    matched.push({
      code: 'EX-WASP',
      evidence_field: policy.sourceField,
      evidence_value: String(value[policy.sourceField] ?? ''),
    });
  }

  if (!classification.known || !verifiedMapping) {
    matched.push({
      code: 'EX-LIC-UNKNOWN',
      evidence_field: resolved.origin === 'record' ? policy.licenseField : `${policy.sourceField}->license`,
      evidence_value: `${resolved.value ?? 'absent'} (origin=${resolved.origin}, status=${resolved.status})`,
    });
  } else {
    if (classification.commercial !== true) {
      matched.push({
        code: 'EX-LIC-NC',
        evidence_field: resolved.origin === 'record' ? policy.licenseField : policy.sourceField,
        evidence_value: classification.spdx,
      });
    }
    if (classification.derivatives === false) {
      matched.push({ code: 'EX-LIC-ND', evidence_field: 'license', evidence_value: classification.spdx });
    }
    if (classification.shareAlike === true && policy.excludeShareAlike) {
      matched.push({ code: 'EX-LIC-SA', evidence_field: 'license', evidence_value: classification.spdx });
    }
  }

  const primary = matched[0] ?? null;
  // A WASP-provenanced record that carries a commercially usable licence is a
  // contradiction between two upstream statements, so it goes to a human instead
  // of being resolved by rule order.
  const contradiction = isWaspRecord(value, policy) && classification.known && classification.commercial === true;
  return {
    pass: 'license',
    decision: primary ? 'exclude' : 'include',
    reason_code: primary ? primary.code : null,
    also_matched: matched.slice(1),
    contradiction,
    evidence_field: primary ? primary.evidence_field : (resolved.origin === 'record' ? policy.licenseField : policy.sourceField),
    evidence_value: primary ? primary.evidence_value : (classification.spdx ?? 'n/a'),
    decided_by: primary ? `rule:${primary.code}` : 'rule:license-include',
    license: {
      origin: resolved.origin,
      status: resolved.status,
      documented_in: resolved.documented_in,
      spdx: classification.spdx,
      commercial: classification.commercial,
      derivatives: classification.derivatives,
      share_alike: classification.shareAlike,
      unclear: classification.unclear,
    },
  };
}

// ---------------------------------------------------------------------------
// Safety pass
// ---------------------------------------------------------------------------

function safetyDecision(record, { policy = DEFAULT_POLICY } = {}) {
  policy = resolvePolicy(policy);
  const value = record?.value ?? {};
  const payload = String(value[policy.payloadField] ?? '');
  const targets = findUnsafeTargets(payload);
  if (targets.length > 0) {
    return {
      pass: 'safety',
      decision: 'exclude',
      reason_code: 'EX-UNSAFE-TARGET',
      also_matched: [],
      evidence_field: policy.payloadField,
      evidence_value: targets.map((t) => `${t.kind}:${t.match}`).join(', ').slice(0, 200),
      decided_by: 'rule:EX-UNSAFE-TARGET',
      targets,
    };
  }

  if (value.requires_network === true || value.callback_url) {
    return {
      pass: 'safety',
      decision: 'exclude',
      reason_code: 'EX-UNSAFE-EXFIL',
      also_matched: [],
      evidence_field: value.callback_url ? 'callback_url' : 'requires_network',
      evidence_value: String(value.callback_url ?? value.requires_network),
      decided_by: 'rule:EX-UNSAFE-EXFIL',
    };
  }

  if (value.contains_executable === true) {
    return {
      pass: 'safety',
      decision: 'exclude',
      reason_code: 'EX-UNSAFE-CODE',
      also_matched: [],
      evidence_field: 'contains_executable',
      evidence_value: 'true',
      decided_by: 'rule:EX-UNSAFE-CODE',
    };
  }

  const flags = Array.isArray(value.content_flags) ? value.content_flags.map((f) => String(f).toLowerCase()) : [];
  const hit = flags.find((flag) => policy.contentFlagDenylist.includes(flag));
  if (hit || value.targets_real_person === true) {
    return {
      pass: 'safety',
      decision: 'exclude',
      reason_code: 'EX-UNSAFE-CONTENT',
      also_matched: [],
      evidence_field: hit ? 'content_flags' : 'targets_real_person',
      evidence_value: hit || 'true',
      decided_by: 'rule:EX-UNSAFE-CONTENT',
    };
  }

  return {
    pass: 'safety',
    decision: 'include',
    reason_code: null,
    also_matched: [],
    evidence_field: null,
    evidence_value: null,
    decided_by: 'rule:safety-include',
  };
}

// ---------------------------------------------------------------------------
// Relevance pass
// ---------------------------------------------------------------------------

const PLACEHOLDER_PATTERNS = Object.freeze([
  /\{[A-Z_][A-Z0-9_]{2,}\}/,
  /\{\{[^}]{1,60}\}\}/,
  /<\s*INSERT\b/i,
  /<\s*PLACEHOLDER\b/i,
  /\bTODO\b/,
]);

function relevanceDecision(record, { policy = DEFAULT_POLICY, placements = PLACEMENT_IDS } = {}) {
  policy = resolvePolicy(policy);
  const value = record?.value ?? {};
  const payload = String(value[policy.payloadField] ?? '');

  if (payload.trim().length < policy.minPayloadChars) {
    return {
      pass: 'relevance',
      decision: 'exclude',
      reason_code: 'EX-IRRELEVANT-EMPTY',
      also_matched: [],
      evidence_field: policy.payloadField,
      evidence_value: `${payload.trim().length} characters`,
      decided_by: 'rule:EX-IRRELEVANT-EMPTY',
    };
  }

  const placeholder = PLACEHOLDER_PATTERNS.find((re) => re.test(payload));
  if (placeholder) {
    return {
      pass: 'relevance',
      decision: 'exclude',
      reason_code: 'EX-IRRELEVANT-PLACEHOLDER',
      also_matched: [],
      evidence_field: policy.payloadField,
      evidence_value: payload.slice(0, 80),
      decided_by: 'rule:EX-IRRELEVANT-PLACEHOLDER',
    };
  }

  const embeddable = placements.filter((placementId) => canEmbed(placementId, payload));
  if (embeddable.length === 0) {
    return {
      pass: 'relevance',
      decision: 'exclude',
      reason_code: 'EX-IRRELEVANT-EMBED',
      also_matched: [],
      evidence_field: policy.payloadField,
      evidence_value: payload.slice(0, 80),
      decided_by: 'rule:EX-IRRELEVANT-EMBED',
    };
  }

  return {
    pass: 'relevance',
    decision: 'include',
    reason_code: null,
    also_matched: [],
    evidence_field: null,
    evidence_value: null,
    decided_by: 'rule:relevance-include',
    embeddable_placements: embeddable,
  };
}

// ---------------------------------------------------------------------------
// The three passes, in order, with a ledger
// ---------------------------------------------------------------------------

function assignRecord(record, { policy = DEFAULT_POLICY, sourceLicenseMap = {}, placements = PLACEMENT_IDS } = {}) {
  policy = resolvePolicy(policy);
  const passes = [
    licenseDecision(record, { policy, sourceLicenseMap }),
    safetyDecision(record, { policy }),
    relevanceDecision(record, { policy, placements }),
  ];
  const excluded = passes.filter((p) => p.decision === 'exclude');
  const primary = excluded[0] ?? null;
  return {
    record_uid: record.record_uid,
    record_sha256: record.record_sha256,
    line_no: record.line_no,
    decision: primary ? 'exclude' : 'include',
    reason_code: primary ? primary.reason_code : null,
    reason: primary ? EXCLUSION_REASONS[primary.reason_code] : null,
    decided_by: primary ? primary.decided_by : 'rule:include',
    evidence_field: primary ? primary.evidence_field : null,
    evidence_value: primary ? primary.evidence_value : null,
    also_excluded_by: excluded.slice(1).map((p) => p.reason_code),
    review_required: passes[0].contradiction === true,
    passes,
  };
}

/**
 * Filter a parsed corpus. Returns the included records and the full ledger.
 *
 * @param {Array<{record_uid: string, record_sha256: string, line_no: number, value: object}>} records
 */
function filterRecords(records, options = {}) {
  if (!Array.isArray(records)) throw new Error('filterRecords expects an array of parsed records');
  const included = [];
  const excluded = [];
  const reviewQueue = [];
  const countsByReason = {};

  for (const record of records) {
    const assignment = assignRecord(record, options);
    if (assignment.decision === 'include') {
      included.push(record);
      continue;
    }
    countsByReason[assignment.reason_code] = (countsByReason[assignment.reason_code] || 0) + 1;
    const ledgerEntry = {
      record_uid: assignment.record_uid,
      record_sha256: assignment.record_sha256,
      line_no: assignment.line_no,
      reason_code: assignment.reason_code,
      reason: assignment.reason,
      evidence_field: assignment.evidence_field,
      evidence_value: assignment.evidence_value,
      also_excluded_by: assignment.also_excluded_by,
      decided_by: assignment.decided_by,
      decided_at: null,
    };
    excluded.push(ledgerEntry);
    if (assignment.review_required) reviewQueue.push({ ...ledgerEntry, review_reason: 'WASP provenance contradicts an otherwise permissive licence' });
  }

  return {
    included,
    excluded,
    review_queue: reviewQueue,
    counts_by_reason: countsByReason,
    counts: { total: records.length, included: included.length, excluded: excluded.length },
  };
}

module.exports = {
  EXCLUSION_REASONS,
  DEFAULT_POLICY,
  LICENSE_RULES,
  PLACEHOLDER_PATTERNS,
  resolvePolicy,
  normalizeLicenseString,
  classifyLicense,
  resolveLicense,
  isWaspRecord,
  licenseDecision,
  safetyDecision,
  relevanceDecision,
  assignRecord,
  filterRecords,
};
