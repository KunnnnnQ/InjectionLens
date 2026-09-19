// Tests for the Step 7 evaluation identifiers and provenance recording.
//
// Evidence: Wave A Lane 3 scope ("source revision and provenance recording",
// "stable seeded sampling", "proof of stable identifiers"). The invariant under
// test is that identity comes from bytes that are pinned by a hash, never from a
// file position or a re-serialisation, and that a provenance claim cannot look
// verified without evidence.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  sha256Hex,
  recordSha256,
  makeRecordUid,
  makeCellId,
  samplingKey,
  compareHexKeys,
  canonicalJson,
  canonicalSha256,
} = require('../eval/scripts/step7/ids');
const {
  parseJsonl,
  loadCorpusFile,
  createProvenanceRecord,
  assertPinned,
  provenanceSummary,
  isNetworkLocation,
  EvaluationInputError,
} = require('../eval/scripts/step7/corpus');

const LINE = '{"id":"x-0001","payload":"Fictional note for the assistant."}';

test('the record hash ignores the line terminator but nothing else', () => {
  assert.equal(recordSha256(LINE), recordSha256(`${LINE}\n`));
  assert.equal(recordSha256(LINE), recordSha256(`${LINE}\r\n`));
  assert.notEqual(recordSha256(LINE), recordSha256(`${LINE} `));
  assert.notEqual(recordSha256(LINE), recordSha256(LINE.replace('x-0001', 'x-0002')));
  assert.match(recordSha256(LINE), /^[0-9a-f]{64}$/);
});

test('a record uid is a readable pointer that starts with the record hash', () => {
  const hash = recordSha256(LINE);
  const uid = makeRecordUid({ sourceSlug: 'ipi-proxy-mit', lineNo: 7, recordSha256: hash });
  assert.equal(uid, `ipi-proxy-mit:L000007:${hash.slice(0, 12)}`);
  assert.throws(() => makeRecordUid({ sourceSlug: '', lineNo: 1, recordSha256: hash }), /sourceSlug is required/);
  assert.throws(() => makeRecordUid({ sourceSlug: 's', lineNo: 0, recordSha256: hash }), /positive integer/);
});

test('a cell id names every factor of one observation and rejects separators', () => {
  const id = makeCellId({
    recordUid: 'src:L000001:abcdef123456',
    transformId: 'T0-original',
    placementId: 'p-css-hidden',
    subRecipe: 'h-display-none',
    capability: 'summary-only',
  });
  assert.equal(id, 'src:L000001:abcdef123456|T0-original|p-css-hidden|h-display-none|summary-only');
  assert.equal(
    makeCellId({ recordUid: 'r', transformId: 't', placementId: 'p', capability: 'c' }),
    'r|t|p|c',
    'a placement without sub-recipes must not add an empty component',
  );
  assert.throws(
    () => makeCellId({ recordUid: 'r|x', transformId: 't', placementId: 'p', capability: 'c' }),
    /must not contain/,
  );
});

test('the sampling key depends on the seed and on the record bytes only', () => {
  const hash = recordSha256(LINE);
  const a = samplingKey({ seed: 'seed-a', recordSha256: hash });
  const b = samplingKey({ seed: 'seed-a', recordSha256: hash });
  const c = samplingKey({ seed: 'seed-b', recordSha256: hash });
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.throws(() => samplingKey({ seed: '', recordSha256: hash }), /no default seed/);
});

test('key ordering is a total order, so it cannot depend on input order', () => {
  const entries = [
    { key: 'aa', recordSha256: 'b', recordUid: 'u2' },
    { key: 'aa', recordSha256: 'a', recordUid: 'u3' },
    { key: 'ab', recordSha256: 'a', recordUid: 'u1' },
  ];
  const sorted = entries.slice().sort(compareHexKeys).map((e) => e.recordUid);
  assert.deepEqual(sorted, ['u3', 'u2', 'u1']);
});

test('canonical JSON does not depend on key order and refuses lossy values', () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] }), canonicalJson({ a: [2, { c: 3, d: 4 }], b: 1 }));
  assert.equal(canonicalJson({ a: 1 }), '{"a":1}');
  assert.equal(canonicalSha256({ a: 1 }), sha256Hex('{"a":1}'));
  assert.throws(() => canonicalJson({ a: undefined }), /undefined value/);
  assert.throws(() => canonicalJson({ a: Number.NaN }), /non-finite/);
});

test('parsing a corpus keeps line numbers, CRLF input and malformed lines', () => {
  const text = `${LINE}\r\n{"id":"broken"\r\n${LINE.replace('x-0001', 'x-0003')}\n`;
  const parsed = parseJsonl(text, { sourceSlug: 'demo' });
  assert.equal(parsed.records.length, 2);
  assert.equal(parsed.malformed.length, 1);
  assert.deepEqual(parsed.records.map((r) => r.line_no), [1, 3]);
  assert.equal(parsed.malformed[0].line_no, 2);
  assert.match(parsed.malformed[0].parse_error, /JSON/);
  assert.equal(parsed.records[0].record_uid.startsWith('demo:L000001:'), true);
  assert.equal(
    parsed.records[0].record_sha256,
    parseJsonl(text.replace(/\r\n/g, '\n'), { sourceSlug: 'demo' }).records[0].record_sha256,
    'CRLF and LF must produce the same record identity',
  );
});

test('the loader refuses network locations and reads local files by hash', () => {
  assert.equal(isNetworkLocation('https://example.com/corpus.jsonl'), true);
  assert.equal(isNetworkLocation('git@github.com:VulcanLab/IPI-Proxy.git'), true);
  assert.equal(isNetworkLocation('C:\\data\\unified.jsonl'), false);
  assert.throws(() => loadCorpusFile('https://example.com/unified.jsonl', { sourceSlug: 'x' }), EvaluationInputError);

  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'step7-corpus-'));
  const file = path.join(dir, 'tiny.jsonl');
  fs.writeFileSync(file, `${LINE}\n`, 'utf8');
  const corpus = loadCorpusFile(file, { sourceSlug: 'demo' });
  assert.equal(corpus.records.length, 1);
  assert.equal(corpus.file_bytes, Buffer.byteLength(`${LINE}\n`, 'utf8'));
  assert.equal(corpus.file_sha256, sha256Hex(Buffer.from(`${LINE}\n`, 'utf8')));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a provenance claim cannot be marked verified without evidence', () => {
  assert.throws(
    () => createProvenanceRecord({
      sourceSlug: 's',
      canonicalUrl: 'https://example.com/repo',
      archiveSha256: sha256Hex('x'),
      claimChecks: [{ claim: 'the licence is MIT', status: 'artifact-verified' }],
    }),
    /without evidence/,
  );

  const provenance = createProvenanceRecord({
    sourceSlug: 's',
    canonicalUrl: 'https://example.com/repo',
    revision: 'abc123',
    archiveSha256: sha256Hex('x'),
    archiveBytes: 1,
    sourceLicenseMap: { 'demo-source': { license: 'MIT', documented_in: 'README.md@abc123', status: 'claimed-only' } },
    claimChecks: [{ claim: 'the corpus is inert', status: 'artifact-verified', evidence: 'scan output' }],
  });
  assert.equal(provenance.claim_checks[0].status, 'artifact-verified');

  const summary = provenanceSummary(provenance);
  assert.equal(summary.verified_claims, 1);
  assert.deepEqual(
    summary.unresolved.map((entry) => entry.kind).sort(),
    ['repository_license', 'source_license'],
    'an unverified source mapping and a missing repository licence must both stay visible',
  );
});

test('an unpinned source cannot be sampled from', () => {
  const base = {
    sourceSlug: 's',
    canonicalUrl: 'https://example.com/repo',
    archiveSha256: sha256Hex('x'),
  };
  assert.throws(() => assertPinned(createProvenanceRecord(base)), /revision is required/);
  assert.throws(
    () => createProvenanceRecord({ ...base, archiveSha256: 'not-a-hash' }),
    /64-character lowercase hex/,
  );
});
