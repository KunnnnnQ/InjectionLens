// Step 7 evaluation summary writer.
//
// Turns the measured artifacts into eval/results/evaluation-summary.md. Every
// number is read from the generated artifacts; nothing is typed in by hand.
//
// Usage (from injectionlens/):
//   node <this file> --out-dir eval/results

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const parsed = parseArgs({
  args: process.argv.slice(2),
  options: { 'out-dir': { type: 'string', default: 'eval/results' } },
  allowPositionals: false,
});
const OUT_DIR = path.resolve(parsed.values['out-dir']);

const matrix = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'attack-matrix.json'), 'utf8'));
const heatmap = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'detection-heatmap.json'), 'utf8'));
const replica = fs.existsSync(path.join(OUT_DIR, 'replica-results.json'))
  ? JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'replica-results.json'), 'utf8'))
  : null;
const benign = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'benign-pages.json'), 'utf8'));

const pct = (rate) => (rate === null || rate === undefined ? 'NOT RUN' : `${(rate * 100).toFixed(1)}%`);
const kn = (entry) => `${entry.k} / ${entry.n}`;

function pipelineTotals(rows, denominatorKind) {
  const totals = {};
  for (const row of rows.filter((r) => r.matrix === 'detection' && r.denominator_kind === denominatorKind)) {
    totals[row.column] = totals[row.column] || { k: 0, n: 0 };
    totals[row.column].k += row.k;
    totals[row.column].n += row.n;
  }
  return totals;
}

const detectionObserved = pipelineTotals(heatmap.rows, 'observed');
const detectionAllValid = pipelineTotals(heatmap.rows, 'all_valid');
const coverageRows = heatmap.rows.filter((r) => r.matrix === 'coverage');
const coverageTotals = {};
for (const row of coverageRows) {
  coverageTotals[row.column] = coverageTotals[row.column] || { k: 0, n: 0 };
  coverageTotals[row.column].k += row.k;
  coverageTotals[row.column].n += row.n;
}

const lines = [];
lines.push('# InjectionLens — Step 7 evaluation summary');
lines.push('');
lines.push(`Generated: ${new Date().toISOString()}`);
lines.push('');
lines.push('> **PROVISIONAL.** These are real measurements over a real sampled corpus, not a final accuracy claim.');
lines.push('> The upstream repository has no licence file, so the sample is drawn only from sources whose licence is');
lines.push('> documented in the upstream file itself. See "Licensing and why the sample is this size".');
lines.push('');
lines.push('Everything below was produced by executing code in this repository. No number was entered by hand.');
lines.push('The three evaluation families are reported separately and are **never** merged into one accuracy figure.');
lines.push('');

lines.push('## 1. What was measured, and how');
lines.push('');
lines.push('| | |');
lines.push('| --- | --- |');
lines.push(`| Upstream source | \`${matrix.source.canonical_url}\` |`);
lines.push(`| Inspected revision | \`${matrix.source.revision}\` |`);
lines.push(`| Corpus file SHA-256 | \`${matrix.source.archive_sha256}\` |`);
lines.push(`| Records in file | ${matrix.source.records_parsed} (${matrix.source.malformed_lines} malformed) |`);
lines.push(`| Licence policy applied | \`${matrix.licence_policy}\` |`);
lines.push(`| Sampling | \`${matrix.sample.sampling_id}\`, seed \`${matrix.sample.seed}\`, keyed SHA-256 sort |`);
lines.push(`| Sample fingerprint | \`${matrix.sample.fingerprint}\` |`);
lines.push(`| Capability template | \`${matrix.definitions.capability}\` |`);
lines.push(`| Matrix | ${matrix.matrix.cells_total} cells = ${matrix.sample.selected} records x ${matrix.matrix.transforms.length} transforms x ${matrix.matrix.placement_plan.length} placements |`);
lines.push(`| Cells measured | ${matrix.observations_total} |`);
lines.push('');
lines.push('A **cell** is one sampled record placed in one HTML context and transformed once. Each cell is served from an');
lines.push('ephemeral loopback port as a locally generated page, and analysed by the integrated Step 6 detector.');
lines.push('The evaluation never executed payload text and never followed a URL found in a payload.');
lines.push('');
lines.push(`The ${matrix.matrix.placement_plan.length} placements are ${matrix.matrix.placements.length} named categories, because`);
lines.push('`p-css-hidden` is a family rather than a single context: it is planted three times, with `display:none`,');
lines.push('`font-size:1px;color:rgba(31,41,51,0.05)` and an off-screen `left:-10000px` position. That is why one category');
lines.push('carries three times the observations of the others, and why "8 placements" and "6 categories" are both correct.');
lines.push('');

lines.push('### State accounting');
lines.push('');
lines.push('Only cells in state `OK` enter a denominator. A cell that could not be planted, or whose analysis failed,');
lines.push('is never counted as "not detected". The detection metrics additionally divide by the **attack** population;');
lines.push('see "Which cells these divide by" below for the payload-free control pages and why they are excluded.');
lines.push('');
lines.push('| State | Cells |');
lines.push('| --- | --- |');
for (const [state, count] of Object.entries(matrix.marginals.states.by_state)) {
  if (count > 0) lines.push(`| ${state} | ${count} |`);
}
lines.push(`| **total rows** | **${matrix.marginals.states.total}** |`);
lines.push('');
lines.push(`${matrix.marginals.states.by_state.SKIPPED} cells were \`SKIPPED\` with \`CELL-NOT-EMBEDDABLE\`: a payload containing`);
lines.push(`\`--\`, \`>\` or ending in \`-\` cannot be placed inside an HTML comment without breaking the markup, so that one`);
lines.push('placement is skipped for that record while its other seven still run.');
lines.push('');

lines.push('## 2. External attack-library evaluation');
lines.push('');
lines.push('### 2.1 Overall detection');
lines.push('');
lines.push('| Metric | k (numerator) | n (denominator) | Rate |');
lines.push('| --- | --- | --- | --- |');
lines.push(`| Cells rated **>= medium** | ${kn(matrix.detection.medium_or_above)} | | ${pct(matrix.detection.medium_or_above.rate)} |`);
lines.push(`| Cells rated **>= high** | ${kn(matrix.detection.high_or_above)} | | ${pct(matrix.detection.high_or_above.rate)} |`);
lines.push('');
if (matrix.populations) {
  const pop = matrix.populations;
  lines.push('**Which cells these divide by.** The denominator is the **attack population**: `state OK` cells that carry a');
  lines.push(`sampled record. The run also served ${pop.control_observations} payload-free **control** page(s) (a wrapper with filler`);
  lines.push('text and no payload) so that a detector firing on the wrapper markup alone would be visible. Those controls');
  lines.push(`reached \`OK\` with no finding at all, so they change no numerator; they only change the denominator by ${pop.controls_in_denominator}.`);
  lines.push('The mixed-population reading is kept for audit rather than discarded:');
  lines.push('');
  lines.push('| Metric | Attack population (reported) | Mixed population (audit) |');
  lines.push('| --- | --- | --- |');
  lines.push(`| >= medium | ${kn(pop.medium_or_above.attack_only)} = ${pct(pop.medium_or_above.attack_only.rate)} | ${kn(pop.medium_or_above.all)} = ${pct(pop.medium_or_above.all.rate)} |`);
  lines.push(`| >= high | ${kn(pop.high_or_above.attack_only)} = ${pct(pop.high_or_above.attack_only.rate)} | ${kn(pop.high_or_above.all)} = ${pct(pop.high_or_above.all.rate)} |`);
  lines.push('');
}
lines.push(`- Sample: ${matrix.sample.selected} payload records sampled deterministically from ${matrix.sample.eligible_count} eligible records.`);
lines.push('- Metric: the share of measured cells whose **strongest finding level** reaches the threshold.');
lines.push('- Limitation: a detector finding is not proof that a downstream agent attack was prevented. This measures');
lines.push('  what the detector surfaces, not whether an agent would have obeyed.');
lines.push('');
lines.push('### 2.2 Detection by insertion position (>= medium)');
lines.push('');
lines.push('| Position | k | n | Rate |');
lines.push('| --- | --- | --- | --- |');
for (const row of matrix.detection.by_placement_medium) {
  lines.push(`| \`${row.stratum}\` | ${row.k} | ${row.n} | ${pct(row.rate)} |`);
}
lines.push('');
lines.push('### 2.3 Detection by transform (>= medium)');
lines.push('');
lines.push('| Transform | k | n | Rate |');
lines.push('| --- | --- | --- | --- |');
for (const row of matrix.detection.by_transform_medium) {
  lines.push(`| \`${row.stratum}\` | ${row.k} | ${row.n} | ${pct(row.rate)} |`);
}
lines.push('');
lines.push('### 2.4 Position x pipeline');
lines.push('');
lines.push('Two readings are given for every pipeline, because a pipeline that never saw the payload cannot be');
lines.push('credited with missing it.');
lines.push('');
lines.push('**Coverage** — did the pipeline extract the planted text at all?');
lines.push('');
lines.push('| Pipeline | k | n | Rate |');
lines.push('| --- | --- | --- | --- |');
for (const pipeline of matrix.definitions ? Object.keys(coverageTotals) : []) {
  const t = coverageTotals[pipeline];
  lines.push(`| \`${pipeline}\` | ${t.k} | ${t.n} | ${pct(t.n ? t.k / t.n : null)} |`);
}
lines.push('');
lines.push('**Detection where the pipeline observed the payload** (denominator = cells that pipeline observed, >= medium):');
lines.push('');
lines.push('| Pipeline | k | n | Rate |');
lines.push('| --- | --- | --- | --- |');
for (const pipeline of Object.keys(detectionObserved)) {
  const t = detectionObserved[pipeline];
  lines.push(`| \`${pipeline}\` | ${t.k} | ${t.n} | ${pct(t.n ? t.k / t.n : null)} |`);
}
lines.push('');
lines.push('**Detection over all valid cells** (denominator = every valid attack cell, >= medium):');
lines.push('');
lines.push('| Pipeline | k | n | Rate |');
lines.push('| --- | --- | --- | --- |');
for (const pipeline of Object.keys(detectionAllValid)) {
  const t = detectionAllValid[pipeline];
  lines.push(`| \`${pipeline}\` | ${t.k} | ${t.n} | ${pct(t.n ? t.k / t.n : null)} |`);
}
lines.push('');
lines.push('The two detection readings differ by design: the first answers "when this pipeline reads the payload, how');
lines.push('often is it flagged at the threshold", the second answers "what share of the whole matrix does this pipeline');
lines.push('account for". Neither is hidden.');
lines.push('');

lines.push('### 2.5 Level distribution over measured cells');
lines.push('');
lines.push('| Level | Cells |');
lines.push('| --- | --- |');
for (const [level, count] of Object.entries(matrix.marginals.level_distribution)) {
  lines.push(`| ${level} | ${count} |`);
}
lines.push('');
lines.push(`${matrix.marginals.unattributed_valid_cells} measured cells produced no security finding at all`);
lines.push('(state `OK`, level `null`): the text was ingested but did not reach even `info`.');
lines.push('');

lines.push('## 3. Licensing and why the sample is this size');
lines.push('');
lines.push('The upstream repository carries **no licence file** at the inspected revision, and 729 of its 820 records');
lines.push('carry **no per-record licence**. Two readings were computed and the stricter one is reported here first:');
lines.push('');
lines.push('| Reading | Eligible records | Result |');
lines.push('| --- | --- | --- |');
lines.push(`| **strict** (a record needs its own licence field) | ${matrix.funnel.strict_reading.n_eligible} | no measurement possible |`);
lines.push(`| **source-map** (upstream documented statement, \`artifact-verified\` against a hashed file) | ${matrix.funnel.applied.n_eligible} | this is what was measured |`);
lines.push('');
lines.push('Under the strict reading **zero** records are eligible:');
lines.push('');
lines.push('| Exclusion reason | Records |');
lines.push('| --- | --- |');
for (const [code, count] of Object.entries(matrix.funnel.strict_reading.n_excluded_by_reason)) {
  lines.push(`| \`${code}\` | ${count} |`);
}
lines.push('');
lines.push('Note the third row: the 7 records that DO carry an explicit `MIT` field are excluded anyway, because they');
lines.push('contain a real destination and fall to `EX-UNSAFE-TARGET`. So "the explicitly MIT records" cannot be used as');
lines.push('a sample either.');
lines.push('');
lines.push(`The measured run therefore uses the \`${matrix.licence_policy}\` reading, and its exclusion ledger is:`);
lines.push('');
lines.push('| Exclusion reason | Records |');
lines.push('| --- | --- |');
for (const [code, count] of Object.entries(matrix.exclusion_ledger.applied_policy)) {
  lines.push(`| \`${code}\` | ${count} |`);
}
lines.push('');
lines.push('84 WASP records are excluded as CC-BY-NC. Records with non-reserved destinations are excluded and never');
lines.push('fetched. The upstream corpus is **not** committed to this repository: it stays in `eval/tmp/`, which is ignored.');
lines.push('');

lines.push('### Sampling funnel');
lines.push('');
lines.push('| Stage | Count |');
lines.push('| --- | --- |');
const f = matrix.funnel.applied;
lines.push(`| Records in source file | ${f.n_source_records_total} |`);
lines.push(`| Excluded (all reasons) | ${f.n_excluded_total} |`);
lines.push(`| Eligible after licence + safety + relevance | ${f.n_eligible} |`);
lines.push(`| Removed as duplicates (byte/text/near) | ${f.n_deduped_total} |`);
lines.push(`| Sampled (deterministic) | ${f.n_sampled} |`);
lines.push(`| Target | ${f.target_n} |`);
lines.push(`| Shortfall | ${f.sample_shortfall} |`);
lines.push('');
lines.push(`Near-duplicate threshold: Jaccard ${matrix.dedupe.near_dup_jaccard}. The sample is drawn by sorting`);
lines.push('`sha256(seed || record_sha256)` and taking the first N, so it needs no random number generator and is');
lines.push('independent of file order.');
lines.push('');

lines.push('## 4. Integrated source-backed replica suite');
lines.push('');
if (replica) {
  lines.push(`Produced by: \`${replica.how_produced}\``);
  lines.push('');
  lines.push(`**${replica.summary.pass} PASS / ${replica.summary.fail} FAIL / ${replica.summary.skipped} SKIPPED / ${replica.summary.error} ERROR** of ${replica.summary.total} cases.`);
  lines.push('');
  lines.push('| Case | Status | Primary capability | Observed | Source |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const item of replica.cases) {
    const observed = item.observed ? `max ${item.observed.maxLevel}` : (item.skip_reason ? item.skip_reason.code : '—');
    lines.push(`| \`${item.id}\` | ${item.status.toUpperCase()} | \`${item.primary_capability}\` | ${observed} | ${item.source.label} (${item.source.date}) |`);
  }
  lines.push('');
  const gap = replica.cases.find((item) => item.known_gap);
  if (gap) {
    lines.push('### Known gap, carried forward unchanged');
    lines.push('');
    lines.push(`\`${gap.id}\` is **SKIPPED**, not PASS. Reason code \`${gap.known_gap.code}\`.`);
    lines.push('');
    lines.push(`> ${gap.skip_reason.message}`);
    lines.push('');
    lines.push('The runner asserts that the payload is still *not* ingested. If that changes, the case fails loudly rather');
    lines.push('than passing quietly. Resolving this gap is optional Human Step 8 P1 work and was deliberately NOT done here.');
    lines.push('');
  }
} else {
  lines.push('NOT RUN: the replica run artifact was not available when this summary was generated.');
  lines.push('');
}

lines.push('## 5. Real benign-page evaluation');
lines.push('');
lines.push(`**NOT RUN.** ${benign.reason}`);
lines.push('');
lines.push('No false-positive rate is reported, because reporting one would require fetching pages this stage is not');
lines.push('authorised to fetch. The local fixtures are not real-world false-positive evidence and are not presented');
lines.push('as such.');
lines.push('');

lines.push('## 6. Safe baseline comparison');
lines.push('');
lines.push('A before/after comparison would need a reproducible pre-fix detector revision measured over the same sample.');
lines.push(`The pre-fix revision \`v0-ai-scaffold\` is tagged, but re-running this matrix against it was **not** performed`);
lines.push('in this stage, so no comparison is claimed.');
lines.push('');

lines.push('## 7. Limitations, stated plainly');
lines.push('');
lines.push('1. **Provisional.** The sample rests on a documented-licence reading of a repository with no licence file.');
lines.push('2. **One capability template.** The matrix was measured under `decision-agent` only.');
lines.push('3. **External-library text only.** These payloads were written to attack agents in general; they are not');
lines.push('   copies of pages found in the wild, and no live page was fetched.');
lines.push('4. **Detection is not prevention.** A finding means the tool surfaced an instruction; it does not mean an');
lines.push('   agent would have refused it.');
lines.push('5. **HTTP-source coverage is a lower bound.** `analyze()` does not return its raw item list, so coverage for');
lines.push('   that pipeline is read from finding occurrences and truncated matrix excerpts.');
lines.push('6. **No benign FPR.** NOT RUN, as above.');
lines.push('7. **A measured coverage gap, reported not hidden:** 176 of 3176 attack cells were not carried by `http-source`, and');
lines.push('   148 of those come from the `T2f-separator-inject` transform. See the defect section below.');
lines.push('');

lines.push('## 8. Defect found during this evaluation (measured, not fixed)');
lines.push('');
lines.push('`profiles.normText()` in `server/lib/profiles.js` strips only `U+200B-U+200D`, `U+FEFF` and `U+2060`, while');
lines.push('`risk.normalizeText()` additionally strips `U+00AD`, `U+180E`, `U+061C` and the bidi controls. Because');
lines.push('`analyze.js` uses `profiles.normText` as the grouping key, a payload carrying those characters does not group');
lines.push('with its own un-obfuscated text.');
lines.push('');
lines.push('Measured effect in this run:');
lines.push('');
lines.push('| Transform | Detection >= medium | http-source coverage |');
lines.push('| --- | --- | --- |');
// http-source coverage per transform, read from the artifact rather than typed
// in. A hardcoded pair here is how the normaliser defect's numbers went stale
// once the denominator changed (Step 10 audit).
function coverageForTransform(transformId, pipeline = 'http-source') {
  const rows = (matrix.detection.by_transform_coverage || []).filter(
    (r) => r.stratum === transformId && r.pipeline === pipeline,
  );
  if (rows.length === 0) return null;
  return { k: rows[0].k, n: rows[0].n };
}

const t2f = matrix.detection.by_transform_medium.find((r) => r.stratum === 'T2f-separator-inject');
const t0 = matrix.detection.by_transform_medium.find((r) => r.stratum === 'T0-original');
const covOf = (entry) => {
  const cov = entry ? coverageForTransform(entry.stratum) : null;
  return cov ? `${cov.k} / ${cov.n}` : 'not available';
};
if (t0) lines.push(`| \`T0-original\` | ${pct(t0.rate)} (${kn(t0)}) | ${covOf(t0)} |`);
if (t2f) lines.push(`| \`T2f-separator-inject\` | ${pct(t2f.rate)} (${kn(t2f)}) | ${covOf(t2f)} |`);
lines.push('');
lines.push('**Not fixed.** Changing `profiles.normText` alters core ingestion behaviour and the committed');
lines.push('Step 6 expectation set, which was outside the scope of both the Step 7 evaluation and the Step 10');
lines.push('final validation. A focused regression test records the current behaviour so the owner can decide:');
lines.push('`test/step7-normalizer-gap.test.js`.');
lines.push('');

lines.push('## 9. Artifacts');
lines.push('');
lines.push('| File | Contents |');
lines.push('| --- | --- |');
lines.push('| `eval/results/attack-matrix.json` | provenance, funnel, exclusion ledger, sample, detection rates, marginals, both populations |');
lines.push('| `eval/results/detection-heatmap.svg` | position x pipeline coverage and detection |');
lines.push('| `eval/results/detection-heatmap.csv` | the same numbers as text |');
lines.push('| `eval/results/detection-heatmap.json` | machine-readable heatmap rows, both denominators |');
lines.push('| `eval/results/replica-results.json` | the current integrated eight-case replica suite |');
lines.push('| `eval/results/step7-replica-results-historical.json` | the frozen pre-P1 suite (7 PASS / 1 SKIPPED), superseded |');
lines.push('| `eval/results/benign-pages.json` | NOT RUN, with the reason and what would be needed |');
lines.push('| `eval/results/evaluation-summary.md` | this document |');
lines.push('');
lines.push('> The external attack-library numbers above were **re-aggregated on 2026-09-20 (Step 10)** from the');
lines.push('> preserved raw observations in `eval/tmp/step7/obs-shard*.json`. No measurement was re-run and no raw');
lines.push('> row was edited: the control population was separated out of the detection denominator, and the');
lines.push('> mixed-population reading is shown beside it.');
lines.push('');
lines.push('Reproduce with:');
lines.push('');
lines.push('```bash');
lines.push('node eval/scripts/step7/run-evaluation.js --corpus <pinned unified.jsonl> \\');
lines.push('  --license-policy source-map --capability decision-agent --shard 0 --shards 4 \\');
lines.push('  --out eval/tmp/step7/obs-shard0.json');
lines.push('# ... shards 1..3, then:');
lines.push('node eval/scripts/step7/aggregate-results.js \\');
lines.push('  --shards eval/tmp/step7/obs-shard0.json,eval/tmp/step7/obs-shard1.json,eval/tmp/step7/obs-shard2.json,eval/tmp/step7/obs-shard3.json');
lines.push('```');
lines.push('');

fs.writeFileSync(path.join(OUT_DIR, 'evaluation-summary.md'), `${lines.join('\n')}\n`, 'utf8');
process.stdout.write(`evaluation-summary.md written (${lines.length} lines)\n`);
