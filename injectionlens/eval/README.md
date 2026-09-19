# InjectionLens evaluation harness (Step 7 utilities)

This directory holds the deterministic evaluation machinery for Human Step 7. It
is **not** a result: it contains no measurement of the detector, no percentages,
no attack matrix, no heatmap of real data and no replica results. Those need the
integrated Step 6 base plus a licensed, pinned corpus, and both are still in
progress.

Everything here was written in Wave A, Lane 3, on branch
`codex/step7-evaluation-harness`, based on `0952410` (the Step 5 acceptance
commit). It adds new files only; it does not touch the server, the client, the
Step 6 fixtures or any existing result file.

## What is in the box

| Module | Purpose |
| --- | --- |
| `eval/scripts/step7/ids.js` | stable record/cell identifiers, canonical JSON, keyed-hash sampling keys |
| `eval/scripts/step7/corpus.js` | local-only JSONL loading, provenance records, claim statuses, pinning |
| `eval/scripts/step7/targets.js` | string classifier for real destinations (never contacts anything) |
| `eval/scripts/step7/filters.js` | licence / safety / relevance passes and the exclusion ledger |
| `eval/scripts/step7/sample.js` | three-level deduplication, keyed-hash sampling, corpus funnel |
| `eval/scripts/step7/variants.js` | transformation matrix (original, wrapper, six Unicode recipes) and cell builder |
| `eval/scripts/step7/placement.js` | the six local HTML contexts, escaping, page safety referee |
| `eval/scripts/step7/aggregate.js` | level ladder, states, rates, attack-vs-control populations, heatmap input |
| `eval/scripts/step7/states.js` | `OK` / `NOT_RUN` / `SKIPPED` / `PENDING` / `FAILED` / `N/A` and provisional-vs-final stamping |
| `eval/scripts/step7/demo-synthetic.js` | synthetic end-to-end demonstration that prints to stdout and writes nothing |

## Commands

```bash
# from injectionlens/
npm test                                  # includes the step7 tests below
node --test "test/step7-*.test.js"        # focused harness tests, no browser needed
node eval/scripts/step7/demo-synthetic.js # synthetic plan, PROVISIONAL, stdout only
```

There is deliberately no CLI that writes result files. A future runner (after
Step 6 is integrated) is what will write `eval/results/step7-*`; until then any
artefact produced from this folder is stamped `PROVISIONAL` and
`assertFinal()` refuses to treat it as a result.

## Reproducing a sample

```js
const { corpus, filters, sample, variants, placement } = require('./eval/scripts/step7');

const loaded = corpus.loadCorpusFile('eval/tmp/step7/corpus/unified.jsonl', { sourceSlug: 'ipi-proxy' });
const provenance = corpus.createProvenanceRecord({ /* revision, hashes, licence files, claims */ });
corpus.assertPinned(provenance);

const filtered = filters.filterRecords(loaded.records, { sourceLicenseMap: provenance.source_license_map });
const deduped = sample.dedupe(filtered.included, { nearDupJaccard: 0.9 });
const picked = sample.sampleDeterministic(deduped.kept, { seed: '<explicit seed>', targetN: 50 });
```

Rules that the code enforces rather than documents:

* the harness reads pinned local files only — `loadCorpusFile()` rejects anything
  that looks like a URL or a UNC path;
* the seed is mandatory, and selection is `sha256(seed || record hash)` sorted, so
  it does not depend on file order and needs no random number generator;
* a target larger than the eligible set produces `sample_shortfall: true`, never
  a smaller sample presented as the plan;
* a licence established only by prose stays `claimed-only` and the records fall
  to `EX-LIC-UNKNOWN`, which excludes them.

## State vocabulary

`OK` is the only state that enters a denominator. `FAILED` (we tried, it broke),
`SKIPPED` (deliberately passed over), `NOT_RUN` (not started, for example no
authorisation), `PENDING` (not attempted yet) and `N/A` (nothing to divide by)
all produce `rate: null`. `0/0` is never rendered as `0%`.

## Population: attack cells vs payload-free controls

`OK` alone is not enough to say what a detection rate is *about*. The runner also
serves **control pages** — a page wrapper with filler text and no payload — one per
wrapper per shard, so that a detector firing on the wrapper markup alone would be
visible. A control is a real observation of a real page, but it is not an attack
sample.

Two populations are therefore named and computed separately, and both are
published:

| `population` | What divides | Use |
| --- | --- | --- |
| `attack_only` (default) | `OK` cells that carry a sampled record | the attack-detection rate |
| `all` | every `OK` cell, attacks plus controls | audit; kept so a correction can be checked |

A control is identified **structurally**, not by its id prefix: the runner writes
`record_uid: null` for exactly those rows (`isControlObservation()`), and a test
asserts that no attack cell has a null `record_uid`.

This distinction was introduced in the Step 10 audit. In the Step 7 run of
2026-09-20, 8 controls reached `OK` with no finding at all, so they changed no
numerator but were dividing the detection metrics: the reported `>= high` rate was
`628/3184 = 19.7%` where the attack population gives `628/3176 = 19.8%`. The task
brief's hypothesis `3200 - 24 + 8 = 3184` was correct: 3200 planned cells, 24
`SKIPPED`, plus 8 controls appended by the runner. The published metric now uses
`attack_only`, the mixed reading is retained beside it, and the correction was
applied to the **preserved raw observations** — no measurement was re-run and no
raw row was edited.

Note that `aggregate.js` defaults to `attack_only`, so a caller that builds its own
observation fixtures must give attack cells a `record_uid`, or it will be
aggregating only controls.

Per-cell feasibility follows the same logic: a payload that cannot be planted in
one context (for example text containing `-->` cannot go inside an HTML comment)
marks that one cell `SKIPPED` with `CELL-NOT-EMBEDDABLE`; the other five contexts
still run. A record is excluded only when no context accepts it.

## Upstream provenance and licence facts (inspected, not assumed)

Inspected during Wave A Lane 3, read-only, in the official repository only.
Nothing below is committed: the files were fetched into `injectionlens/eval/tmp/`
(already gitignored) and are not part of the repository.

| Fact | Value |
| --- | --- |
| Repository | `https://github.com/VulcanLab/IPI-Proxy` (default branch `main`) |
| Inspected revision | `272a61a7ee33c06805ceb87e832cb4a3aefb40d0` — the only commit, dated 2026-05-05T07:08:27Z |
| Repository-level licence file | **none** — the GitHub trees API listed 44 entries at the pinned revision and none is a `LICENSE`/`COPYING` file; the GitHub API reports `license: null` |
| `payloads/unified.jsonl` | 569,705 bytes, SHA-256 `3c757e34c900868dcf1190ce572153e75e22e67de885bae90fb380560c53fde1` |
| Records | 820 lines, 0 JSON parse failures |
| Per-record `license` field | present on only 91 of 820 records: `CC-BY-NC-4.0` ×84, `MIT` ×7, absent ×729 |
| Sources | bipia 220, injecagent 62, agentdojo 47, tensor_trust 400, wasp 84, llmail_inject 7 |
| Source × licence | every `wasp` record carries `CC-BY-NC-4.0`; every `llmail_inject` record carries `MIT`; the other four sources carry no per-record licence |
| Documented mapping | `payloads/SOURCES.md` (SHA-256 `8578f7fa2624c194624f1b4cbdc4836ea52f682e963f570573928c61258961d9`) and `README.md` (`ce7845f05cad8b94ee6db6f6ab623243801d577f53c6fcf60dffa15992f32770`) state that BIPIA / InjecAgent / AgentDojo / Tensor Trust are MIT-compatible and that WASP is CC-BY-NC 4.0 |

Verified licence facts: the 84 WASP records are non-commercial, and the
repository's own prose says so twice. Unresolved licence facts: the repository
has **no licence file**, so 729 records (89%) are MIT only by a documented
source-level statement, not by a per-record field. Under this harness that
statement must be recorded as `artifact-verified` **against those two hashed
files** before those records can enter a sample; anything weaker leaves them
`EX-LIC-UNKNOWN`.

Safety note from the same scan (text only; no URL from any record was followed),
produced by `targets.findUnsafeTargets()` over the pinned file: **165 of 820**
records contain at least one real destination — 105 URL findings, 76 mail-address
findings, 2 IPv4 literals and 0 wallet addresses. Those records fall to
`EX-UNSAFE-TARGET` unless the owner approves neutralised variants. Exactly 1
record contains `rm -rf`, and it is *not* excluded, because AGENTS.md rule 7
allows destructive text inside fixtures as long as nothing executes it (the
harness never does).

## What is deliberately not here

* no percentages, detection rates, false-positive rates or heatmap of real data;
* no `replica-results.json`, no attack-matrix results, no benign-page results;
* no external benign-page evaluation — that needs explicit owner approval for
  each host and is not authorised in this lane;
* no upstream dataset in the repository, and no code path that downloads one.

## Assumptions this harness makes about the integrated Step 6 base

1. `analyze(url, capabilityKey, { policy })` keeps returning per-finding
   `impact.level`, `occurrences[].path`, `occurrences[].pipeline` and the
   `matrix[]` summary; the heatmap attribution depends on those fields.
2. The level ladder stays `info < low < medium < high < critical`
   (`server/lib/risk.js`); a test asserts the harness ladder equals it.
3. The pipeline ids stay `http-source`, `rendered-dom`, `reader-markdown`,
   `accessibility-tree`.
4. `normText` in `server/lib/profiles.js` stays the comparison key; a test
   asserts the harness copy equals it.
5. Extraction paths keep their current shapes (`body > main > p`,
   `(HTML comment)`, `meta[name="description"]`, `…@data-agent-note`,
   `review.reviewBody`); a test asserts the product extractor finds each planted
   payload at the declared path.
