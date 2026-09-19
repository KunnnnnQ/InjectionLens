# InjectionLens — Step 7 evaluation summary

Generated: 2026-09-19T21:23:04.759Z

> **PROVISIONAL.** These are real measurements over a real sampled corpus, not a final accuracy claim.
> The upstream repository has no licence file, so the sample is drawn only from sources whose licence is
> documented in the upstream file itself. See "Licensing and why the sample is this size".

Everything below was produced by executing code in this repository. No number was entered by hand.
The three evaluation families are reported separately and are **never** merged into one accuracy figure.

## 1. What was measured, and how

| | |
| --- | --- |
| Upstream source | `https://github.com/VulcanLab/IPI-Proxy` |
| Inspected revision | `272a61a7ee33c06805ceb87e832cb4a3aefb40d0` |
| Corpus file SHA-256 | `3c757e34c900868dcf1190ce572153e75e22e67de885bae90fb380560c53fde1` |
| Records in file | 820 (0 malformed) |
| Licence policy applied | `source-map` |
| Sampling | `keyed-sha256-sort-v1`, seed `injectionlens-step7-2026-09-20`, keyed SHA-256 sort |
| Sample fingerprint | `59487072d99ea6f2d3797eb3a3065a37853cd726add55bad1c38b2a6fd48e7ca` |
| Capability template | `decision-agent` |
| Matrix | 3200 cells = 50 records x 8 transforms x 8 placements |
| Cells measured | 3208 |

A **cell** is one sampled record placed in one HTML context and transformed once. Each cell is served from an
ephemeral loopback port as a locally generated page, and analysed by the integrated Step 6 detector.
The evaluation never executed payload text and never followed a URL found in a payload.

The 8 placements are 6 named categories, because
`p-css-hidden` is a family rather than a single context: it is planted three times, with `display:none`,
`font-size:1px;color:rgba(31,41,51,0.05)` and an off-screen `left:-10000px` position. That is why one category
carries three times the observations of the others, and why "8 placements" and "6 categories" are both correct.

### State accounting

Only cells in state `OK` enter a denominator. A cell that could not be planted, or whose analysis failed,
is never counted as "not detected". The detection metrics additionally divide by the **attack** population;
see "Which cells these divide by" below for the payload-free control pages and why they are excluded.

| State | Cells |
| --- | --- |
| OK | 3184 |
| SKIPPED | 24 |
| **total rows** | **3208** |

24 cells were `SKIPPED` with `CELL-NOT-EMBEDDABLE`: a payload containing
`--`, `>` or ending in `-` cannot be placed inside an HTML comment without breaking the markup, so that one
placement is skipped for that record while its other seven still run.

## 2. External attack-library evaluation

### 2.1 Overall detection

| Metric | k (numerator) | n (denominator) | Rate |
| --- | --- | --- | --- |
| Cells rated **>= medium** | 808 / 3176 | | 25.4% |
| Cells rated **>= high** | 628 / 3176 | | 19.8% |

**Which cells these divide by.** The denominator is the **attack population**: `state OK` cells that carry a
sampled record. The run also served 8 payload-free **control** page(s) (a wrapper with filler
text and no payload) so that a detector firing on the wrapper markup alone would be visible. Those controls
reached `OK` with no finding at all, so they change no numerator; they only change the denominator by 8.
The mixed-population reading is kept for audit rather than discarded:

| Metric | Attack population (reported) | Mixed population (audit) |
| --- | --- | --- |
| >= medium | 808 / 3176 = 25.4% | 808 / 3184 = 25.4% |
| >= high | 628 / 3176 = 19.8% | 628 / 3184 = 19.7% |

- Sample: 50 payload records sampled deterministically from 551 eligible records.
- Metric: the share of measured cells whose **strongest finding level** reaches the threshold.
- Limitation: a detector finding is not proof that a downstream agent attack was prevented. This measures
  what the detector surfaces, not whether an agent would have obeyed.

### 2.2 Detection by insertion position (>= medium)

| Position | k | n | Rate |
| --- | --- | --- | --- |
| `p-css-hidden` | 324 | 1200 | 27.0% |
| `p-data-attribute` | 108 | 400 | 27.0% |
| `p-html-comment` | 90 | 376 | 23.9% |
| `p-jsonld-string` | 108 | 400 | 27.0% |
| `p-meta-content` | 108 | 400 | 27.0% |
| `p-visible-body` | 70 | 400 | 17.5% |

### 2.3 Detection by transform (>= medium)

| Transform | k | n | Rate |
| --- | --- | --- | --- |
| `T0-original` | 103 | 396 | 26.0% |
| `T1-contextual-wrapper` | 103 | 396 | 26.0% |
| `T2a-zwsp-interleaved` | 105 | 396 | 26.5% |
| `T2b-bidi-wrapped` | 105 | 396 | 26.5% |
| `T2c-tag-encoded` | 109 | 400 | 27.3% |
| `T2d-homoglyph-mixed` | 105 | 396 | 26.5% |
| `T2e-nfkc-compat` | 106 | 400 | 26.5% |
| `T2f-separator-inject` | 72 | 396 | 18.2% |

### 2.4 Position x pipeline

Two readings are given for every pipeline, because a pipeline that never saw the payload cannot be
credited with missing it.

**Coverage** — did the pipeline extract the planted text at all?

| Pipeline | k | n | Rate |
| --- | --- | --- | --- |
| `http-source` | 3000 | 3176 | 94.5% |
| `rendered-dom` | 2739 | 3176 | 86.2% |
| `reader-markdown` | 1160 | 3176 | 36.5% |
| `accessibility-tree` | 1172 | 3176 | 36.9% |

**Detection where the pipeline observed the payload** (denominator = cells that pipeline observed, >= medium):

| Pipeline | k | n | Rate |
| --- | --- | --- | --- |
| `http-source` | 759 | 3000 | 25.3% |
| `rendered-dom` | 589 | 2739 | 21.5% |
| `reader-markdown` | 269 | 1160 | 23.2% |
| `accessibility-tree` | 269 | 1172 | 23.0% |

**Detection over all valid cells** (denominator = every valid attack cell, >= medium):

| Pipeline | k | n | Rate |
| --- | --- | --- | --- |
| `http-source` | 759 | 3176 | 23.9% |
| `rendered-dom` | 589 | 3176 | 18.5% |
| `reader-markdown` | 269 | 3176 | 8.5% |
| `accessibility-tree` | 269 | 3176 | 8.5% |

The two detection readings differ by design: the first answers "when this pipeline reads the payload, how
often is it flagged at the threshold", the second answers "what share of the whole matrix does this pipeline
account for". Neither is hidden.

### 2.5 Level distribution over measured cells

| Level | Cells |
| --- | --- |
| info | 2194 |
| low | 22 |
| medium | 180 |
| high | 628 |
| critical | 0 |
| null | 152 |

152 measured cells produced no security finding at all
(state `OK`, level `null`): the text was ingested but did not reach even `info`.

## 3. Licensing and why the sample is this size

The upstream repository carries **no licence file** at the inspected revision, and 729 of its 820 records
carry **no per-record licence**. Two readings were computed and the stricter one is reported here first:

| Reading | Eligible records | Result |
| --- | --- | --- |
| **strict** (a record needs its own licence field) | 0 | no measurement possible |
| **source-map** (upstream documented statement, `artifact-verified` against a hashed file) | 551 | this is what was measured |

Under the strict reading **zero** records are eligible:

| Exclusion reason | Records |
| --- | --- |
| `EX-LIC-UNKNOWN` | 729 |
| `EX-WASP` | 84 |
| `EX-UNSAFE-TARGET` | 7 |

Note the third row: the 7 records that DO carry an explicit `MIT` field are excluded anyway, because they
contain a real destination and fall to `EX-UNSAFE-TARGET`. So "the explicitly MIT records" cannot be used as
a sample either.

The measured run therefore uses the `source-map` reading, and its exclusion ledger is:

| Exclusion reason | Records |
| --- | --- |
| `EX-UNSAFE-TARGET` | 99 |
| `EX-IRRELEVANT-PLACEHOLDER` | 1 |
| `EX-WASP` | 84 |

84 WASP records are excluded as CC-BY-NC. Records with non-reserved destinations are excluded and never
fetched. The upstream corpus is **not** committed to this repository: it stays in `eval/tmp/`, which is ignored.

### Sampling funnel

| Stage | Count |
| --- | --- |
| Records in source file | 820 |
| Excluded (all reasons) | 184 |
| Eligible after licence + safety + relevance | 551 |
| Removed as duplicates (byte/text/near) | 85 |
| Sampled (deterministic) | 50 |
| Target | 50 |
| Shortfall | false |

Near-duplicate threshold: Jaccard 0.9. The sample is drawn by sorting
`sha256(seed || record_sha256)` and taking the first N, so it needs no random number generator and is
independent of file order.

## 4. Integrated source-backed replica suite

Produced by: `node scripts/run-fixtures.js --json eval/tmp/step7/replica-run.json`

**8 PASS / 0 FAIL / 0 SKIPPED / 0 ERROR** of 8 cases.

| Case | Status | Primary capability | Observed | Source |
| --- | --- | --- | --- | --- |
| `unit42-scam-ad-review` | PASS | `decision-agent` | max high | Unit 42 - AI agent prompt injection on real web pages (2026-03-03) |
| `forcepoint-5000-payment` | PASS | `browser-agent` | max critical | Forcepoint X-Labs - 10 live indirect prompt injection payloads (2026-04-22) |
| `forcepoint-rm-rf` | PASS | `coding-agent` | max critical | Forcepoint X-Labs - payloads targeting AI coding tools (2026-04-22) |
| `unit42-offscreen-hiring` | PASS | `decision-agent` | max high | Unit 42 - hiring and ranking manipulation on real pages (2026-03-03) |
| `brave-comet-spoiler` | PASS | `browser-agent` | max high | Brave - Comet account takeover via a Reddit spoiler tag (2025-08-20) |
| `splx-chatgpt-user-cloaking` | PASS | `summary-only` | max high | SPLX - AI-targeted cloaking in a resume-ranking test (2025-10-01) |
| `msft-ai-summary-link` | PASS | `summary-only` | max high | Microsoft Security - AI recommendation poisoning via pre-filled assistant links (2026-02-10) |
| `arxiv-content-protection` | PASS | `summary-only` | max low | arXiv 2604.27202 - content-protection notices found in the wild (2026-04-29) |

## 5. Real benign-page evaluation

**NOT RUN.** NOT RUN: no explicit owner-approved URL/host allowlist was supplied for this stage. Ordinary real-world page scanning is not authorised, and the local fixtures are not real-world false-positive evidence.

No false-positive rate is reported, because reporting one would require fetching pages this stage is not
authorised to fetch. The local fixtures are not real-world false-positive evidence and are not presented
as such.

## 6. Safe baseline comparison

A before/after comparison would need a reproducible pre-fix detector revision measured over the same sample.
The pre-fix revision `v0-ai-scaffold` is tagged, but re-running this matrix against it was **not** performed
in this stage, so no comparison is claimed.

## 7. Limitations, stated plainly

1. **Provisional.** The sample rests on a documented-licence reading of a repository with no licence file.
2. **One capability template.** The matrix was measured under `decision-agent` only.
3. **External-library text only.** These payloads were written to attack agents in general; they are not
   copies of pages found in the wild, and no live page was fetched.
4. **Detection is not prevention.** A finding means the tool surfaced an instruction; it does not mean an
   agent would have refused it.
5. **HTTP-source coverage is a lower bound.** `analyze()` does not return its raw item list, so coverage for
   that pipeline is read from finding occurrences and truncated matrix excerpts.
6. **No benign FPR.** NOT RUN, as above.
7. **A measured coverage gap, reported not hidden:** 176 of 3176 attack cells were not carried by `http-source`, and
   148 of those come from the `T2f-separator-inject` transform. See the defect section below.

## 8. Defect found during this evaluation (measured, not fixed)

`profiles.normText()` in `server/lib/profiles.js` strips only `U+200B-U+200D`, `U+FEFF` and `U+2060`, while
`risk.normalizeText()` additionally strips `U+00AD`, `U+180E`, `U+061C` and the bidi controls. Because
`analyze.js` uses `profiles.normText` as the grouping key, a payload carrying those characters does not group
with its own un-obfuscated text.

Measured effect in this run:

| Transform | Detection >= medium | http-source coverage |
| --- | --- | --- |
| `T0-original` | 26.0% (103 / 396) | 389 / 396 |
| `T2f-separator-inject` | 18.2% (72 / 396) | 248 / 396 |

**Not fixed.** Changing `profiles.normText` alters core ingestion behaviour and the committed
Step 6 expectation set, which was outside the scope of both the Step 7 evaluation and the Step 10
final validation. A focused regression test records the current behaviour so the owner can decide:
`test/step7-normalizer-gap.test.js`.

## 9. Artifacts

| File | Contents |
| --- | --- |
| `eval/results/attack-matrix.json` | provenance, funnel, exclusion ledger, sample, detection rates, marginals, both populations |
| `eval/results/detection-heatmap.svg` | position x pipeline coverage and detection |
| `eval/results/detection-heatmap.csv` | the same numbers as text |
| `eval/results/detection-heatmap.json` | machine-readable heatmap rows, both denominators |
| `eval/results/replica-results.json` | the current integrated eight-case replica suite |
| `eval/results/step7-replica-results-historical.json` | the frozen pre-P1 suite (7 PASS / 1 SKIPPED), superseded |
| `eval/results/benign-pages.json` | NOT RUN, with the reason and what would be needed |
| `eval/results/evaluation-summary.md` | this document |

> The external attack-library numbers above were **re-aggregated on 2026-09-20 (Step 10)** from the
> preserved raw observations in `eval/tmp/step7/obs-shard*.json`. No measurement was re-run and no raw
> row was edited: the control population was separated out of the detection denominator, and the
> mixed-population reading is shown beside it.

Reproduce with:

```bash
node eval/scripts/step7/run-evaluation.js --corpus <pinned unified.jsonl> \
  --license-policy source-map --capability decision-agent --shard 0 --shards 4 \
  --out eval/tmp/step7/obs-shard0.json
# ... shards 1..3, then:
node eval/scripts/step7/aggregate-results.js \
  --shards eval/tmp/step7/obs-shard0.json,eval/tmp/step7/obs-shard1.json,eval/tmp/step7/obs-shard2.json,eval/tmp/step7/obs-shard3.json
```

