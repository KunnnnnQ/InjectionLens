# Owner checklist — what only you can do

**Deadline: 2026-09-20 10:00 AM EDT = 22:00 UTC+8.** The plan targets submitting by **21:00 UTC+8**
with a one-hour buffer. Work top to bottom; the order is deliberate.

Everything a coding agent could do in Steps 9 and 10 is already done. This file lists only the items
that require you: your accounts, your words, your decisions, and every Git operation.

> **Git is yours.** No commit, tag, branch or push has been performed on your behalf. Do not assume
> any of the history below exists yet.

---

## Phase 1 — Review before you publish (about 20 minutes)

| # | Item | Where | Owner decision |
| --- | --- | --- | --- |
| 1 | Read the README end to end. Correct anything that is not true of your project, and adjust tone. | `README.md` | ☐ |
| 2 | Verify every factual claim you intend to defend on camera. The evidence pointer for each is in the *Verification status* table at the end of the README. | `README.md` | ☐ |
| 3 | Read the Devpost copy and fill in the three `[TO FILL — OWNER]` sections **in your own words**: the inspiration, two or three challenges, and what you learned. | `submission/devpost.md` | ☐ |
| 4 | Read the video script once aloud with a timer. If any sentence feels unnatural in your voice, rewrite it — it is your video. | `submission/video-script.md` | ☐ |
| 5 | Confirm the source list and attributions are ones you are comfortable publishing. | `README.md` → *Data attribution and licence* | ☐ |
| 6 | **Choose a licence.** Currently stated as "not yet chosen". Candidates: `MIT`, `Apache-2.0`, or `MIT` for code plus `CC-BY-4.0` for docs. Note that the project excludes CC-BY-NC upstream data, so a non-commercial licence on your own code is a choice you would have to justify. | new `LICENSE` file + `README.md` | ☐ |
| 7 | Decide whether to publish the UA probe as-is or soften it. It is currently framed as a lower bound and never leaves your machine. | `README.md` §21, `server/lib/ingest.js` | ☐ |
| 8 | Confirm you are comfortable with the AI disclosure exactly as written. Hiding AI use is the rule violation; using it is not. | `submission/devpost.md` + `README.md` | ☐ |
| 9 | Read the two audit results a judge may probe: **8 placements are 6 named categories** (`p-css-hidden` is planted three ways), and the **headline high-or-above rate is 19.8%**, not the 19.7% first reported, because the attack-detection denominator used to include 8 payload-free control pages. Both are explained in README §17.2 and `eval/results/evaluation-summary.md`, with both populations shown side by side. | `README.md` §17.2 | ☐ |

## Phase 2 — Repository (about 15 minutes)

| # | Item | Command / action | Owner decision |
| --- | --- | --- | --- |
| 10 | Review the Step 10 changes before committing: `eval/scripts/step7/aggregate.js` (population handling), `aggregate-results.js`, `write-summary.js`, the regenerated files in `eval/results/`, and the new `test/step7-aggregate.test.js` cases. | `git diff` / GitHub Desktop | ☐ |
| 11 | Make sure the working tree contains exactly what you want to publish. Check that `injectionlens/eval/tmp/` (the external corpus) and `injectionlens/shots/` are ignored — they already are. | `git status` | ☐ |
| 12 | Create the commit(s), one logical change each, with the trailer your working agreement specifies. Keep the audit correction as its own commit so the history reads honestly. | `git add` / `git commit` | ☐ |
| 13 | Push to GitHub. **Do this before you record** — the video references the repository. | `git push` | ☐ |
| 14 | Make the repository **public**, or confirm it is visible to judges. | GitHub settings | ☐ |
| 15 | Paste the real repository URL into `README.md` (bottom) and `submission/devpost.md` (Links table), replacing `[TO FILL — OWNER]`. | both files | ☐ |
| 16 | Confirm the `v0-ai-scaffold` tag still exists if you reference it. If it does not, remove that sentence rather than leaving a claim you cannot show. | `git tag --list` | ☐ |

## Phase 3 — Record the video (about 45–60 minutes)

| # | Item | Detail | Owner decision |
| --- | --- | --- | --- |
| 17 | Install and start the app; confirm http://127.0.0.1:7100 loads and the dropdown is populated. | `cd injectionlens && npm install && npm --prefix client install && npm run dev` | ☐ |
| 18 | Do one **silent** run-through of every on-screen action first, so you never hunt for a button on camera. | `submission/video-script.md` → *Before you record* | ☐ |
| 19 | Record. Target **4:44**; hard ceiling 5:00. | OBS / ScreenPal / Windows Xbox Game Bar (`Win+G`) | ☐ |
| 20 | Use `replica-payment-5000.html` for the capability-switch segment. **Not** the default scam-ad page — it rates high under all five templates and would misrepresent the feature. | Segment 4 | ☐ |
| 21 | Say the AI disclosure out loud (Segment 7). Do not cut it for time; cut Segment 4 instead. | Segment 7 | ☐ |
| 22 | Check the finished duration in the editor (not by estimate), and scrub for any window showing personal data. | editor | ☐ |
| 23 | Upload to YouTube (unlisted is fine) or Vimeo, and copy the URL. | — | ☐ |

## Phase 4 — Submit (about 20 minutes)

| # | Item | Detail | Owner decision |
| --- | --- | --- | --- |
| 24 | Paste the video URL into the Devpost form and into `submission/devpost.md`. | — | ☐ |
| 25 | Fill in every Devpost field: title, tagline, elevator pitch, the "Built with" tags, the repository URL, and the category/track. Verify the built-with tags match `README.md`. | Devpost | ☐ |
| 26 | Paste the **AI & External Tools Disclosure** section verbatim into whatever disclosure field the form provides. If the form has no such field, put it in the project description. | `submission/devpost.md` | ☐ |
| 27 | Do **not** fill in a "live demo" field. There is no deployment, by design. If the form requires a URL, use the repository and say plainly that the tool runs locally. | Devpost | ☐ |
| 28 | Press Submit, then **verify the submitted page renders**: all links resolve, the video plays, the disclosure is visible, and no `[TO FILL]` text leaked into it. | Devpost | ☐ |
| 29 | Confirm the deadline the form displays, and submit with buffer. | Devpost | ☐ |

## Phase 5 — Final safety check (5 minutes)

| # | Item | Why |
| --- | --- | --- |
| 30 | `git status` is clean and your last commit is pushed. | ☐ |
| 31 | Nothing under `injectionlens/eval/tmp/` and no upstream corpus file was committed. | Licence compliance — the upstream repository has no licence file and 84 of its records are CC-BY-NC. |
| 32 | No fixture contains a real domain, brand, login page or payment link. | ☐ |
| 33 | No screenshot or frame in the video shows a personal file path, email or account. | ☐ |
| 34 | Ports 7100 and 7101 are free — you stopped the dev server you started. | ☐ |
| 35 | You can explain every module a judge might open. | This is the disclosure's own promise. |

---

## Deliberately left undone (and why)

These are **not** oversights. Each was consciously left for you or left out of scope:

| Item | Status | Reason |
| --- | --- | --- |
| Real benign-page false-positive rate | **NOT RUN** | Needs an explicit, owner-approved host allowlist; ordinary third-party scanning was never authorised. `eval/results/benign-pages.json` records this. |
| Before/after comparison against the pre-fix revision | **NOT RUN** | Would need the whole matrix re-run against `v0-ai-scaffold`. No improvement figure exists, so none is claimed. |
| Normaliser defect (`profiles.normText` vs `risk.normalizeText`) | **Documented, not fixed** | Fixing it changes core ingestion behaviour and the committed expectation set. Measured, pinned by a test, and reported. |
| DNS rebinding | **Not solved** | The guard validates every DNS answer but does not pin the connection to it. Published in `GET /api/network-policy` and README §21. |
| Public deployment | **Out of scope** | Would require reliable rebinding protection first. A repository plus the video satisfies the requirements. |
| Second-stage LLM judge | **Out of scope** | Optional. If added later it must be hardened as an attack surface itself. |
| Matrix label "8 placements" in the generated summary | **Investigated, not a defect** | The run really did use 8 concrete placements: 6 named categories, where `p-css-hidden` is planted three ways (`display:none`, `font-size:1px`, off-screen). README §17.2 and the generated summary now explain this. No result file was rewritten for it. |
| Attack-detection denominator included 8 payload-free control pages | **Fixed in Step 10** | The controls carried no finding, so only the denominator changed: the reported high-or-above rate moved from 19.7% to **19.8%**. The aggregation now uses the attack population, the mixed reading is kept beside it in `evaluation-summary.md` and `attack-matrix.json`, and regression tests pin it. No raw observation was altered and the evaluation was not re-run. |

## Placeholders still in the repository — all of them are yours

```bash
# from the repository root — list every remaining placeholder
grep -rn "TO FILL" README.md submission/ 2>/dev/null
```

If that command lists nothing, you have replaced them all. Note that the four planning documents at
the repository root contain their **own** `[TO FILL]` / `【待填】` markers. Those are your own words
from an earlier stage and were deliberately left untouched — decide separately whether you want to
complete them before publishing.
