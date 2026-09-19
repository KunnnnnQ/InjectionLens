# InjectionLens — demo video script

**Target length: 4:44 (hard ceiling 5:00).** Every segment below is budgeted; if you run long,
cut from Segment 4 and Segment 2 first, never from Segment 6 or 7.

| # | Segment | In | Out | Duration |
| --- | --- | --- | --- | --- |
| 0 | Cold open | 0:00 | 0:20 | 0:20 |
| 1 | The problem | 0:20 | 0:58 | 0:38 |
| 2 | Four pipelines, one page | 0:58 | 1:36 | 0:38 |
| 3 | The scam-ad demo | 1:36 | 2:26 | 0:50 |
| 4 | Capability changes the verdict | 2:26 | 3:12 | 0:46 |
| 5 | Cloaking and the hidden channels | 3:12 | 3:42 | 0:30 |
| 6 | The measurement | 3:42 | 4:12 | 0:30 |
| 7 | Limitations and AI disclosure | 4:12 | 4:44 | 0:32 |
| | **Total** | | | **4:44** |

---

## Before you record

**Start the app and leave it running** (two terminals, or one with `npm run dev`):

```bash
cd injectionlens
npm run dev          # server on 127.0.0.1:7101, client on 127.0.0.1:7100
```

Then open **http://127.0.0.1:7100** and confirm the page loads and the fixture dropdown is
populated. If the client does not load, run `npm install` and `npm --prefix client install` first.

**Set up before you hit record, so you never install anything on camera:**

* Browser window at **1920×1080**, zoom at 100%, no bookmarks bar, no other tabs, notifications off.
* Close anything that shows personal data — email, chat, file paths with your name in them.
* Have `shots/01-initial.png` … `shots/09-channel-checks.png` open in a second window as an **edit
  source**, so a slow analysis never leaves dead air: you can cut to a still and keep talking.
* Cursor visible; move it slowly and deliberately. Do not hunt for buttons on camera.

**Two demo targets, and why each one is the right one:**

* `/fixtures/replica-scam-ad-review.html` — the default. Use it for the pipeline comparison and the
  evidence view. **Note:** this page rates **high under all five capabilities**, so it is *not* the
  capability-switch demo.
* `/fixtures/replica-payment-5000.html` — use this one for the capability switch. It rates **high**
  for `summary-only` and `decision-agent` and reaches **critical** for `browser-agent`,
  `full-access` and `coding-agent`, which the runner validates in
  `server/fixtures/replicas.manifest.json`.

**Say it this way.** Use *surfaces*, *detects*, *shows*, *explains*, *reduces risk*. Never say
*prevents*, *solves*, *guarantees*, or *stops attacks*. Never present the eight local fixtures as a
random sample of the web — they are replicas you rebuilt from published reports.

---

## Segment 0 — Cold open (0:00 → 0:20)

**Narration**

> "This page looks like an ordinary advertisement. A human reading it sees a headline, a price, and a
> footer. But an AI agent reading the same page can receive a very different message — one written
> specifically for it. InjectionLens shows you exactly what the machine is being told, and what it
> could do about it."

**On-screen action**

* Start on the rendered scam-ad replica in the browser's normal view — the page as a human sees it.
* Slow scroll from the top of the page to the footer. Stop on the footer text.
* Cut to the InjectionLens UI, still empty, with the target and capability controls visible.

**Expected result**

* Viewer understands the core idea in one sentence: the same page says different things to a person
  and to an agent.

**Caveats / risks**

* Do not say the replica *is* a real page from the wild. It is a local replica you rebuilt from a
  published report. If you mention the source on camera, say "rebuilt from Unit 42's March 2026
  report".
* Keep the scroll slow; a fast scroll reads as filler.

---

## Segment 1 — The problem (0:20 → 0:58)

**Narration**

> "This is not hypothetical. In March 2026, Palo Alto Networks' Unit 42 found hidden instructions on
> real web pages: approve scam ads, pay five thousand dollars, delete databases, rate a candidate
> extremely qualified. Google's measurement of billions of crawled pages found the malicious
> category grew thirty-two percent in three months. And here is the part that shaped our design:
> thirty-eight percent of those payloads were visible plain text, and about twenty percent arrived
> through HTML attributes — which text-only scanners often never even read. So 'is it hidden?' is the
> wrong question."

**On-screen action**

* Show a simple slide or a README screenshot of the source table (Unit 42, Google, Forcepoint,
  arXiv, Brave, Microsoft, Cato CTRL) with dates visible.
* Highlight the two numbers — 37.8% visible plain text, 19.8% attributes.
* Cut back to the UI.

**Expected result**

* Viewer accepts that the threat is current, evidenced, and not a "hidden text" problem.

**Caveats / risks**

* Attribute every number to its report on screen. These are the *reports'* figures, not our
  measurements — never imply we produced them.
* Do not claim we measured anything in this segment.

---

## Segment 2 — Four pipelines, one page (0:58 → 1:36)

**Narration**

> "Agents do not agree on what a web page is. Some read the raw HTTP source. Some read the DOM after
> the browser has rendered it. Some use reader mode. Some read the accessibility tree. InjectionLens
> ingests the same page all four ways and shows you the disagreement instead of averaging it away.
> Look at the pipeline grid: raw source picked up nineteen items, the rendered DOM ten, reader mode
> four, the accessibility tree twenty. Each one reads a different page — and an instruction that only
> one of them carries is only seen by the agents that use that path."

**On-screen action**

* In the UI with the scam-ad replica selected and `decision-agent` set, press **Analyze**.
* Let the verdict panel appear, then point at the pipeline grid with its four item counts.
* Optional cut to `shots/07-matrix.png` if the live render is slow.

**Expected result**

* Four different item counts for one page (raw source 19, rendered DOM 10, reader mode 4,
  accessibility tree 20), and a verdict level clearly derived from them.

**Caveats / risks**

* **Read the item counts off the live screen as they appear.** The figures quoted above are from the
  verified scam-ad run; if your screen shows different numbers, say the numbers on screen — do not
  recite numbers that are not visible.
* Never say a pipeline with no finding is "safe". The UI says *no instruction observed*; use its
  wording.

---

## Segment 3 — The scam-ad demo (1:36 → 2:26)

**Narration**

> "Here is what it found on the ad page. Several findings, and each one points at a specific place in
> the markup. This one lives in a `data-*` attribute. This one is an HTML comment. This one is a
> JSON-LD string, invisible to a reader-mode agent. The tool tells you the intent — this one is
> trying to dictate the reviewer's verdict — and it tells you whether the text is addressed to an AI
> at all. Click a finding, and the page source highlights the exact node it came from. No score
> without evidence."

**On-screen action**

* Expand the findings list; open two or three findings in turn.
* Point at the delivery label under each one (`HTML attribute`, `HTML comment`, `JSON-LD string`).
* Click the highlight action and show the source view jumping to the node.
* Cut to `shots/04-findings.png` and `shots/05-highlight.png` if the live interaction drags.

**Expected result**

* Findings are traceable to concrete extraction paths, not to an opaque number.

**Caveats / risks**

* Keep to two or three findings. Listing all of them eats the budget for Segment 6.
* **Say the number of findings you can see on screen**, not a number from this script — the count
  depends on the capability template selected.
* Do not claim the tool "identifies the attacker" or attributes the page to anyone. It reports what
  the page says, not who wrote it.

---

## Segment 4 — Capability changes the verdict (2:26 → 3:12)

**Narration**

> "Now the part that matters most. The same instruction has a different weight depending on what the
> agent is allowed to do. On this payment page, a summariser — an agent that can only return text —
> rates this high: it will repeat the instruction, which is bad, but it cannot act on it. Switch to a
> browser agent that can submit forms, and the same text is critical: the instruction is now
> reachable. The page did not change. The reader did. That is why we do not show a single 'safety
> probability' — a number like that hides the only thing worth knowing."

**On-screen action**

* Switch the target to `/fixtures/replica-payment-5000.html`.
* Analyze under `summary-only`; show the level.
* Change the capability to `browser-agent`. **Confirm the dropdown has settled on the new value
  before pressing Analyze** — the UI re-reads it on click.
* Show the level change, and the explanation line that says whether it is reachable under this
  template.

**Expected result**

* `summary-only` → high; `browser-agent` → critical, on the same page.

**Caveats / risks**

* **This is the one segment that must use `replica-payment-5000.html`.** The default scam-ad fixture
  rates high under every capability, so using it here would misrepresent the feature.
* Do not say "critical means the attack succeeds". Say "critical means the instruction is reachable
  for this agent, given the evidence on the page".

---

## Segment 5 — Cloaking and the hidden channels (3:12 → 3:42)

**Narration**

> "Two more checks that no ingestion pipeline can perform. First, some sites serve different content
> depending on the User-Agent. InjectionLens probes eight AI-crawler tokens against its own local
> fixture and names the one that triggered a different response — here, GPTBot got a body more than
> twice the size of the human version. Second, a page can pre-fill a prompt into a 'summarize with
> AI' link, or hide an instruction in the URL fragment, which the server never even sees. Both are
> reported as their own channels, and neither is ever blamed on a pipeline."

**On-screen action**

* Analyze `/fixtures/cloaking.html`; show the cloaking banner and the named trigger token.
* Cut to `shots/08-cloaking.png` if the analysis is slow.
* Switch to `/fixtures/replica-ai-summary-link.html`; show the channel rows for the assistant links
  and the URL fragment.

**Expected result**

* A named trigger token (`GPTBot`) with the two response sizes, then two channel rows that are not
  attributed to any pipeline.

**Caveats / risks**

* Say clearly that this probe ran against **our own local fixture**, not a third-party site.
* Say that the UA probe is a **lower bound**: cloaking can also be driven by behavioural
  fingerprinting, which this tool does not detect. Do not skip this; it is the honest framing.

---

## Segment 6 — The measurement (3:42 → 4:12)

**Narration**

> "We also attacked our own detector. Our first version was AI-generated in about half an hour, and
> it was bad: it rated an ordinary 'visit us at' sentence as severe, and two words — 'for example' —
> dropped a hidden exfiltration instruction to low risk. So we rebuilt the test set from the
> published reports, and we measured against an external attack library: fifty payloads, transformed
> eight ways, planted in eight different positions on a page. Twenty-five percent of the resulting
> cells rate medium or above, and twenty percent reach high. Our eight report-derived replica cases
> now pass eight of eight. We report the twenty-five percent on purpose. This is a triage and
> forensics tool, not a classifier with a strong recall story."

**On-screen action**

* Show the eval results table from `eval/results/evaluation-summary.md`, or `detection-heatmap.svg`.
* Show the replica suite summary line: `total=8 pass=8 fail=0 skipped=0 error=0`.
* Keep both on screen while the numbers are spoken.

**Expected result**

* Viewer sees real measured numbers, including the unflattering one.

**Caveats / risks**

* The **25.4% / 19.8% figures are provisional** and were measured under one capability template
  (`decision-agent`) over external-library text. Say "provisional" out loud.
* The denominator is the **attack population**: the payload-free control pages the harness serves are
  excluded from it, and `evaluation-summary.md` shows both readings side by side. If a judge asks,
  that table is the answer.
* The **8/8 pass** figure is our own declared expectations on our own replicas. Say "our replica
  cases", not "real-world pages".
* **Never mention an FPR number.** It was NOT RUN. If you mention it at all, say plainly that the
  real-page false-positive measurement has not been run yet and is the next thing to do.
* Never merge the replica suite and the matrix into one accuracy number.

---

## Segment 7 — Limitations and AI disclosure (4:12 → 4:44)

**Narration**

> "What this does not do. It does not prevent prompt injection — nothing does. A finding means an
> instruction was surfaced, not that an agent would have refused it. The levels are rule-based tiers,
> not probabilities. Our UA probe cannot catch cloaking driven by behaviour. And we have not yet
> measured false positives on real pages — that is the honest gap, and it is next. On AI: the
> scaffold was generated by a coding agent in half an hour, and we disclose that. Choosing the
> problem, the scope and the design, and attacking, measuring and fixing the result — that was the
> work. InjectionLens makes the risk visible. Visibility is where defence starts."

**On-screen action**

* Show the limitations list from `README.md` §21 (or the app's own limitations text).
* Cut to the disclosure section, then to the repository URL and project name.
* End on the tagline card: **"See what the AI sees that you do not."**

**Expected result**

* The video ends on stated limits and an honest disclosure, not on a victory claim.

**Caveats / risks**

* Do not add a claim here that the tool "reduces attacks by X%". No such measurement exists.
* Say the AI disclosure out loud. Hiding it is the actual rule violation; using AI is not.

---

## After recording — checklist

1. **Cut to under 5:00.** Verify the final duration in the editor, not by estimate.
2. **Watch it once with sound off** — is the story still followable from the screen alone?
3. **Watch it once with the screen covered** — does the narration explain every number you show?
4. Confirm no terminal window on screen shows a path containing your real name, and no personal
   data appears in any frame.
5. Upload (YouTube unlisted or public, or Vimeo). Paste the URL into `submission/devpost.md` and the
   Devpost form.
6. Add the video URL to the repository README if you want judges to find it from the code.

## What must never be said on camera

| Never say | Say instead |
| --- | --- |
| "InjectionLens prevents prompt injection." | "InjectionLens surfaces AI-directed instructions and explains their reach." |
| "It guarantees the agent will refuse." | "It shows what the agent would ingest, so a human can decide." |
| "Critical means the attack succeeds." | "Critical means the instruction is reachable for this agent." |
| "We measured the false-positive rate." | "The real-page false-positive rate has not been run yet." |
| "We scanned thousands of real pages." | "We measured an external attack library, and rebuilt eight report-derived replicas." |
| "This catches cloaking." | "The UA probe names a User-Agent difference; it is a lower bound." |
| "The AI built this in 30 minutes." | "A coding agent generated the scaffold in 30 minutes; the audit, fixes and measurement are the work." |
