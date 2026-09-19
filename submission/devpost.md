# Devpost submission copy — InjectionLens

> **How to use this file.** Everything below is either (a) verified by a file in
> `injectionlens/eval/results/`, or (b) explicitly marked as the owner's own words.
> Replace every `[TO FILL — …]` placeholder with your own writing before submitting.
> Do not paste the angle-bracket instructions into Devpost.
>
> **Honesty rule that governs this copy:** detection is not prevention. Say *surfaces*,
> *detects*, *shows*, *explains*, *reduces risk* — never *prevents*, *solves* or *guarantees*.

---

## Project name

**InjectionLens**

## Tagline / elevator pitch (one line)

Attackers have started writing instructions to AI agents inside ordinary web pages.
InjectionLens shows what each kind of agent would ingest from a page — including what humans
cannot see — and which of those instructions could reach real damage.

## Inspiration — `[TO FILL — OWNER: write this in your own words]`

Prompts for what belongs here (say it your way, and do not copy the source documents verbatim):

* What you noticed while reading the 2026 reports that made you pick this problem — that the
  attacks already exist on real pages rather than being a theoretical concern, and that the
  industry's answer so far returns a verdict without saying *which part of the page* caused it.
* Why you chose this over the direction an AI assistant recommended to you (the safer, smaller
  idea) — this is already documented honestly in `InjectionLens-Design-and-Decision-Log.md` §2,
  so you can summarise it there in one or two sentences.
* The moment the problem became concrete for you: a page that reads as harmless to a human and as
  an instruction to a machine.

## What it does

InjectionLens is a **page-forensics tool for indirect prompt injection**. Point it at one page and
it answers four questions:

1. **What does each agent actually read?** The same HTML is ingested four different ways — raw HTTP
   source, rendered DOM, Reader/Markdown, and the accessibility tree. The tool reports, per
   pipeline, how many items it ingested and which pipeline carried each instruction. A pipeline that
   did not observe an instruction is reported as *no instruction observed*, never as *safe*.
2. **Which of it is aimed at an AI?** Instructions are detected across fifteen intent categories —
   override games, task replacement, identity manipulation, system-prompt probing, authority
   framing, verdict manipulation, secrecy, obfuscation, data and credential exfiltration,
   transactions, browser actions, destructive commands, and content-protection notices.
3. **Where exactly is it?** Every finding maps back to a concrete extraction path: an element, an
   HTML comment, a `meta` tag, a `data-*` attribute, a JSON-LD string, or an accessibility node.
   The UI highlights the spot in the page source.
4. **How bad is it for *this* agent?** You pick a capability template — `summary-only`,
   `browser-agent`, `full-access`, `decision-agent`, `coding-agent` — and the same page re-rates.
   "Approve this ad" is a bent verdict for a summariser and a business outcome for an ad reviewer.
   "$5,000 to this address" is a paragraph for a summariser and a payment for a browser agent.

It also checks **two channels no ingestion pipeline can see**: prompts pre-filled into
"summarize with AI" links, and instructions hidden in a URL `#` fragment (which is never sent to
the server at all). Both are reported as their own delivery channels, and neither is ever
attributed to a pipeline.

## How we built it

* **Ingestion** — four pipelines over one fetch: raw HTTP source (element text, comments, `meta`,
  attributes, `<title>`, `noscript`/`template`, JSON-LD), the rendered DOM with rendering
  forensics (display, visibility, opacity, font size, colour contrast — thresholds chosen so that
  `font-size:1px` and `rgba(…,0.01)` are caught), Readability → Markdown, and the accessibility tree.
* **Risk model** — `assessSegment(segment, capabilityKey)` in `server/lib/risk.js` combines intent,
  AI-addressing, delivery channel and capability reach into an ordinal level
  (`info < low < medium < high < critical`). Hidden content is weighted up but is never a
  requirement, because 37.8% of the payloads in the published reports were visible plaintext.
* **Network safety** — one deny-by-default policy (`server/lib/net-guard.js`) covers the target
  check, IP classification of every DNS answer, up to five manually re-checked redirects, and a
  Playwright subrequest guard. External analysis is off unless you name a host explicitly.
* **UI** — React + Vite. Live human-view vs AI-view comparison, a pipeline grid, expandable evidence
  per finding, and explicit **blocked** and **partial** states so a refusal never renders as a pass.
* **Verification** — 254 tests, a deterministic eight-case replica runner with declared
  expectations, an end-to-end smoke sweep, a real-browser UI script that writes nine screenshots,
  and a seeded evaluation harness with an exclusion ledger.

**Built with:** JavaScript, Node.js, Express, React, Vite, `jsdom`, Mozilla Readability, Turndown,
`playwright-core` (driving the system Chrome/Edge), `node:test`.

## The measurement (the part we are most careful about)

Three evaluation families, reported separately and **never merged into one accuracy figure**:

| Family | Result | Evidence |
| --- | --- | --- |
| Integrated replica suite (8 local pages rebuilt from published 2025–2026 reports) | **8 PASS / 0 FAIL / 0 SKIPPED / 0 ERROR** | `eval/results/stage10-fixtures.txt` |
| External attack-library matrix (IPI-Proxy, 50 records × 8 transforms × 8 placements) | **3176 valid attack cells**; **≥ medium 25.4%** (808/3176); **≥ high 19.8%** (628/3176) — **PROVISIONAL** | `eval/results/evaluation-summary.md` |
| Real benign-page false-positive rate | **NOT RUN** — would require fetching third-party pages, which was not authorised | `eval/results/benign-pages.json` |

Pipeline coverage in the measured matrix is itself a result: `http-source` 94.5%,
`rendered-dom` 86.2%, `reader-markdown` 36.5%, `accessibility-tree` 36.9%. An instruction that only
one ingestion path carries is seen by only the agents that use that path.

**The denominator, stated plainly.** The detection rate divides by the **attack** population: cells
that carry a sampled payload. Our harness also serves payload-free **control** pages, so a detector
that fired on the page wrapper alone would be visible; all 8 controls came back clean, so they change
no numerator, but counting them in the denominator understated the result by 0.05 points. We found
that in a final audit, corrected the aggregation, kept both readings side by side in the report, and
pinned the behaviour with regression tests rather than quietly restating the number.

**We report the unflattering number on purpose.** Roughly one in four transformed external payloads
is rated medium or above. InjectionLens is a triage and forensics aid, not a classifier with a
strong recall story, and the matrix is provisional because the upstream corpus has no licence file —
under a strict licence reading, zero records would be eligible, so the measured run uses a
documented-source-map reading (551 eligible records; 84 CC-BY-NC records excluded).

## Challenges we ran into — `[TO FILL — OWNER: pick two or three and tell them your way]`

Candidates that are already documented with evidence, so nothing here is invented:

* **The detector was generated in about half an hour, and it showed.** The first version rated an
  ordinary "visit us at …" line as severe, and dropped a hidden exfiltration instruction to low risk
  as soon as the words "for example" were added. Two words were enough to defeat it. That audit
  result is what set the whole plan for the remaining time.
* **Hidden-ness is the wrong signal.** Rebuilding the fixtures from the published reports showed
  that most real payloads are visible plaintext, and that HTML attributes — which text-only scanners
  often never read — were about a fifth of delivery methods. The model had to be re-centred on
  who is being addressed and what the reader can do, with hidden-ness demoted to a boosting signal.
* **Coverage is not detection.** Early on, a pipeline that simply never read a payload looked like a
  detection failure. The evaluation now reports both numbers — detection where the pipeline observed
  the payload, and detection over all cells — instead of quietly flattering itself.
* **A defence that must not become a weapon.** The tool fetches untrusted pages, so the analyser is
  itself an attack surface. That is why analysis is deny-by-default, why UA probing never leaves the
  local fixture origin without explicit permission, and why the decoded prompt of an AI-summary link
  is analysed as text and never followed.
* **A known defect we chose to report rather than hide.** Two normalisers in the codebase strip
  different sets of invisible characters, so payloads using the extra ones do not group with their
  own unobfuscated text. It is measured (`T0-original` 26.0% vs `T2f-separator-inject` 18.2%), it is
  pinned by a test, and it is documented as unfixed rather than quietly patched to flatter a number.

## Accomplishments we are proud of

* A working **four-pipeline ingestion matrix** that explains *why* two agents disagree about a page,
  rather than emitting one opaque score.
* A risk model that makes **capability reach** the hinge: the same page rates differently for five
  agent templates, and the delivered capability-dependence is visible in the UI.
* **Two channel checks that almost nothing else performs** — pre-filled prompts inside "summarize
  with AI" links, and URL-fragment instructions that the server never sees.
* An evaluation harness that treats `SKIPPED`, `NOT_RUN` and `N/A` as first-class states, never
  renders `0/0` as `0%`, and stamps anything non-final as `PROVISIONAL`.
* A published network policy that **states its own limitations in the API response**, including
  that DNS rebinding is not solved and that the UA probe is only a lower bound.
* A final audit that **found a defect in our own measurement**, corrected it, kept the superseded
  reading visible beside the corrected one, and added regression tests — instead of quietly
  restating the number.

## What we learned — `[TO FILL — OWNER: two or three sentences in your own voice]`

Candidates: that detection is not prevention and saying so is a strength rather than a weakness;
that an honest negative result (a low detection rate, an unrun measurement) is worth more to a
reviewer than a flattering one; and that the hard part of this problem is not finding scary words
but deciding what an instruction is worth *to a specific reader*.

## What's next

* Run the real benign-page false-positive measurement with an explicit host allowlist — the missing
  number, and the one that would change how the tool is positioned.
* Evaluate across all five capability templates rather than `decision-agent` alone.
* Resolve the normaliser gap, in its own change, with the expectation set updated deliberately.
* Optional second-stage LLM judge, hardened as an attack surface itself: no tools, content quoted,
  JSON-only output.
* Longer-horizon items: snapshot diffing for delayed injections, and PDF/OCR ingestion for agents
  that read pages as images.

## Built with

`javascript` · `node.js` · `express` · `react` · `vite` · `jsdom` · `mozilla-readability` ·
`turndown` · `playwright-core` · `node:test` · `html` · `css`

## Links

| Field | Value |
| --- | --- |
| Repository | `[TO FILL — OWNER: GitHub URL]` |
| Demo video | `[TO FILL — OWNER: upload to YouTube/Vimeo, paste the URL]` |
| Live demo | **None by design.** InjectionLens binds to `127.0.0.1` and analyses only its own fixtures. Deploying it without solving DNS rebinding would be irresponsible, so the honest answer is: run it locally, it takes one `npm install`. |
| Video script | `submission/video-script.md` in this repository |

## AI & External Tools Disclosure

> **AI & External Tools Disclosure**
>
> **ChatGPT** — used for pre-event preparation only, before the permitted start
> (2026-09-19 22:00 UTC+8). It proposed three candidate directions (I chose InjectionLens over the
> one it recommended), researched existing prompt-injection defences and products, and revised the
> design after I challenged its first draft. It wrote no project code.
>
> **Kimi coding agent** — after the start, generated the initial MVP scaffold (four ingestion
> pipelines, the React UI, the first seven test pages) from a scope I had fixed before the event.
> This revision is tagged `v0-ai-scaffold`.
>
> **DeepSeek (coding agent)** — implemented the subsequent work under stage-gated instructions:
> the corrections to the risk model, the ingestion and network-guard rework, the two P1 channel
> checks, the deterministic replica runner, the evaluation harness and the documentation. Every
> claim it produced had to be backed by a file in `injectionlens/eval/results/`.
>
> **Claude** — researched 2025–2026 incident reports and ran adversarial tests against the
> generated detector, which is what surfaced the false positives and the two-word bypass.
>
> **What was mine:** the choice of problem, the scope, the design trade-offs, the direction and
> supervision of every stage, the integration, and the validation. I reviewed the generated code
> and can explain every module.
>
> `[TO FILL — OWNER: add anything else you used, or state plainly that the list above is complete.]`

## Safety and responsible research

* Every test page uses only inert domains (`*.example`, `*.invalid`, `*.test`) and fictional brand
  names — no real login pages, no real payment links, no live malicious hosts.
* Destructive commands appear only as inert text inside fixtures and are never executed.
* The live malicious sites named in the source reports were never visited; their patterns were
  rebuilt locally from the published descriptions.
* AI-crawler User-Agent strings are never sent to third parties. The UA probe runs against the local
  fixture origin, or a host the operator explicitly allowlists.
* The external evaluation corpus is not redistributed: it stays in a gitignored directory, and the
  84 non-commercial (CC-BY-NC) records are excluded.

## Honest limitations (also stated in the app itself)

1. **Detection is not prevention.** A finding means an instruction was surfaced; it is not evidence
   that an agent would have refused it.
2. **Levels are rule-based tiers, not probabilities.**
3. **No real-page false-positive rate has been measured yet — NOT RUN.**
4. **The external matrix is provisional** and was measured under one capability template.
5. **The UA probe is a lower bound**; behavioural fingerprinting can cloak without any UA difference.
6. **DNS rebinding is not solved.**
7. **Screenshot/OCR-based agents and PDFs are out of scope.**
8. **A known normaliser defect is documented and pinned by a test rather than hidden.**

See `README.md` §21 for the full list with evidence pointers.
