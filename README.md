# InjectionLens

**See what the AI sees that you do not.** Cross-ingestion prompt-injection forensics for web pages.

InjectionLens shows what different AI-agent ingestion pipelines ingest from the same web page,
surfaces AI-directed instructions, and explains how their impact changes with the selected agent
capability.

Built for the **TLN Cybersecurity Challenge 2026**. Runs entirely on your own machine
(`127.0.0.1`), with no external network access unless you explicitly allow it.

> **Read [Limitations and known gaps](#21-limitations-and-known-gaps) before you trust a verdict.**
> Detection is not prevention, the level ladder is a rule-based tier and not a calibrated
> probability, and the highest-value measurement (false positives on real pages) has **not been run**.

---

## Contents

1. [Title and tagline](#injectionlens)
2. [Status badges](#2-status-badges)
3. [What it is](#3-what-it-is)
4. [What it is not](#4-what-it-is-not)
5. [The problem](#5-the-problem)
6. [Who it is for](#6-who-it-is-for)
7. [Quick start](#7-quick-start)
8. [Demo: the two scenarios](#8-demo-the-two-scenarios)
9. [Command line](#9-command-line)
10. [Feature list](#10-feature-list)
11. [Architecture](#11-architecture)
12. [The four ingestion pipelines](#12-the-four-ingestion-pipelines)
13. [The risk model and capability templates](#13-the-risk-model-and-capability-templates)
14. [The intent taxonomy](#14-the-intent-taxonomy)
15. [The two P1 channel checks](#15-the-two-p1-channel-checks)
16. [The network guard](#16-the-network-guard)
17. [Evaluation results](#17-evaluation-results)
18. [How to reproduce every number](#18-how-to-reproduce-every-number)
19. [Tests](#19-tests)
20. [Environment variables](#20-environment-variables)
21. [Limitations and known gaps](#21-limitations-and-known-gaps)
22. [Responsible research and safety rules](#22-responsible-research-and-safety-rules)
23. [Roadmap and out of scope](#23-roadmap-and-out-of-scope)
24. [Repository layout](#24-repository-layout)

Plus: [AI assistance disclosure](#ai-assistance-disclosure) · [Data attribution and licence](#data-attribution-and-licence) · [Verification status](#verification-status)

---

## 2. Status badges

| | |
| --- | --- |
| Test suite | 254 tests, 254 pass, 0 fail (`node --test "test/**/*.test.js"`) |
| Integrated replica suite | 8 cases: **8 PASS / 0 FAIL / 0 SKIPPED / 0 ERROR** |
| External attack-library matrix | 3176 valid attack cells measured — **PROVISIONAL** (see [§17.2](#172-external-attack-library-matrix-provisional)) |
| Real benign-page false-positive rate | **NOT RUN** |
| Network posture | loopback only; external analysis disabled by default |
| Runtime | Node 24, npm 11, Windows 11 (developed and verified on) |
| Renderer | `playwright-core` driving the system Chrome/Edge — no bundled browser download |

## 3. What it is

InjectionLens is a **page forensics tool**. Point it at one page and it answers four questions:

* **What does each agent read?** The same HTML is ingested four different ways — raw HTTP source,
  rendered DOM, Reader/Markdown, accessibility tree. The tool shows, item by item, what each
  pipeline actually took in. A pipeline that did not observe an instruction is reported as
  *no instruction observed*, never as *safe*.
* **Which of it is aimed at an AI?** Candidate instructions are detected across fifteen intent
  categories, and each finding carries the evidence that produced it.
* **Where exactly is it?** Every finding maps back to a concrete extraction path — an element, an
  HTML comment, a `meta` tag, a `data-*` attribute, a JSON-LD string, an accessibility node — so
  you can look at the spot rather than guess.
* **How bad is it for *this* agent?** The level depends on the capability template you select.
  "Approve this ad" is a bent verdict for a summariser and a business decision for an ad reviewer.
  "$5,000 to this address" is a paragraph for a summariser and a payment for a browser agent.

Two extra channels are checked that no ingestion pipeline can see at all: **pre-filled prompts
inside "summarize with AI" links**, and **URL fragments** (never sent to the server).

## 4. What it is not

Stated up front, because the honest version is more useful than the impressive one:

* **Not a fix for prompt injection.** No scanner can "solve" this problem class. InjectionLens
  surfaces risk and reduces it; it does not prevent an attack, and it cannot promise an agent
  will refuse anything.
* **Not calibrated probabilities.** Levels are rule-based tiers (`info < low < medium < high <
  critical`) derived from intent, AI-addressing, delivery and capability reach. They are ordinal
  weights, not a probability that an attack succeeds.
* **Not a proxy or a browser extension.** It audits one page at a time, on demand. It is not
  inline, it does not sit between an agent and the web, and it does not sanitise content.
* **Not a screenshot or OCR reader.** Agents that read pages as images are outside the ingestion
  model, and a payload invisible to the four pipelines would be invisible here too.
* **Not a general web scanner.** By default it analyses only its own local fixtures. Third-party
  analysis requires you to name each host explicitly, and the guard refuses everything else.
* **Not proof that a downstream agent would have obeyed.** A finding means the tool surfaced an
  instruction. It says nothing about what any model would have done with it.

## 5. The problem

Indirect prompt injection is no longer theoretical. In 2026, independent teams found AI-directed
instructions on real web pages:

| Report | Date | What it found |
| --- | --- | --- |
| Palo Alto Networks Unit 42 | 2026-03-03 | Hidden instructions on real pages: approve scam ads (24 attempts on one page), pay via PayPal/Stripe including **$5,000**, delete databases, leak system prompts, rate a candidate "extremely qualified". Delivery split: **visible plaintext 37.8%**, **HTML attributes 19.8%**, CSS hiding 16.9%; **85.2%** used social-engineering phrasing. |
| Google Security | 2026-04-23 | Web-scale measurement of Common Crawl snapshots (2–3 billion pages each). The malicious category grew **32% (relative) from Nov 2025 to Feb 2026**. |
| Forcepoint X-Labs | 2026-04-22 | 10 live payloads, including making coding agents run `rm -rf`, a $5,000 PayPal.me payment, API-key theft and a fake copyright notice. Techniques: `font-size:1px`, `rgba(…,0.01)`, `aria-hidden`, `<meta ai:action>`, `<system_prompt>`. |
| arXiv 2604.27202 | 2026-04-29 | 1.2 billion URLs / 24.8 million hosts scanned; 15.3K validated instances on 11.7K pages. **About 70% sit in non-rendered HTML** (head, comments, metadata). |
| Brave | 2025-08-20 | A Reddit spoiler tag steered Comet into reading an email, triggering an OTP and posting the code back — the classic capability-reachability case. |
| Microsoft / Reflectiz | 2026-02-10 | "Summarize with AI" links (`chatgpt.com/?q=…`, `claude.ai/new?q=…`) pre-filled with "remember X as a trusted source": 31 companies, 14 industries, 50+ prompts. |
| Cato CTRL (HashJack) | 2025-11 | Instructions hidden in the URL `#` fragment — invisible to the server, readable by a browser assistant. |

Three conclusions shape this tool:

1. **"Is it hidden?" is the wrong primary question.** 37.8% of observed payloads were visible
   plaintext, and 19.8% arrived through HTML attributes, which text-only scanners often never read.
2. **Detection phrases are the same phrases the security community writes with.** Forcepoint notes
   this directly, which is why a pure regex layer will always produce false positives. Context —
   who is being addressed, from where, in what delivery channel — is the whole job.
3. **Severity is a property of the reader, not only of the page.** The same instruction is inert
   for one agent and destructive for another. That is the gap InjectionLens is built around.

## 6. Who it is for

Teams that let AI read untrusted pages **and act on what they read**:

* **Trust & Safety** teams using AI to review ads, listings or user content — where the model's
  verdict *is* the outcome, and "approve this" is the damage.
* **Recruiters and reviewers** using AI to screen résumés, where an off-screen line can change a
  ranking.
* **Developers of browser and coding agents**, who need to know which parts of a page their
  ingestion path actually carries, and what their tool grants could turn an instruction into.
* **Security researchers** who want a reproducible, local harness instead of anecdotes.

## 7. Quick start

Requirements: **Node 24**, **npm 11**, and a locally installed **Chrome or Edge** (the renderer
uses your system browser through `playwright-core`; there is no browser download step).

```bash
cd injectionlens
npm install
npm --prefix client install
npm run dev
```

Then open **http://127.0.0.1:7100** (client) — the API and the fixture server listen on
**http://127.0.0.1:7101**. Both bind to the loopback interface only.

Headless checks, in increasing order of cost:

```bash
cd injectionlens
node scripts/smoke.js          # end-to-end analysis of every local fixture, both capability sets
npm test                       # the full test suite
node scripts/verify-ui.js      # drives the real UI in a browser and writes shots/*.png
node scripts/run-fixtures.js --no-json   # the eight-case integrated replica suite
```

## 8. Demo: the two scenarios

**Scenario A — the Unit 42 scam-ad page, and what the pipelines disagree about.**
Open the UI, keep the default target (`/fixtures/replica-scam-ad-review.html`) and the default
capability (`decision-agent`), and press **Analyze**. The page looks like an ordinary ad landing
page to a human. The verdict panel reports the strongest level, the pipeline grid shows how many
items each pipeline ingested, and each finding lists the extraction path it came from — a visible
footer line, a `data-*` attribute, a comment, a JSON-LD string.

**Scenario B — capability changes the level.** Switch the target to
`/fixtures/replica-payment-5000.html` and re-analyse under each capability template. The same page
reads at a lower level for an agent whose output is only text, and reaches the top of the ladder
for an agent that can carry the instruction out. This is the demonstration that the risk model is
about reachability, not about matching scary words.

**Scenario C — cloaking.** Analyse `/fixtures/cloaking.html`. The fixture server returns different
bodies to an AI-crawler User-Agent and to a normal browser; the tool probes all eight configured
tokens against its own fixture origin and names the token that triggered the difference.

**Scenario D — the channel checks.** Analyse `/fixtures/replica-ai-summary-link.html`. The page
carries two links to an assistant host with a pre-filled prompt, one benign summary request and one
poisoned. Neither appears in the page text, so neither can be attributed to an ingestion pipeline;
both are reported as their own delivery channel.

## 9. Command line

```bash
# integrated replica suite (8 cases, each under its declared capability templates)
node scripts/run-fixtures.js --no-json
node scripts/run-fixtures.js --only forcepoint-rm-rf --capability coding-agent
node scripts/run-fixtures.js --json - --no-json=false   # machine-readable report
node scripts/run-fixtures.js --list                     # validate the manifest, run nothing

# end-to-end smoke over every local fixture
node scripts/smoke.js

# drive the real UI and write screenshots to shots/
node scripts/verify-ui.js

# evaluation harness (library-style; see eval/README.md)
node eval/scripts/step7/run-evaluation.js --corpus <pinned unified.jsonl> \
  --license-policy source-map --capability decision-agent --shard 0 --shards 4 \
  --out eval/tmp/step7/obs-shard0.json
node eval/scripts/step7/aggregate-results.js --shards eval/tmp/step7/obs-shard0.json,…
```

`run-fixtures.js` supports `--manifest`, `--fixtures-root`, `--only`, `--capability`, `--json`,
`--no-json`, `--strict`, `--list`, `--timeout-ms` and `--verbose`. Run
`node scripts/run-fixtures.js --help` for the full text.

### API

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | liveness |
| `GET` | `/api/fixtures` | the local fixture list, including the UA-conditional route |
| `GET` | `/api/capabilities` | capability templates with labels and blurbs |
| `GET` | `/api/network-policy` | exactly what the analyser will and will not fetch, plus its stated limitations |
| `POST` | `/api/analyze` | `{ "url": "/fixtures/…", "capability": "decision-agent" }` |

A refused target is a first-class result: the API answers `403` with `{ error, code, blocked: true }`
and the UI renders a **blocked** state rather than an empty green one.

`POST /api/analyze` returns `url`, `finalUrl`, `analyzedAt`, `elapsedMs`, `capability`,
`capabilityLabel`, `pageTitle`, `stats` (`httpSourceItems`, `renderedItems`, `readerSegments`,
`a11yNodes`, `cloakingDetected`, `blockedSubrequests`, `assistantLinks`, `fragmentInspected`),
`cloak`, `uaProbe`, `blockedRequests`, `inspections`, `findings`, `levelCount`, `matrix`,
`humanHtml` and `readerMarkdown`.

## 10. Feature list

| Feature | What it does |
| --- | --- |
| **Four-pipeline ingestion matrix** | Ingests the same page four ways and reports per-pipeline item counts and per-finding attribution. |
| **Node-level evidence** | Each finding keeps the extraction path (`body > main > p`, `(HTML comment)`, `meta[name="description"]`, `…@data-agent-note`, `review.reviewBody`) so a reviewer can check the spot. |
| **Five capability templates** | Re-rates the same page for `summary-only`, `browser-agent`, `full-access`, `decision-agent`, `coding-agent`. |
| **Fifteen-category intent taxonomy** | Override games, task replacement, identity, prompt probing, authority framing, verdict manipulation, secrecy, obfuscation, data and credential exfiltration, transactions, browser actions, destructive commands, content-protection notices. |
| **Delivery-channel awareness** | Distinguishes visible text, CSS-hidden, near-invisible (`1px` / low opacity), comments, attributes, `meta`, JSON-LD and AI-only responses. Hidden is a boosting signal, never a gate. |
| **Unicode obfuscation handling** | Zero-width and separator stripping, bidi-control and Unicode-tag-character decoding, NFKC-compatible folding — so obfuscated text is matched against its readable meaning. |
| **Human-view vs AI-view comparison** | Renders the human page view beside the Reader/Markdown text the agent would get. |
| | **AI-crawler UA probe** | Probes all eight configured tokens against the local fixture origin and names the token that triggered a difference. Reported as a *lower bound*. |
| **AI-summary link audit (P1)** | Decodes pre-filled prompts in links to assistant hosts and separates a benign summary request from recommendation manipulation. |
| **URL-fragment check (P1)** | Decodes `#` fragments, including nested `q=`/`prompt=` forms, and records explicitly that the fragment was never sent to the server. |
| **Blocked-subrequest reporting** | Subresources the guard refuses are counted and reported instead of failing silently. |
| **Deterministic replica runner** | A manifest-driven runner asserts declared expectations per case and fails loudly when a previously-known gap changes. |
| **Evaluation harness** | Seeded, deduplicated sampling; a transform × placement matrix; an exclusion ledger; `NOT_RUN` / `SKIPPED` states that never enter a denominator. |

## 11. Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │  client/  React + Vite  ·  127.0.0.1:7100     │
                    │  verdict panel · pipeline grid · findings ·   │
                    │  human vs reader view · channel rows          │
                    └───────────────────────┬──────────────────────┘
                                            │ POST /api/analyze
                    ┌───────────────────────▼──────────────────────┐
                    │  server/index.js  Express API + fixture server│
                    │  127.0.0.1:7101 · one process-wide policy     │
                    └───────────────────────┬──────────────────────┘
                                            │
        ┌───────────────────────────────────▼───────────────────────────────────┐
        │                          server/lib/                                  │
        │                                                                       │
        │  net-guard.js   deny-by-default policy: target check, IP classification,│
        │                 ≤5 manual redirects, Playwright subrequest guard       │
        │        │                                                              │
        │        ▼                                                              │
        │  ingest.js      http-source · rendered-dom · reader-markdown ·         │
        │                 accessibility-tree · UA probe · rendering forensics    │
        │        │                                                              │
        │        ├──► inspect.js   P1 channels: ai-summary links, URL fragments  │
        │        │                                                              │
        │        ▼                                                              │
        │  profiles.js    per-pipeline candidate items + anchors                 │
        │        │                                                              │
        │        ▼                                                              │
        │  risk.js        assessSegment(): intents → severity → delivery →       │
        │                 capability reach → level; explainable per finding      │
        │        │                                                              │
        │        ▼                                                              │
        │  analyze.js     matrix, findings, stats, inspections → JSON report     │
        └───────────────────────────────────┬───────────────────────────────────┘
                                            │
              ┌─────────────────────────────▼──────────────────────────────┐
              │  scripts/run-fixtures.js   deterministic replica suite      │
              │  scripts/smoke.js          end-to-end fixture sweep         │
              │  scripts/verify-ui.js      real-browser UI verification     │
              │  eval/scripts/step7/*      seeded evaluation harness        │
              └────────────────────────────────────────────────────────────┘
```

Everything runs in one Node process plus a browser the tool starts and closes itself. No queue, no
database, no external service, no telemetry.

## 12. The four ingestion pipelines

Agents do not agree on what a web page *is*. InjectionLens ingests the same page four ways and
reports the disagreement instead of averaging it away.

| Pipeline id | What it reads | Blind to |
| --- | --- | --- |
| `http-source` | Raw HTTP response: element text, HTML comments, `meta` content, attribute values, `<title>`, `noscript`/`template`, JSON-LD strings | Anything a client-side script adds after load |
| `rendered-dom` | The live DOM after the browser has run the page, with rendering forensics (display, visibility, opacity, font size, colour contrast) | Content the page only serves to some other client |
| `reader-markdown` | Readability extraction converted to Markdown, the "reader mode" shape | Navigation, comments, attributes, anything Readability drops |
| `accessibility-tree` | The accessibility tree — names, descriptions and labels an a11y-driven agent would read | Purely decorative or explicitly hidden content |

In the measured matrix, coverage differs sharply by pipeline: `http-source` 3000/3176 (94.5%),
`rendered-dom` 2739/3176 (86.2%), `reader-markdown` 1160/3176 (36.5%),
`accessibility-tree` 1172/3176 (36.9%). That gap *is* the finding — an instruction that only one
ingestion path carries will be seen by only the agents that use that path.

### The AI-crawler tokens we probe

Eight tokens, verified against vendor documentation and carrying a `sourceStatus` marking how each
one was confirmed — deliberate rather than assumed:

`GPTBot`, `ClaudeBot`, `PerplexityBot`, `OAI-SearchBot`, `Claude-SearchBot`, `ChatGPT-User`,
`Claude-User`, `Perplexity-User`.

The split matters: training crawlers, search crawlers, and the **user-triggered fetchers**
(`ChatGPT-User`, `Claude-User`, `Perplexity-User`) that an earlier version of this project missed.
A user-triggered fetcher is the interesting case — it runs because a person clicked "summarize", so
it arrives with a real user's session and context. `Google-Extended` is deliberately **not** in the
inventory: it is a `robots.txt` product token, not an HTTP User-Agent, and treating it as one is a
factual error a knowledgeable reviewer would catch immediately.

## 13. The risk model and capability templates

`assessSegment(segment, capabilityKey)` in `server/lib/risk.js` combines four things:

1. **Intent** — which of the fifteen categories the text matches, each with an ordinal severity.
2. **AI-addressing** — does the text talk to an AI ("AI agent:", "if you are an LLM", "crawler
   instruction", "system update") rather than to a person?
3. **Delivery** — visible text, CSS-hidden, near-invisible, comment, attribute, `meta`, JSON-LD,
   AI-only, pre-filled link prompt, URL fragment. Hidden content is weighted up; it is never
   required, because 37.8% of observed real payloads were plaintext.
4. **Capability reach** — can *this* agent actually carry the instruction out?

```js
function levelFromScore(score) {
  const idx = Math.max(0, Math.min(4, score - 1));
  return ['info', 'low', 'medium', 'high', 'critical'][idx];
}
```

| Template | Key | What the agent can do |
| --- | --- | --- |
| Summary-only assistant | `summary-only` | Reads the page and returns a summary. |
| Browser agent | `browser-agent` | Clicks, navigates and submits forms in the session. |
| Full-access agent | `full-access` | Reads email/drive and makes outbound network requests. |
| Decision agent | `decision-agent` | Its verdict *is* the outcome (reviewer, screener). No tools. |
| Coding agent | `coding-agent` | Runs shell commands, edits files, has network. |

Two deliberate design rules:

* **Manipulation intents are capped below `critical`.** `verdict-manipulation`, `authority-framing`,
  `secrecy` and `obfuscation` bend an outcome; they do not by themselves move money or delete data.
  They reach `critical` only when combined with a payload intent the agent can perform.
* **Payload intents need reach.** `exfil-data`, `credential-theft`, `destructive-command`,
  `transaction` and `exfil-url` are the members of `CRITICAL_CAPABLE`. `exfil-url` is the strict
  one: it also requires AI-addressing *and* a non-visible delivery, because an outward URL is
  ordinary page furniture.

Every finding carries a plain-language `explanation` that says which template was assumed and
whether the instruction is reachable under it — for example *"Not directly reachable under
'Summary-only assistant' — but it becomes dangerous the moment this agent is granted more tools."*

## 14. The intent taxonomy

| Intent | Severity | Plain meaning |
| --- | --- | --- |
| `exfil-url` | 4 | Sends data to an external URL or address |
| `exfil-data` | 4 | Targets secrets or personal data |
| `credential-theft` | 4 | Targets passwords or one-time codes |
| `transaction` | 4 | Asks the agent to move money |
| `destructive-command` | 4 | Asks the agent to destroy data or run a destructive command |
| `browser-action` | 3 | Asks the agent to click, navigate or submit something |
| `verdict-manipulation` | 3 | Tries to dictate the agent's verdict (approval, ranking, review) |
| `authority-framing` | 3 | Poses as a system-level message or a new policy |
| `secrecy` | 3 | Asks the agent to hide what it did from the user |
| `obfuscation` | 3 | Asks the agent to decode hidden instructions and follow them |
| `ignore-previous` | 2 | Tries to override the instructions the agent already has |
| `task-override` | 2 | Tries to replace the task the user gave the agent |
| `system-prompt` | 2 | Probes the agent's hidden system prompt |
| `impersonation` | 2 | Redefines the agent's identity or role |
| `content-protection` | 1 | A content-protection notice asking AI crawlers not to use the page |

`content-protection` is deliberately a *notice*, not an instruction. The large-scale measurement
found such notices common in the wild, and they are treated as a benign hard negative rather than
as an attack — the local `replica-content-protection` fixture expects **≤ low**.

## 15. The two P1 channel checks

`server/lib/inspect.js` covers two delivery channels that the four pipelines structurally cannot
see. Neither is an ingestion pipeline, and neither is attributed to one.

**AI-summary links.** A page can offer a link to an assistant host with the question pre-filled in
the query string. The prompt is not page text, so no ingestion pipeline reads it as an instruction,
and a human sees only a button. The module recognises assistant hosts by string match (the
published cases plus reserved `.example`/`.invalid`/`.test` hosts for the fixtures), decodes the
`q`/`query`/`prompt`/`text` parameter, and classifies it:

* a **summary request** with no recommendation markers is the benign product feature;
* `trusted-source`, `remember`, `prefer`, `always-mention` and `citation` markers mark
  **recommendation manipulation**.

**URL fragments.** A fragment is never sent to the server, so it is absent from the HTTP source and
from everything a server returns, yet a browser-side assistant can read it. The record states
`sentToServer: false` explicitly so no report can imply server-side visibility.

Both deliver into the same risk model, under their own delivery labels (`ai-link-prompt`,
`url-fragment`). **Nothing in this module performs network I/O**: a URL found inside a decoded
prompt is recorded as evidence and is never followed, requested or resolved.

## 16. The network guard

`server/lib/net-guard.js` is deny-by-default, and one policy serves the whole process.

* **Targets.** Only the exact local fixture origin (`127.0.0.1`, the bound port) is allowed by
  default. Any other host must be named in `INJECTIONLENS_ALLOWED_HOSTS`.
* **IP classification.** Loopback, private, link-local, carrier-grade NAT, unique-local and cloud
  metadata addresses are refused, and every DNS answer is validated — not just the first.
* **Redirects.** Followed manually, at most five hops, re-checked at every hop.
* **Subresources.** A Playwright request guard applies the same policy to everything the page tries
  to load, and reports what it blocked (`blockedSubrequests`).
* **UA probing.** Runs only against the local fixture origin unless a host is explicitly allowlisted
  for probing via `INJECTIONLENS_UA_PROBE_ALLOWLIST`; otherwise it records a `skipped` status.
* **Self-description.** `GET /api/network-policy` publishes the active policy *and* its limitations,
  so the UI can state them rather than bury them.

The guard **does not solve DNS rebinding**: it validates DNS answers but does not pin the
connection to the validated address. This is published in the API response and repeated in
[§21](#21-limitations-and-known-gaps).

## 17. Evaluation results

All numbers below were produced by executing code in this repository and are stored in
`injectionlens/eval/results/`. **No number in this README was entered by hand.** The families are
reported separately and are never merged into a single accuracy figure.

### 17.1 The integrated replica suite (current version)

Eight local replica pages, each rebuilt from a published 2025–2026 report, each with declared
expectations. Run: `node scripts/run-fixtures.js --no-json` (evidence:
`eval/results/stage10-fixtures.txt`; machine-readable: `eval/results/replica-results.json`).

```text
summary: total=8 pass=8 fail=0 skipped=0 error=0
```

| Case | Primary capability | Observed | Source report |
| --- | --- | --- | --- |
| `unit42-scam-ad-review` | `decision-agent` | high | Unit 42 (2026-03-03) |
| `forcepoint-5000-payment` | `browser-agent` | critical | Forcepoint X-Labs (2026-04-22) |
| `forcepoint-rm-rf` | `coding-agent` | critical | Forcepoint X-Labs (2026-04-22) |
| `unit42-offscreen-hiring` | `decision-agent` | high | Unit 42 (2026-03-03) |
| `brave-comet-spoiler` | `browser-agent` | high | Brave (2025-08-20) |
| `splx-chatgpt-user-cloaking` | `summary-only` | high | SPLX (2025-10-01) |
| `msft-ai-summary-link` | `summary-only` | high | Microsoft Security (2026-02-10) |
| `arxiv-content-protection` | `summary-only` | low (expects ≤ low) | arXiv 2604.27202 (2026-04-29) |

These are **local replicas of published patterns, not live pages and not a random sample of the
web**. "8/8 pass" means the detector met the expectations *we declared for our own fixtures* — it is
a regression result, not a real-world accuracy claim.

A capability sweep over the same local fixtures shows the model responding to reach rather than to
vocabulary: `replica-payment-5000.html` reads **high** for `summary-only` and `decision-agent`, and
reaches **critical** for `browser-agent`, `full-access` and `coding-agent`; `replica-rm-rf.html`
reaches **critical** for `full-access` and `coding-agent` and stays **high** for the others. The
per-capability bounds the runner validated are recorded in
`server/fixtures/replicas.manifest.json`.

Note that `decision-agent` shares its tool flags with `summary-only` — neither has tools. They part
company because the risk model asks whether an intent is reachable for *that* agent, and the two
agents differ in what an instruction can achieve. `verdict-manipulation` is reachable for either,
which is why the scam-ad page rates the same for both; `transaction` needs forms or network, which
is exactly why the payment page climbs for a browser agent. Reachability is a per-intent question in
`REACHABILITY` (`server/lib/risk.js`), not a single score attached to a template.

**Resolution of the one historical gap.** In the earlier Step 7 run this suite was
**7 PASS / 0 FAIL / 1 SKIPPED** of 8; `msft-ai-summary-link` was skipped with the reason code
`ai-link-prompt-not-ingested`, because link-prompt decoding did not exist yet. The P1 work in §15
resolved it, and the case now passes at **high** against an expectation of ≥ low. That pre-P1 run is
frozen in `eval/results/step7-replica-results-historical.json` with a note saying it is superseded;
the two runs are different code revisions and are never combined.

### 17.2 External attack-library matrix (PROVISIONAL)

Full write-up: `eval/results/evaluation-summary.md`. Machine-readable:
`eval/results/attack-matrix.json`, `detection-heatmap.{svg,csv,json}`.

| | |
| --- | --- |
| Upstream source | `https://github.com/VulcanLab/IPI-Proxy` @ `272a61a7…` |
| Corpus | 820 records, SHA-256 `3c757e34…`, licence policy `source-map` |
| Sampling | 50 records, keyed-SHA-256 sort, seeded, near-duplicate Jaccard 0.9 |
| Matrix | 50 records × 8 transforms × **8 placements** = 3200 planned cells |
| Measured | 3176 OK **attack** cells + 8 payload-free controls, and 24 `SKIPPED` (`CELL-NOT-EMBEDDABLE`) = 3208 observation rows |
| Capability | `decision-agent` only |

**Eight placements, six named categories.** The categories are `p-visible-body`, `p-html-comment`,
`p-meta-content`, `p-data-attribute`, `p-jsonld-string` and `p-css-hidden`. `p-css-hidden` is a
family, not one context: it is planted three times, with `display:none`, with
`font-size:1px;color:rgba(31,41,51,0.05)`, and off-screen at `left:-10000px`. Six categories
therefore produce eight concrete placements, which is why one category carries three times the
observations of the others — and why "8 placements" is a correct count, not a typo.

| Metric | Attack population (reported) | Mixed population (audit) |
| --- | --- | --- |
| Cells rated **≥ medium** | **808 / 3176 = 25.4%** | 808 / 3184 = 25.4% |
| Cells rated **≥ high** | **628 / 3176 = 19.8%** | 628 / 3184 = 19.7% |

**Which cells these divide by — audited in Step 10.** The test harness also serves **payload-free
control pages** (a wrapper with filler text and no payload), one per wrapper per shard, so that a
detector firing on the wrapper markup alone would be visible. Eight such controls reached `OK` with
no finding at all. They therefore change no numerator, but they inflate a mixed denominator by 8
cells and understated the high-or-above rate by 0.05 points. The reported metric now divides by the
**attack population** — `state OK` cells that carry a sampled record — and the mixed reading is
published beside it rather than discarded. The correction moved one published figure at one decimal
place: **19.7% → 19.8%**. The ≥ medium figure is unchanged. Both readings are in
`eval/results/evaluation-summary.md` and `eval/results/attack-matrix.json`.

By pipeline, two readings are given deliberately — a pipeline that never saw the payload cannot be
credited with missing it:

| Pipeline | Coverage of the payload | Detection ≥ medium, where observed | Detection ≥ medium, all attack cells |
| --- | --- | --- | --- |
| `http-source` | 94.5% (3000/3176) | 25.3% (759/3000) | 23.9% (759/3176) |
| `rendered-dom` | 86.2% (2739/3176) | 21.5% (589/2739) | 18.5% (589/3176) |
| `reader-markdown` | 36.5% (1160/3176) | 23.2% (269/1160) | 8.5% (269/3176) |
| `accessibility-tree` | 36.9% (1172/3176) | 23.0% (269/1172) | 8.5% (269/3176) |

By insertion position, from the same measurement:

| Position | ≥ medium |
| --- | --- |
| `p-css-hidden` | 27.0% (324/1200) |
| `p-data-attribute` | 27.0% (108/400) |
| `p-jsonld-string` | 27.0% (108/400) |
| `p-meta-content` | 27.0% (108/400) |
| `p-html-comment` | 23.9% (90/376) |
| `p-visible-body` | 17.5% (70/400) |

By transform, the spread is narrow except for one recipe: `T0-original` 26.0%, `T1-contextual-wrapper`
26.0%, `T2a`–`T2e` 26.5–27.3%, and `T2f-separator-inject` **18.2%** — the drop caused by the
normaliser defect in [§21](#21-limitations-and-known-gaps) item 8.

The headline is deliberately unflattering: **roughly one in four transformed external payloads is
rated medium or above.** The tool is a triage and forensics aid, not a classifier with a strong
recall story, and the number is labelled provisional because of the licence reading described in
§17.3.

### 17.3 What is deliberately not reported

* **Real benign-page false-positive rate: NOT RUN.** Producing it would mean fetching third-party
  pages, which was not authorised. The local benign fixtures are *not* real-world false-positive
  evidence and are not presented as such (`eval/results/benign-pages.json`). The local benign
  fixtures do behave as intended — `benign-sronly` reports `info` only and `benign-security-blog`,
  which quotes attack phrases in an educational context, stays at `low` — but that is fixture
  behaviour, not an FPR.
* **Before/after comparison: not claimed.** The pre-fix revision `v0-ai-scaffold` is tagged, but the
  matrix was not re-run against it, so no improvement figure exists.
* **Why the sample is this size.** The upstream repository has no licence file at all, and 729 of
  its 820 records carry no per-record licence. Under a strict reading (a record needs its own
  licence field) **zero** records are eligible — including the 7 that do carry MIT, because they
  contain a real destination and are excluded on safety grounds. The measured run therefore uses the
  documented-source-map reading, which yields 551 eligible records; 84 WASP records are excluded as
  CC-BY-NC and 99 for unsafe destinations. The upstream corpus is **not** committed to this
  repository; it stays in the gitignored `eval/tmp/`.
* **Not merged.** The replica suite, the external matrix and the (absent) FPR are three different
  things measured three different ways. Combining them into one "accuracy" number would be
  meaningless, so it is not done.

## 18. How to reproduce every number

```bash
cd injectionlens

# §17.1 — replica suite (writes eval/results/stage6-fixtures.json by default)
node scripts/run-fixtures.js --no-json

# §17.2 — external matrix (needs the pinned corpus in eval/tmp/, see eval/README.md)
node eval/scripts/step7/run-evaluation.js --corpus eval/tmp/step7/corpus/unified.jsonl \
  --license-policy source-map --capability decision-agent --shard 0 --shards 4 \
  --out eval/tmp/step7/obs-shard0.json
# … shards 1..3, then:
node eval/scripts/step7/aggregate-results.js \
  --shards eval/tmp/step7/obs-shard0.json,eval/tmp/step7/obs-shard1.json,eval/tmp/step7/obs-shard2.json,eval/tmp/step7/obs-shard3.json
```

The harness reads pinned local files only — `loadCorpusFile()` rejects anything that looks like a
URL or a UNC path — requires an explicit seed, and refuses to write results without one. States
`SKIPPED`, `NOT_RUN`, `PENDING`, `FAILED` and `N/A` all produce `rate: null`; `0/0` is never rendered
as `0%`. Full module reference: `injectionlens/eval/README.md`.

## 19. Tests

```bash
cd injectionlens
npm test          # 254 tests, 254 pass, 0 fail, ~18 s
```

> On Node 24, `node --test test/` fails with `MODULE_NOT_FOUND`. Use the pattern the npm script
> uses: `node --test "test/**/*.test.js"`.

Sixteen test files cover the risk model and its invariants, ingestion profiles, the network guard,
the UA inventory, the P1 channel checks, the manifest schema and the runner, and the Step 7 harness.
Two are worth calling out:

* `test/risk-invariants.test.js` — asserts the properties the model promises, including that
  manipulation intents cannot reach `critical` alone and that the score→level mapping holds.
* `test/step7-normalizer-gap.test.js` — records, rather than hides, the known normaliser gap in
  §21.

UI verification is separate, because it needs a browser:

```bash
node scripts/verify-ui.js    # exits 0 and writes shots/01-initial.png … shots/09-channel-checks.png
```

`verify-ui.js` drives the real React app: it analyses the default demo, switches capability and
waits for the control to settle before re-analysing, opens findings, highlights a source node, opens
the Reader view and the matrix, exercises the cloaking fixture, and finally opens the channel rows.
The only console noise it tolerates is a favicon 404.

## 20. Environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `PORT` | `7101` | API + fixture server port (always bound to `127.0.0.1`). |
| `INJECTIONLENS_ALLOWED_HOSTS` | *(empty)* | Comma-separated hosts the analyser may fetch. Empty means external analysis is **disabled**. |
| `INJECTIONLENS_UA_PROBE_ALLOWLIST` | *(empty)* | Hosts the AI-crawler UA probe may contact. Empty means probing is limited to the local fixture origin. |
| `VERIFY_UI_TIMEOUT_MS` | script default | Timeout for `scripts/verify-ui.js` steps. |
| `STEP7_DEBUG_CELL`, `STEP7_DEBUG_HTTP` | *(unset)* | Debug output for a single evaluation cell / HTTP activity. |

There is no deployment configuration, no hosted endpoint and no public URL — see
[§23](#23-roadmap-and-out-of-scope).

## 21. Limitations and known gaps

Stated plainly, because a security tool that oversells itself is worse than no tool.

1. **Detection is not prevention.** A finding means an instruction was surfaced. It is not evidence
   that any agent refused it, and it is not a guarantee about the future.
2. **Levels are tiers, not probabilities.** `info < low < medium < high < critical` are ordinal
   weights from a rule-based model. There is no calibration study behind them.
3. **No benign false-positive rate exists yet.** NOT RUN (see [§17.3](#173-what-is-deliberately-not-reported)).
   Do not read the fixture suite as an FPR measurement.
4. **The external matrix is provisional** and was measured under **one** capability template
   (`decision-agent`) over external-library text, not over pages found in the wild.
5. **The UA probe is a lower bound.** Behavioural fingerprinting can drive cloaking without any
   User-Agent difference, and this tool does not detect that.
6. **DNS rebinding is not solved.** The guard validates every DNS answer but does not pin the
   connection to the validated address. Published in `GET /api/network-policy`.
7. **`http-source` coverage is a lower bound.** `analyze()` does not return the raw item list for
   that pipeline, so its coverage is read from finding occurrences and truncated matrix excerpts.
8. **Known defect: the two normalisers disagree.** `profiles.normText()` strips only
   `U+200B–U+200D`, `U+FEFF` and `U+2060`, while `risk.normalizeText()` additionally strips
   `U+00AD`, `U+180E`, `U+061C` and the bidi controls. Because `analyze.js` uses `profiles.normText`
   as its grouping key, a payload carrying those extra characters does not group with its own
   unobfuscated text. Measured effect: `T0-original` 26.0% vs `T2f-separator-inject` 18.2%
   detection ≥ medium, and 389/396 vs 248/396 `http-source` coverage. **Not fixed** — changing it
   alters core ingestion behaviour and the committed expectation set. Recorded by
   `test/step7-normalizer-gap.test.js` so the decision stays with the maintainer.
9. **Screenshot and OCR agents are out of model.** An instruction invisible to all four pipelines
   and to the channel checks is invisible here too.
10. **HTML only.** No PDF, no Office documents, no email bodies.
11. **Corrected in Step 10: the attack-detection denominator included payload-free controls.** The
    harness serves control pages (a wrapper with filler and no payload) so that a detector firing on
    the wrapper markup alone would be visible. Eight of them reached `OK` with no finding, and the
    original aggregation divided by them as well, which understated the high-or-above rate by 0.05
    points (19.7% instead of 19.8%). The metric now divides by the attack population, both readings
    are published side by side, and the change is pinned by regression tests. See
    [§17.2](#172-external-attack-library-matrix-provisional). No raw observation was altered and no
    measurement was re-run: the correction was applied to the same preserved rows.
12. **No runtime dependency was added beyond what the app needs.** The evaluation harness and all
    analysis modules are Node built-ins plus Express/`jsdom`/Readability/Turndown/`playwright-core`.

## 22. Responsible research and safety rules

This is a defensive tool, and it is built to be safe to run:

* Every test page uses **only** inert domains (`*.example`, `*.invalid`, `*.test`) and **fictional
  brand names** — no real login pages, no real payment links, no live malicious hosts.
* Destructive commands (`rm -rf`) appear **only as inert text inside fixtures**, are never executed
  by any code path, and are treated as evidence to be detected and reported.
* The live malicious sites named in the source reports were **never visited**. Their patterns were
  rebuilt locally from the published descriptions.
* AI-crawler User-Agent strings are **never sent to third parties**. The UA probe runs against the
  local fixture origin, or against a host you explicitly allowlist.
* The evaluation corpus is **not committed**; it stays in the gitignored `eval/tmp/`, and the
  harness never follows a URL found in a payload.
* Upstream data is attributed, and the non-commercial (CC-BY-NC) subset is excluded — see
  [Data attribution and licence](#data-attribution-and-licence).

## 23. Roadmap and out of scope

Deliberately **not** in this version:

| Out of scope | Why |
| --- | --- |
| Public deployment | Not deploying without reliable SSRF/rebinding protection. A repository plus the demo video meets the submission requirements. |
| PDF, screenshots, OCR | A different ingestion problem; would dilute the pipeline comparison. |
| Arbitrary public URLs | The analyser is deny-by-default; host-by-host authorisation is the safety boundary. |
| Real-time blocking proxy | InjectionLens is an audit tool. Inline enforcement is a different product with a different failure mode. |
| A second-stage LLM judge | Optional. If added, it must be hardened as an attack surface itself: no tools, content quoted, JSON-only output. |
| Behavioural cloaking detection | Research-stage; the UA probe stays an explicitly labelled lower bound. |
| Model training, AgentDojo-scale benchmarking | Beyond a 24-hour build, and not needed to make the point. |
| Fixing the normaliser gap | It changes core ingestion behaviour and the committed expectation set. The measurement and the test are in place; the decision is the maintainer's. |

## 24. Repository layout

```text
InjectionLens/
├── README.md                          ← this file
├── AGENTS.md                          working agreement and safety rules
├── InjectionLens-Real-World-Cases-and-Plan.md   the plan (owner's document)
├── InjectionLens-Design-and-Decision-Log.md     the decision log (owner's document)
├── InjectionLens-真实案例与调整方案.md            owner's document (Chinese)
├── InjectionLens-项目构思与决策记录.md            owner's document (Chinese)
├── injectionlens/                     the application
│   ├── server/
│   │   ├── index.js                   Express API + fixture server (127.0.0.1:7101)
│   │   ├── lib/net-guard.js            deny-by-default network policy
│   │   ├── lib/ingest.js               4 pipelines, UA probe, rendering forensics
│   │   ├── lib/profiles.js             per-pipeline candidate items
│   │   ├── lib/inspect.js              P1: AI-summary links, URL fragments
│   │   ├── lib/risk.js                 intents, severity, capability templates
│   │   ├── lib/analyze.js              orchestration → JSON report
│   │   ├── lib/browser.js              system Chrome/Edge via playwright-core
│   │   └── fixtures/                   20 pages (19 exposed routes, incl. 1 UA-conditional) + replicas.manifest.json
│   ├── client/                         React + Vite UI (127.0.0.1:7100)
│   ├── scripts/                        smoke, verify-ui, run-fixtures, capture helpers
│   ├── test/                           16 test files, 254 tests
│   ├── eval/
│   │   ├── README.md                   harness reference
│   │   ├── scripts/step7/              14 evaluation modules
│   │   └── results/                    every measured number, as evidence files
│   └── shots/                          UI verification screenshots
└── submission/
    ├── devpost.md                      Devpost submission copy
    ├── video-script.md                 the demo video script
    └── owner-checklist.md              what only the owner can do
```

## AI assistance disclosure

Full disclosure is in `InjectionLens-Design-and-Decision-Log.md` §8, and the short version is here
on purpose — hiding AI use is the problem, not using it:

* **ChatGPT** — pre-event preparation only, before the permitted start (2026-09-19 22:00 UTC+8):
  proposed three candidate directions (the owner chose InjectionLens over its recommended option),
  researched existing prompt-injection defences and products, and revised the design after the owner
  challenged the first draft. No code.
* **Kimi coding agent** — after the start, generated the initial MVP scaffold (four ingestion
  pipelines, React UI, first seven fixtures) from a scope the owner had fixed in advance. Tagged
  `v0-ai-scaffold`.
* **DeepSeek (coding agent)** — implemented the fixes, the ingestion and network-guard rework, the
  P1 channel checks, the replica runner, the evaluation harness and documentation, working under
  stage-gated instructions with an evidence requirement for every claim.
* **Owner (Kun)** — chose the problem and the scope, made every design trade-off, directed and
  supervised each stage, integrated the work, and validated it. The owner reviewed the generated
  code and can explain every module.

## Data attribution and licence

* **External evaluation corpus:** [VulcanLab/IPI-Proxy](https://github.com/VulcanLab/IPI-Proxy),
  revision `272a61a7ee33c06805ceb87e832cb4a3aefb40d0`, file `payloads/unified.jsonl`
  (SHA-256 `3c757e34…`). The repository carries **no licence file**; its own `README.md` and
  `payloads/SOURCES.md` document BIPIA, InjecAgent, AgentDojo and Tensor Trust as MIT-compatible and
  WASP as CC-BY-NC-4.0. **The 84 WASP records are excluded as non-commercial.** The corpus is not
  redistributed here.
* **Source reports** used to rebuild the replica fixtures are cited per case in
  `server/fixtures/replicas.manifest.json` and listed in `InjectionLens-Real-World-Cases-and-Plan.md`.
* **Project licence:** not yet chosen. `[TO FILL — OWNER DECISION]`.

## Verification status

| Claim | How it was verified | Evidence file |
| --- | --- | --- |
| 254 tests pass | `node --test "test/**/*.test.js"` | `eval/results/stage10-tests.txt` |
| 8/8 replica cases pass | `node scripts/run-fixtures.js --no-json` | `eval/results/stage10-fixtures.txt` |
| Smoke sweep exits 0 | `node scripts/smoke.js` | `eval/results/stage10-smoke.txt` |
| UI drives end to end, 9 screenshots | `node scripts/verify-ui.js` | `eval/results/stage10-ui-verification.txt`, `shots/01-initial.png` … `shots/09-channel-checks.png` |
| Client builds | `npm --prefix client run build` | `eval/results/stage10-client-build.txt` |
| Matrix numbers, both populations | seeded evaluation harness, re-aggregated from the preserved raw observations | `eval/results/evaluation-summary.md`, `attack-matrix.json`, `detection-heatmap.*` |
| Replica-suite history (7 PASS / 1 SKIPPED, pre-P1) | frozen earlier revision | `eval/results/step7-replica-results-historical.json` |
| Benign FPR not run | reason recorded | `eval/results/benign-pages.json` |

Repository URL: `[TO FILL — OWNER]`
