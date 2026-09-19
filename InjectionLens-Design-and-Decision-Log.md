# InjectionLens: Design and Decision Log

> This log records how InjectionLens went from picking a topic to the build after the start. It marks the AI tools used at each step, as required by the hackathon's "AI & External Tools Disclosure" rule.
> Places marked **[TO FILL]** must be completed in your own words. Judges are likely to ask about these points, so think them through in advance.

---

## 1. Timeline

| Time (UTC+8) | Phase | What I did / decided | What the AI tools did |
|---|---|---|---|
| 9/18 (Fri) 14:24 | Pre-event: finding a direction | Had no idea yet; asked AI for candidate directions based on the hackathon themes | ChatGPT suggested three directions: ScamLens Student (its recommendation), InjectionLens, and BeforeShare |
| 9/18 14:31 | Pre-event: choosing the topic | **Chose InjectionLens instead of ScamLens, the option the AI recommended**, and asked for technical research before settling on a design | — |
| 9/18 15:15 | Pre-event: research | Asked for research on mainstream approaches, academic discussion, and existing solutions | ChatGPT compiled the threat model, defense approaches, representative research, and existing products into a first-draft design |
| 9/18 15:18 | Pre-event: challenge | Raised 10 challenges to the first draft (see section 4) **[TO FILL: whether I wrote these challenges myself or organized them with the help of a tool]** | **[TO FILL]** |
| 9/18 19:53 | Pre-event: revision | Adopted the revised positioning | ChatGPT revised the design based on the challenges and re-checked competitors (finding BrowseSafe, Check Point, and others) |
| 9/18 20:08 | Pre-event: compliance | Read the hackathon rules and the organizer's clarification; confirmed that only research and preparation would happen before the start | ChatGPT provided a pre-event preparation checklist and the MVP scope |
| 9/19 22:00 | **Start** | Wrote no project code before the start (the earliest project file was created at 22:07:19) | — |
| 9/19 22:07–22:37 | Build | Handed the MVP scope fixed before the event to a coding agent, then ran verification | The Kimi coding agent generated the MVP code (the exact instructions are in the Kimi session log) |
| 9/19 22:40 onward | Audit | Audited the MVP against 2025–2026 real attack reports and found false positives, bypasses, and coverage gaps | Claude Code searched for real cases and ran adversarial tests |

---

## 2. Decision 1: InjectionLens rather than the AI-recommended ScamLens

- **Fact**: ChatGPT recommended ScamLens Student (a scam-screenshot explainer for students) because it has concrete users, a small scope, and is easy to demo.
- **My choice**: InjectionLens, which detects prompt injection in web pages aimed at AI agents.
- **Reason**: I wanna to take on a harder technical problem

---

## 3. Decision 2: Research first, then settle on a design

Key points from the pre-event research (done with ChatGPT's help):

**Problem definition**
- Three kinds of problems need to be distinguished: jailbreaks (the user makes the model break its safety rules), direct prompt injection (the user overrides the developer's instructions), and indirect prompt injection (malicious instructions hidden in web pages, emails, documents, or tool results).
- The project focuses on the third kind. OWASP lists Prompt Injection as LLM01:2025.
- The level of risk depends on the agent's permissions. For a summarizer, the worst outcome is a manipulated result. If the agent can access email, cloud storage, or the internet, data exfiltration becomes possible.

**Mainstream defense approaches**

| Approach | Idea | Main problem |
|---|---|---|
| Rule and structure scanning | Look for hidden DOM, zero-width characters, and encoded text | Easy to bypass, and prone to false positives |
| Dedicated classifiers | Use a small model or an LLM to judge whether content is malicious | Struggles with long text, attacks split across segments, and novel attacks |
| Source marking (Spotlighting) | Mark content as untrusted data | Not a real security boundary |
| Model training (Instruction Hierarchy, StruQ) | Train the model to obey higher-privilege instructions first | Hard for ordinary developers to do themselves |
| Task/action checks (Task Shield) | Check whether each action serves the user's goal | Adds latency and complexity |
| Privilege isolation (CaMeL, sandboxing, least privilege) | Limit the consequences once an injection succeeds | Can't identify the attack itself |

**Existing products**: Azure Prompt Shields, Google Model Armor, Amazon Bedrock Guardrails, Meta Prompt Guard 2, and others. The revision also found that Perplexity has open-sourced BrowseSafe (web-page injection classification), and that Check Point already offers agent-behavior protection (checking whether tool calls deviate from the task).

**Points of debate**
1. False positives are a serious problem, because security tutorials themselves contain attack phrases.
2. Whether content is malicious depends on the user's task.
3. Detection is not protection.
4. No single approach can guarantee safety.

**Pre-event judgment vs. post-start evidence**: Before the event, the view was that real-world attacks were not yet mature. The audit after the start found that Unit 42, Google, and Forcepoint all reported attacks on real web pages in 2026. The problem statement is therefore updated to "already happening and growing" (see `InjectionLens-Real-World-Cases-and-Plan.md`).

---

## 4. Decision 3: Overturning the core design of the first draft

The first draft combined a single AI view, hidden content as the core signal, and a multiplicative risk formula. The challenges raised against it **[TO FILL: source]** and the resulting changes:

| First-draft design | Problem | After the change |
|---|---|---|
| A single "AI View" | Different agents read pages differently: some read raw HTML, some use Readability, and some read the accessibility tree or screenshots | **Multi-pipeline ingestion matrix**: HTTP source, rendered DOM, Reader/Markdown, and accessibility tree |
| Suspiciousness × stealth × task conflict × capability reachability | Under multiplication, a stealth score of 0 lets visible malicious instructions through | Evidence level and impact level are computed separately; stealth only adds weight and never acts as a gate |
| "Is it hidden?" as the core signal | Hidden isn't necessarily malicious (sr-only text, SEO), and visible isn't necessarily safe (social-engineering phrasing) | Look at whether the text addresses the AI, what its intent is, and whether it can reach dangerous capabilities |
| Users fill in the agent's tool permissions themselves | Ordinary users can't fill that in | Preset capability templates (summary-only, browser agent, full access) |
| No evaluation plan | No way to prove it works | Evaluate with an attack set plus benign hard negatives, with the false-positive rate as the headline metric |
| The detector isn't in the threat model | The LLM doing the judging can itself be injected | Include the detector in the threat model |
| Only compares different renderings of the same HTML | The server may return different content to AI based on the User-Agent | Add a UA-difference probe (a signal, not proof) |

**Narrowing the positioning**: BrowseSafe can already classify injection in web pages, and Check Point can already check for task deviation, so neither can serve as the core innovation anymore. The positioning was therefore narrowed to:

> **InjectionLens compares how different agent pipelines ingest the same webpage, highlights suspicious instructions, and shows what dangerous capabilities those instructions could reach.**

---

## 5. Decision 4: Pre-event compliance

- Read the organizer's clarification: before the start (9/19 10:00 AM EDT, i.e. 22:00 UTC+8), only brainstorming, research, and getting familiar with tools are allowed. Code, project skeletons, and UI designs must all wait until after the start.
- In practice: only research and planning happened before the start, and no project code was written. The earliest project file was created at 22:07:19. The file timestamps and the Kimi session log are kept for verification.

---

## 6. Decision 5: Locking the MVP scope (handed to Kimi after the start)

**Core path**: the same web page → four different ingestion results → pinpoint the nodes that differ → switching agent permissions changes the risk level accordingly.

**Must have**
- Only analyze HTML pages under our own control
- Four ingestion pipelines: HTTP Source, Rendered DOM, Reader/Markdown, and Accessibility Tree
- An ingestion matrix that maps back to specific DOM nodes and highlights them on the page
- Capability templates that output evidence and impact levels, not a fake "safety probability"
- Test pages: 2 visible attacks, 2 hidden attacks, 2 benign hard negatives, and 1 UA-conditional response

**Should have**: comparing responses to a browser UA with responses to AI fetcher UAs, simple task-conflict classification, a small evaluation, and JSON report export

**Won't have (future work)**: PDF, screenshots and OCR, arbitrary public URLs, precisely emulating any specific product, model training, the full AgentDojo benchmark, and automatic content sanitization

> Note: this is the scope fixed before the event. The exact instructions sent to Kimi are in the Kimi session log.

---

## 7. After the start: audit and next steps

The MVP ran end to end within 30 minutes. I then audited it against real attack reports with Claude Code's help and found:
- ordinary sentences rated severe;
- hidden malicious instructions downgraded to low risk as soon as "for example" was added;
- real attack phrasing missed;
- HTML attributes not covered;
- an SSRF guard that can be bypassed.

The fix and evaluation plan is in `InjectionLens-Real-World-Cases-and-Plan.md`.

---

## 8. AI usage disclosure (for Devpost)

> **AI & External Tools Disclosure**
> - **ChatGPT**: before the 10:00 AM EDT start (pre-event preparation, as permitted by the organizers), proposed three candidate directions (I chose InjectionLens over its recommended option), researched existing prompt-injection defenses and products, and revised the design after I challenged its first draft. No code.
> - **[Fill in, if applicable]**: helped me structure the 10-point critique of the first design.
> - **Kimi coding agent**: after the start (22:07–22:37 UTC+8), generated the initial MVP (four ingestion pipelines, React UI, first seven test pages) from the scope I had fixed before the event.
> - **Claude (Claude Code)**: researched 2025–2026 incident reports and ran adversarial tests against the MVP detector, surfacing false positives and a two-word bypass.
> - **[Fill in]**: how the fixes and the evaluation were implemented.
>
> The choice of problem, the scope, and the design trade-offs were my decisions. I reviewed the generated code and can explain every module.
