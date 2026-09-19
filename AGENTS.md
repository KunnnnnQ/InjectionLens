# AGENTS.md — InjectionLens working agreement

You are my coding agent for InjectionLens, a hackathon project (TLN Cybersecurity Challenge 2026).

Hard deadline: 2026-09-20 10:00 AM EDT (22:00 UTC+8).

We work in STAGES. I send one stage at a time. Do ONLY the stage I send, then report and STOP.

## Project

InjectionLens shows what different AI-agent ingestion pipelines (HTTP source, rendered DOM, Reader/Markdown, accessibility tree) read from the same web page, flags instructions aimed at AI (indirect prompt injection), and rates the impact for different agent capability templates.

## Repo layout

Repo root:
C:\Users\kunqi\Kun\GitHub-Portfolio\00-INBOX\InjectionLens

- injectionlens/: the app (Express API on :7101 + React/Vite client on :7100)
- server/index.js: API, fixture server, URL guard
- server/lib/{ingest,profiles,analyze,risk,browser}.js
- server/fixtures/*.html: test pages
- scripts/smoke.js
- scripts/verify-ui.js
- InjectionLens-Real-World-Cases-and-Plan.md: THE PLAN. §2 real-world cases, §3 audit of the current code (11 issues with file:line), §4 refined idea, §5 schedule. Read §2–§4 before coding.
- InjectionLens-Design-and-Decision-Log.md + two Chinese .md files: the owner's documents.

## Environment

Windows 11, Node 24, npm 11, git.

Headless rendering uses the system Chrome/Edge via playwright-core (server/lib/browser.js).

Run app commands from injectionlens/.

Dev: npm run dev
Smoke: node scripts/smoke.js

## Working rules

1. Stage-gated: do only the current stage. Anything outside its scope goes under "Out of scope" in the report; do not fix it.

2. Commits: one logical change per commit.

   Subject: type(scope): summary

   Body line:
   Evidence: <audit item #, report name, or failing test>

   Trailer:
   AI-assisted: DeepSeek (coding agent)

   Never amend, rebase, force-push, or change commit dates.

   Push to origin/main at the end of each stage.

3. Start of every stage: re-read AGENTS.md, run git status (must be clean) and npm test (from Stage 2 on).

   End of every stage: npm test green unless the stage says otherwise.

4. Dependencies: prefer Node built-ins (node:test, node:assert, node:dns, node:net, node:http).

   No new runtime dependency unless unavoidable; justify any new dependency in the report.

5. Do not edit the four planning docs at the repo root.

   Never fill in "[TO FILL]" / "【待填】" placeholders: those are the owner's own words.

6. Honesty: code comments, UI text, and docs must not claim anything that a test or script output does not show.

   Say "reduces / surfaces risk", never "prevents / solves / guarantees".

   Every number in docs must come from a file in injectionlens/eval/results/.

7. Safety and responsible research (hackathon rule: no damage, no malware):

   - Test pages use only inert domains (*.example, *.invalid, *.test) and fictional brand names.
   - No real login pages, no real payment links.
   - Destructive commands may appear only as inert text inside fixtures. Never execute them.
   - Never visit the live malicious sites named in the reports; rebuild the patterns locally.
   - Never send AI-crawler User-Agent strings to third-party sites.
   - UA probing runs only against the local fixture server or hosts I explicitly allowlist.
   - Respect licenses: attribute external data; exclude non-commercial (CC-BY-NC) data.

8. Only kill processes you started (e.g. on ports 7100/7101).

   If a port is busy, prefer the in-process runners on ephemeral ports.

9. Language:

   Code, comments, commit messages and docs in English.

   Reports to me in Simplified Chinese (keep identifiers and commands in English).

## Report format

End of every stage:

- Stage N: done / partially done (and why)
- Commits: hash + subject
- Test results: paste the summary lines of npm test and of any runner
- What changed: bullets with file paths
- Explanation for the owner: 5 plain-language bullets on what changed and why, so I can explain it to judges
- Out of scope / open issues
- Last line: "STOP — waiting for Stage N+1"

Then wait.
