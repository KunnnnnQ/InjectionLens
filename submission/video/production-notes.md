# InjectionLens — demo video production notes

**Deliverable:** `submission/video/injectionlens-demo.mp4`
**Made:** 2026-09-20, from the finished local build of InjectionLens.
**Status:** rendered, playable, verified. **Not uploaded anywhere** — the owner handles
publication and the Devpost submission.

---

## At a glance

| | |
| --- | --- |
| Duration | **4:22.99** (262.99 s) — strictly under the 5-minute limit |
| Resolution | 1920 × 1080 (16:9, SAR 1:1, DAR 16:9) |
| Frame rate | 30 fps |
| Video | H.264 High, `yuv420p`, CRF 21, ~1050 kb/s |
| Audio | AAC-LC, 44.1 kHz mono, 160 kb/s |
| File size | 39.4 MB |
| Narration | AI-generated English, Microsoft Neural TTS (`en-US-AndrewMultilingualNeural`) |
| Subtitles | burned in **and** supplied as `subtitles.srt` (56 cues) |
| Footage | real screen recordings of the running application, 1920×1080 |

## What the video shows

Eight scenes, each backed by a real recording of the local application:

| # | Scene | Content |
| --- | --- | --- |
| 1 | Intro | The scam-ad replica as a human sees it, scrolled inside the product's own human-view panel |
| 2 | One-click demo | `▶ Run the demo` → verdict **HIGH**, 8 findings, intents, F1 expanded to its original instruction and source path |
| 3 | Four ingestion pipelines | HTTP source 19 / Rendered DOM 10 / Reader-Markdown 4 / Accessibility tree 20, with the product's own "not a statement that the pipeline is safe" note |
| 4 | Capability-aware risk | `replica-payment-5000.html` under `summary-only` (**HIGH**) then `browser-agent` (**CRITICAL**) |
| 5 | Local UA cloaking | `/fixtures/cloaking.html`, banner naming **GPTBot**, 1155 B vs 759 B, 8/8 tokens probed |
| 6 | Hidden channels | Assistant-link prompts and a URL fragment, under the product's own heading "Channel checks (not ingestion pipelines)" |
| 7 | Measurement and limits | The real contents of `eval/results/` files, plus the stated limitations |
| 8 | Close | Title card — "You cannot defend against what you cannot see." |

## How it was made

1. **Narration** — `edge-tts` (Microsoft Neural TTS) via Python, one MP3 per scene so each
   could be timed and measured independently, then concatenated with 0.35 s editorial gaps.
   Rate `-4%` for a measured, non-advertising delivery. The voice is presented in the video
   itself as **AI-generated narration**; it is **not** an imitation of the owner's voice, and
   the owner did not record any audio.
2. **Footage** — Playwright driving the real application at 1920×1080 (`deviceScaleFactor: 1`),
   recording each scene separately. Real clicks, real analyses, real scrolling; no simulated or
   redrawn UI. Two supporting pages (the results-file view and the closing card) are built from
   the **actual contents of the result files**, read from disk at build time.
3. **Assembly** — each clip was stretched to its own narration segment's measured length with
   ffmpeg `setpts`, concatenated, then muxed with the narration and the burned-in subtitles.

### The one rendering problem worth recording

Subtitles first came out **blurry and washed out**. The cause was not the styling: the
`subtitles` filter builds its canvas from libass's default assumption, so text was rasterised
at a fraction of the output resolution. Verified by comparison across several style variants;
fixed by scaling to 1920×1080 before the filter and passing
`original_size=1920x1080`. Without that parameter the subtitles look soft no matter what
`force_style` says.

## Measured timings

| Scene | Narration | Clip used | Speed applied |
| --- | --- | --- | --- |
| scene0-intro | 18.26 s | 23.64 s | 1.270× faster |
| scene1-scamad | 45.67 s | 43.36 s | 0.942× (stretched) |
| scene2-pipelines | 45.96 s | 45.64 s | 0.986× |
| scene3-capability | 28.66 s | 18.64 s | 0.643× (stretched) |
| scene4-cloaking | 31.85 s | 34.20 s | 1.062× |
| scene5-channels | 23.35 s | 27.24 s | 1.149× |
| scene6-measurement | 40.15 s | 42.24 s | 1.043× |
| scene7-close | 26.64 s | 27.32 s | 1.012× |

Every speed factor is within 1.27× of real time, so the interface still moves at a believable
pace — no scene was compressed to the point of looking sped up.

## Verification performed

| Check | Result |
| --- | --- |
| File exists, decodes cleanly | **0 decode errors** on a full `-f null` pass |
| Duration | 262.99 s — **under 5 minutes** |
| Streams | H.264 High 1920×1080 30 fps + AAC-LC 44.1 kHz mono |
| Audio present and audible | `mean_volume -21.8 dB`, `max_volume -3.7 dB` |
| Long silence / dead audio | **0** silence events > 3 s at −45 dB |
| Subtitles | 56 cues, timed from the real narration track; last cue ends at 262.99 s |
| Subtitle legibility | inspected over both light and dark panels after the fix above |
| Coverage of every scene | 16-frame contact sheet + 12 timeline frames inspected |
| Number accuracy | every figure re-verified against the live application before recording |
| Private data | no credentials, keys, or personal paths appear on screen; fixtures use reserved domains only |
| `[TO FILL]` placeholders | none appear anywhere in the video |

## What the video deliberately does not claim

* No prevention claim. The closing card states plainly: **detection is not prevention**.
* The matrix figures (**808 / 3176 = 25.4 %** at medium-or-above, **628 / 3176 = 19.8 %** at
  high-or-above) are shown with the wording **"historical, pre-P1 ... provisional ... not
  current real-world detection accuracy"**, read from `eval/results/evaluation-summary.md`.
* The eight replica cases are described as **"our own declared expectations on our own local
  fixtures — a regression result, not proof of prevention"**.
* Real-world benign-page false positives are stated as **NOT RUN**.
* The Unicode normalisation gap is stated as **unresolved and documented**.
* No live deployment, no award, no submission status is implied anywhere.

## Safety boundaries observed

All footage is of the local application on loopback. No third-party host was contacted, no URL
inside an attack fixture was followed, no extracted prompt was sent to any assistant, and no
unauthorised User-Agent probe was performed. No production code, test, evaluation result or
protected planning document was modified, and no Git command was run.

## Reproducing

The production scripts are working files and live outside the repository (temporary directory),
by design: the repository carries the output, not the toolchain. They are:

`gen_narration.py` → `capture_footage.js` → `build_pages.js` → `measure_footage.py` →
`assemble.py` → `qc_video.py`

Requirements: Node 24 with the project's `playwright-core` and a system Chrome/Edge, Python 3,
and two small user-scoped packages — `edge-tts` (narration) and `imageio-ffmpeg` (a bundled
static FFmpeg, since none was on `PATH`). No system-wide installation was performed.
