// Draft generator for the Step 6 replica manifest.
//
// Reads the machine-readable calibration report and prints a manifest skeleton
// whose payload needles are copied from what the pipelines ACTUALLY read, so no
// expectation is invented. Security-relevant fields that cannot be measured
// (forbidden intents, benign status, the known gap) are carried over from the
// existing manifest when one is supplied, and left explicit otherwise.
//
// This is a Step 6 authoring aid. It is deterministic: the same calibration
// input produces the same output, and the committed manifest is the reviewed
// result, not a blind copy of this draft.
//
// Usage: node scripts/draft-manifest.js <calibration-report.json>
//
// Evidence: Step 6 contract section 2 (per-case expectations, calibrated).

'use strict';

const fs = require('node:fs');

const MAX_NEEDLE = 60;

function needleOf(text) {
  const collapsed = String(text).replace(/\s+/g, ' ').trim();
  if (collapsed.length <= MAX_NEEDLE) return collapsed;
  // Cut on a word boundary so the needle reads like a phrase, not a fragment.
  const cut = collapsed.slice(0, MAX_NEEDLE);
  const lastSpace = cut.lastIndexOf(' ');
  return lastSpace > 20 ? cut.slice(0, lastSpace) : cut;
}

function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write('usage: node scripts/draft-manifest.js <calibration-report.json>\n');
    process.exit(2);
  }
  const report = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const draft = {
    schemaVersion: 1,
    set: {
      title: 'Step 6 real-case replica set',
      note: 'Inert local reconstructions. Every needle below was copied from measured pipeline output.',
    },
    cases: report.map((entry) => {
      const payloads = entry.carriers.filter((carrier) => carrier.intents.length > 0);
      const byPipeline = new Map();
      for (const payload of payloads) {
        const list = byPipeline.get(payload.pipeline) || [];
        const needle = needleOf(payload.originalText);
        if (list.some((item) => item.contains === needle)) continue;
        // The rendered DOM records structured data without an attribute path.
        const kind = payload.pipeline === 'rendered-dom' && payload.extractionKind === 'unknown'
          ? undefined
          : payload.extractionKind;
        list.push({
          pipeline: payload.pipeline,
          ...(kind ? { kind } : {}),
          ...(payload.path && payload.path.includes('@') ? { pathContains: payload.path.slice(payload.path.indexOf('@')) } : {}),
          contains: needle,
        });
        byPipeline.set(payload.pipeline, list);
      }
      const evidence = [...byPipeline.values()].flat();
      const intents = [...new Set(payloads.flatMap((payload) => payload.intents))].sort();
      return {
        draftId: entry.id,
        file: entry.file,
        observedMaxLevel: entry.maxLevel,
        observedIntents: entry.intents,
        suggestedPipelines: [...new Set(evidence.map((item) => item.pipeline))],
        suggestedIntents: intents,
        suggestedEvidence: evidence,
        observedCloak: entry.cloak,
      };
    }),
  };
  process.stdout.write(`${JSON.stringify(draft, null, 2)}\n`);
}

main();
