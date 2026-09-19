// InjectionLens — Step 7 evaluation utilities (Wave A, Lane 3).
//
// What this folder is: the deterministic machinery for the Human Step 7
// evaluation — provenance recording, licence filtering with explicit exclusion
// reasons, keyed-hash sampling, the transformation matrix, safe local page
// placement, and aggregation with explicit numerators, denominators and states.
//
// What this folder deliberately is NOT: a result. It contains no measurement of
// the detector, no percentages, no attack matrix, no heatmap of real data and no
// replica results. Those require the integrated Step 6 base and a real corpus,
// and until then every artefact produced here is stamped PROVISIONAL by
// finalizeArtifact() and may not be presented as a result (assertFinal()).
//
// Entry points:
//   require('./index').sample.sampleDeterministic(...)
//   require('./index').placement.renderPage(...)
//   node eval/scripts/step7/demo-synthetic.js      (prints a synthetic plan to stdout)
//
// Programmatic only: there is no CLI that writes result files, on purpose.
'use strict';

module.exports = {
  states: require('./states'),
  ids: require('./ids'),
  targets: require('./targets'),
  corpus: require('./corpus'),
  filters: require('./filters'),
  sample: require('./sample'),
  variants: require('./variants'),
  placement: require('./placement'),
  aggregate: require('./aggregate'),
};
