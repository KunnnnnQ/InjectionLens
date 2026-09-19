// Smoke test: start the app in-process on a random port and run the analysis
// engine over every fixture (no external server, no port conflicts).
const { app } = require('../server/index');
const { analyze } = require('../server/lib/analyze');

const FIXTURES = [
  'attack-visible-comment',
  'attack-visible-product',
  'attack-hidden-displaynone',
  'attack-hidden-whitewhite-comment',
  'benign-sronly',
  'benign-security-blog',
  'cloaking',
];

(async () => {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  console.log(`fixture server on ephemeral port ${port}`);

  for (const capability of ['summary-only', 'full-access']) {
    console.log(`\n########## capability = ${capability} ##########`);
    for (const f of FIXTURES) {
      const url = `http://localhost:${port}/fixtures/${f}.html`;
      try {
        const r = await analyze(url, capability);
        console.log(`\n== ${f} == cloak:${!!r.cloak} levels:${JSON.stringify(r.levelCount)}`);
        console.log(`   pipelines: http=${r.stats.httpSourceItems} dom=${r.stats.renderedItems} reader=${r.stats.readerSegments} a11y=${r.stats.a11yNodes}`);
        for (const x of r.findings.slice(0, 4)) {
          console.log(`   [${x.impact.level}] ${x.id} instr=${x.instruction || '-'} vis=${x.humanVisible} :: ${x.excerpt.slice(0, 62)}`);
        }
      } catch (e) {
        console.log(`\n== ${f} == ERROR: ${e.message}`);
      }
    }
  }
  server.close();
  process.exit(0);
})();
