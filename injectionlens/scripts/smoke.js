// Smoke test: start the app in-process on a random port and run the analysis
// engine over every fixture (no external server, no port conflicts).
//
// The listener and the fixture URLs both use the literal 127.0.0.1 so the
// network boundary can recognise the exact fixture origin; "localhost" may
// resolve to ::1 on Windows and would not match.
const { app, policy } = require('../server/index');
const { analyze } = require('../server/lib/analyze');
const { createPolicy } = require('../server/lib/net-guard');

const FIXTURES = [
  'attack-visible-comment',
  'attack-visible-product',
  'attack-hidden-displaynone',
  'attack-hidden-whitewhite-comment',
  'attack-attribute-cloaking',
  'attack-near-invisible',
  'attack-unicode-smuggling',
  'benign-sronly',
  'benign-security-blog',
  'cloaking',
];

const HOST = '127.0.0.1';

(async () => {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, HOST, () => resolve(s));
  });
  const port = server.address().port;
  console.log(`fixture server on ephemeral port ${port} (bound to ${HOST})`);

  // The API's default policy knows the configured port, not this ephemeral one,
  // so the smoke run builds its own policy for the exact origin it just bound.
  const scanPolicy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port }] });
  console.log(`external analysis: ${scanPolicy.allowedHosts.size ? Array.from(scanPolicy.allowedHosts).join(', ') : 'disabled (no allowlisted hosts)'}`);

  for (const capability of ['summary-only', 'full-access']) {
    console.log(`\n########## capability = ${capability} ##########`);
    for (const f of FIXTURES) {
      const url = `http://${HOST}:${port}/fixtures/${f}.html`;
      try {
        const r = await analyze(url, capability, { policy: scanPolicy });
        console.log(`\n== ${f} == cloak:${!!r.cloak} levels:${JSON.stringify(r.levelCount)}`);
        console.log(`   pipelines: http=${r.stats.httpSourceItems} dom=${r.stats.renderedItems} reader=${r.stats.readerSegments} a11y=${r.stats.a11yNodes}`);
        if (r.cloak) {
          console.log(`   cloaking: triggerToken=${r.cloak.triggerToken} uaUsed="${r.cloak.uaUsed}" category=${r.cloak.category} humanBytes=${r.cloak.humanBytes} aiBytes=${r.cloak.aiBytes}`);
        }
        const probed = (r.uaProbe || []).filter((p) => p.status === 'probed');
        if (probed.length) {
          console.log(`   ua probe: ${probed.length}/${(r.uaProbe || []).length} probed (${probed.map((p) => p.token).join(', ')})`);
        }
        const skippedOrFailed = (r.uaProbe || []).filter((p) => p.status !== 'probed' && p.token);
        for (const p of skippedOrFailed) {
          console.log(`   ua probe NOT run: ${p.token} -> ${p.status}`);
        }
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
