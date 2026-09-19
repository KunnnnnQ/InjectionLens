// InjectionLens server — API + controlled test fixtures
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { analyze } = require('./lib/analyze');
const { CAPABILITY_TEMPLATES } = require('./lib/risk');
const { createPolicy, DEFAULT_FIXTURE_PORT } = require('./lib/net-guard');
const { detectCrawlerToken } = require('./lib/ingest');

const PORT = Number(process.env.PORT) || DEFAULT_FIXTURE_PORT;
// Bind to loopback only. "localhost" resolves to ::1 on Windows as often as to
// 127.0.0.1, so everything internal uses the literal address to avoid the two
// stacks disagreeing about where the server is.
const HOST = '127.0.0.1';

const app = express();
app.use(cors());
app.use(express.json({ limit: '256kb' }));

// ---------- network boundary ----------
// One policy for the whole process: the exact fixture origin locally, plus any
// host named in INJECTIONLENS_ALLOWED_HOSTS. External analysis is off by default.
const policy = createPolicy({
  allowedHosts: process.env.INJECTIONLENS_ALLOWED_HOSTS,
  fixtureOrigins: [{ host: HOST, port: PORT }],
});

async function resolveTarget(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) throw new Error('url is required');
  const candidate = rawUrl.startsWith('/') ? `http://${HOST}:${PORT}${rawUrl}` : rawUrl;
  const verdict = await policy.checkTarget(candidate, { purpose: 'api-analyze' });
  if (!verdict.allowed) {
    const err = new Error(verdict.reason);
    err.code = verdict.code;
    throw err;
  }
  return verdict.url.toString();
}

// ---------- Cloaking fixture (dynamic — must come before static) ----------
app.get('/fixtures/cloaking.html', (req, res) => {
  // Only real HTTP User-Agent tokens decide this. Google-Extended is a
  // robots.txt product token, not an HTTP UA, so it is not matched here
  // (plan §3 item 9).
  const token = detectCrawlerToken(req.get('user-agent') || '');
  const file = token ? 'cloaking-ai.html' : 'cloaking-human.html';
  res.type('html').send(fs.readFileSync(path.join(__dirname, 'fixtures', file), 'utf8'));
});

app.use('/fixtures', express.static(path.join(__dirname, 'fixtures')));

// ---------- API ----------
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'injectionlens', time: new Date().toISOString() }));

app.get('/api/fixtures', (_req, res) => {
  const files = fs
    .readdirSync(path.join(__dirname, 'fixtures'))
    .filter((f) => f.endsWith('.html') && !f.startsWith('cloaking-'))
    .map((f) => `/fixtures/${f}`);
  files.push('/fixtures/cloaking.html'); // virtual route — UA-conditional content
  res.json({ fixtures: files });
});

app.get('/api/capabilities', (_req, res) => {
  res.json(Object.entries(CAPABILITY_TEMPLATES).map(([key, t]) => ({ key, label: t.label, blurb: t.blurb })));
});

// What the analyse endpoint will and will not fetch, so the UI can explain it.
app.get('/api/network-policy', (_req, res) => {
  res.json({
    host: HOST,
    port: PORT,
    externalAnalysis: 'disabled by default',
    allowedHosts: Array.from(policy.allowedHosts),
    allowedHostsEnvVar: 'INJECTIONLENS_ALLOWED_HOSTS',
    fixtureOrigins: policy.fixtureOrigins,
    uaProbeAllowlistEnvVar: 'INJECTIONLENS_UA_PROBE_ALLOWLIST',
    uaProbeScope: 'local fixture origin only, unless a host is explicitly allowlisted',
    limitations: [
      'The guard validates every DNS answer, but does not pin the connection to the validated address, so DNS rebinding is not fully solved.',
      'UA probing is a lower bound: cloaking can also be driven by behavioural fingerprinting, which this tool does not detect.',
      'Blocked subresources are reported, but a page may still behave differently in ways this analysis cannot observe.',
    ],
  });
});

app.post('/api/analyze', async (req, res) => {
  try {
    const { url, capability } = req.body || {};
    const target = await resolveTarget(url);
    const result = await analyze(target, capability, { policy });
    res.json(result);
  } catch (err) {
    const blocked = ['unallowlisted-host', 'blocked-ip', 'url-credentials', 'unsupported-protocol', 'malformed-url', 'fixture-origin-not-literal'];
    const status = blocked.includes(err.code) ? 403 : 500;
    res.status(status).json({ error: String(err.message || err), code: err.code || null, blocked: status === 403 });
  }
});

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`[InjectionLens] API + fixtures on http://${HOST}:${PORT}`);
    console.log(`[InjectionLens] external analysis: ${policy.allowedHosts.size ? Array.from(policy.allowedHosts).join(', ') : 'disabled (no allowlisted hosts)'}`);
  });
}

module.exports = { app, PORT, HOST, policy };
