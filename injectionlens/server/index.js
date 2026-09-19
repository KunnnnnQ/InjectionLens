// InjectionLens server — API + controlled test fixtures
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { analyze } = require('./lib/analyze');
const { CAPABILITY_TEMPLATES } = require('./lib/risk');

const PORT = process.env.PORT || 7101;
const app = express();
app.use(cors());
app.use(express.json({ limit: '256kb' }));

// ---------- SSRF guard ----------
// Only http(s). Private/loopback targets are allowed ONLY on this server's own
// fixture port — we never fetch internal network resources on behalf of a user.
function assertFetchable(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { throw new Error('Invalid URL'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http/https URLs are supported');
  const host = u.hostname.toLowerCase();
  const isLocalhost = host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  if (isLocalhost && Number(u.port) !== PORT) {
    throw new Error('Refused: localhost targets other than the built-in fixture server are blocked (SSRF guard)');
  }
  if (!isLocalhost && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(host)) {
    throw new Error('Refused: private network targets are blocked (SSRF guard)');
  }
  return u.toString();
}

// ---------- Cloaking fixture (dynamic — must come before static) ----------
app.get('/fixtures/cloaking.html', (req, res) => {
  const ua = req.get('user-agent') || '';
  const isAiBot = /GPTBot|ClaudeBot|PerplexityBot|Google-Extended|Bytespider/i.test(ua);
  const file = isAiBot ? 'cloaking-ai.html' : 'cloaking-human.html';
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

app.post('/api/analyze', async (req, res) => {
  try {
    const { url, capability } = req.body || {};
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url is required' });
    const target = url.startsWith('/') ? `http://localhost:${PORT}${url}` : assertFetchable(url);
    const result = await analyze(target, capability);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[InjectionLens] API + fixtures on http://localhost:${PORT}`);
  });
}

module.exports = { app, PORT };
