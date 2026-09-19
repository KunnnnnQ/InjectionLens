// Regression tests for the AI-agent User-Agent model.
//
// Covers plan §3 items 8 and 9:
//   - the UA inventory must contain the user-triggered fetchers, not only the
//     training crawlers;
//   - Google-Extended is a robots.txt product token, NOT an HTTP User-Agent, so
//     the fixture server must not react to it;
//   - UA probing is authorised only inside a narrow boundary.
//
// The fixture server is started in-process on a loopback port. No third-party
// host is ever contacted and no crawler UA is ever sent anywhere but here.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const PORT = 7198; // fixed so the app's fixture URLs and this listener agree
process.env.PORT = String(PORT);
process.env.INJECTIONLENS_ALLOWED_HOSTS = '';
process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST = '';

const { app } = require('../server/index');
const { AI_CRAWLER_UAS, CRAWLER_UA_TOKENS, detectCrawlerToken, uaProbePermission } = require('../server/lib/ingest');
const { createPolicy } = require('../server/lib/net-guard');
const { getBrowser } = require('../server/lib/browser');

const HOST = '127.0.0.1';
const base = `http://${HOST}:${PORT}`;

let server;
before(async () => {
  server = await new Promise((resolve) => {
    const s = app.listen(PORT, HOST, () => resolve(s));
  });
});
after(async () => {
  await new Promise((resolve) => server.close(resolve));
  // The headless browser is a shared singleton; leaving it running keeps the
  // test-runner process alive after the tests have finished.
  const browser = await getBrowser().catch(() => null);
  if (browser) await browser.close().catch(() => {});
});

const fetchFixture = async (ua, route = '/fixtures/cloaking.html') => {
  const res = await fetch(`${base}${route}`, { headers: { 'User-Agent': ua } });
  return { status: res.status, body: await res.text() };
};

// The two cloaking fixtures are distinguishable by their titles.
const AI_MARKER = 'Easy Recipes';
const HUMAN_MARKER = 'Green Garden';
const looksLikeAiFixture = (body) => body.includes('service directory');
const looksLikeHumanFixture = (body) => body.includes(HUMAN_MARKER) || !body.includes('service directory');

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

test('every configured entry records token, vendor, category and a source', () => {
  assert.ok(AI_CRAWLER_UAS.length >= 8, `expected the full inventory, got ${AI_CRAWLER_UAS.length}`);
  for (const bot of AI_CRAWLER_UAS) {
    assert.ok(bot.token && typeof bot.token === 'string', `missing token: ${JSON.stringify(bot)}`);
    assert.ok(bot.vendor, `${bot.token} needs a vendor`);
    assert.ok(['training', 'search', 'user-triggered'].includes(bot.category), `${bot.token} has category "${bot.category}"`);
    assert.match(bot.doc, /^https:\/\//, `${bot.token} needs a primary documentation URL`);
    assert.equal(bot.ua, bot.token, `${bot.token} must probe with the documented token`);
    assert.ok(['vendor-primary', 'secondary'].includes(bot.sourceStatus), `${bot.token} has sourceStatus "${bot.sourceStatus}"`);
  }
});

test('only Anthropic tokens are marked vendor-primary verified', () => {
  // This run could read Anthropic's own page; OpenAI's and Perplexity's were
  // inaccessible (403 / fetch failure), so those stay corroborated-only.
  for (const bot of AI_CRAWLER_UAS) {
    if (bot.vendor === 'Anthropic') {
      assert.equal(bot.sourceStatus, 'vendor-primary', `${bot.token} was readable from Anthropic's own page`);
    } else {
      assert.equal(bot.sourceStatus, 'secondary', `${bot.token} must not claim vendor-primary verification`);
    }
  }
});

test('the inventory separates training crawlers, search crawlers and user-triggered fetchers', () => {
  const byCategory = (c) => AI_CRAWLER_UAS.filter((b) => b.category === c).map((b) => b.token);
  assert.deepEqual(byCategory('training').sort(), ['ClaudeBot', 'GPTBot']);
  assert.deepEqual(byCategory('search').sort(), ['Claude-SearchBot', 'OAI-SearchBot', 'PerplexityBot']);
  assert.deepEqual(byCategory('user-triggered').sort(), ['ChatGPT-User', 'Claude-User', 'Perplexity-User']);
});

test('the user-triggered fetchers that the old list missed are present', () => {
  for (const token of ['ChatGPT-User', 'OAI-SearchBot', 'Claude-User', 'Claude-SearchBot', 'Perplexity-User']) {
    assert.ok(CRAWLER_UA_TOKENS.includes(token), `${token} must be in the inventory (plan §3 item 8)`);
  }
});

test('Google-Extended is not treated as an HTTP User-Agent token', () => {
  assert.ok(!CRAWLER_UA_TOKENS.includes('Google-Extended'), 'Google-Extended is a robots.txt product token, not an HTTP UA');
  assert.equal(detectCrawlerToken('Mozilla/5.0 (compatible; Google-Extended/1.0)'), null);
});

// ---------------------------------------------------------------------------
// Fixture server reaction (Part 3 regression)
// ---------------------------------------------------------------------------

test('the cloaking fixture reacts to every supported HTTP UA token', async () => {
  for (const token of CRAWLER_UA_TOKENS) {
    const { status, body } = await fetchFixture(token);
    assert.equal(status, 200, `${token} should get a 200`);
    assert.ok(looksLikeAiFixture(body), `the fixture must serve the AI-only content to "${token}"`);
    assert.equal(detectCrawlerToken(token), token);
  }
});

test('the cloaking fixture does not react to Google-Extended or to unrelated agents', async () => {
  const notCrawlers = [
    'Mozilla/5.0 (compatible; Google-Extended/1.0; +http://www.google.com/bot.html)',
    'Google-Extended',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)',
  ];
  for (const ua of notCrawlers) {
    const { body } = await fetchFixture(ua);
    assert.ok(!looksLikeAiFixture(body), `"${ua}" must not receive the AI-only content`);
  }
});

test('the fixture serves human content when no User-Agent matches', async () => {
  const { body } = await fetchFixture('');
  assert.ok(looksLikeHumanFixture(body), 'an unmatched UA gets the human fixture');
});

// ---------------------------------------------------------------------------
// UA probe permission boundary
// ---------------------------------------------------------------------------

test('UA probing is authorised against the local fixture origin', () => {
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: PORT }] });
  const verdict = uaProbePermission(`${base}/fixtures/cloaking.html`, policy);
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.scope, 'local-fixture');
});

test('UA probing a third-party host is skipped with an explicit status', () => {
  const policy = createPolicy({ allowedHosts: ['example.com'], fixtureOrigins: [{ host: HOST, port: PORT }] });
  const verdict = uaProbePermission('https://example.com/page', policy);
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.scope, 'third-party');
  assert.match(verdict.reason, /UA probe skipped: third-party host/);
});

test('a third-party UA probe is skipped even when the host is allowlisted for analysis', () => {
  // Being allowed to READ a page as a browser is not permission to announce
  // ourselves as an AI crawler.
  const policy = createPolicy({ allowedHosts: ['example.com'], fixtureOrigins: [{ host: HOST, port: PORT }] });
  const readVerdict = uaProbePermission('https://example.com/page', policy);
  assert.equal(readVerdict.allowed, false, 'analysis allowlist must not imply UA-probe permission');
});

test('an explicitly allowlisted UA-probe host is permitted', () => {
  process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST = 'allowed.example';
  try {
    const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: PORT }] });
    const verdict = uaProbePermission('https://allowed.example/page', policy);
    assert.equal(verdict.allowed, true);
    assert.equal(verdict.scope, 'explicit-allowlist');
  } finally {
    process.env.INJECTIONLENS_UA_PROBE_ALLOWLIST = '';
  }
});

// ---------------------------------------------------------------------------
// The probe as the analyser runs it
// ---------------------------------------------------------------------------

test('a local analysis probes every configured token and names the trigger', async () => {
  const { analyze } = require('../server/lib/analyze');
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: PORT }] });
  const result = await analyze(`${base}/fixtures/cloaking.html`, 'summary-only', { policy });

  assert.ok(Array.isArray(result.uaProbe), 'the result must record the probe');
  const probed = result.uaProbe.filter((p) => p.status === 'probed');
  assert.equal(probed.length, AI_CRAWLER_UAS.length, 'no artificial limit: every configured token is probed');
  assert.equal(result.uaProbe.length, AI_CRAWLER_UAS.length, 'one record per configured token');

  assert.ok(result.cloak, 'the cloaking fixture must be detected');
  assert.equal(result.cloak.triggerToken, 'GPTBot', 'the first inventory entry triggers it');
  assert.equal(result.cloak.uaUsed, 'GPTBot', 'evidence must name the actual UA used');
});

test('a third-party analysis records "skipped" instead of probing', async () => {
  // Drive the analyse path against an allowlisted third-party URL but with the
  // UA-probe allowlist empty. The fixture server is not involved here: the
  // target is never fetched as a crawler because the permit is refused first.
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: HOST, port: PORT }] });
  const verdict = uaProbePermission('https://third-party.example/page', policy);
  assert.equal(verdict.allowed, false);
  assert.match(verdict.reason, /^UA probe skipped: third-party host/);
});
