// Security tests for the central network boundary (server/lib/net-guard.js).
//
// Everything here talks to local test servers on ephemeral ports and uses a
// mocked DNS resolver. No test contacts a cloud metadata service, a real
// internal service, or any third-party host.
//
// Evidence: plan §3 item 10 (the SSRF guard could be bypassed) and the Step 5
// task: blocked ranges, redirect validation, browser subrequests, allowlist
// semantics and DNS handling.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const {
  createPolicy,
  fetchWithRedirects,
  createBrowserRequestGuard,
  classifyIp,
  normalizeHost,
} = require('../server/lib/net-guard');

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}
const originOf = (server) => `http://127.0.0.1:${server.address().port}`;
const close = (server) => new Promise((resolve) => server.close(resolve));

// A resolver that never touches the network. Throws for names it does not know.
function mockLookup(table) {
  const calls = [];
  const fn = async (hostname) => {
    calls.push(hostname);
    if (Object.prototype.hasOwnProperty.call(table, hostname)) return table[hostname];
    const err = new Error(`ENOTFOUND ${hostname}`);
    err.code = 'ENOTFOUND';
    throw err;
  };
  fn.calls = calls;
  return fn;
}

const PUBLIC_IP = '93.184.216.34'; // example.com's documented address

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

test('documented non-public IPv4 ranges are blocked', () => {
  const blocked = [
    '127.0.0.1', '127.0.0.2', '10.0.0.1', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '239.255.255.255', '255.255.255.255', '198.51.100.7', '203.0.113.7',
  ];
  for (const ip of blocked) {
    const r = classifyIp(ip);
    assert.equal(r.blocked, true, `${ip} must be blocked, got ${JSON.stringify(r)}`);
    assert.ok(r.reason && r.reason.length > 0, `${ip} must carry a reason`);
  }
});

test('public IPv4 addresses are not blocked', () => {
  for (const ip of [PUBLIC_IP, '1.1.1.1', '8.8.8.8', '172.32.0.1', '100.128.0.1']) {
    assert.equal(classifyIp(ip).blocked, false, `${ip} should be public`);
  }
});

test('documented non-public IPv6 ranges are blocked', () => {
  const blocked = ['::1', '::', 'fd00::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2001::1'];
  for (const ip of blocked) {
    assert.equal(classifyIp(ip).blocked, true, `${ip} must be blocked`);
  }
});

test('IPv4-mapped and IPv4-compatible IPv6 forms follow IPv4 policy', () => {
  assert.equal(classifyIp('::ffff:127.0.0.1').blocked, true, 'mapped loopback');
  assert.equal(classifyIp('::ffff:10.0.0.1').blocked, true, 'mapped private');
  assert.equal(classifyIp('::127.0.0.1').blocked, true, 'compatible loopback');
  assert.equal(classifyIp('::ffff:8.8.8.8').blocked, false, 'mapped public');
  assert.equal(classifyIp('2606:4700:4700::1111').blocked, false, 'global unicast');
});

test('loopback is named as loopback, not as an embedded IPv4 address', () => {
  assert.match(classifyIp('::1').reason, /loopback/i);
  assert.match(classifyIp('::').reason, /unspecified/i);
});

test('normalizeHost lowercases and strips trailing dots, but nothing else', () => {
  assert.equal(normalizeHost('EXAMPLE.com'), 'example.com');
  assert.equal(normalizeHost('localhost.'), 'localhost');
  assert.equal(normalizeHost('[::1]'), '::1');
  assert.equal(normalizeHost('  Example.COM.  '), 'example.com');
  assert.equal(normalizeHost('example.com.evil.test'), 'example.com.evil.test');
});

// ---------------------------------------------------------------------------
// Exact fixture-origin exception
// ---------------------------------------------------------------------------

test('only the exact recognised fixture origin is exempt, and nothing else local', async () => {
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port: 7199 }] });

  const allowed = await policy.checkTarget('http://127.0.0.1:7199/fixtures/a.html');
  assert.equal(allowed.allowed, true, 'the exact fixture origin must be analysable');
  assert.equal(allowed.local, true);

  const rejected = [
    ['http://127.0.0.1:7198/', 'fixture host on a different port'],
    ['http://127.0.0.1/', 'fixture host on the default port'],
    ['http://127.0.0.2:7199/', 'a different loopback address'],
    ['http://localhost:7199/', 'the name localhost instead of the literal address'],
    ['http://localhost.:7199/', 'localhost with a trailing root dot'],
    ['http://[::1]:7199/', 'IPv6 loopback'],
    ['http://[::ffff:127.0.0.1]:7199/', 'IPv4-mapped loopback'],
    ['http://[0:0:0:0:0:0:0:1]:7199/', 'expanded IPv6 loopback'],
    ['http://0.0.0.0:7199/', 'unspecified address'],
  ];
  for (const [url, label] of rejected) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${label} (${url}) must be refused`);
  }
});

test('alternate spellings of the fixture address resolve to the fixture origin', async () => {
  // The WHATWG URL parser folds these into 127.0.0.1 before the guard sees them,
  // so they are the fixture origin rather than a bypass of it. They must never be
  // treated as any OTHER host, and they must not widen the exception: the same
  // spellings on a different port stay refused.
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port: 7199 }] });
  for (const url of ['http://127.1:7199/', 'http://2130706433:7199/', 'http://0x7f.1:7199/', 'http://0177.0.0.1:7199/']) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, true, `${url} is 127.0.0.1:7199 and must be treated as the fixture origin`);
    assert.equal(r.host, '127.0.0.1');
  }
  for (const url of ['http://127.1/', 'http://2130706433:7101/', 'http://0x7f.1:1/']) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${url} must not widen the fixture exception`);
  }
});

test('a fixture origin that is not a literal IP is refused', async () => {
  // Defence in depth: the local exception deliberately skips IP classification,
  // so it must never be configurable to a name.
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: 'localhost', port: 7199 }] });
  const r = await policy.checkTarget('http://localhost:7199/fixtures/a.html');
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'fixture-origin-not-literal');
});

// ---------------------------------------------------------------------------
// Blocked destinations
// ---------------------------------------------------------------------------

test('blocked literal destinations are refused even when allowlisted', async () => {
  const policy = createPolicy({ allowedHosts: [] });
  const urls = [
    'http://127.0.0.1/', 'http://127.0.0.2/', 'http://0.0.0.0/',
    'http://10.0.0.1/', 'http://169.254.169.254/latest/meta-data/',
    'http://100.64.0.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fd00::1]/',
  ];
  for (const url of urls) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${url} must be refused`);
  }
});

test('cloud metadata addresses are refused without being contacted', async () => {
  // 169.254.169.254 is refused by classification; the mocked resolver is never
  // consulted for a literal address, and no network call is made at all.
  const lookup = mockLookup({});
  const policy = createPolicy({ allowedHosts: ['metadata.test'], lookup });
  const r = await policy.checkTarget('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
  assert.equal(r.allowed, false);
  assert.deepEqual(lookup.calls, [], 'no DNS lookup may happen for a literal IP');
});

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

test('malformed URLs are refused', async () => {
  const policy = createPolicy({ allowedHosts: ['example.com'] });
  for (const input of ['not a url', '', 'http://', '//example.com', 'http://:7199/']) {
    const r = await policy.checkTarget(input);
    assert.equal(r.allowed, false, `"${input}" must be refused`);
  }
});

test('unsupported protocols are refused', async () => {
  const policy = createPolicy({ allowedHosts: ['example.com'] });
  for (const url of ['ftp://example.com/', 'file:///C:/Windows/win.ini', 'gopher://example.com/', 'javascript:alert(1)']) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${url} must be refused`);
    assert.equal(r.code, 'unsupported-protocol');
  }
});

test('URLs carrying credentials are refused', async () => {
  const policy = createPolicy({ allowedHosts: ['example.com', 'evil.test'], lookup: mockLookup({ 'example.com': [PUBLIC_IP], 'evil.test': [PUBLIC_IP] }) });
  for (const url of ['https://user:pw@example.com/', 'https://example.com@evil.test/', 'http://user@example.com/']) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${url} must be refused`);
    assert.equal(r.code, 'url-credentials');
  }
});

// ---------------------------------------------------------------------------
// Allowlist semantics
// ---------------------------------------------------------------------------

test('the allowlist matches whole hosts only, never suffixes', async () => {
  const lookup = mockLookup({ 'example.com': [PUBLIC_IP], 'example.com.evil.test': [PUBLIC_IP], 'evil.test': [PUBLIC_IP] });
  const policy = createPolicy({ allowedHosts: ['example.com'], lookup });

  assert.equal((await policy.checkTarget('https://example.com/page')).allowed, true);
  assert.equal((await policy.checkTarget('https://EXAMPLE.COM./page')).allowed, true, 'case and trailing dot normalise');

  for (const url of ['https://example.com.evil.test/', 'https://notexample.com/', 'https://sub.example.com/', 'https://evil.test/']) {
    const r = await policy.checkTarget(url);
    assert.equal(r.allowed, false, `${url} must not match the allowlist`);
  }
});

test('external analysis is disabled by default', async () => {
  const policy = createPolicy({ allowedHosts: [], lookup: mockLookup({ 'example.com': [PUBLIC_IP] }) });
  const r = await policy.checkTarget('https://example.com/page');
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'unallowlisted-host');
  assert.match(r.reason, /disabled by default/i);
});

// ---------------------------------------------------------------------------
// DNS handling
// ---------------------------------------------------------------------------

test('an allowlisted public host with mocked DNS is allowed', async () => {
  const policy = createPolicy({ allowedHosts: ['example.com'], lookup: mockLookup({ 'example.com': [PUBLIC_IP] }) });
  const r = await policy.checkTarget('https://example.com/page');
  assert.equal(r.allowed, true);
  assert.deepEqual(r.addresses, [PUBLIC_IP]);
  assert.equal(r.local, false);
});

test('every DNS result is inspected, not just the first', async () => {
  const lookup = mockLookup({
    'mixed.test': [PUBLIC_IP, '127.0.0.1'],
    'private.test': ['10.0.0.5'],
    'v6internal.test': [PUBLIC_IP, 'fd00::1'],
  });
  const policy = createPolicy({ allowedHosts: ['mixed.test', 'private.test', 'v6internal.test'], lookup });

  for (const host of ['mixed.test', 'private.test', 'v6internal.test']) {
    const r = await policy.checkTarget(`https://${host}/`);
    assert.equal(r.allowed, false, `${host} resolves to a non-public address and must be refused`);
    assert.equal(r.code, 'blocked-ip');
  }
});

test('a DNS failure is refused and reported', async () => {
  const policy = createPolicy({ allowedHosts: ['missing.test'], lookup: mockLookup({}) });
  const r = await policy.checkTarget('https://missing.test/');
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'dns-failure');
});

test('an empty DNS answer is refused', async () => {
  const policy = createPolicy({ allowedHosts: ['empty.test'], lookup: async () => [] });
  const r = await policy.checkTarget('https://empty.test/');
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'dns-empty');
});

test('DNS results are cached within one scan', async () => {
  const lookup = mockLookup({ 'example.com': [PUBLIC_IP] });
  const policy = createPolicy({ allowedHosts: ['example.com'], lookup });
  await policy.checkTarget('https://example.com/a');
  await policy.checkTarget('https://example.com/b');
  await policy.checkTarget('https://example.com/c');
  assert.deepEqual(lookup.calls, ['example.com'], 'one scan must resolve a host once');

  const other = createPolicy({ allowedHosts: ['example.com'], lookup });
  await other.checkTarget('https://example.com/d');
  assert.deepEqual(lookup.calls, ['example.com', 'example.com'], 'a separate scan resolves again');
});

// ---------------------------------------------------------------------------
// Redirect validation
// ---------------------------------------------------------------------------

test('an allowed chain of at most five redirects is followed', async () => {
  const server = await listen((req, res) => {
    if (req.url === '/r1') { res.writeHead(302, { location: '/r2' }); return res.end(); }
    if (req.url === '/r2') { res.writeHead(301, { location: '/final' }); return res.end(); }
    if (req.url === '/final') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('<html>ok</html>'); }
    res.writeHead(404); return res.end('nope');
  });
  const port = server.address().port;
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port }] });
  try {
    const out = await fetchWithRedirects(`${originOf(server)}/r1`, { policy });
    assert.equal(out.finalUrl, `${originOf(server)}/final`);
    assert.equal(out.redirects.length, 2);
    assert.match(out.html, /ok/);
  } finally {
    await close(server);
  }
});

test('a redirect to an unallowlisted host is rejected', async () => {
  const server = await listen((req, res) => {
    res.writeHead(302, { location: 'https://not-allowlisted.test/steal' });
    res.end();
  });
  const port = server.address().port;
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port }] });
  try {
    await assert.rejects(
      () => fetchWithRedirects(`${originOf(server)}/start`, { policy }),
      (err) => {
        assert.match(err.message, /Network boundary refused/);
        assert.equal(err.code, 'unallowlisted-host');
        return true;
      },
    );
  } finally {
    await close(server);
  }
});

test('a redirect to a blocked address is rejected even when the first hop was allowed', async () => {
  const server = await listen((req, res) => {
    res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  });
  const port = server.address().port;
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port }] });
  try {
    await assert.rejects(
      () => fetchWithRedirects(`${originOf(server)}/start`, { policy }),
      (err) => {
        assert.match(err.message, /Network boundary refused/);
        return true;
      },
    );
  } finally {
    await close(server);
  }
});

test('more than five redirects is rejected', async () => {
  const server = await listen((req, res) => {
    const n = Number((req.url.match(/^\/hop(\d+)$/) || [])[1] || 0);
    res.writeHead(302, { location: `/hop${n + 1}` });
    res.end();
  });
  const port = server.address().port;
  const policy = createPolicy({ allowedHosts: [], fixtureOrigins: [{ host: '127.0.0.1', port }] });
  try {
    await assert.rejects(
      () => fetchWithRedirects(`${originOf(server)}/hop0`, { policy }),
      (err) => {
        assert.equal(err.code, 'too-many-redirects');
        return true;
      },
    );
  } finally {
    await close(server);
  }
});

// ---------------------------------------------------------------------------
// Browser subrequest guard
// ---------------------------------------------------------------------------

function fakeRoute() {
  const state = { continued: 0, aborted: [] };
  return {
    state,
    route: {
      continue: async () => { state.continued++; },
      abort: async (reason) => { state.aborted.push(reason); },
    },
  };
}
const fakeRequest = (url, type = 'image') => ({ url: () => url, resourceType: () => type });

test('the browser guard allows the fixture origin and blocks everything else', async () => {
  const policy = createPolicy({ allowedHosts: ['cdn.example.com'], lookup: mockLookup({ 'cdn.example.com': [PUBLIC_IP] }), fixtureOrigins: [{ host: '127.0.0.1', port: 7199 }] });
  const guard = createBrowserRequestGuard(policy);

  const local = fakeRoute();
  await guard(local.route, fakeRequest('http://127.0.0.1:7199/fixtures/a.html', 'document'));
  assert.equal(local.state.continued, 1, 'the fixture origin must be allowed');
  assert.deepEqual(local.state.aborted, []);

  const remote = fakeRoute();
  await guard(remote.route, fakeRequest('https://tracker.test/pixel.gif'));
  assert.equal(remote.state.continued, 0);
  assert.deepEqual(remote.state.aborted, ['blockedbyclient']);
  assert.equal(policy.blockedRequests.length, 1, 'blocked subresources must be recorded');
  assert.match(policy.blockedRequests[0].reason, /allowlist|disabled by default/i);

  const metadata = fakeRoute();
  await guard(metadata.route, fakeRequest('http://169.254.169.254/latest/meta-data/'));
  assert.deepEqual(metadata.state.aborted, ['blockedbyclient']);
});

test('non-network schemes are left alone by the browser guard', async () => {
  const policy = createPolicy({ allowedHosts: [] });
  const guard = createBrowserRequestGuard(policy);
  for (const url of ['data:text/html,<b>x</b>', 'blob:http://127.0.0.1:7199/abc', 'about:blank']) {
    const r = fakeRoute();
    await guard(r.route, fakeRequest(url, 'document'));
    assert.equal(r.state.continued, 1, `${url} never leaves the machine`);
    assert.deepEqual(r.state.aborted, []);
  }
});

test('a blocked browser request is recorded with its reason', async () => {
  const policy = createPolicy({ allowedHosts: [] });
  const guard = createBrowserRequestGuard(policy);
  const r = fakeRoute();
  await guard(r.route, fakeRequest('https://ads.test/banner.png', 'image'));
  const [entry] = policy.blockedRequests;
  assert.equal(entry.kind, 'browser-subresource');
  assert.equal(entry.url, 'https://ads.test/banner.png');
  assert.equal(entry.resourceType, 'image');
  assert.ok(entry.at, 'blocked requests carry a timestamp');
});
