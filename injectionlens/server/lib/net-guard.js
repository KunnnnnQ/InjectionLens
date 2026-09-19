// Central network boundary for InjectionLens.
//
// Every outbound step the analyser takes — the HTTP source fetch, each redirect
// hop, and every browser subresource request — goes through this module. The
// policy is deny-by-default: external analysis is OFF unless a host is named in
// the allowlist, and the only local exception is the exact fixture origin.
//
// What this does and does not do:
//   - it validates the URL, the host, and EVERY address DNS returns for it;
//   - it re-validates each redirect hop instead of trusting the first URL;
//   - it does NOT pin the connection to the validated address, so it cannot
//     prove the socket that is finally opened went to that address. Defence
//     against a DNS answer that changes between our lookup and the connect
//     ("DNS rebinding") therefore remains an open limitation, not a solved one.
//   - it does not treat a vendor IP range or an rDNS name as proof of identity.

const dns = require('node:dns');
const net = require('node:net');

const DEFAULT_FIXTURE_PORT = Number(process.env.PORT) || 7101;
const DEFAULT_FIXTURE_HOSTS = ['127.0.0.1'];
const MAX_REDIRECTS = 5;

// ---------------------------------------------------------------------------
// IP classification
// ---------------------------------------------------------------------------

const IPV4_BLOCKED_CIDRS = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, incl. cloud metadata 169.254.169.254
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
];

const IPV6_BLOCKED_CIDRS = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['::ffff:0:0', 96], // IPv4-mapped (also decoded below)
  ['64:ff9b::', 96], // IPv4/IPv6 translation
  ['100::', 64], // discard-only
  ['2001::', 32], // Teredo
  ['2001:2::', 48], // benchmarking
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['ff00::', 8], // multicast
];

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inIpv4Cidr(ip, base, bits) {
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(base);
  if (a === null || b === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

// Expand a compressed IPv6 literal into 8 groups of 16 bits, or null.
function expandIpv6(ip) {
  let text = ip.trim();
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone); // strip fe80::1%eth0 zone id
  if (!net.isIPv6(text)) return null;

  // Decode a trailing embedded IPv4 form (::ffff:127.0.0.1) into hex groups.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToInt(tail);
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const [headPart, tailPart] = text.split('::');
  const head = headPart ? headPart.split(':') : [];
  const tailGroups = tailPart !== undefined ? (tailPart ? tailPart.split(':') : []) : null;
  let groups;
  if (tailGroups === null) {
    groups = head;
  } else {
    const fill = 8 - head.length - tailGroups.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...tailGroups];
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => {
    if (g === '') return 0;
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    return parseInt(g, 16);
  });
  return nums.includes(null) ? null : nums;
}

function ipv6ToBigInt(ip) {
  const groups = expandIpv6(ip);
  if (!groups) return null;
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}

function inIpv6Cidr(ip, base, bits) {
  const a = ipv6ToBigInt(ip);
  const b = ipv6ToBigInt(base);
  if (a === null || b === null) return false;
  const shift = BigInt(128 - bits);
  return (a >> shift) === (b >> shift);
}

/**
 * Classify a numeric IP address.
 * @returns {{ip: string, family: 4|6, blocked: boolean, reason: string|null}}
 */
function classifyIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) {
    for (const [base, bits] of IPV4_BLOCKED_CIDRS) {
      if (inIpv4Cidr(ip, base, bits)) {
        return { ip, family: 4, blocked: true, reason: `IPv4 ${ip} is inside non-public range ${base}/${bits}` };
      }
    }
    return { ip, family: 4, blocked: false, reason: null };
  }
  if (family === 6) {
    const groups = expandIpv6(ip);
    // Unspecified and loopback are named directly: "::1" is not "IPv4 0.0.0.1".
    if (groups && groups.every((g) => g === 0)) {
      return { ip, family: 6, blocked: true, reason: 'IPv6 "::" is the unspecified address' };
    }
    if (groups && groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
      return { ip, family: 6, blocked: true, reason: 'IPv6 "::1" is the loopback address' };
    }
    if (groups) {
      // RFC 4291 IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
      // forms are IPv4 policy questions. "::" and "::1" are handled above.
      const isMapped = groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff;
      const isCompat = groups.slice(0, 6).every((g) => g === 0);
      if (isMapped || isCompat) {
        const v4 = `${groups[6] >> 8}.${groups[6] & 0xff}.${groups[7] >> 8}.${groups[7] & 0xff}`;
        const inner = classifyIp(v4);
        return {
          ip,
          family: 6,
          blocked: inner.blocked,
          reason: inner.blocked
            ? `IPv6 ${ip} embeds IPv4 ${v4}, which is inside a non-public range`
            : null,
        };
      }
    }
    for (const [base, bits] of IPV6_BLOCKED_CIDRS) {
      if (inIpv6Cidr(ip, base, bits)) {
        return { ip, family: 6, blocked: true, reason: `IPv6 ${ip} is inside non-public range ${base}/${bits}` };
      }
    }
    return { ip, family: 6, blocked: false, reason: null };
  }
  return { ip, family: 0, blocked: true, reason: `"${ip}" is not a valid IP address` };
}

// ---------------------------------------------------------------------------
// Policy + host handling
// ---------------------------------------------------------------------------

function normalizeHost(rawHost) {
  if (!rawHost) return '';
  let host = String(rawHost).trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.endsWith('.')) host = host.replace(/\.+$/, ''); // trailing root dots
  return host;
}

function parseAllowedHosts(value) {
  const list = Array.isArray(value) ? value : String(value || '').split(',');
  const out = new Set();
  for (const entry of list) {
    const host = normalizeHost(entry);
    if (host) out.add(host);
  }
  return out;
}

/**
 * Build the policy for one scan (or one process).
 *
 * @param {object} [options]
 * @param {string|string[]} [options.allowedHosts] hostnames allowed for external
 *   analysis. Defaults to INJECTIONLENS_ALLOWED_HOSTS, which is empty — external
 *   analysis is disabled by default.
 * @param {Array<{host: string, port?: number}>} [options.fixtureOrigins] the exact
 *   local fixture origins. Nothing else local is reachable.
 * @param {(hostname: string) => Promise<string[]>} [options.lookup] DNS resolver,
 *   injectable for tests.
 */
function createPolicy(options = {}) {
  const allowedHosts = parseAllowedHosts(
    options.allowedHosts !== undefined ? options.allowedHosts : process.env.INJECTIONLENS_ALLOWED_HOSTS,
  );
  const fixtureOrigins = (options.fixtureOrigins || [{ host: '127.0.0.1', port: DEFAULT_FIXTURE_PORT }])
    .map((o) => ({ host: normalizeHost(o.host), port: o.port === undefined ? null : Number(o.port) }));
  const lookup = options.lookup || ((hostname) => dns.promises.lookup(hostname, { all: true, verbatim: true }).then((rows) => rows.map((r) => r.address)));
  const cache = new Map(); // hostname -> Promise<string[]>, one scan only
  const blockedRequests = [];

  const resolve = (hostname) => {
    if (!cache.has(hostname)) cache.set(hostname, Promise.resolve().then(() => lookup(hostname)).then((addrs) => (Array.isArray(addrs) ? addrs : [])));
    return cache.get(hostname);
  };

  function isFixtureOrigin(host, port) {
    return fixtureOrigins.some((o) => o.host === host && (o.port === null || o.port === port));
  }

  /**
   * Validate one destination.
   * @param {string|URL} target
   * @param {{ allowedHosts?: string|string[], purpose?: string }} [ctx]
   * @returns {Promise<{allowed: boolean, reason: string|null, url?: URL, host?: string, port?: number|string, addresses?: string[], local?: boolean}>}
   */
  async function checkTarget(target, ctx = {}) {
    let url;
    try {
      url = target instanceof URL ? new URL(target.toString()) : new URL(String(target));
    } catch {
      return { allowed: false, reason: `malformed URL: ${String(target).slice(0, 120)}`, code: 'malformed-url' };
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { allowed: false, reason: `unsupported protocol "${url.protocol}" — only http and https are analysed`, code: 'unsupported-protocol' };
    }
    if (url.username || url.password) {
      return { allowed: false, reason: 'URLs with embedded credentials are refused', code: 'url-credentials' };
    }

    const host = normalizeHost(url.hostname);
    if (!host) return { allowed: false, reason: 'URL has no host', code: 'no-host' };

    // Ambiguous / malformed host shapes.
    if (/[\s/@\\]/.test(host)) return { allowed: false, reason: `ambiguous host "${host}"`, code: 'ambiguous-host' };
    if (host.startsWith('.') || host.includes('..')) return { allowed: false, reason: `malformed host "${host}"`, code: 'malformed-host' };

    const explicitPort = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port);

    // The narrow local exception: only the exact fixture origin, never
    // "localhost" or any other loopback target. This is the single local
    // exception in the whole policy.
    //
    // Note on normalisation: the WHATWG URL parser has already folded alternate
    // IPv4 spellings of the same address ("127.1", "2130706433", "0x7f.1") into
    // "127.0.0.1", so those forms legitimately match the fixture origin. That is
    // correct — they ARE that address. It is only safe because the default
    // fixture origin is a literal loopback address; if it were a hostname, this
    // branch would skip IP classification entirely.
    if (isFixtureOrigin(host, explicitPort)) {
      if (!net.isIP(host)) {
        return {
          allowed: false,
          reason: `fixture origins must be literal IP addresses, got "${host}"`,
          code: 'fixture-origin-not-literal',
        };
      }
      return { allowed: true, reason: null, url, host, port: explicitPort, addresses: [host], local: true };
    }

    // Allowlist check before DNS: exact hostname match only, no suffix matching.
    const extra = parseAllowedHosts(ctx.allowedHosts);
    const allowlisted = allowedHosts.has(host) || extra.has(host);
    if (!allowlisted) {
      return {
        allowed: false,
        reason: `host "${host}" is not on the analysis allowlist — external analysis is disabled by default`,
        code: 'unallowlisted-host',
      };
    }

    // Any host that is not allowlisted was rejected above, so from here the host
    // is explicitly authorised. Still verify what it resolves to.
    if (net.isIP(host)) {
      const cls = classifyIp(host);
      if (cls.blocked) return { allowed: false, reason: cls.reason, code: 'blocked-ip' };
      return { allowed: true, reason: null, url, host, port: explicitPort, addresses: [host], local: false };
    }

    let addresses;
    try {
      addresses = await resolve(host);
    } catch (err) {
      return { allowed: false, reason: `DNS lookup failed for "${host}": ${err.message}`, code: 'dns-failure' };
    }
    if (!addresses.length) {
      return { allowed: false, reason: `DNS returned no addresses for "${host}"`, code: 'dns-empty' };
    }
    for (const address of addresses) {
      const cls = classifyIp(address);
      if (cls.blocked) {
        return { allowed: false, reason: `"${host}" resolves to a non-public address (${cls.reason})`, code: 'blocked-ip', addresses };
      }
    }
    return { allowed: true, reason: null, url, host, port: explicitPort, addresses, local: false };
  }

  function recordBlocked(entry) {
    blockedRequests.push({ at: new Date().toISOString(), ...entry });
    return blockedRequests[blockedRequests.length - 1];
  }

  return {
    allowedHosts,
    fixtureOrigins,
    blockedRequests,
    checkTarget,
    recordBlocked,
    isFixtureOrigin,
    resolve,
  };
}

/** Default process-wide policy. */
const defaultPolicy = createPolicy();

/**
 * Fetch a URL by hand so every redirect hop is validated.
 * @returns {Promise<{response: Response, html: string, finalUrl: string, redirects: string[]}>}
 */
async function fetchWithRedirects(url, { headers = {}, policy = defaultPolicy, timeoutMs = 15000, maxRedirects = MAX_REDIRECTS } = {}) {
  let current = String(url);
  const visited = [];
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const check = await policy.checkTarget(current, { purpose: 'http-fetch' });
    if (!check.allowed) {
      const err = new Error(`Network boundary refused ${current}: ${check.reason}`);
      err.code = check.code;
      throw err;
    }
    const res = await fetch(check.url.toString(), {
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      if (hop === maxRedirects) {
        const err = new Error(`Too many redirects (limit ${maxRedirects}) starting at ${url}`);
        err.code = 'too-many-redirects';
        throw err;
      }
      const next = new URL(location, check.url).toString();
      visited.push(next);
      current = next;
      continue;
    }
    return { response: res, html: await res.text(), finalUrl: check.url.toString(), redirects: visited };
  }
  const err = new Error(`Too many redirects (limit ${maxRedirects}) starting at ${url}`);
  err.code = 'too-many-redirects';
  throw err;
}

/**
 * Playwright request filter: enforce the boundary on navigation and subresources.
 * Register it with context.route using a glob that matches all URLs, e.g.
 *   await context.route(allUrlsGlob, createBrowserRequestGuard(policy))
 * where allUrlsGlob is the string of two asterisks, a slash and another asterisk.
 */
function createBrowserRequestGuard(policy = defaultPolicy, onBlocked) {
  return async (route, request) => {
    const target = request.url();
    // Non-network schemes (data:, blob:, about:) never leave the machine.
    if (!/^https?:/i.test(target)) return route.continue();
    const check = await policy.checkTarget(target, { purpose: 'browser-subresource' });
    if (check.allowed) return route.continue();
    const entry = policy.recordBlocked({
      kind: 'browser-subresource',
      url: target,
      resourceType: typeof request.resourceType === 'function' ? request.resourceType() : undefined,
      reason: check.reason,
      code: check.code,
    });
    if (onBlocked) onBlocked(entry);
    return route.abort('blockedbyclient');
  };
}

module.exports = {
  createPolicy,
  defaultPolicy,
  checkTarget: (target, ctx) => defaultPolicy.checkTarget(target, ctx),
  fetchWithRedirects,
  createBrowserRequestGuard,
  classifyIp,
  normalizeHost,
  parseAllowedHosts,
  expandIpv6,
  MAX_REDIRECTS,
  DEFAULT_FIXTURE_PORT,
  DEFAULT_FIXTURE_HOSTS,
};
