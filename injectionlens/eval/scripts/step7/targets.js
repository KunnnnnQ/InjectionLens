// Step 7 evaluation utilities — inert-target rules.
//
// The harness renders third-party payload text into local pages. That text may
// contain absolute URLs, IP literals, mail addresses or wallet addresses taken
// from the upstream corpus. This module is the single place that decides whether
// a string is inert enough to be planted in a local page.
//
// Scope, stated plainly:
//   - It never resolves, fetches or pings anything. It is a string classifier.
//   - It does not judge intent, and it does not treat destructive command text
//     as unsafe. AGENTS.md rule 7 allows destructive strings as inert text
//     inside fixtures; the harness never executes payload text.
'use strict';

// RFC 2606 / RFC 6761 reserved names. Everything else is treated as a real
// destination, so a placeholder like "server.url" is flagged too — a false
// positive here costs a review entry, a false negative costs a live target.
const RESERVED_HOST_SUFFIXES = Object.freeze(['.example', '.invalid', '.test', '.localhost', '.local']);
const RESERVED_HOST_NAMES = Object.freeze(['example.com', 'example.net', 'example.org', 'localhost']);
const ALLOWED_IPV4_LITERALS = Object.freeze(['127.0.0.1', '0.0.0.0']);

const URL_RE = /https?:\/\/[^\s"'<>()\][]+/gi;
const PROTOCOL_RELATIVE_RE = /(?:^|[\s"'(=])\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_RE = /\b[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/gi;
const EVM_ADDRESS_RE = /\b0x[0-9a-fA-F]{40}\b/g;
const BECH32_RE = /\bbc1[02-9ac-hj-np-z]{11,71}\b/g;

function isReservedHost(host) {
  if (typeof host !== 'string' || host === '') return false;
  const normalized = host.toLowerCase().replace(/\.$/, '');
  if (RESERVED_HOST_NAMES.includes(normalized)) return true;
  if (ALLOWED_IPV4_LITERALS.includes(normalized)) return true;
  if (normalized === '::1' || normalized === '[::1]') return true;
  return RESERVED_HOST_SUFFIXES.some((suffix) => normalized === suffix.slice(1) || normalized.endsWith(suffix));
}

function hostOfUrl(raw) {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https:${raw}`).hostname;
  } catch {
    return null;
  }
}

/**
 * Real destinations in a string.
 * @param {string} text
 * @returns {Array<{kind: 'url'|'protocol-relative'|'ipv4'|'email'|'wallet', match: string, host: string|null}>}
 */
function findUnsafeTargets(text) {
  if (typeof text !== 'string' || text === '') return [];
  const found = [];
  const push = (kind, match, host) => {
    found.push({ kind, match, host: host || null });
  };

  for (const match of text.match(URL_RE) || []) {
    const host = hostOfUrl(match);
    if (!host || !isReservedHost(host)) push('url', match, host);
  }
  for (const m of text.matchAll(PROTOCOL_RELATIVE_RE)) {
    const host = m[1];
    if (!isReservedHost(host)) push('protocol-relative', `//${host}`, host);
  }
  for (const match of text.match(IPV4_RE) || []) {
    if (!ALLOWED_IPV4_LITERALS.includes(match)) push('ipv4', match, match);
  }
  for (const m of text.matchAll(EMAIL_RE)) {
    const host = m[1];
    if (!isReservedHost(host)) push('email', m[0], host);
  }
  for (const match of text.match(EVM_ADDRESS_RE) || []) push('wallet', match, null);
  for (const match of text.match(BECH32_RE) || []) push('wallet', match, null);

  // De-duplicate identical findings so a repeated URL counts once per string.
  const seen = new Set();
  return found.filter((entry) => {
    const key = `${entry.kind}\u001f${entry.match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isInertText(text) {
  return findUnsafeTargets(text).length === 0;
}

module.exports = {
  RESERVED_HOST_SUFFIXES,
  RESERVED_HOST_NAMES,
  ALLOWED_IPV4_LITERALS,
  isReservedHost,
  hostOfUrl,
  findUnsafeTargets,
  isInertText,
};
