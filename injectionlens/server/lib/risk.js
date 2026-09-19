// Capability templates + impact model.
// Impact is tiered and explainable — no fake "safety probability".
// Formula: impact = f(intent severity, delivery evidence, capability reachability)
//
// The decision core is assessSegment(segment, capabilityKey): one pure function
// that turns a single text segment into a level + intents + explanation. The
// older helpers (analyzeInstruction / computeImpact) are kept so existing
// callers keep working, but they are now backed by the same tables.

const CAPABILITY_TEMPLATES = {
  'summary-only': {
    label: 'Summary-only assistant',
    blurb: 'The agent only reads the page and returns a summary to the user.',
    caps: { network: false, forms: false, email: false, drive: false, shell: false },
  },
  'browser-agent': {
    label: 'Browser agent (click + forms)',
    blurb: 'The agent can click, navigate and submit forms inside the browser session.',
    caps: { network: false, forms: true, email: false, drive: false, shell: false },
  },
  'full-access': {
    label: 'Full-access agent (email + drive + network)',
    blurb: 'The agent can read the user\'s email/drive and make outbound network requests.',
    caps: { network: true, forms: true, email: true, drive: true, shell: false },
  },
};

// ---------------------------------------------------------------------------
// Text normalization
//
// Real payloads hide inside Unicode: zero-width joiners split trigger phrases,
// Cyrillic/Greek homoglyphs defeat the regex, bidi controls reorder text, and
// Unicode tag characters (U+E0000-E007F) carry a whole invisible ASCII message.
// We analyze the cleaned text AND, when present, the decoded/attached text.
// ---------------------------------------------------------------------------

const ZERO_WIDTH_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD]/g;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;

// Common Cyrillic/Greek look-alikes -> Latin. Kept deliberately small: each
// entry is a character that renders identically (or near-identically) to Latin.
const HOMOGLYPHS = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y',
  '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u0458': 'j', '\u04CF': 'l',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u0417': '3', '\u041A': 'K', '\u041C': 'M',
  '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y',
  '\u0425': 'X', '\u0406': 'I',
  '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p', '\u03C5': 'u', '\u03BD': 'v', '\u03B9': 'i',
  '\u03BA': 'k', '\u03C7': 'x', '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z',
  '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A5': 'Y', '\u03A7': 'X',
};
const HOMOGLYPH_RE = new RegExp('[' + Object.keys(HOMOGLYPHS).join('') + ']', 'g');

// Decode a run of Unicode tag characters back to ASCII.
// 'Ignore' -> U+E0049 U+E0067 ... (0xE0000 + char code).
function decodeTagChars(str) {
  let out = '';
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xE0000 && cp <= 0xE007F) {
      const ascii = cp - 0xE0000;
      if (ascii >= 0x20 && ascii <= 0x7E) out += String.fromCharCode(ascii);
    }
  }
  return out;
}

// NFKC + strip invisibles + map homoglyphs. Returns the cleaned text and the
// invisibility channels that were actually used (evidence of deliberate hiding).
function normalizeText(raw) {
  const input = typeof raw === 'string' ? raw : '';
  const nfkc = input.normalize('NFKC');

  const tags = [];
  const withoutTags = nfkc.replace(TAG_CHARS, (m) => {
    const decoded = decodeTagChars(m);
    if (decoded.length >= 8) tags.push(decoded);
    return ' ';
  });

  const zeroWidth = ZERO_WIDTH_CHARS.test(withoutTags);
  ZERO_WIDTH_CHARS.lastIndex = 0;
  const stripped = withoutTags.replace(ZERO_WIDTH_CHARS, '');

  let homoglyphs = false;
  const homoglyphFixed = stripped.replace(HOMOGLYPH_RE, (m) => {
    homoglyphs = true;
    return HOMOGLYPHS[m];
  });

  // NFKC leaves combining voiced marks behind on Japanese kana.
  const combiningMarks = /[\u3099\u309A]/.test(homoglyphFixed);
  const spaced = homoglyphFixed.replace(/[\u3099\u309A]/g, '').replace(/\s+/g, ' ').trim();

  return { text: spaced, zeroWidth, glyphsNormalized: homoglyphs, combiningMarks, tags };
}

// After an invisible separator is stripped, words can end up glued together
// ("Ignore\u200Ball previous instructions"). Repair that before matching.
const GLUED_OVERRIDE_FIX = /ignoreallpreviousinstructions/gi;

const LEGACY_INSTRUCTION_TYPES = {
  'ignore-previous': { severity: 3, needs: 'any', desc: 'Attempts to override the agent\'s higher-priority instructions.' },
  'task-override': { severity: 3, needs: 'any', desc: 'Attempts to replace or redirect the user\'s original task.' },
  'system-prompt': { severity: 2, needs: 'any', desc: 'References or probes the agent\'s hidden system prompt.' },
  impersonation: { severity: 2, needs: 'any', desc: 'Redefines the agent\'s identity or role.' },
  'exfil-url': { severity: 4, needs: 'network', desc: 'Instructs data to be sent to an external URL/address.' },
  'exfil-data': { severity: 4, needs: 'datastore', desc: 'Instructs secrets or personal data to be included in output.' },
  'silent-action': { severity: 3, needs: 'any', desc: 'Instructs the agent to act without informing the user.' },
  obfuscation: { severity: 3, needs: 'any', desc: 'Instructs the agent to decode/obfuscate content before following it.' },
};

// Kept for callers that still import INSTRUCTION_TYPES.
const INSTRUCTION_TYPES = LEGACY_INSTRUCTION_TYPES;

// ---------------------------------------------------------------------------
// Legacy helpers (kept for analyze.js and the existing fixtures)
// ---------------------------------------------------------------------------

const INSTRUCTION_PATTERNS = [
  { type: 'ignore-previous', re: /ignore\s+(all|any|the|your)\s+(previous|above|prior|preceding|earlier)\s+(instructions?|prompts?|directions?|guidelines?)/i },
  { type: 'ignore-previous', re: /ignore\s+everything\s+(above|before|in\s+this\s+(page|document))/i },
  { type: 'task-override', re: /(disregard|forget|do not follow|override|bypass)\s+(your|all|the|any|these)\s+.{0,40}?(instructions?|guidelines?|rules?|policies|safety)/i },
  { type: 'system-prompt', re: /(system prompt|developer message|your instructions say|reveal your (instructions|prompt))/i },
  { type: 'impersonation', re: /you are (now )?(a|an|the) [a-z ]{0,30}(assistant|agent|bot|curl command)/i },
  { type: 'exfil-url', re: /(send|post|upload|transmit|email|forward|curl|wget|beacon|append|add|include|log|report|open|visit).{0,100}?(to|at|towards)\s*[:：]?\s*(https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)/i },
  { type: 'exfil-data', re: /(include|attach|append|leak|reveal|exfiltrate|add).{0,80}?(api[- ]?keys?|passwords?|tokens?|secrets?|credentials?|session|cookies?|email addresses?|contact list|phone numbers?|ssn)/i },
  { type: 'silent-action', re: /(do not (tell|inform|mention|warn|alert|ask) (the )?user|without (telling|informing|asking|notifying|mentioning)[^.|]{0,40}?user|keep this (a )?(secret|hidden)|the user (must not|should not) (know|see|notice))/i },
  { type: 'obfuscation', re: /(base64|hex|urlencoded?|rot13).{0,60}?(decode|decrypt|unescape).{0,60}?(then |and )?(follow|execute|run|obey)/i },
];

function detectInstruction(text) {
  for (const p of INSTRUCTION_PATTERNS) {
    if (p.re.test(text)) return { type: p.type, match: true };
  }
  return null;
}

// Is the matched text wrapped in quotation marks (a quotation of an attack,
// rather than an attack)?
function sitsInsideQuotes(text, index, length) {
  const before = text.slice(Math.max(0, index - 3), index);
  const after = text.slice(index + length, index + length + 3);
  return /["'\u201C\u201D\u2018\u2019]\s*$/.test(before) || /^\s*["'\u201C\u201D\u2018\u2019]/.test(after);
}

// Returns ALL matched instruction types (a segment can carry several), each
// with its own quotedContext judgment.
function analyzeInstruction(text, inCodeOrQuote = false) {
  const matches = [];
  for (const p of INSTRUCTION_PATTERNS) {
    const m = p.re.exec(text);
    if (!m) continue;
    let quotedContext = !!inCodeOrQuote;
    if (!quotedContext) quotedContext = sitsInsideQuotes(text, m.index, m[0].length);
    matches.push({ type: p.type, quotedContext });
  }
  return matches;
}

function primaryInstruction(matches) {
  if (!matches || !matches.length) return null;
  return matches.reduce((a, b) => (INSTRUCTION_TYPES[b.type].severity > INSTRUCTION_TYPES[a.type].severity ? b : a));
}

function reachable(needs, caps) {
  if (needs === 'any') return { ok: true, via: 'behavior manipulation works against every agent' };
  if (needs === 'network') return caps.network
    ? { ok: true, via: 'agent can make outbound network requests' }
    : { ok: false, via: 'agent has no network access under this template' };
  if (needs === 'datastore') {
    if (caps.network) return { ok: true, via: 'agent can exfiltrate via network' };
    if (caps.email) return { ok: true, via: 'agent can exfiltrate via email' };
    if (caps.drive) return { ok: true, via: 'agent can write to cloud drive' };
    return { ok: false, via: 'agent can only return text to the user — data stays in the conversation' };
  }
  return { ok: false, via: 'unknown requirement' };
}

// Legacy impact model. New code should call assessSegment() instead; this stays
// so older callers keep producing the same shape.
function computeImpact(instructionType, evidenceTier, capabilityKey, extra = {}) {
  const caps = CAPABILITY_TEMPLATES[capabilityKey].caps;
  if (!instructionType) {
    const level = extra.cloaked && evidenceTier >= 3 ? 'medium' : evidenceTier >= 2 ? 'low' : 'info';
    return {
      level,
      explanation: extra.cloaked && evidenceTier >= 3
        ? 'Same URL serves different content to an AI-crawler User-Agent. No injection semantics in the AI-only segment, but conditional serving alone defeats "just read the page" assumptions.'
        : evidenceTier >= 2
          ? 'Hidden or pipeline-only content without injection semantics — likely SEO/a11y residue, but worth an eyeball.'
          : 'No injection semantics detected; cross-pipeline content difference only.',
      reachable: null,
    };
  }
  const t = INSTRUCTION_TYPES[instructionType];
  const r = reachable(t.needs, caps);
  let score = t.severity + evidenceTier - 1 + (r.ok ? 1 : 0) + (extra.cloaked ? 1 : 0);
  if (extra.quotedContext) score = Math.min(score, 2);
  const idx = Math.max(1, Math.min(4, score - 2));
  const level = ['info', 'low', 'medium', 'high', 'critical'][idx];
  const explanation = [
    `${t.desc} Evidence is ${['none', 'weak', 'moderate', 'strong'][evidenceTier]}.`,
    r.ok
      ? `Reachable under "${CAPABILITY_TEMPLATES[capabilityKey].label}" — ${r.via}.`
      : `Not directly reachable under "${CAPABILITY_TEMPLATES[capabilityKey].label}" (${r.via}) — but it becomes dangerous the moment this agent is granted more tools.`,
    extra.quotedContext ? 'Detected inside code/quote context — may be quoted attack material (e.g. a security article).' : null,
    extra.cloaked ? 'Content was only served to an AI-crawler User-Agent — consistent with AI-targeted cloaking.' : null,
  ].filter(Boolean).join(' ');
  return { level, explanation, reachable: r.ok, needs: t.needs };
}

module.exports = {
  CAPABILITY_TEMPLATES,
  INSTRUCTION_TYPES,
  INSTRUCTION_PATTERNS,
  detectInstruction,
  analyzeInstruction,
  primaryInstruction,
  computeImpact,
  normalizeText,
  decodeTagChars,
  LEVELS: ['info', 'low', 'medium', 'high', 'critical'],
};
