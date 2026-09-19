// Capability templates + impact model.
// Impact is tiered and explainable — no fake "safety probability".
// Formula: impact = f(instruction severity, evidence strength, capability reachability)

const CAPABILITY_TEMPLATES = {
  'summary-only': {
    label: 'Summary-only assistant',
    blurb: 'The agent only reads the page and returns a summary to the user.',
    caps: { network: false, forms: false, email: false, drive: false },
  },
  'browser-agent': {
    label: 'Browser agent (click + forms)',
    blurb: 'The agent can click, navigate and submit forms inside the browser session.',
    caps: { network: false, forms: true, email: false, drive: false },
  },
  'full-access': {
    label: 'Full-access agent (email + drive + network)',
    blurb: 'The agent can read the user\'s email/drive and make outbound network requests.',
    caps: { network: true, forms: true, email: true, drive: true },
  },
};

// instruction type -> { severity, needs: which capability would make it dangerous }
const INSTRUCTION_TYPES = {
  'ignore-previous': { severity: 3, needs: 'any', desc: 'Attempts to override the agent\'s higher-priority instructions.' },
  'task-override': { severity: 3, needs: 'any', desc: 'Attempts to replace or redirect the user\'s original task.' },
  'system-prompt': { severity: 2, needs: 'any', desc: 'References or probes the agent\'s hidden system prompt.' },
  impersonation: { severity: 2, needs: 'any', desc: 'Redefines the agent\'s identity or role.' },
  'exfil-url': { severity: 4, needs: 'network', desc: 'Instructs data to be sent to an external URL/address.' },
  'exfil-data': { severity: 4, needs: 'datastore', desc: 'Instructs secrets or personal data to be included in output.' },
  'silent-action': { severity: 3, needs: 'any', desc: 'Instructs the agent to act without informing the user.' },
  'obfuscation': { severity: 3, needs: 'any', desc: 'Instructs the agent to decode/obfuscate content before following it.' },
};

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

const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];

// evidenceTier: 0 none, 1 weak, 2 moderate, 3 strong
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
  // Quoted/educational context caps the tier: pattern-matching a quoted attack string is expected.
  if (extra.quotedContext) score = Math.min(score, 2);
  const idx = Math.max(1, Math.min(4, score - 2)); // map to low..critical
  const level = LEVELS[idx];
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

// Instruction detection with context awareness. A pattern match inside code/quote
// markup, inside quotation marks, or inside clearly defensive/educational prose
// is reported as quotedContext so the impact model caps it instead of crying wolf.
const DEFENSIVE_CONTEXT = /(attackers?|defensive|defenses?|mitigat|prevention|educational|inert|should never follow|attack strings?|for example|such as|looks like this)/i;

// Returns ALL matched instruction types (a segment can carry several attacks at once),
// each with its own quotedContext judgment.
function analyzeInstruction(text, inCodeOrQuote = false) {
  const matches = [];
  for (const p of INSTRUCTION_PATTERNS) {
    const m = p.re.exec(text);
    if (!m) continue;
    let quotedContext = !!inCodeOrQuote;
    if (!quotedContext) {
      const before = text.slice(Math.max(0, m.index - 3), m.index);
      const after = text.slice(m.index + m[0].length, m.index + m[0].length + 3);
      if (/["'“”‘’]\s*$/.test(before) || /^\s*["'“”‘’]/.test(after)) quotedContext = true;
    }
    if (!quotedContext && DEFENSIVE_CONTEXT.test(text)) quotedContext = true;
    matches.push({ type: p.type, quotedContext });
  }
  return matches;
}

// The highest-severity match drives the headline impact; all matches are listed as evidence.
function primaryInstruction(matches) {
  if (!matches || !matches.length) return null;
  return matches.reduce((a, b) => (INSTRUCTION_TYPES[b.type].severity > INSTRUCTION_TYPES[a.type].severity ? b : a));
}

module.exports = { CAPABILITY_TEMPLATES, INSTRUCTION_TYPES, INSTRUCTION_PATTERNS, detectInstruction, analyzeInstruction, primaryInstruction, computeImpact, LEVELS };
