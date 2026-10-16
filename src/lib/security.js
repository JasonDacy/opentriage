// Security primitives shared by the agent, tools and memory system.
//
// Threat model in one sentence: everything read from a web page (alert
// fields, command lines, file names, email subjects, URLs) may have been
// written by an attacker, so it is wrapped and labelled as data, it can never
// write to memory directly, and actions that could change state need a human.
// See docs/threat-model.md.

const UNTRUSTED_TAG = 'untrusted_page_content';

/**
 * Wrap untrusted text so the model can always tell where it starts and ends.
 * Any attempt inside the content to close the wrapper is neutralised.
 */
export function wrapUntrusted(text, meta = {}) {
  const attrs = Object.entries(meta)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}="${String(v).replace(/["<>\n]/g, ' ').slice(0, 300)}"`)
    .join(' ');
  const safe = String(text ?? '').replace(new RegExp(`</?\\s*${UNTRUSTED_TAG}[^>]*>`, 'gi'), '[removed-tag]');
  return `<${UNTRUSTED_TAG}${attrs ? ' ' + attrs : ''}>\n${safe}\n</${UNTRUSTED_TAG}>`;
}

export function maskEmails(text) {
  return String(text).replace(/\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, '$1***@$2');
}

// Words that suggest a click will change state in the console.
const STATE_CHANGING = [
  'close', 'resolve', 'resolved', 'dismiss', 'suppress', 'delete', 'remove', 'purge', 'isolate', 'contain',
  'quarantine', 'block', 'unblock', 'allow', 'whitelist', 'allowlist', 'disable', 'enable', 'kill',
  'terminate', 'stop', 'restart', 'reboot', 'reset', 'revoke', 'lock', 'unlock', 'submit', 'save',
  'apply', 'assign', 'reassign', 'confirm', 'approve', 'reject', 'run', 'execute', 'deploy', 'push',
  'send', 'post', 'publish', 'merge', 'change status', 'set status', 'mark as', 'update', 'create',
  'add', 'import', 'upload', 'acknowledge', 'escalate', 'release', 'restore', 'rollback', 'uninstall',
  'sign out', 'log out', 'logout', 'yes', 'ok',
];

const SAFE_HINTS = ['search', 'filter', 'query', 'find', 'expand', 'collapse', 'details', 'view', 'show', 'open'];

/**
 * Decide whether an action needs analyst approval.
 * Returns { requiresApproval: boolean, reason: string }.
 */
export function classifyAction({ kind, element = {}, approvalMode = 'standard', url, trustedOrigins = [] }) {
  if (kind === 'navigate' || kind === 'open_tab') {
    let origin = '';
    try {
      origin = new URL(url).origin;
    } catch {
      return { requiresApproval: true, reason: 'URL could not be parsed' };
    }
    if (!/^https:$/.test(new URL(url).protocol)) return { requiresApproval: true, reason: 'Non-HTTPS destination' };
    if (trustedOrigins.includes(origin)) return { requiresApproval: false, reason: 'Trusted origin' };
    return { requiresApproval: true, reason: `New destination: ${origin}` };
  }

  if (kind === 'click' || kind === 'submit') {
    if (approvalMode === 'strict') return { requiresApproval: true, reason: 'Strict mode: every interaction is approved' };
    const label = [element.name, element.text, element.role, element.type, element.title]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    if (element.type === 'submit' || element.role === 'menuitemradio') {
      return { requiresApproval: true, reason: 'Form submission' };
    }
    const hit = STATE_CHANGING.find((w) => new RegExp(`(^|[^a-z])${w.replace(/ /g, '\\s+')}([^a-z]|$)`).test(label));
    if (hit) return { requiresApproval: true, reason: `Looks state-changing ("${hit}")` };
    if (!label.trim()) return { requiresApproval: true, reason: 'Unlabelled control' };
    if (kind === 'submit') {
      const safe = SAFE_HINTS.some((w) => label.includes(w)) || element.role === 'searchbox' || element.type === 'search';
      return safe ? { requiresApproval: false, reason: 'Search or filter field' } : { requiresApproval: true, reason: 'Submits a field that is not a search box' };
    }
    return { requiresApproval: false, reason: 'Read-only navigation control' };
  }

  if (kind === 'memory_write' || kind === 'playbook_save') {
    return { requiresApproval: true, reason: 'Learning always requires the analyst' };
  }
  return { requiresApproval: true, reason: 'Unknown action type' };
}

function shingles(text, n = 4) {
  const words = String(text)
    .toLowerCase()
    .replace(/[^a-z0-9._\-\\/@:]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean);
  const out = new Set();
  if (words.length < n) {
    if (words.length) out.add(words.join(' '));
    return out;
  }
  for (let i = 0; i + n <= words.length; i++) out.add(words.slice(i, i + n).join(' '));
  return out;
}

/**
 * Memory-poisoning check. A proposed fact that closely matches text the agent
 * read from a web page (and not text the analyst typed) gets flagged so the
 * analyst can see it may have been planted in alert data.
 * Returns { tainted: boolean, pageOverlap: number, analystOverlap: number }.
 */
export function provenanceCheck(fact, { pageTexts = [], analystTexts = [] } = {}) {
  const f = shingles(fact, 3);
  if (!f.size) return { tainted: false, pageOverlap: 0, analystOverlap: 0 };
  const overlap = (texts) => {
    const pool = new Set();
    for (const t of texts) for (const s of shingles(t, 3)) pool.add(s);
    let hits = 0;
    for (const s of f) if (pool.has(s)) hits++;
    return hits / f.size;
  };
  const pageOverlap = overlap(pageTexts);
  const analystOverlap = overlap(analystTexts);
  return { tainted: pageOverlap >= 0.5 && analystOverlap < pageOverlap, pageOverlap, analystOverlap };
}

/** Cheap check for text that tries to instruct an AI. Used to warn, never to trust. */
export function looksLikeInjection(text) {
  const t = String(text).toLowerCase();
  return /(ignore (all |any )?(previous|prior|above) instructions|you are now|system prompt|as an ai|assistant:|remember that|from now on|always classify|mark (this|it) as (benign|false positive)|do not (report|escalate|flag))/.test(
    t,
  );
}

// ---------------------------------------------------------------------------
// Indicator sharing. Typing an indicator into a site, or putting one in a URL,
// sends it to whoever runs that site. That is fine for the analyst's own
// consoles and not something to do silently anywhere else.

/** Well-known external intelligence and analysis services. Never treated as internal. */
export const KNOWN_EXTERNAL_SERVICES = [
  'virustotal.com', 'shodan.io', 'censys.io', 'censys.com', 'abuseipdb.com', 'talosintelligence.com', 'otx.alienvault.com',
  'urlscan.io', 'hybrid-analysis.com', 'any.run', 'app.any.run', 'joesandbox.com', 'greynoise.io', 'viz.greynoise.io',
  'threatfox.abuse.ch', 'urlhaus.abuse.ch', 'bazaar.abuse.ch', 'abuse.ch', 'ipinfo.io', 'whois.domaintools.com',
  'securitytrails.com', 'pulsedive.com', 'threatminer.org', 'exchange.xforce.ibmcloud.com', 'riskiq.net', 'community.riskiq.com',
  'spur.us', 'ipqualityscore.com', 'urlvoid.com', 'scamalytics.com', 'google.com', 'bing.com', 'duckduckgo.com', 'chatgpt.com',
  'pastebin.com', 'github.com',
];

export function isKnownExternal(origin) {
  let host = '';
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return false;
  }
  return KNOWN_EXTERNAL_SERVICES.some((d) => host === d || host.endsWith('.' + d));
}

/**
 * Public indicators in `text` that would be disclosed to a third party.
 * `extract` is extractIocs (injected to keep this module dependency-light).
 */
export function publicIndicators(text, extract, isPrivate) {
  const r = extract(text || '');
  return [
    ...r.sha256, ...r.sha1, ...r.md5,
    ...r.ipv4.filter((ip) => !isPrivate(ip)),
    ...r.url, ...r.domain, ...r.email,
  ].filter((v, i, a) => a.indexOf(v) === i);
}

/**
 * Decide whether sending `text` to `origin` needs approval.
 * Returns { needed, indicators, external } — external=true for known third-party services.
 */
export function shareCheck({ text, origin, internalOrigins = [], extract, isPrivate }) {
  const indicators = publicIndicators(text, extract, isPrivate);
  if (!indicators.length) return { needed: false, indicators, external: false };
  const external = isKnownExternal(origin);
  if (!external && internalOrigins.includes(origin)) return { needed: false, indicators, external };
  return { needed: true, indicators, external };
}

/** The part of a URL that carries data to the destination (path, query, fragment), decoded. */
export function urlPayload(url) {
  try {
    const u = new URL(url);
    return decodeURIComponent((u.pathname + ' ' + u.search + ' ' + u.hash).replace(/[/?&=#+]/g, ' '));
  } catch {
    return '';
  }
}
