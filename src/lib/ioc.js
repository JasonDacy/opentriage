// Indicator extraction, refanging and defanging.
// Pure functions: no browser APIs, fully unit-tested.

const RE = {
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  url: /\bhttps?:\/\/[^\s"'<>`]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  domain: /\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
};

// Common file extensions that the domain regex would otherwise pick up.
const NOT_TLDS = new Set([
  'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'js', 'jse', 'hta', 'lnk', 'msi', 'zip', 'rar',
  '7z', 'gz', 'tar', 'iso', 'img', 'txt', 'log', 'csv', 'json', 'xml', 'yml', 'yaml', 'ini', 'cfg', 'conf',
  'py', 'sh', 'pl', 'rb', 'php', 'jar', 'class', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt',
  'pptx', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'tmp', 'dat', 'db', 'bak', 'plist', 'app',
  'dmg', 'pkg', 'deb', 'rpm', 'so', 'dylib', 'md', 'html', 'htm', 'css', 'ts', 'map', 'lock', 'node',
]);

/** Undo common defanging so indicators can be matched and looked up. */
export function refang(text) {
  return String(text)
    .replace(/hxxp(s?):\/\//gi, 'http$1://')
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}/gi, '.')
    .replace(/\[(:|colon)\]/gi, ':')
    .replace(/\[@\]|\[at\]/gi, '@');
}

/** Make an indicator safe to paste into tickets, chat and playbooks. */
export function defang(ioc) {
  let s = String(ioc);
  s = s.replace(/^http(s?):\/\//i, 'hxxp$1://');
  // Defang dots in host part only for URLs, everywhere for bare domains/IPs.
  if (/^hxxps?:\/\//i.test(s)) {
    const m = s.match(/^(hxxps?:\/\/)([^/?#]+)(.*)$/i);
    if (m) s = m[1] + m[2].replace(/\./g, '[.]') + m[3];
  } else if (!/\[\.\]/.test(s)) {
    s = s.replace(/\./g, '[.]');
  }
  s = s.replace(/@/g, '[@]');
  return s;
}

export function isDefanged(ioc) {
  return /hxxp|\[\.\]|\[@\]/i.test(ioc);
}

function uniq(arr) {
  return [...new Set(arr)];
}

/**
 * Extract indicators from free text. Defanged indicators are recognised too.
 * Returns { sha256, sha1, md5, ipv4, url, domain, email, cve }.
 */
export function extractIocs(text) {
  const src = refang(text || '');
  const out = {};
  const sha256 = uniq(src.match(RE.sha256) || []).map((h) => h.toLowerCase());
  const sha1 = uniq(src.match(RE.sha1) || [])
    .map((h) => h.toLowerCase())
    .filter((h) => !sha256.some((x) => x.includes(h)));
  const md5 = uniq(src.match(RE.md5) || [])
    .map((h) => h.toLowerCase())
    .filter((h) => !sha256.some((x) => x.includes(h)) && !sha1.some((x) => x.includes(h)));
  out.sha256 = uniq(sha256);
  out.sha1 = uniq(sha1);
  out.md5 = uniq(md5);
  out.ipv4 = uniq(src.match(RE.ipv4) || []);
  out.url = uniq((src.match(RE.url) || []).map((u) => u.replace(/[),.;\]]+$/, '')));
  out.email = uniq((src.match(RE.email) || []).map((e) => e.toLowerCase()));
  out.domain = uniq(
    (src.match(RE.domain) || [])
      .map((d) => d.toLowerCase())
      .filter((d) => !NOT_TLDS.has(d.split('.').pop())),
  );
  out.cve = uniq((src.match(RE.cve) || []).map((c) => c.toUpperCase()));
  return out;
}

export function iocType(ioc) {
  const s = refang(ioc).trim();
  if (/^[a-f0-9]{64}$/i.test(s) || /^[a-f0-9]{40}$/i.test(s) || /^[a-f0-9]{32}$/i.test(s)) return 'hash';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (/^[^@\s]+@[^@\s]+$/.test(s)) return 'email';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return 'domain';
  return 'unknown';
}

/** RFC1918 / loopback / link-local / CGNAT — internal addresses need no external lookup. */
export function isPrivateIp(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
  );
}
