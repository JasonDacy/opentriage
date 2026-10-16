// Repository hygiene check: keeps environment-specific data out of the build.
//
//   npm run check
//
// Built-in rules catch secrets and organisation identifiers that commonly leak
// into tools like this (API keys, tenant/subscription GUIDs, private IPs,
// internal email addresses, wiki page IDs). Add your own organisation's terms
// — company domains, host prefixes, team names, colleagues' names — to a local
// `.opentriage-denylist` file (one term or /regex/ per line). That file is
// git-ignored, so your terms never reach the repository either.

import { readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'icons']);
const TEXT_EXT = new Set(['.js', '.mjs', '.json', '.md', '.html', '.css', '.py', '.yml', '.yaml', '.txt']);

const RULES = [
  { id: 'anthropic-key', re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'openai-key', re: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { id: 'aws-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { id: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: 'guid', re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i, note: 'tenant/subscription/workspace IDs belong in environment memory, not the repo' },
  { id: 'atlassian-site', re: /\b(?!example\b)[a-z0-9-]+\.atlassian\.net\b/i },
  { id: 'sharepoint-site', re: /\b[a-z0-9-]+\.sharepoint\.com\b/i },
  { id: 'email', re: /\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b|users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
];
// Private IPs are fine in tests and docs examples; elsewhere they are a smell.
const PRIVATE_IP = /\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/;
const ALLOW_PRIVATE_IP = [/^tests\//, /^docs\//, /^src\/lib\/ioc\.js$/];

async function* walk(dir) {
  for (const name of await readdir(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = path.join(dir, name);
    const s = await stat(p);
    if (s.isDirectory()) yield* walk(p);
    else if (TEXT_EXT.has(path.extname(name)) && name !== '.opentriage-denylist') yield p;
  }
}

async function loadDenylist() {
  const f = path.join(root, '.opentriage-denylist');
  if (!existsSync(f)) return [];
  return (await readFile(f, 'utf8'))
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => (/^\/.*\/[a-z]*$/.test(l) ? new RegExp(l.slice(1, l.lastIndexOf('/')), l.slice(l.lastIndexOf('/') + 1) || 'i') : new RegExp(l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')));
}

const problems = [];
const deny = await loadDenylist();

for await (const file of walk(root)) {
  const rel = path.relative(root, file).split(path.sep).join('/');
  const lines = (await readFile(file, 'utf8')).split('\n');
  lines.forEach((line, i) => {
    for (const r of RULES) if (r.re.test(line)) problems.push(`${rel}:${i + 1} [${r.id}] ${line.trim().slice(0, 120)}${r.note ? ' — ' + r.note : ''}`);
    if (PRIVATE_IP.test(line) && !ALLOW_PRIVATE_IP.some((a) => a.test(rel))) problems.push(`${rel}:${i + 1} [private-ip] ${line.trim().slice(0, 120)}`);
    for (const d of deny) if (d.test(line)) problems.push(`${rel}:${i + 1} [denylist ${d}] ${line.trim().slice(0, 120)}`);
  });
}

// Structural checks
const manifest = JSON.parse(await readFile(path.join(root, 'manifest.json'), 'utf8'));
if (manifest.manifest_version !== 3) problems.push('manifest.json: manifest_version must be 3');
if ((manifest.host_permissions || []).some((h) => h !== 'https://api.anthropic.com/*')) {
  problems.push('manifest.json: only model API hosts belong in host_permissions; console sites are requested at runtime');
}
const index = JSON.parse(await readFile(path.join(root, 'src/knowledge/profiles/index.json'), 'utf8'));
for (const p of index) {
  const f = path.join(root, 'src/knowledge/profiles', p.file);
  if (!existsSync(f)) {
    problems.push(`profiles/index.json: missing ${p.file}`);
    continue;
  }
  const head = (await readFile(f, 'utf8')).match(/^---\nid: (.+)\n/);
  if (!head || head[1].trim() !== p.id) problems.push(`${p.file}: front matter id must be "${p.id}"`);
  for (const h of p.hosts || []) {
    try {
      new RegExp(h);
    } catch {
      problems.push(`profiles/index.json: bad host regex ${h}`);
    }
  }
}

if (problems.length) {
  console.error(`✗ ${problems.length} problem(s):\n` + problems.map((p) => '  ' + p).join('\n'));
  process.exit(1);
}
console.log(`✓ Hygiene check passed${deny.length ? ` (including ${deny.length} local denylist terms)` : ''}.`);
