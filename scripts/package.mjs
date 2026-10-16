// Build loadable extension folders and zips containing only the runtime files.
//
//   npm run package            → dist/opentriage/            + dist/opentriage-<version>.zip
//   npm run package:trusted    → dist/opentriage-trusted/    + dist/opentriage-trusted-<version>.zip
//   add  -- --env <file> --team <name>  to make a TEAM build that carries an
//   exported environment file (e.g. npm run package:trusted -- --env soc.json --team soc)
//
// Team builds contain your organisation's environment facts. They are written
// only to dist/ (git-ignored) — never commit or publish them.
//
// The trusted build adds Chrome's `debugger` permission (required for trusted
// input; Chrome does not allow it to be optional), so it shows an extra
// warning at install. The standard build is what goes to the Web Store.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const trusted = process.argv.includes('--trusted');
const arg = (flag) => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : null;
};
const envFile = arg('--env');
const team = (arg('--team') || (envFile ? 'team' : '')).toLowerCase().replace(/[^a-z0-9-]/g, '');
const manifest = JSON.parse(readFileSync(path.join(root, 'manifest.json'), 'utf8'));
const name = ['opentriage', team, trusted ? 'trusted' : ''].filter(Boolean).join('-');
const outDir = path.join(root, 'dist', name);
const zip = path.join(root, 'dist', `${name}-${manifest.version}.zip`);

rmSync(outDir, { recursive: true, force: true });
rmSync(zip, { force: true });
mkdirSync(outDir, { recursive: true });
for (const item of ['icons', 'src', 'LICENSE']) cpSync(path.join(root, item), path.join(outDir, item), { recursive: true });
rmSync(path.join(outDir, 'src/providers/_template.js'), { force: true });

if (trusted) {
  manifest.name = 'OpenTriage (trusted input)';
  manifest.permissions = [...new Set([...manifest.permissions, 'debugger'])];
}
if (envFile) {
  const env = JSON.parse(readFileSync(path.resolve(envFile), 'utf8'));
  if (env.format !== 'opentriage-environment' || !Array.isArray(env.facts)) throw new Error(`${envFile} is not an OpenTriage environment export`);
  env.exportedAt ||= new Date().toISOString();
  mkdirSync(path.join(outDir, 'src/team'), { recursive: true });
  writeFileSync(path.join(outDir, 'src/team/environment.json'), JSON.stringify(env, null, 2));
  manifest.name = `OpenTriage (${team.toUpperCase()} team build${trusted ? ', trusted input' : ''})`;
  manifest.version_name = `${manifest.version} ${team.toUpperCase()} team build`;
  console.log(`Bundled ${env.facts.length} environment facts. This build contains internal details — share it only inside your team.`);
}
writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
execFileSync('zip', ['-r', '-q', zip, '.'], { cwd: outDir, stdio: 'inherit' });
console.log(`Wrote ${path.relative(root, outDir)}/ and ${path.relative(root, zip)}`);
