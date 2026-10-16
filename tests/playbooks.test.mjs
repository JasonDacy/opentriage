import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePlaybook, validateMarkdownPlaybook, templateHeadings } from '../src/playbooks/validator.js';
import { toMarkdown, toHtml } from '../src/playbooks/render.js';
import { createLibrary, scorePlaybook } from '../src/playbooks/library.js';
import { blankPlaybook, SECTIONS } from '../src/playbooks/template.js';
import { memoryStorage } from '../src/lib/storage.js';
import { samplePlaybook } from './fixtures.mjs';

const today = '2026-10-16';

test('a complete playbook passes validation', () => {
  const r = validatePlaybook(samplePlaybook(), { today });
  assert.deepEqual(r.errors, []);
  assert.equal(r.ok, true);
});

test('blank skeleton fails with actionable errors', () => {
  const r = validatePlaybook(blankPlaybook(today), { today });
  assert.equal(r.ok, false);
  const fields = r.errors.map((e) => e.field);
  for (const f of ['detectionName', 'mitre', 'referenceCases', 'decisionFlow', 'findings.attackChain']) assert.ok(fields.includes(f), f);
});

test('hygiene: usernames in paths, emails, placeholders, refanged IOCs, relative dates', () => {
  const pb = samplePlaybook();
  pb.findings.iocs.push({ type: 'path', value: 'C:\\Users\\jsmith\\Downloads\\a.exe' });
  pb.findings.iocs.push({ type: 'domain', value: 'evil.example.com' });
  pb.findings.attackChain += ' Reported by jane.doe@example.com.';
  pb.findings.threatIntel = '[insert VT result]';
  pb.nextReviewDue = 'in 90 days';
  pb.detectionName = 'Trojan.Win32.Agent';
  const msgs = validatePlaybook(pb, { today }).errors.map((e) => e.message).join('\n');
  assert.match(msgs, /Username in a path/);
  assert.match(msgs, /Email address present/);
  assert.match(msgs, /Placeholder text/);
  assert.match(msgs, /Defang domain/);
  assert.match(msgs, /absolute date/);
  assert.match(msgs, /malware\/signature name/);
});

test('bad technique IDs are rejected', () => {
  const pb = samplePlaybook();
  pb.mitre[0].techniqueId = 'T59';
  assert.equal(validatePlaybook(pb, { today }).ok, false);
});

test('duplicate detection is warned so the agent merges instead', () => {
  const existing = [{ playbook: samplePlaybook() }];
  const r = validatePlaybook(samplePlaybook(), { today, existing });
  assert.ok(r.warnings.some((w) => /already exists/.test(w.message)));
});

test('markdown render contains all eight sections in order', () => {
  const md = toMarkdown(samplePlaybook());
  let last = -1;
  for (const s of SECTIONS) {
    const i = md.indexOf(`${s.n}. ${s.title}`);
    assert.ok(i > last, `section ${s.n} present and ordered`);
    last = i;
  }
  assert.match(md, /```kql/);
});

test('html render escapes content', () => {
  const pb = samplePlaybook();
  pb.findings.attackChain = '<script>alert(1)</script> ' + pb.findings.attackChain;
  const html = toHtml(pb);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('custom template mode checks headings and hygiene', () => {
  const tpl = '# Title\n## Overview\n## Triage Steps\n## Escalation\n';
  const heads = templateHeadings(tpl);
  assert.deepEqual(heads, ['Title', 'Overview', 'Triage Steps', 'Escalation']);
  const bad = validateMarkdownPlaybook('# X\n## Overview\nTBD\n', { requiredHeadings: heads.slice(1) });
  assert.equal(bad.ok, false);
  const good = validateMarkdownPlaybook('# X\n## Overview\nok\n## Triage Steps\nok\n## Escalation\nReview 2026-12-01\n', { requiredHeadings: heads.slice(1) });
  assert.equal(good.ok, true);
});

test('library saves, searches by detection name and sorts', async () => {
  const lib = createLibrary(memoryStorage());
  await lib.save({ playbook: samplePlaybook() });
  const other = samplePlaybook();
  other.detectionName = 'Anomalous Sign-in From New Country';
  other.mitre = [{ tactic: 'Initial Access', techniqueId: 'T1078', techniqueName: 'Valid Accounts' }];
  other.findings.attackChain = 'A user signed in from a country never seen for the account, without a prior travel record or VPN egress.';
  await lib.save({ playbook: other });
  const all = await lib.all();
  assert.equal(all[0].title, 'Anomalous Sign-in From New Country');
  const hits = await lib.search('Suspicious Encoded PowerShell Command');
  assert.equal(hits[0].score, 100);
  assert.equal((await lib.search('powershell encoded'))[0].title, 'Suspicious Encoded PowerShell Command');
  assert.equal((await lib.search('kerberoasting')).length, 0);
  const cov = await lib.coverage();
  assert.deepEqual(Object.keys(cov).sort(), ['Execution', 'Initial Access']);
  assert.ok(scorePlaybook(all[1], 'PowerShell') > 0);
});

test('library export/import round-trip skips duplicates', async () => {
  const a = createLibrary(memoryStorage());
  await a.save({ playbook: samplePlaybook() });
  const json = await a.exportJson();
  const b = createLibrary(memoryStorage());
  assert.equal(await b.importJson(json), 1);
  assert.equal(await b.importJson(json), 0);
});
