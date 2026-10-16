import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMemory, renderMemoryForPrompt } from '../src/memory/memory.js';
import { memoryStorage } from '../src/lib/storage.js';

test('add, dedupe, update, remove', async () => {
  const mem = createMemory(memoryStorage());
  const a = await mem.add({ fact: 'Hosts prefixed LAB- are the isolated test lab.', category: 'naming' });
  await mem.add({ fact: 'hosts prefixed lab- are the isolated test lab.', category: 'naming' });
  assert.equal((await mem.all()).length, 1);
  await mem.update(a.id, { fact: 'Hosts prefixed LAB- are the test lab and out of scope.', category: 'scope' });
  assert.equal((await mem.all())[0].category, 'scope');
  await mem.remove(a.id);
  assert.equal((await mem.all()).length, 0);
});

test('unknown categories fall back to other; control chars stripped', async () => {
  const mem = createMemory(memoryStorage());
  const f = await mem.add({ fact: 'x\u0000y  z', category: 'nope' });
  assert.equal(f.category, 'other');
  assert.equal(f.fact, 'xy z');
});

test('export / import between analysts', async () => {
  const a = createMemory(memoryStorage());
  await a.add({ fact: 'Escalate confirmed TPs to the IR on-call channel.', category: 'escalation' });
  const json = await a.exportJson();
  const b = createMemory(memoryStorage());
  assert.equal(await b.importJson(json), 1);
  assert.equal((await b.all())[0].source, 'import');
  await assert.rejects(() => b.importJson('{"facts":[]}'));
});

test('prompt rendering groups by category and handles empty memory', () => {
  assert.match(renderMemoryForPrompt([]), /do not know this environment/);
  const out = renderMemoryForPrompt([
    { fact: 'A', category: 'scope' },
    { fact: 'B', category: 'naming' },
  ]);
  assert.ok(out.indexOf('### scope') < out.indexOf('### naming'));
});

test('team bundle: added once, updated with new versions, analyst edits and additions kept', async () => {
  const mem = createMemory(memoryStorage());
  const v1 = { format: 'opentriage-environment', exportedAt: 'v1', facts: [
    { fact: 'Owners are in Intune.', category: 'asset_lookup' },
    { fact: 'Roles are in Teams.', category: 'identity_lookup' },
    { fact: 'Old closure rule.', category: 'closure' },
  ] };
  assert.deepEqual(await mem.syncBundle(v1, ''), { added: 3, removed: 0, kept: 0, version: 'v1' });
  assert.equal(await mem.syncBundle(v1, 'v1'), null, 'same version is a no-op');
  await mem.add({ fact: 'My own note.', category: 'other' });
  const roles = (await mem.all()).find((f) => f.fact === 'Roles are in Teams.');
  await mem.update(roles.id, { fact: 'Roles are in Teams (People tab).' });
  const v2 = { format: 'opentriage-environment', exportedAt: 'v2', facts: [
    { fact: 'Owners are in Intune.', category: 'asset_lookup' },
    { fact: 'New closure rule.', category: 'closure' },
  ] };
  const r = await mem.syncBundle(v2, 'v1');
  assert.deepEqual(r, { added: 1, removed: 1, kept: 1, version: 'v2' });
  const facts = (await mem.all()).map((f) => `${f.source}:${f.fact}`).sort();
  assert.deepEqual(facts, [
    'analyst:My own note.',
    'analyst:Roles are in Teams (People tab).',
    'team-bundle:New closure rule.',
    'team-bundle:Owners are in Intune.',
  ]);
});

test('team bundle does not duplicate facts already imported by hand', async () => {
  const mem = createMemory(memoryStorage());
  await mem.add({ fact: 'Owners are in Intune.', category: 'asset_lookup', source: 'import' });
  const r = await mem.syncBundle({ format: 'opentriage-environment', exportedAt: 'v1', facts: [{ fact: 'owners are in intune.', category: 'asset_lookup' }] }, '');
  assert.equal(r.added, 0);
  assert.equal((await mem.all()).length, 1);
});
