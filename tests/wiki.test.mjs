import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toStorage, storageToText, appendTableRow, planSort, inversions, markdownToStorage, diffSummary, sortKey, codeMacro } from '../src/wiki/storage.js';
import { createConfluenceClient, isConfluenceUrl } from '../src/wiki/confluence.js';
import { samplePlaybook } from './fixtures.mjs';

test('playbook renders to storage with lozenges, note panel and code macros', () => {
  const s = toStorage(samplePlaybook());
  assert.match(s, /<h1>1\. Alert Metadata<\/h1>/);
  assert.match(s, /<h1>8\. Review History<\/h1>/);
  assert.match(s, /ac:name="status"><ac:parameter ac:name="colour">Yellow<\/ac:parameter><ac:parameter ac:name="title">Medium/);
  assert.match(s, /ac:name="note"><ac:rich-text-body><p><strong>Determination: Benign True Positive/);
  assert.match(s, /ac:name="code"><ac:parameter ac:name="language">kql<\/ac:parameter><ac:plain-text-body><!\[CDATA\[DeviceProcessEvents/);
  // Balanced tags (rough well-formedness check)
  for (const tag of ['table', 'tbody', 'tr', 'td', 'th', 'p', 'ac:structured-macro', 'h1', 'h2']) {
    const open = (s.match(new RegExp(`<${tag}[\\s>]`, 'g')) || []).length;
    const close = (s.match(new RegExp(`</${tag}>`, 'g')) || []).length;
    assert.equal(open, close, tag);
  }
});

test('CDATA terminators inside code are split safely', () => {
  assert.match(codeMacro('a]]>b'), /a]]]]><!\[CDATA\[>b/);
});

test('storage → text keeps content and code, drops markup', () => {
  const t = storageToText(toStorage(samplePlaybook()));
  assert.match(t, /Suspicious Encoded PowerShell Command/);
  assert.match(t, /DeviceProcessEvents/);
  assert.doesNotMatch(t, /<ac:|colour/);
});

test('append a row to the table identified by its header', () => {
  const page = '<p>Intro</p><table><tbody><tr><th><p>Other</p></th></tr></tbody></table><table><tbody><tr><th><p>Model name</p></th><th><p>MITRE</p></th></tr><tr><td><p>A</p></td><td><p>T1</p></td></tr></tbody></table>';
  const r = appendTableRow(page, 'model name', [{ link_page_title: 'B', text: 'B' }, 'T2']);
  assert.match(r.storage, /<tr><td><p><ac:link><ri:page ri:content-title="B" \/>.*<\/ac:link><\/p><\/td><td><p>T2<\/p><\/td><\/tr><\/tbody><\/table>$/);
  assert.match(r.storage, /^<p>Intro<\/p><table><tbody><tr><th><p>Other/);
  assert.throws(() => appendTableRow(page, 'model name', ['only one']), /2 columns/);
  assert.throws(() => appendTableRow(page, 'nope', ['x']), /No table/);
});

test('sort plan ignores brackets and moves only what is out of place', () => {
  const cur = [
    { id: '1', title: 'Credential Access via Keychain' },
    { id: '2', title: '[Heuristic Attribute] Hidden Window' },
    { id: '3', title: 'Anomalous Sign-in' },
    { id: '4', title: 'PowerShell Encoded' },
  ];
  assert.equal(sortKey('[Heuristic Attribute] X'), 'heuristic attribute x');
  const { desired, moves } = planSort(cur);
  assert.deepEqual(desired.map((d) => d.id), ['3', '1', '2', '4']);
  // Simulate the moves and confirm the result
  let order = cur.map((c) => c.id);
  for (const m of moves) {
    order.splice(order.indexOf(m.id), 1);
    const t = order.indexOf(m.targetId);
    order.splice(m.position === 'before' ? t : t + 1, 0, m.id);
  }
  assert.deepEqual(order, ['3', '1', '2', '4']);
  assert.ok(moves.length <= 2);
  assert.equal(inversions(desired).length, 0);
  assert.equal(inversions(cur).length, 1);
});

test('markdown → storage and diff summary', () => {
  const s = markdownToStorage('# T\n\n## A\n- x\n- y\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n```kql\nX | take 1\n```');
  assert.match(s, /<h2>A<\/h2><ul><li><p>x<\/p><\/li>/);
  assert.match(s, /ac:name="code"/);
  const d = diffSummary('a\nb\nc', 'a\nB\nc\nd');
  assert.equal(d.added, 2);
  assert.equal(d.removed, 1);
  assert.match(d.text, /- b\n\+ B/);
});

test('Confluence URL detection', () => {
  assert.ok(isConfluenceUrl('https://example.atlassian.net/wiki/spaces/IR/pages/1'));
  assert.ok(isConfluenceUrl('https://wiki.example.org/wiki/x'));
  assert.ok(!isConfluenceUrl('https://example.atlassian.net/jira/'));
  assert.ok(!isConfluenceUrl('http://example.atlassian.net/wiki/'));
});

test('client: CQL escaping, version bump, folder fallback, pagination', async () => {
  const calls = [];
  const client = createConfluenceClient(async (path, method, body) => {
    calls.push({ path, method, body });
    if (path.startsWith('/wiki/rest/api/content/search')) return { status: 200, json: { results: [{ id: 5, title: 'X', _links: { webui: '/spaces/IR/pages/5' } }] } };
    if (path.startsWith('/wiki/api/v2/pages/9/direct-children')) return { status: 404, json: {} };
    if (path === '/wiki/api/v2/folders/9/direct-children?limit=250') return { status: 200, json: { results: [{ id: 1, title: 'A', type: 'page' }], _links: { next: '/api/v2/folders/9/direct-children?cursor=abc' } } };
    if (path.startsWith('/wiki/api/v2/folders/9/direct-children?cursor')) return { status: 200, json: { results: [{ id: 2, title: 'B', type: 'page' }] } };
    if (method === 'PUT') return { status: 200, json: { id: 7, title: 'T', version: { number: body.version.number } } };
    return { status: 500, json: { message: 'unexpected' } };
  });
  const hits = await client.search({ title: 'He said "hi"', spaceKey: 'IR' });
  assert.equal(hits[0].id, '5');
  assert.match(decodeURIComponent(calls[0].path), /title ~ "He said \\"hi\\""/);
  const kids = await client.children('9');
  assert.deepEqual(kids.map((k) => k.title), ['A', 'B']);
  const up = await client.updatePage({ id: 7, title: 'T', storage: '<p/>', version: 3, message: 'm' });
  assert.equal(up.version, 4);
  await assert.rejects(() => client.getPage('nope'), /failed \(500\): unexpected/);
});
