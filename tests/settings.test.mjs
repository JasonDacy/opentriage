import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateEnrichmentSource as check } from '../src/lib/settings.js';

const good = { name: 'Censys', url: 'https://platform.censys.io/hosts/{ioc}', types: ['ip'] };

test('accepts a complete source', () => {
  assert.deepEqual(check(good), { ok: true, url: good.url });
});

test('accepts braces encoded by the address bar', () => {
  const r = check({ ...good, url: 'https://search.censys.io/search?q=%7Bioc%7D' });
  assert.equal(r.ok, true);
  assert.equal(r.url, 'https://search.censys.io/search?q={ioc}');
  assert.equal(check({ ...good, url: 'https://x.example/%7bIOC%7d' }).url, 'https://x.example/{ioc}');
});

test('names each missing field', () => {
  assert.match(check({ ...good, name: '  ' }).error, /a name/);
  assert.match(check({ ...good, types: [] }).error, /indicator type/);
  assert.match(check({ ...good, url: 'http://x.example/{ioc}' }).error, /https:\/\//);
  assert.match(check({ ...good, url: 'https://x.example/hosts/8.8.8.8' }).error, /\{ioc\} in the URL/);
  assert.match(check({ ...good, url: 'https://{ioc}' }).error, /host name/);
});

test('lists every problem at once', () => {
  const r = check({ name: '', url: '', types: [] });
  assert.equal(r.ok, false);
  assert.match(r.error, /a name; a URL starting with https:\/\/; at least one indicator type/);
});
