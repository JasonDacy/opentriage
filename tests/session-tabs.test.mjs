import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTabSession, GROUP_TITLE } from '../src/agent/session-tabs.js';

function fakeChrome() {
  const tabs = new Map([
    [1, { id: 1, url: 'https://siem.example.com/a', title: 'SIEM', groupId: -1, windowId: 1, index: 0, active: true }],
    [2, { id: 2, url: 'https://edr.example.com/b', title: 'EDR', groupId: -1, windowId: 1, index: 1 }],
    [3, { id: 3, url: 'chrome://settings', title: 'Settings', groupId: -1, windowId: 1, index: 2 }],
  ]);
  const groups = new Map();
  const sess = {};
  let next = 100;
  return {
    tabs: {
      async query(q) {
        return [...tabs.values()].filter((t) => q.groupId === undefined || t.groupId === q.groupId);
      },
      async get(id) {
        if (!tabs.has(id)) throw new Error('no tab');
        return tabs.get(id);
      },
      async group({ tabIds, groupId }) {
        const gid = groupId ?? next++;
        if (!groups.has(gid)) groups.set(gid, { id: gid, title: '' });
        for (const id of tabIds) tabs.get(id).groupId = gid;
        return gid;
      },
      async ungroup(ids) {
        for (const id of ids) tabs.get(id).groupId = -1;
        for (const [gid] of groups) if (![...tabs.values()].some((t) => t.groupId === gid)) groups.delete(gid);
      },
    },
    tabGroups: {
      async get(id) {
        if (!groups.has(id)) throw new Error('no group');
        return groups.get(id);
      },
      async query({ title }) {
        return [...groups.values()].filter((g) => g.title === title);
      },
      async update(id, p) {
        Object.assign(groups.get(id), p);
      },
    },
    storage: {
      session: {
        async get(k) {
          return { [k]: sess[k] };
        },
        async set(o) {
          Object.assign(sess, o);
        },
        async remove(k) {
          delete sess[k];
        },
      },
    },
    _groups: groups,
    _sess: sess,
  };
}

test('creates a titled group on first add and reuses it', async () => {
  const api = fakeChrome();
  const s = createTabSession(api);
  assert.deepEqual(await s.list(), []);
  const g = await s.add(1);
  assert.equal(api._groups.get(g).title, GROUP_TITLE);
  assert.equal(await s.add(2), g);
  assert.deepEqual((await s.list()).map((t) => t.id), [1, 2]);
  assert.equal(await s.has(2), true);
  assert.equal(await s.has(3), false);
});

test('candidates are web tabs outside the session', async () => {
  const s = createTabSession(fakeChrome());
  await s.add(1);
  assert.deepEqual((await s.candidates()).map((t) => t.id), [2]);
});

test('removing the last tab ends the group; next add creates a new one', async () => {
  const api = fakeChrome();
  const s = createTabSession(api);
  const g1 = await s.add(1);
  await s.remove(1);
  assert.deepEqual(await s.list(), []);
  const g2 = await s.add(2);
  assert.notEqual(g1, g2);
});

test('re-adopts an existing OpenTriage group if the stored id is lost', async () => {
  const api = fakeChrome();
  const s = createTabSession(api);
  const g = await s.add(1);
  delete api._sess['ot.sessionGroupId'];
  assert.equal(await s.groupId(), g);
});
