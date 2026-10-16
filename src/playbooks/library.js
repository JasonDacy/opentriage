// Local playbook library. Playbooks are the analyst's (and their team's) —
// they are stored in the browser and exported on request, never bundled.

import { KEYS, uid } from '../lib/storage.js';
import { playbookTitle } from './template.js';
import { toMarkdown } from './render.js';

function tokens(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .split(' ')
    .filter((t) => t.length > 1);
}

/** Simple relevance score: token overlap, with a bonus for exact detection-name matches. */
export function scorePlaybook(entry, query) {
  const q = tokens(query);
  if (!q.length) return 0;
  const name = (entry.playbook?.detectionName || entry.title || '').toLowerCase();
  if (name && name === String(query).trim().toLowerCase()) return 100;
  const hay = new Set(
    tokens(
      [
        entry.title,
        entry.playbook?.detectionName,
        entry.playbook?.variant,
        ...(entry.playbook?.platforms || []),
        ...(entry.playbook?.mitre || []).map((m) => `${m.techniqueId} ${m.techniqueName} ${m.tactic}`),
        entry.playbook?.findings?.attackChain,
        entry.markdown?.slice(0, 2000),
      ].join(' '),
    ),
  );
  let hits = 0;
  for (const t of q) if (hay.has(t)) hits++;
  const nameTokens = new Set(tokens(name));
  let nameHits = 0;
  for (const t of q) if (nameTokens.has(t)) nameHits++;
  return Math.round((hits / q.length) * 50 + (nameHits / Math.max(nameTokens.size, 1)) * 40);
}

export function createLibrary(storage, audit) {
  async function all() {
    return (await storage.get(KEYS.playbooks, [])) || [];
  }
  async function write(list) {
    await storage.set(KEYS.playbooks, list);
  }

  return {
    all,

    async get(id) {
      return (await all()).find((p) => p.id === id) || null;
    },

    async search(query, limit = 5) {
      return (await all())
        .map((e) => ({ e, score: scorePlaybook(e, query) }))
        .filter((x) => x.score >= 25)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit)
        .map(({ e, score }) => ({ id: e.id, title: e.title, score, updatedAt: e.updatedAt, classification: e.playbook?.determination?.classification }));
    },

    /** Save a playbook. Called by the UI only, after analyst approval. */
    async save({ playbook = null, markdown = null, id = null, format = playbook ? 'structured' : 'markdown' }) {
      const list = await all();
      const now = new Date().toISOString();
      const title = playbook ? playbookTitle(playbook) : (String(markdown).match(/^#\s+(.+)$/m) || [, 'Untitled playbook'])[1].trim();
      const md = playbook ? toMarkdown(playbook) : String(markdown);
      const clean = playbook ? JSON.parse(JSON.stringify(playbook)) : null;
      if (clean) delete clean._replacing;
      if (id) {
        const i = list.findIndex((p) => p.id === id);
        if (i >= 0) {
          list[i] = { ...list[i], title, format, playbook: clean, markdown: md, updatedAt: now };
          await write(list);
          await audit?.log({ type: 'playbook.update', id, title });
          return list[i];
        }
      }
      const entry = { id: uid('pb'), title, format, playbook: clean, markdown: md, createdAt: now, updatedAt: now };
      list.push(entry);
      list.sort((a, b) => a.title.replace(/^\W+/, '').localeCompare(b.title.replace(/^\W+/, ''), undefined, { sensitivity: 'base' }));
      await write(list);
      await audit?.log({ type: 'playbook.create', id: entry.id, title });
      return entry;
    },

    async remove(id) {
      await write((await all()).filter((p) => p.id !== id));
      await audit?.log({ type: 'playbook.remove', id });
    },

    async exportJson() {
      return JSON.stringify({ format: 'opentriage-playbooks', version: 1, exportedAt: new Date().toISOString(), playbooks: await all() }, null, 2);
    },

    async importJson(json) {
      const data = typeof json === 'string' ? JSON.parse(json) : json;
      if (!data || data.format !== 'opentriage-playbooks' || !Array.isArray(data.playbooks)) throw new Error('Not an OpenTriage playbook file');
      const list = await all();
      const titles = new Set(list.map((p) => p.title.toLowerCase()));
      let added = 0;
      for (const p of data.playbooks) {
        if (!p.title || titles.has(String(p.title).toLowerCase())) continue;
        list.push({ ...p, id: uid('pb'), importedAt: new Date().toISOString() });
        titles.add(String(p.title).toLowerCase());
        added++;
      }
      await write(list);
      await audit?.log({ type: 'playbook.import', added });
      return added;
    },

    /** Coverage map: playbooks grouped by MITRE tactic. */
    async coverage() {
      const byTactic = {};
      for (const e of await all()) {
        for (const m of e.playbook?.mitre || []) (byTactic[m.tactic] ||= new Set()).add(e.title);
      }
      return Object.fromEntries(Object.entries(byTactic).map(([k, v]) => [k, [...v]]));
    },
  };
}
