// Environment memory: what OpenTriage learns about the environment it runs in.
//
// Rules this module enforces (see docs/threat-model.md):
//  1. The agent can only *propose* a fact. Nothing is stored until the
//     analyst approves it in the side panel.
//  2. Every proposal is checked against the page text read during the run;
//     facts that look copied from alert data are flagged to the analyst.
//  3. Memory never leaves the browser except as context in the analyst's own
//     model requests, or when the analyst exports it.

import { KEYS, uid } from '../lib/storage.js';

export const CATEGORIES = {
  scope: 'What is in scope for this analyst or team (regions, device groups, business units)',
  naming: 'Naming conventions (hosts, accounts, groups) and what they mean',
  asset_lookup: 'Where and how to find a device owner, asset criticality or location',
  identity_lookup: 'Where and how to find a user\'s role, manager or department',
  sanctioned_tools: 'Tools, automation and agents that are authorised in this environment',
  classification: 'Local rules for TP / benign TP / FP decisions',
  closure: 'How to close, resolve or document an alert in this environment\'s consoles',
  escalation: 'Who to escalate to, when, and through which channel',
  consoles: 'Which consoles are used and how they link to each other',
  playbook_location: 'Where the team\'s existing playbooks live (wiki space, index page, naming) and how to find one for a detection',
  playbook_rules: 'Local playbook standards that extend the built-in template',
  other: 'Anything else the analyst wants remembered',
};

const MAX_FACTS = 400;
const MAX_FACT_LEN = 600;

export function normaliseFact(text) {
  return String(text || '')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_FACT_LEN);
}

export function createMemory(storage, audit) {
  async function all() {
    return (await storage.get(KEYS.memory, [])) || [];
  }
  async function write(list) {
    await storage.set(KEYS.memory, list);
  }

  return {
    all,

    /** Store a fact. Only the UI calls this, after the analyst approves. */
    async add({ fact, category = 'other', source = 'analyst', note = '' }) {
      const clean = normaliseFact(fact);
      if (!clean) throw new Error('Empty fact');
      if (!CATEGORIES[category]) category = 'other';
      const list = await all();
      if (list.length >= MAX_FACTS) throw new Error(`Memory is full (${MAX_FACTS} facts). Remove or merge some first.`);
      const dupe = list.find((f) => f.fact.toLowerCase() === clean.toLowerCase());
      if (dupe) return dupe;
      const item = { id: uid('mem'), fact: clean, category, source, note: normaliseFact(note), createdAt: new Date().toISOString() };
      list.push(item);
      await write(list);
      await audit?.log({ type: 'memory.add', id: item.id, category, source, fact: clean });
      return item;
    },

    async update(id, patch) {
      const list = await all();
      const i = list.findIndex((f) => f.id === id);
      if (i < 0) throw new Error('Not found');
      const next = { ...list[i], ...patch, updatedAt: new Date().toISOString() };
      next.fact = normaliseFact(next.fact);
      if (!CATEGORIES[next.category]) next.category = 'other';
      list[i] = next;
      await write(list);
      await audit?.log({ type: 'memory.update', id, fact: next.fact });
      return next;
    },

    async remove(id) {
      const list = await all();
      await write(list.filter((f) => f.id !== id));
      await audit?.log({ type: 'memory.remove', id });
    },

    async clear() {
      await write([]);
      await audit?.log({ type: 'memory.clear' });
    },

    /** Export for sharing inside a team. The file is the team's, not the repo's. */
    async exportJson() {
      return JSON.stringify({ format: 'opentriage-environment', version: 1, exportedAt: new Date().toISOString(), facts: await all() }, null, 2);
    },

    /**
     * Sync facts bundled into a team build. Bundle facts are added once; when a
     * newer bundle arrives, bundle facts that were dropped from it are removed
     * — unless the analyst edited them, in which case they are kept as the
     * analyst's own. Facts the analyst added are never touched.
     * Returns { added, removed, kept, version } or null if already in sync.
     */
    async syncBundle(bundle, storedVersion) {
      if (!bundle || bundle.format !== 'opentriage-environment' || !Array.isArray(bundle.facts)) throw new Error('Not an OpenTriage environment file');
      const version = String(bundle.exportedAt || bundle.version || '');
      if (version && version === storedVersion) return null;
      const list = await all();
      const wanted = new Map(bundle.facts.map((f) => [normaliseFact(f.fact).toLowerCase(), f]).filter(([k]) => k));
      let removed = 0;
      let kept = 0;
      const next = [];
      for (const f of list) {
        if (f.source === 'team-bundle' && !wanted.has(f.fact.toLowerCase())) {
          if (f.updatedAt) {
            next.push({ ...f, source: 'analyst' });
            kept++;
          } else removed++;
          continue;
        }
        next.push(f);
      }
      const have = new Set(next.map((f) => f.fact.toLowerCase()));
      let added = 0;
      for (const [key, f] of wanted) {
        if (have.has(key) || next.length >= MAX_FACTS) continue;
        next.push({
          id: uid('mem'),
          fact: normaliseFact(f.fact),
          category: CATEGORIES[f.category] ? f.category : 'other',
          source: 'team-bundle',
          note: normaliseFact(f.note || 'Included in the team build'),
          createdAt: new Date().toISOString(),
        });
        have.add(key);
        added++;
      }
      await write(next);
      await audit?.log({ type: 'memory.bundle_sync', added, removed, kept, version });
      return { added, removed, kept, version };
    },

    /** Import a team environment file. Facts are merged, never executed. */
    async importJson(json) {
      const data = typeof json === 'string' ? JSON.parse(json) : json;
      if (!data || data.format !== 'opentriage-environment' || !Array.isArray(data.facts)) {
        throw new Error('Not an OpenTriage environment file');
      }
      const list = await all();
      const seen = new Set(list.map((f) => f.fact.toLowerCase()));
      let added = 0;
      for (const f of data.facts) {
        const fact = normaliseFact(f.fact);
        if (!fact || seen.has(fact.toLowerCase()) || list.length >= MAX_FACTS) continue;
        list.push({
          id: uid('mem'),
          fact,
          category: CATEGORIES[f.category] ? f.category : 'other',
          source: 'import',
          note: normaliseFact(f.note || ''),
          createdAt: new Date().toISOString(),
        });
        seen.add(fact.toLowerCase());
        added++;
      }
      await write(list);
      await audit?.log({ type: 'memory.import', added });
      return added;
    },
  };
}

/** Render memory for the system prompt, grouped by category. */
export function renderMemoryForPrompt(facts) {
  if (!facts.length) {
    return 'No environment facts have been recorded yet. You do not know this environment. Ask the analyst rather than guessing, and propose what you learn with propose_memory.';
  }
  const groups = {};
  for (const f of facts) (groups[f.category] ||= []).push(f);
  return Object.keys(CATEGORIES)
    .filter((c) => groups[c])
    .map((c) => `### ${c}\n` + groups[c].map((f) => `- ${f.fact}`).join('\n'))
    .join('\n\n');
}
