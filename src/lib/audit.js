import { KEYS } from './storage.js';

const MAX_ENTRIES = 2000;

// Append-only (from the agent's point of view) log of every tool call,
// approval decision and memory/playbook change. Analysts can export it from
// the options page for their own records.
export function createAudit(storage) {
  return {
    async log(entry) {
      const list = (await storage.get(KEYS.audit, [])) || [];
      list.push({ at: new Date().toISOString(), ...entry });
      while (list.length > MAX_ENTRIES) list.shift();
      await storage.set(KEYS.audit, list);
    },
    async list() {
      return (await storage.get(KEYS.audit, [])) || [];
    },
    async clear() {
      await storage.set(KEYS.audit, []);
    },
  };
}
