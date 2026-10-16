// Small key/value storage abstraction.
// In the extension it wraps chrome.storage.local; in tests it is an in-memory map.
// Everything OpenTriage learns about an environment lives here, on the
// analyst's machine. Nothing is written to the repository or sent anywhere
// except as context in the analyst's own model requests.

export function chromeStorage(area = 'local') {
  const store = chrome.storage[area];
  return {
    async get(key, fallback = null) {
      const out = await store.get(key);
      return out[key] === undefined ? fallback : out[key];
    },
    async set(key, value) {
      await store.set({ [key]: value });
    },
    async remove(key) {
      await store.remove(key);
    },
  };
}

export function memoryStorage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    async get(key, fallback = null) {
      return map.has(key) ? structuredClone(map.get(key)) : fallback;
    },
    async set(key, value) {
      map.set(key, structuredClone(value));
    },
    async remove(key) {
      map.delete(key);
    },
    _dump() {
      return Object.fromEntries(map);
    },
  };
}

export const KEYS = {
  settings: 'ot.settings',
  apiKey: 'ot.apiKey',
  memory: 'ot.memory',
  playbooks: 'ot.playbooks',
  audit: 'ot.audit',
  customTemplate: 'ot.customTemplate',
  cases: 'ot.cases',
};

export function uid(prefix = 'id') {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now().toString(36)}${rand}`;
}
