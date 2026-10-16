// Loads methodology and platform profiles that ship with the extension.
// `readText(path)` is injected: fetch() of an extension URL in the browser,
// fs.readFile in tests.

export function extensionReader() {
  return async (path) => {
    const res = await fetch(chrome.runtime.getURL(path));
    if (!res.ok) throw new Error(`Could not load ${path}`);
    return res.text();
  };
}

function stripFrontMatter(md) {
  return String(md).replace(/^---\n[\s\S]*?\n---\n?/, '').trim();
}

export function createKnowledge(readText) {
  let cache = null;

  async function load() {
    if (cache) return cache;
    const [methodology, index, generic] = await Promise.all([
      readText('src/knowledge/methodology.md'),
      readText('src/knowledge/profiles/index.json').then(JSON.parse),
      readText('src/knowledge/profiles/generic.md'),
    ]);
    const profiles = await Promise.all(
      index.map(async (p) => ({ ...p, body: stripFrontMatter(await readText(`src/knowledge/profiles/${p.file}`)) })),
    );
    cache = { methodology: methodology.trim(), profiles, generic: stripFrontMatter(generic) };
    return cache;
  }

  return {
    load,

    /** Pick the platform profile for a page by hostname, then by title hints. */
    async matchProfile({ url = '', title = '' } = {}, disabled = []) {
      const { profiles, generic } = await load();
      let host = '';
      try {
        host = new URL(url).hostname.toLowerCase();
      } catch {
        /* ignore */
      }
      const active = profiles.filter((p) => !disabled.includes(p.id));
      const byHost = active.find((p) => (p.hosts || []).some((h) => new RegExp(h, 'i').test(host)));
      if (byHost) return byHost;
      const t = title.toLowerCase();
      const byTitle = active.find((p) => (p.titleHints || []).some((h) => h.length > 4 && t.includes(h)));
      if (byTitle) return byTitle;
      return { id: 'generic', name: 'Unknown console', body: generic };
    },

    async listProfiles() {
      const { profiles } = await load();
      return profiles.map(({ id, name, hosts }) => ({ id, name, hosts }));
    },
  };
}
