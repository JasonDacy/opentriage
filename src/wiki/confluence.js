// Confluence Cloud client.
//
// Requests run *inside a Confluence tab the analyst is signed in to* (via
// chrome.scripting), so they use the analyst's existing session and
// permissions — OpenTriage never sees or stores Atlassian credentials.
// Only the fixed, parameterised endpoints below can be called; the model
// never supplies a raw URL or HTTP method.

/** Injected into the Confluence tab. Must be self-contained. */
export function confluenceFetch(path, method, body) {
  if (typeof path !== 'string' || !path.startsWith('/wiki/')) return Promise.resolve({ status: 0, error: 'Bad path' });
  const opts = {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'X-Atlassian-Token': 'no-check' },
  };
  if (body !== null && body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(location.origin + path, opts).then(
    async (res) => {
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        /* not json */
      }
      return { status: res.status, json, text: json ? '' : text.slice(0, 500), origin: location.origin };
    },
    (e) => ({ status: 0, error: String(e && e.message ? e.message : e) }),
  );
}

export function isConfluenceUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && /^\/wiki(\/|$)/.test(u.pathname);
  } catch {
    return false;
  }
}

const enc = encodeURIComponent;

function apiError(r, what) {
  if (r.status === 0) return new Error(`${what} failed: ${r.error || 'network error'}`);
  if (r.status === 401 || r.status === 403) return new Error(`${what} was refused (${r.status}). The analyst may not be signed in to Confluence in that tab, or lacks permission for this space/page.`);
  if (r.status === 404) return new Error(`${what}: not found (404). Check the page/space id.`);
  const msg = r.json?.errors?.[0]?.title || r.json?.message || r.json?.errorMessage || r.text || '';
  return new Error(`${what} failed (${r.status})${msg ? ': ' + String(msg).slice(0, 300) : ''}`);
}

const cqlString = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';

/**
 * @param {(path:string, method:string, body:any) => Promise<{status:number,json:any,text?:string,error?:string,origin?:string}>} call
 */
export function createConfluenceClient(call) {
  async function req(path, method = 'GET', body = null, what = 'Confluence request') {
    const r = await call(path, method, body);
    if (r.status < 200 || r.status >= 300) throw apiError(r, what);
    return r.json;
  }

  async function pagedResults(path, what, limit = 500) {
    const out = [];
    let next = path;
    while (next && out.length < limit) {
      const j = await req(next, 'GET', null, what);
      out.push(...(j?.results || []));
      next = j?._links?.next || null;
      if (next && !next.startsWith('/wiki/')) next = '/wiki' + next;
    }
    return out;
  }

  const client = {
    async spaceIdForKey(key) {
      const j = await req(`/wiki/api/v2/spaces?keys=${enc(key)}&limit=1`, 'GET', null, `Looking up space ${key}`);
      const s = j?.results?.[0];
      if (!s) throw new Error(`No space with key "${key}" is visible to the analyst.`);
      return s.id;
    },

    async getPage(id) {
      const j = await req(`/wiki/api/v2/pages/${enc(id)}?body-format=storage`, 'GET', null, `Reading page ${id}`);
      return {
        id: String(j.id),
        title: j.title,
        spaceId: j.spaceId,
        parentId: j.parentId ?? null,
        parentType: j.parentType ?? null,
        version: j.version?.number ?? 1,
        storage: j.body?.storage?.value ?? '',
        webui: j._links?.webui || '',
      };
    },

    /** CQL search by title and/or text, optionally within a space. */
    async search({ title, text, spaceKey, limit = 20 }) {
      const parts = ['type = page'];
      if (spaceKey) parts.push(`space = ${cqlString(spaceKey)}`);
      if (title) parts.push(`title ~ ${cqlString(title)}`);
      if (text) parts.push(`text ~ ${cqlString(text)}`);
      const cql = parts.join(' AND ');
      const j = await req(`/wiki/rest/api/content/search?cql=${enc(cql)}&limit=${Math.min(50, limit)}`, 'GET', null, 'Searching Confluence');
      return (j?.results || []).map((r) => ({ id: String(r.id), title: r.title, webui: r._links?.webui || '' }));
    },

    async createPage({ spaceId, parentId, title, storage }) {
      const body = { spaceId: String(spaceId), status: 'current', title, body: { representation: 'storage', value: storage } };
      if (parentId) body.parentId = String(parentId);
      const j = await req('/wiki/api/v2/pages', 'POST', body, `Creating page "${title}"`);
      return { id: String(j.id), title: j.title, version: j.version?.number ?? 1, webui: j._links?.webui || '' };
    },

    async updatePage({ id, title, storage, version, message }) {
      const body = { id: String(id), status: 'current', title, body: { representation: 'storage', value: storage }, version: { number: version + 1, message: message || 'Updated by OpenTriage (analyst approved)' } };
      const j = await req(`/wiki/api/v2/pages/${enc(id)}`, 'PUT', body, `Updating page ${id}`);
      return { id: String(j.id), title: j.title, version: j.version?.number ?? version + 1 };
    },

    /** Direct children of a page or folder, in tree order. */
    async children(parentId) {
      let list;
      try {
        list = await pagedResults(`/wiki/api/v2/pages/${enc(parentId)}/direct-children?limit=250`, 'Listing child pages');
      } catch (e) {
        if (!/not found|404/.test(e.message)) throw e;
        list = await pagedResults(`/wiki/api/v2/folders/${enc(parentId)}/direct-children?limit=250`, 'Listing folder contents');
      }
      return list.map((c) => ({ id: String(c.id), title: c.title, type: c.type || 'page', position: c.childPosition ?? null }));
    },

    async movePage(pageId, position, targetId) {
      if (!['before', 'after', 'append'].includes(position)) throw new Error('Bad move position');
      await req(`/wiki/rest/api/content/${enc(pageId)}/move/${position}/${enc(targetId)}`, 'PUT', null, `Moving page ${pageId}`);
    },
  };
  return client;
}
