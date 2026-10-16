// Shared helpers for model providers.
//
// The agent speaks the Anthropic Messages format internally. Providers for
// other APIs translate requests and responses with these helpers.

/** Split a tool_result's content into its text and any images. */
export function resultParts(content) {
  if (typeof content === 'string') return { text: content, images: [] };
  const texts = [];
  const images = [];
  for (const c of content || []) {
    if (c.type === 'text') texts.push(c.text);
    else if (c.type === 'image' && c.source?.type === 'base64') images.push({ mediaType: c.source.media_type, data: c.source.data });
  }
  return { text: texts.join('\n'), images };
}

export function imageOf(block) {
  return block?.type === 'image' && block.source?.type === 'base64' ? { mediaType: block.source.media_type, data: block.source.data } : null;
}

export const dataUrl = (img) => `data:${img.mediaType};base64,${img.data}`;

export const NO_VISION_NOTE = '[A screenshot was taken, but the selected model does not accept images. Use read_page or find_text instead.]';

/** Normalise message content to an array of blocks. */
export const blocksOf = (content) => (typeof content === 'string' ? [{ type: 'text', text: content }] : content || []);

/** Tool names keyed by tool_use id, so results can be matched by name where an API needs it. */
export function toolNamesById(messages) {
  const map = new Map();
  for (const m of messages) {
    if (m.role !== 'assistant' || !Array.isArray(m.content)) continue;
    for (const b of m.content) if (b.type === 'tool_use') map.set(b.id, b.name);
  }
  return map;
}

export function parseArgs(raw) {
  if (raw && typeof raw === 'object') return raw;
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : { value: v };
  } catch {
    // Some local models emit almost-JSON. Hand the agent something it can report.
    return { _unparsed_arguments: String(raw).slice(0, 2000) };
  }
}

let counter = 0;
export const newToolId = (prefix = 'call') => `${prefix}_${Date.now().toString(36)}${(counter++).toString(36)}`;

/** The origin pattern Chrome needs permission for, e.g. http://localhost:11434/*. */
export function originPattern(url) {
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) return null;
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * POST JSON with retries on rate limits and server errors, and readable errors.
 * `name` is the provider's display name for error messages.
 */
export async function postJSON({ fetchImpl, url, headers = {}, body, signal, name, method = 'POST' }) {
  let res;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      res = await fetchImpl(url, {
        method,
        signal,
        headers: method === 'POST' ? { 'content-type': 'application/json', ...headers } : headers,
        body: method === 'POST' ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      if (e?.name === 'AbortError') throw e;
      const err = new Error(`Couldn't reach ${name} at ${new URL(url).origin}. ${/localhost|127\.0\.0\.1|\[::1\]/.test(url) ? 'Is the local model server running?' : 'Check your network connection.'}`);
      err.cause = e;
      throw err;
    }
    if (res.status !== 429 && res.status !== 529 && res.status < 500) break;
    if (attempt === 3) break;
    const wait = Number(res.headers?.get?.('retry-after')) * 1000 || 2000 * 2 ** attempt;
    await sleep(Math.min(wait, 20000));
  }
  if (!res.ok) {
    let detail = '';
    try {
      const j = await res.json();
      detail = j?.error?.message || j?.error?.status || (typeof j?.error === 'string' ? j.error : '') || j?.message || '';
    } catch {
      /* not JSON */
    }
    let msg;
    if (res.status === 401) msg = `${name} rejected the API key. Check it in OpenTriage settings.`;
    else if (res.status === 403 && /localhost|127\.0\.0\.1/.test(url)) msg = `The local model server refused the request (403). For Ollama, allow the extension with OLLAMA_ORIGINS=chrome-extension://* and restart it.`;
    else if (res.status === 404) msg = `${name} couldn't find that model or endpoint (404)${detail ? ': ' + detail : ''}. Check the model ID${/localhost|127\.0\.0\.1/.test(url) ? ' and the server URL' : ''} in settings.`;
    else msg = `Model request failed (${res.status})${detail ? ': ' + detail : ''}`;
    const err = new Error(msg);
    err.status = res.status;
    err.detail = detail;
    throw err;
  }
  return res.json();
}
