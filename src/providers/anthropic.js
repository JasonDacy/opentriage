// Anthropic Messages API provider, called directly from the extension with
// the analyst's own API key.

export const ANTHROPIC_MODELS = [
  { id: 'claude-sonnet-5-5', name: 'Claude Sonnet 5.5 (recommended)' },
  { id: 'claude-opus-5-5', name: 'Claude Opus 5.5 (most capable)' },
  { id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5 (fastest, cheapest)' },
];

const ENDPOINT = 'https://api.anthropic.com/v1/messages';

// Other providers can leave private fields on blocks (Gemini thought
// signatures, OpenAI reasoning items). The Messages API rejects them.
const PRIVATE_FIELDS = ['thought_signature', 'gemini_id'];
export function forAnthropic(messages) {
  return messages.map((m) => {
    if (!Array.isArray(m.content)) return m;
    if (!m.content.some((b) => b.type === 'reasoning' || PRIVATE_FIELDS.some((f) => f in b))) return m;
    const content = m.content
      .filter((b) => b.type !== 'reasoning')
      .map((b) => (PRIVATE_FIELDS.some((f) => f in b) ? Object.fromEntries(Object.entries(b).filter(([k]) => !PRIVATE_FIELDS.includes(k))) : b));
    return { ...m, content: content.length ? content : [{ type: 'text', text: '(no text)' }] };
  });
}

export function createAnthropicProvider({ apiKey, model, fetchImpl = globalThis.fetch.bind(globalThis) }) {
  if (!apiKey) throw new Error('No API key set. Add one in OpenTriage settings.');

  return {
    id: 'anthropic',
    model,

    async complete({ system, messages, tools, maxTokens = 4096, signal }) {
      const body = {
        model,
        max_tokens: maxTokens,
        // The methodology, profile and memory are stable across a run; cache them.
        system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
        messages: forAnthropic(messages),
        tools,
      };
      let res;
      for (let attempt = 0; attempt < 4; attempt++) {
        res = await fetchImpl(ENDPOINT, {
          method: 'POST',
          signal,
          headers: {
            'content-type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            // Required for direct calls from a browser context.
            'anthropic-dangerous-direct-browser-access': 'true',
          },
          body: JSON.stringify(body),
        });
        if (res.status !== 429 && res.status !== 529 && res.status < 500) break;
        const wait = Number(res.headers.get('retry-after')) * 1000 || 2000 * 2 ** attempt;
        await new Promise((r) => setTimeout(r, Math.min(wait, 20000)));
      }
      if (!res.ok) {
        let detail = '';
        try {
          detail = (await res.json())?.error?.message || '';
        } catch {
          /* ignore */
        }
        const err = new Error(res.status === 401 ? 'The API key was rejected. Check it in OpenTriage settings.' : `Model request failed (${res.status})${detail ? ': ' + detail : ''}`);
        err.status = res.status;
        throw err;
      }
      const data = await res.json();
      return { content: data.content || [], stopReason: data.stop_reason, usage: data.usage || {} };
    },
  };
}
