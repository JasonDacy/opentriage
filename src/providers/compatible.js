// OpenAI-compatible Chat Completions provider: local model servers (Ollama,
// LM Studio, llama.cpp, vLLM) and hosted gateways (OpenRouter, Groq, Azure
// OpenAI, …). The analyst supplies the base URL, e.g. http://localhost:11434/v1.

import { blocksOf, dataUrl, imageOf, NO_VISION_NOTE, newToolId, parseArgs, postJSON, resultParts } from './common.js';

export const LOCAL_PRESETS = [
  { id: 'ollama', name: 'Ollama', baseUrl: 'http://localhost:11434/v1' },
  { id: 'lmstudio', name: 'LM Studio', baseUrl: 'http://localhost:1234/v1' },
  { id: 'openrouter', name: 'OpenRouter', baseUrl: 'https://openrouter.ai/api/v1' },
];

export function normaliseBaseUrl(url) {
  return String(url || '').trim().replace(/\/+$/, '').replace(/\/chat\/completions$/, '');
}

/** Translate the agent's messages into Chat Completions messages. */
export function toChatMessages(system, messages, { vision = false } = {}) {
  const out = [{ role: 'system', content: system }];
  for (const m of messages) {
    const blocks = blocksOf(m.content);
    if (m.role === 'assistant') {
      const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
      const calls = blocks.filter((b) => b.type === 'tool_use');
      const msg = { role: 'assistant', content: text || (calls.length ? null : '') };
      if (calls.length) msg.tool_calls = calls.map((b) => ({ id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) } }));
      out.push(msg);
      continue;
    }
    const parts = [];
    for (const b of blocks) {
      if (b.type === 'tool_result') {
        const { text, images } = resultParts(b.content);
        out.push({ role: 'tool', tool_call_id: b.tool_use_id, content: (b.is_error ? 'Error: ' : '') + (text || (images.length ? 'Screenshot attached below.' : '(no output)')) });
        for (const img of images) {
          if (vision) parts.push({ type: 'text', text: `Screenshot returned by tool call ${b.tool_use_id}:` }, { type: 'image_url', image_url: { url: dataUrl(img) } });
          else parts.push({ type: 'text', text: NO_VISION_NOTE });
        }
      } else if (b.type === 'text' && b.text) {
        parts.push({ type: 'text', text: b.text });
      } else if (b.type === 'image') {
        const img = imageOf(b);
        if (img) parts.push(vision ? { type: 'image_url', image_url: { url: dataUrl(img) } } : { type: 'text', text: NO_VISION_NOTE });
      }
    }
    if (!parts.length) continue;
    // Plain strings are the most widely supported form for text-only turns.
    out.push({ role: 'user', content: parts.every((p) => p.type === 'text') ? parts.map((p) => p.text).join('\n\n') : parts });
  }
  return out;
}

/** Translate a Chat Completions response into agent blocks. */
export function fromChatResponse(data) {
  const choice = data.choices?.[0] || {};
  const msg = choice.message || {};
  const content = [];
  const text = typeof msg.content === 'string' ? msg.content : Array.isArray(msg.content) ? msg.content.map((p) => p.text || '').join('') : '';
  // Some local reasoning models inline their thinking; don't show it as the answer.
  const visible = text.replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  if (visible) content.push({ type: 'text', text: visible });
  for (const c of msg.tool_calls || []) {
    if (c.type && c.type !== 'function') continue;
    content.push({ type: 'tool_use', id: c.id || newToolId(), name: c.function?.name, input: parseArgs(c.function?.arguments) });
  }
  const hasCalls = content.some((b) => b.type === 'tool_use');
  const stopReason = hasCalls ? 'tool_use' : choice.finish_reason === 'length' ? 'max_tokens' : 'end_turn';
  if (!content.length) content.push({ type: 'text', text: '(The model returned an empty response.)' });
  const u = data.usage || {};
  return { content, stopReason, usage: { input_tokens: u.prompt_tokens, output_tokens: u.completion_tokens } };
}

export function createCompatibleProvider({ apiKey = '', model, baseUrl, vision = false, authStyle = 'bearer', fetchImpl = globalThis.fetch.bind(globalThis) }) {
  const base = normaliseBaseUrl(baseUrl);
  if (!/^https?:\/\//.test(base)) throw new Error('Set the server URL for your OpenAI-compatible provider in OpenTriage settings (for example http://localhost:11434/v1 for Ollama).');
  if (!model) throw new Error('Set the model ID in OpenTriage settings.');
  const headers = apiKey ? (authStyle === 'api-key' ? { 'api-key': apiKey } : { authorization: `Bearer ${apiKey}` }) : {};
  const name = /localhost|127\.0\.0\.1/.test(base) ? 'The local model server' : 'The model server';

  return {
    id: 'compatible',
    model,
    vision,

    async complete({ system, messages, tools = [], maxTokens = 4096, signal }) {
      // Local reasoning models think in the visible budget; leave them room.
      const body = { model, messages: toChatMessages(system, messages, { vision }), max_tokens: Math.max(maxTokens, 8192), stream: false };
      if (tools.length) body.tools = tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.input_schema } }));
      const data = await postJSON({ fetchImpl, url: `${base}/chat/completions`, headers, body, signal, name });
      if (data.error) throw new Error(`Model request failed: ${data.error.message || data.error}`);
      return fromChatResponse(data);
    },

    /** Model IDs the server offers (GET /models), for the settings picker. */
    async listModels(signal) {
      const data = await postJSON({ fetchImpl, url: `${base}/models`, headers, signal, name, method: 'GET' });
      return (data.data || data.models || []).map((m) => m.id || m.name).filter(Boolean).sort();
    },
  };
}
