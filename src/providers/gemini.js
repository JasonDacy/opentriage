// Google Gemini provider (Gemini API, generateContent).
//
// Data handling: on the Gemini API's unpaid (free) tier, Google may use
// prompts and responses to improve its products, and human reviewers may read
// them. Only use a billing-enabled project for real alert data. The settings
// page says so next to the provider.
//
// Gemini 3 models attach "thought signatures" to parts. They are kept on the
// blocks and sent back unchanged, which function calling requires.

import { blocksOf, imageOf, NO_VISION_NOTE, newToolId, postJSON, resultParts, toolNamesById } from './common.js';

export const GEMINI_MODELS = [
  { id: 'gemini-3.8-flash', name: 'Gemini 3.8 Flash (recommended)' },
  { id: 'gemini-3.1-pro-preview', name: 'Gemini 3.1 Pro (most capable, preview)' },
  { id: 'gemini-3.5-flash-lite', name: 'Gemini 3.5 Flash-Lite (fastest, cheapest)' },
];

const BASE = 'https://generativelanguage.googleapis.com/v1beta/models';
// Documented placeholder for function calls that have no signature of their own.
const SKIP_SIGNATURE = 'skip_thought_signature_validator';

const KEEP = new Set(['type', 'description', 'properties', 'required', 'items', 'enum', 'anyOf', 'nullable', 'minimum', 'maximum', 'minItems', 'maxItems', 'format']);
const FORMATS = new Set(['enum', 'date-time']);

/** Reduce a JSON Schema to the OpenAPI subset the Gemini API accepts. */
export function toGeminiSchema(schema) {
  if (!schema || typeof schema !== 'object') return schema;
  if (Array.isArray(schema)) return schema.map(toGeminiSchema);
  const s = { ...schema };
  if (s.oneOf && !s.anyOf) s.anyOf = s.oneOf;
  if (Array.isArray(s.type)) {
    const types = s.type.filter((t) => t !== 'null');
    if (types.length < s.type.length) s.nullable = true;
    s.type = types[0] || 'string';
  }
  const out = {};
  for (const [k, v] of Object.entries(s)) {
    if (!KEEP.has(k)) continue;
    if (k === 'format' && !FORMATS.has(v)) continue;
    if (k === 'properties') out.properties = Object.fromEntries(Object.entries(v).map(([p, ps]) => [p, toGeminiSchema(ps)]));
    else if (k === 'items') out.items = toGeminiSchema(v);
    else if (k === 'anyOf') out.anyOf = v.map(toGeminiSchema);
    else if (k === 'type') out.type = String(v).toUpperCase();
    else if (k === 'enum') out.enum = v.map(String);
    else out[k] = v;
  }
  if (out.anyOf) delete out.type;
  if (out.type === 'OBJECT' && out.properties && !Object.keys(out.properties).length) delete out.properties;
  if (out.required && out.properties) out.required = out.required.filter((r) => r in out.properties);
  return out;
}

const declCache = new WeakMap();
function declarations(tools) {
  if (!declCache.has(tools)) {
    declCache.set(
      tools,
      tools.map((t) => {
        const d = { name: t.name, description: t.description };
        const params = toGeminiSchema(t.input_schema);
        if (params?.properties && Object.keys(params.properties).length) d.parameters = params;
        return d;
      }),
    );
  }
  return declCache.get(tools);
}

/** Translate the agent's messages into Gemini contents. */
export function toGeminiContents(messages, { vision = true } = {}) {
  const names = toolNamesById(messages);
  const contents = [];
  const push = (role, parts) => {
    if (!parts.length) return;
    const last = contents[contents.length - 1];
    if (last && last.role === role) last.parts.push(...parts);
    else contents.push({ role, parts });
  };
  for (const m of messages) {
    const blocks = blocksOf(m.content);
    if (m.role === 'assistant') {
      const parts = [];
      for (const b of blocks) {
        if (b.type === 'text' && b.text) parts.push(b.thought_signature ? { text: b.text, thoughtSignature: b.thought_signature } : { text: b.text });
        else if (b.type === 'tool_use') {
          const fc = { name: b.name, args: b.input ?? {} };
          if (b.gemini_id) fc.id = b.id;
          parts.push(b.thought_signature ? { functionCall: fc, thoughtSignature: b.thought_signature } : { functionCall: fc });
        }
      }
      // A turn with function calls but no signatures (history from elsewhere) needs the placeholder.
      const firstCall = parts.find((p) => p.functionCall);
      if (firstCall && !parts.some((p) => p.thoughtSignature)) firstCall.thoughtSignature = SKIP_SIGNATURE;
      push('model', parts);
      continue;
    }
    const responses = [];
    const rest = [];
    for (const b of blocks) {
      if (b.type === 'tool_result') {
        const { text, images } = resultParts(b.content);
        const fr = { name: names.get(b.tool_use_id) || 'unknown_tool', response: b.is_error ? { error: text } : { result: text || (images.length ? 'Screenshot attached below.' : '(no output)') } };
        if (/^gm_/.test(b.tool_use_id) === false) fr.id = b.tool_use_id;
        responses.push({ functionResponse: fr });
        for (const img of images) {
          if (vision) rest.push({ text: `Screenshot returned by ${fr.name}:` }, { inlineData: { mimeType: img.mediaType, data: img.data } });
          else rest.push({ text: NO_VISION_NOTE });
        }
      } else if (b.type === 'text' && b.text) rest.push({ text: b.text });
      else if (b.type === 'image') {
        const img = imageOf(b);
        if (img) rest.push(vision ? { inlineData: { mimeType: img.mediaType, data: img.data } } : { text: NO_VISION_NOTE });
      }
    }
    push('user', [...responses, ...rest]);
  }
  return contents;
}

/** Translate a generateContent response into agent blocks. */
export function fromGeminiResponse(data) {
  if (data.promptFeedback?.blockReason && !data.candidates?.length) {
    throw new Error(`Gemini blocked the request (${data.promptFeedback.blockReason}). Alert content can trip its safety filters; try another provider for this alert.`);
  }
  const cand = data.candidates?.[0] || {};
  const content = [];
  for (const p of cand.content?.parts || []) {
    if (p.thought) continue; // reasoning summaries aren't part of the answer
    if (p.functionCall) {
      const b = { type: 'tool_use', id: p.functionCall.id || newToolId('gm'), name: p.functionCall.name, input: p.functionCall.args || {} };
      if (p.functionCall.id) b.gemini_id = true;
      if (p.thoughtSignature) b.thought_signature = p.thoughtSignature;
      content.push(b);
    } else if (typeof p.text === 'string' && (p.text || p.thoughtSignature)) {
      const b = { type: 'text', text: p.text };
      if (p.thoughtSignature) b.thought_signature = p.thoughtSignature;
      content.push(b);
    }
  }
  const hasCalls = content.some((b) => b.type === 'tool_use');
  const finish = cand.finishReason || '';
  let stopReason = hasCalls ? 'tool_use' : finish === 'MAX_TOKENS' ? 'max_tokens' : 'end_turn';
  if (!content.some((b) => b.type === 'tool_use' || b.text)) {
    content.push({ type: 'text', text: finish && finish !== 'STOP' ? `(Gemini stopped without an answer: ${finish}.)` : '(The model returned an empty response.)' });
    stopReason = finish === 'MAX_TOKENS' ? 'max_tokens' : 'end_turn';
  }
  const u = data.usageMetadata || {};
  return { content, stopReason, usage: { input_tokens: u.promptTokenCount, output_tokens: u.candidatesTokenCount } };
}

export function createGeminiProvider({ apiKey, model, vision = true, fetchImpl = globalThis.fetch.bind(globalThis) }) {
  if (!apiKey) throw new Error('No API key set. Add one in OpenTriage settings.');

  return {
    id: 'gemini',
    model,
    vision,

    async complete({ system, messages, tools = [], maxTokens = 4096, signal }) {
      const body = {
        systemInstruction: { parts: [{ text: system }] },
        contents: toGeminiContents(messages, { vision }),
        // Thinking models count their reasoning against this budget.
        generationConfig: { maxOutputTokens: Math.max(maxTokens, 16384) },
      };
      if (tools.length) body.tools = [{ functionDeclarations: declarations(tools) }];
      const data = await postJSON({
        fetchImpl,
        url: `${BASE}/${encodeURIComponent(model)}:generateContent`,
        headers: { 'x-goog-api-key': apiKey },
        body,
        signal,
        name: 'Gemini',
      });
      return fromGeminiResponse(data);
    },
  };
}
