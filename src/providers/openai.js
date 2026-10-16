// OpenAI provider, using the Responses API (stateless: store=false).
//
// Reasoning models return encrypted reasoning items; they are kept in the
// conversation as private `reasoning` blocks and sent back while a turn is
// still using tools, so the model keeps its train of thought between calls.

import { blocksOf, dataUrl, imageOf, NO_VISION_NOTE, parseArgs, postJSON, resultParts } from './common.js';

export const OPENAI_MODELS = [
  { id: 'gpt-6-sol', name: 'GPT-6 Sol (recommended)' },
  { id: 'gpt-6-astra', name: 'GPT-6 Astra (most capable)' },
  { id: 'gpt-6-luna', name: 'GPT-6 Luna (fastest, cheapest)' },
  { id: 'gpt-5.6-terra', name: 'GPT-5.6 Terra' },
];

const ENDPOINT = 'https://api.openai.com/v1/responses';

/** Translate the agent's messages into Responses API input items. */
export function toResponsesInput(messages, { vision = true } = {}) {
  const input = [];
  for (const m of messages) {
    const blocks = blocksOf(m.content);
    if (m.role === 'assistant') {
      for (const b of blocks) {
        if (b.type === 'reasoning' && b.provider === 'openai' && b.item) input.push(b.item);
        else if (b.type === 'text' && b.text) input.push({ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: b.text }] });
        else if (b.type === 'tool_use') input.push({ type: 'function_call', call_id: b.id, name: b.name, arguments: JSON.stringify(b.input ?? {}) });
      }
      continue;
    }
    // User turn: tool outputs first (they answer the previous function calls),
    // then one user message with any screenshots and the analyst's text.
    const parts = [];
    for (const b of blocks) {
      if (b.type === 'tool_result') {
        const { text, images } = resultParts(b.content);
        input.push({ type: 'function_call_output', call_id: b.tool_use_id, output: (b.is_error ? 'Error: ' : '') + (text || (images.length ? 'Screenshot attached below.' : '(no output)')) });
        for (const img of images) {
          if (vision) parts.push({ type: 'input_text', text: `Screenshot returned by tool call ${b.tool_use_id}:` }, { type: 'input_image', image_url: dataUrl(img) });
          else parts.push({ type: 'input_text', text: NO_VISION_NOTE });
        }
      } else if (b.type === 'text' && b.text) {
        parts.push({ type: 'input_text', text: b.text });
      } else if (b.type === 'image') {
        const img = imageOf(b);
        if (img) parts.push(vision ? { type: 'input_image', image_url: dataUrl(img) } : { type: 'input_text', text: NO_VISION_NOTE });
      }
    }
    if (parts.length) input.push({ role: 'user', content: parts });
  }
  return input;
}

/** Translate a Responses API result into agent blocks. */
export function fromResponsesOutput(data) {
  const content = [];
  for (const item of data.output || []) {
    if (item.type === 'reasoning') {
      // Only worth keeping when it can be replayed (encrypted content present).
      if (item.encrypted_content) content.push({ type: 'reasoning', provider: 'openai', item: { type: 'reasoning', id: item.id, encrypted_content: item.encrypted_content, summary: item.summary || [] } });
    } else if (item.type === 'message') {
      for (const c of item.content || []) {
        if (c.type === 'output_text' && c.text) content.push({ type: 'text', text: c.text });
        else if (c.type === 'refusal' && c.refusal) content.push({ type: 'text', text: c.refusal });
      }
    } else if (item.type === 'function_call') {
      content.push({ type: 'tool_use', id: item.call_id || item.id, name: item.name, input: parseArgs(item.arguments) });
    }
  }
  const hasCalls = content.some((b) => b.type === 'tool_use');
  let stopReason = hasCalls ? 'tool_use' : 'end_turn';
  if (!hasCalls && data.status === 'incomplete' && /max_output_tokens/.test(data.incomplete_details?.reason || '')) stopReason = 'max_tokens';
  const u = data.usage || {};
  return { content, stopReason, usage: { input_tokens: u.input_tokens, output_tokens: u.output_tokens } };
}

export function createOpenAIProvider({ apiKey, model, vision = true, fetchImpl = globalThis.fetch.bind(globalThis) }) {
  if (!apiKey) throw new Error('No API key set. Add one in OpenTriage settings.');
  let withReasoning = true;

  return {
    id: 'openai',
    model,
    vision,

    async complete({ system, messages, tools = [], maxTokens = 4096, signal }) {
      const body = {
        model,
        instructions: system,
        input: toResponsesInput(messages, { vision }),
        // Reasoning models spend part of the budget thinking; leave room for the answer.
        max_output_tokens: Math.max(maxTokens, 16000),
        store: false,
      };
      if (tools.length) body.tools = tools.map((t) => ({ type: 'function', name: t.name, description: t.description, parameters: t.input_schema, strict: false }));
      if (withReasoning) body.include = ['reasoning.encrypted_content'];
      const call = () => postJSON({ fetchImpl, url: ENDPOINT, headers: { authorization: `Bearer ${apiKey}` }, body, signal, name: 'OpenAI' });
      let data;
      try {
        data = await call();
      } catch (e) {
        // Non-reasoning models reject the reasoning include; retry once without it.
        if (!(e.status === 400 && withReasoning && /reasoning|include/i.test(e.detail || e.message))) throw e;
        withReasoning = false;
        delete body.include;
        body.input = body.input.filter((i) => i.type !== 'reasoning');
        data = await call();
      }
      if (data.error) throw new Error(`Model request failed: ${data.error.message || data.error}`);
      return fromResponsesOutput(data);
    },
  };
}
