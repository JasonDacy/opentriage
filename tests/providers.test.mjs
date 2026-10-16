import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createOpenAIProvider, toResponsesInput, fromResponsesOutput } from '../src/providers/openai.js';
import { createGeminiProvider, toGeminiContents, fromGeminiResponse, toGeminiSchema } from '../src/providers/gemini.js';
import { createCompatibleProvider, toChatMessages, fromChatResponse, normaliseBaseUrl } from '../src/providers/compatible.js';
import { forAnthropic } from '../src/providers/anthropic.js';
import { PROVIDERS, isModelOrigin, visionFor, apiKeyName } from '../src/providers/index.js';
import { stripOldThinking } from '../src/agent/agent.js';
import { TOOL_DEFS } from '../src/agent/tools.js';

const IMG = { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: 'AAAA' } };

// A conversation in the agent's internal format: analyst asks, model calls two
// tools, results come back (one with a screenshot), model answers.
const convo = () => [
  { role: 'user', content: [{ type: 'text', text: 'Investigate this alert' }] },
  {
    role: 'assistant',
    content: [
      { type: 'text', text: 'Reading the page.' },
      { type: 'tool_use', id: 't1', name: 'read_page', input: { tab_id: 5 } },
      { type: 'tool_use', id: 't2', name: 'screenshot', input: {} },
    ],
  },
  {
    role: 'user',
    content: [
      { type: 'tool_result', tool_use_id: 't1', content: 'Alert 4512: encoded PowerShell' },
      { type: 'tool_result', tool_use_id: 't2', content: [IMG, { type: 'text', text: 'Screenshot of tab 5' }] },
    ],
  },
];

function fakeFetch(reply, log = []) {
  return async (url, init) => {
    log.push({ url, init, body: init.body ? JSON.parse(init.body) : null });
    const r = typeof reply === 'function' ? reply(log.length) : reply;
    return { ok: (r.status || 200) < 400, status: r.status || 200, headers: { get: () => null }, json: async () => r.body };
  };
}

// ---------- OpenAI (Responses API) ----------
test('openai: messages become Responses input items in order', () => {
  const input = toResponsesInput(convo());
  assert.deepEqual(input[0], { role: 'user', content: [{ type: 'input_text', text: 'Investigate this alert' }] });
  assert.equal(input[1].type, 'message');
  assert.deepEqual(input[2], { type: 'function_call', call_id: 't1', name: 'read_page', arguments: '{"tab_id":5}' });
  assert.equal(input[3].type, 'function_call');
  assert.deepEqual(input[4], { type: 'function_call_output', call_id: 't1', output: 'Alert 4512: encoded PowerShell' });
  assert.equal(input[5].type, 'function_call_output');
  assert.equal(input[5].output, 'Screenshot of tab 5');
  // The screenshot follows as a user image, after all tool outputs.
  assert.equal(input[6].role, 'user');
  assert.deepEqual(input[6].content[1], { type: 'input_image', image_url: 'data:image/jpeg;base64,AAAA' });
});

test('openai: text-only models get a note instead of the image', () => {
  const input = toResponsesInput(convo(), { vision: false });
  assert.ok(!JSON.stringify(input).includes('input_image'));
  assert.match(JSON.stringify(input), /does not accept images/);
});

test('openai: output parsing keeps reasoning, text and calls', () => {
  const r = fromResponsesOutput({
    status: 'completed',
    output: [
      { type: 'reasoning', id: 'rs_1', encrypted_content: 'enc', summary: [] },
      { type: 'message', content: [{ type: 'output_text', text: 'Checking the EDR.' }] },
      { type: 'function_call', call_id: 'call_9', name: 'open_tab', arguments: '{"url":"https://edr.example.com"}' },
    ],
    usage: { input_tokens: 10, output_tokens: 5 },
  });
  assert.equal(r.stopReason, 'tool_use');
  assert.equal(r.content[0].type, 'reasoning');
  assert.deepEqual(r.content[2], { type: 'tool_use', id: 'call_9', name: 'open_tab', input: { url: 'https://edr.example.com' } });
  assert.deepEqual(r.usage, { input_tokens: 10, output_tokens: 5 });
  // Reasoning is replayed as-is on the next request.
  const input = toResponsesInput([{ role: 'assistant', content: r.content }]);
  assert.deepEqual(input[0], { type: 'reasoning', id: 'rs_1', encrypted_content: 'enc', summary: [] });
  // …and dropped once the turn is over, like Claude's thinking blocks.
  const msgs = [{ role: 'assistant', content: r.content }, { role: 'user', content: 'next' }, { role: 'assistant', content: [{ type: 'text', text: 'done' }] }];
  stripOldThinking(msgs);
  assert.ok(!msgs[0].content.some((b) => b.type === 'reasoning'));
});

test('openai: length limit maps to max_tokens', () => {
  const r = fromResponsesOutput({ status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, output: [{ type: 'message', content: [{ type: 'output_text', text: 'partial' }] }] });
  assert.equal(r.stopReason, 'max_tokens');
});

test('openai: request shape, auth and non-strict tools', async () => {
  const log = [];
  const p = createOpenAIProvider({ apiKey: 'sk-test', model: 'gpt-6-sol', fetchImpl: fakeFetch({ body: { status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'OK' }] }] } }, log) });
  const r = await p.complete({ system: 'sys', messages: [{ role: 'user', content: 'ping' }], tools: TOOL_DEFS.slice(0, 2), maxTokens: 64 });
  assert.equal(r.content[0].text, 'OK');
  assert.equal(log[0].url, 'https://api.openai.com/v1/responses');
  assert.equal(log[0].init.headers.authorization, 'Bearer sk-test');
  const b = log[0].body;
  assert.equal(b.instructions, 'sys');
  assert.equal(b.store, false);
  assert.deepEqual(b.include, ['reasoning.encrypted_content']);
  assert.ok(b.max_output_tokens >= 16000);
  assert.equal(b.tools[0].type, 'function');
  assert.equal(b.tools[0].strict, false);
  assert.deepEqual(b.tools[0].parameters, TOOL_DEFS[0].input_schema);
});

test('openai: retries without reasoning include for models that reject it', async () => {
  const log = [];
  const fetchImpl = fakeFetch((n) => (n === 1 ? { status: 400, body: { error: { message: "Parameter 'include' value 'reasoning.encrypted_content' is not supported with this model." } } } : { body: { status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'OK' }] }] } }), log);
  const p = createOpenAIProvider({ apiKey: 'k', model: 'm', fetchImpl });
  await p.complete({ system: 's', messages: [{ role: 'user', content: 'x' }] });
  assert.equal(log.length, 2);
  assert.equal(log[1].body.include, undefined);
});

test('openai: rejected key gives a readable error', async () => {
  const p = createOpenAIProvider({ apiKey: 'bad', model: 'm', fetchImpl: fakeFetch({ status: 401, body: { error: { message: 'Incorrect API key' } } }) });
  await assert.rejects(p.complete({ system: 's', messages: [{ role: 'user', content: 'x' }] }), /OpenAI rejected the API key/);
});

// ---------- Gemini ----------
test('gemini: schema is reduced to the supported subset', () => {
  const s = toGeminiSchema({
    type: 'object',
    additionalProperties: false,
    properties: {
      a: { type: 'string', format: 'uri', default: 'x' },
      b: { oneOf: [{ type: 'string' }, { type: 'object', properties: { t: { type: 'string' } } }] },
      c: { type: ['integer', 'null'] },
      d: { type: 'array', items: { type: 'string', enum: ['x', 'y'] } },
    },
    required: ['a', 'zzz'],
  });
  assert.equal(s.type, 'OBJECT');
  assert.equal(s.additionalProperties, undefined);
  assert.deepEqual(s.properties.a, { type: 'STRING' });
  assert.equal(s.properties.b.anyOf.length, 2);
  assert.equal(s.properties.b.type, undefined);
  assert.deepEqual(s.properties.c, { type: 'INTEGER', nullable: true });
  assert.deepEqual(s.properties.d.items, { type: 'STRING', enum: ['x', 'y'] });
  assert.deepEqual(s.required, ['a']);
});

test('gemini: every OpenTriage tool schema converts cleanly', () => {
  const walk = (s) => {
    for (const k of Object.keys(s)) assert.ok(['type', 'description', 'properties', 'required', 'items', 'enum', 'anyOf', 'nullable', 'minimum', 'maximum', 'minItems', 'maxItems', 'format'].includes(k), `unexpected key ${k}`);
    if (s.type) assert.match(s.type, /^[A-Z]+$/);
    Object.values(s.properties || {}).forEach(walk);
    if (s.items) walk(s.items);
    (s.anyOf || []).forEach(walk);
  };
  for (const t of TOOL_DEFS) walk(toGeminiSchema(t.input_schema));
});

test('gemini: contents, function responses and screenshots', () => {
  const c = toGeminiContents(convo());
  assert.deepEqual(c.map((x) => x.role), ['user', 'model', 'user']);
  const model = c[1].parts;
  assert.equal(model[1].functionCall.name, 'read_page');
  // No signatures in this (non-Gemini) history, so the first call gets the documented placeholder.
  assert.equal(model[1].thoughtSignature, 'skip_thought_signature_validator');
  assert.equal(model[2].thoughtSignature, undefined);
  const user = c[2].parts;
  assert.deepEqual(user[0].functionResponse.name, 'read_page');
  assert.deepEqual(user[0].functionResponse.response, { result: 'Alert 4512: encoded PowerShell' });
  assert.equal(user[1].functionResponse.name, 'screenshot');
  assert.deepEqual(user[3], { inlineData: { mimeType: 'image/jpeg', data: 'AAAA' } });
});

test('gemini: thought signatures round-trip and generated ids stay local', () => {
  const r = fromGeminiResponse({
    candidates: [
      {
        finishReason: 'STOP',
        content: {
          role: 'model',
          parts: [
            { text: 'thinking…', thought: true },
            { functionCall: { name: 'read_page', args: { tab_id: 1 } }, thoughtSignature: 'SIG1' },
            { functionCall: { name: 'find_text', args: { text: 'x' }, id: 'fc_2' } },
          ],
        },
      },
    ],
    usageMetadata: { promptTokenCount: 7, candidatesTokenCount: 3 },
  });
  assert.equal(r.stopReason, 'tool_use');
  assert.equal(r.content.length, 2);
  assert.equal(r.content[0].thought_signature, 'SIG1');
  assert.deepEqual(r.usage, { input_tokens: 7, output_tokens: 3 });
  const history = [
    { role: 'user', content: 'go' },
    { role: 'assistant', content: r.content },
    { role: 'user', content: r.content.map((b) => ({ type: 'tool_result', tool_use_id: b.id, content: 'ok' })) },
  ];
  const c = toGeminiContents(history);
  assert.equal(c[1].parts[0].thoughtSignature, 'SIG1');
  assert.equal(c[1].parts[0].functionCall.id, undefined); // Gemini didn't issue one
  assert.equal(c[1].parts[1].functionCall.id, 'fc_2');
  assert.equal(c[2].parts[0].functionResponse.id, undefined);
  assert.equal(c[2].parts[1].functionResponse.id, 'fc_2');
});

test('gemini: blocked and empty responses are explained', () => {
  assert.throws(() => fromGeminiResponse({ promptFeedback: { blockReason: 'SAFETY' } }), /blocked the request \(SAFETY\)/);
  const r = fromGeminiResponse({ candidates: [{ finishReason: 'SAFETY', content: { parts: [] } }] });
  assert.match(r.content[0].text, /SAFETY/);
});

test('gemini: request shape', async () => {
  const log = [];
  const p = createGeminiProvider({ apiKey: 'AIzaTest', model: 'gemini-3.8-flash', fetchImpl: fakeFetch({ body: { candidates: [{ finishReason: 'STOP', content: { parts: [{ text: 'OK' }] } }] } }, log) });
  await p.complete({ system: 'sys', messages: [{ role: 'user', content: 'ping' }], tools: TOOL_DEFS, maxTokens: 64 });
  assert.equal(log[0].url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent');
  assert.equal(log[0].init.headers['x-goog-api-key'], 'AIzaTest');
  assert.ok(!log[0].url.includes('AIza'), 'key must not be in the URL');
  assert.deepEqual(log[0].body.systemInstruction, { parts: [{ text: 'sys' }] });
  assert.equal(log[0].body.tools[0].functionDeclarations.length, TOOL_DEFS.length);
});

// ---------- OpenAI-compatible ----------
test('compatible: chat messages with tool calls, tool results and images', () => {
  const m = toChatMessages('sys', convo(), { vision: true });
  assert.deepEqual(m[0], { role: 'system', content: 'sys' });
  assert.equal(m[1].content, 'Investigate this alert');
  assert.equal(m[2].tool_calls.length, 2);
  assert.deepEqual(m[2].tool_calls[0], { id: 't1', type: 'function', function: { name: 'read_page', arguments: '{"tab_id":5}' } });
  assert.deepEqual(m[3], { role: 'tool', tool_call_id: 't1', content: 'Alert 4512: encoded PowerShell' });
  assert.equal(m[4].role, 'tool');
  assert.equal(m[5].role, 'user');
  assert.deepEqual(m[5].content[1], { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,AAAA' } });
  // Text-only (the default for local servers): no image parts at all.
  assert.ok(!JSON.stringify(toChatMessages('sys', convo())).includes('image_url'));
});

test('compatible: response parsing, think tags and missing ids', () => {
  const r = fromChatResponse({
    choices: [{ finish_reason: 'tool_calls', message: { content: '<think>hmm</think>Looking.', tool_calls: [{ type: 'function', function: { name: 'read_page', arguments: '{"tab_id":1}' } }, { function: { name: 'x', arguments: 'not json' } }] } }],
    usage: { prompt_tokens: 9, completion_tokens: 2 },
  });
  assert.equal(r.content[0].text, 'Looking.');
  assert.ok(r.content[1].id);
  assert.deepEqual(r.content[1].input, { tab_id: 1 });
  assert.ok(r.content[2].input._unparsed_arguments);
  assert.equal(r.stopReason, 'tool_use');
  assert.deepEqual(r.usage, { input_tokens: 9, output_tokens: 2 });
});

test('compatible: base URL, auth styles, model listing and server errors', async () => {
  assert.equal(normaliseBaseUrl('http://localhost:11434/v1/chat/completions/'), 'http://localhost:11434/v1');
  const log = [];
  const ok = { body: { choices: [{ finish_reason: 'stop', message: { content: 'OK' } }], data: [{ id: 'qwen3:32b' }, { id: 'llama3.3' }] } };
  const local = createCompatibleProvider({ model: 'qwen3:32b', baseUrl: 'http://localhost:11434/v1/', fetchImpl: fakeFetch(ok, log) });
  await local.complete({ system: 's', messages: [{ role: 'user', content: 'x' }], tools: TOOL_DEFS.slice(0, 1) });
  assert.equal(log[0].url, 'http://localhost:11434/v1/chat/completions');
  assert.equal(log[0].init.headers.authorization, undefined);
  assert.equal(log[0].body.tools[0].function.name, TOOL_DEFS[0].name);
  assert.deepEqual(await local.listModels(), ['llama3.3', 'qwen3:32b']);
  assert.equal(log[1].url, 'http://localhost:11434/v1/models');
  assert.equal(log[1].init.method, 'GET');

  const azure = createCompatibleProvider({ apiKey: 'az', authStyle: 'api-key', model: 'gpt', baseUrl: 'https://x.openai.azure.com/openai/v1', fetchImpl: fakeFetch(ok, log) });
  await azure.complete({ system: 's', messages: [{ role: 'user', content: 'x' }] });
  assert.equal(log[2].init.headers['api-key'], 'az');

  const refused = createCompatibleProvider({ model: 'm', baseUrl: 'http://localhost:11434/v1', fetchImpl: fakeFetch({ status: 403, body: {} }) });
  await assert.rejects(refused.complete({ system: 's', messages: [{ role: 'user', content: 'x' }] }), /OLLAMA_ORIGINS/);
  const down = createCompatibleProvider({ model: 'm', baseUrl: 'http://localhost:1234/v1', fetchImpl: async () => { throw new TypeError('Failed to fetch'); } });
  await assert.rejects(down.complete({ system: 's', messages: [{ role: 'user', content: 'x' }] }), /local model server running/);
  assert.throws(() => createCompatibleProvider({ model: 'm', baseUrl: '' }), /server URL/);
});

// ---------- registry and Anthropic hygiene ----------
test('registry: origins, vision defaults and key names', () => {
  assert.ok(isModelOrigin('https://api.openai.com/*', {}));
  assert.ok(isModelOrigin('http://localhost:11434/*', { baseUrl: 'http://localhost:11434/v1' }));
  assert.ok(!isModelOrigin('https://siem.example.com/*', { baseUrl: 'http://localhost:11434/v1' }));
  assert.equal(visionFor('compatible', {}), false);
  assert.equal(visionFor('compatible', { visionOverride: { compatible: true } }), true);
  assert.equal(visionFor('openai', { visionOverride: { openai: false } }), false);
  assert.equal(apiKeyName('ot.apiKey', 'anthropic'), 'ot.apiKey');
  assert.equal(apiKeyName('ot.apiKey', 'gemini'), 'ot.apiKey.gemini');
  for (const p of Object.values(PROVIDERS)) assert.ok(p.note || p.warning, `${p.id} needs a data-handling note`);
  assert.match(PROVIDERS.gemini.warning, /free/i);
});

test('anthropic: private fields from other providers are removed', () => {
  const msgs = [{ role: 'assistant', content: [{ type: 'reasoning', provider: 'openai', item: {} }, { type: 'tool_use', id: 'a', name: 'n', input: {}, thought_signature: 'S', gemini_id: true }] }];
  const out = forAnthropic(msgs);
  assert.deepEqual(out[0].content, [{ type: 'tool_use', id: 'a', name: 'n', input: {} }]);
  const clean = [{ role: 'user', content: 'x' }];
  assert.equal(forAnthropic(clean)[0], clean[0]);
});
