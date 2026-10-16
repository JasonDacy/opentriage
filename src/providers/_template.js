// Template for adding a model provider. Copy this file, implement complete(),
// and register it in providers/index.js. See docs/adding-a-provider.md.
//
// The agent speaks the Anthropic Messages format internally:
//   messages: [{ role: 'user' | 'assistant', content: string | Block[] }]
//   Block: { type: 'text', text }
//        | { type: 'tool_use', id, name, input }
//        | { type: 'tool_result', tool_use_id, content, is_error? }
//   tools: [{ name, description, input_schema }]
//
// Your provider translates those to its own API and translates the response
// back into { content: Block[], stopReason, usage }.

export const EXAMPLE_MODELS = [{ id: 'model-id', name: 'Display name' }];

export function createExampleProvider({ apiKey, model, fetchImpl = globalThis.fetch.bind(globalThis) }) {
  return {
    id: 'example',
    model,
    async complete({ system, messages, tools, maxTokens, signal }) {
      // 1. Translate system/messages/tools to the provider's request format.
      // 2. POST with fetchImpl(..., { signal }).
      // 3. Translate the response:
      //      text output        -> { type: 'text', text }
      //      tool/function call -> { type: 'tool_use', id, name, input }
      //    and map the finish reason to 'tool_use' when any tool call is present,
      //    otherwise 'end_turn' (or 'max_tokens').
      void apiKey;
      void system;
      void messages;
      void tools;
      void maxTokens;
      void signal;
      void fetchImpl;
      throw new Error('Not implemented');
    },
  };
}
