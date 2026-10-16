# Adding a model provider

OpenTriage ships with four providers: Anthropic (`anthropic.js`), OpenAI's Responses API (`openai.js`), Google Gemini (`gemini.js`) and any OpenAI-compatible Chat Completions server (`compatible.js`, which covers Ollama, LM Studio, OpenRouter, Azure OpenAI and more). Most new services work through `compatible.js` with no code at all. Write a new adapter only for an API with its own format. Providers are small adapters; adding one does not touch the agent. Shared helpers (retries, readable errors, tool-result splitting, image data URLs) live in `common.js`, and the three non-Anthropic adapters are worked examples.

## Contract

```js
createXProvider({ apiKey, model, vision, fetchImpl, ... }) → {
  id, model, vision,
  async complete({ system, messages, tools, maxTokens, signal })
    → { content: Block[], stopReason, usage }
}
```

The agent speaks the Anthropic Messages format internally:

- `messages`: `{ role: 'user' | 'assistant', content: string | Block[] }`
- `Block`: `{ type: 'text', text }` · `{ type: 'tool_use', id, name, input }` · `{ type: 'tool_result', tool_use_id, content, is_error? }`
- `tools`: `{ name, description, input_schema }` (JSON Schema)
- `stopReason`: `'tool_use'` when the response contains tool calls, otherwise `'end_turn'` (or `'max_tokens'`).

Screenshots arrive as `image` blocks inside `tool_result` content. Most APIs can't take images in a tool result, so send the text as the tool output and the image in a following user message (see `openai.js`). If `vision` is false, replace images with `NO_VISION_NOTE`; the agent also stops offering screenshot tools. Keep any data the API needs replayed (reasoning items, signatures) on the blocks under private fields or a `reasoning` block, which the agent drops once a turn is over and `anthropic.js` strips.

Your adapter translates requests into the provider's format and responses back. For OpenAI-compatible chat APIs this means mapping `tool_use` ↔ `tool_calls`, `tool_result` ↔ `role: "tool"` messages, and `input_schema` ↔ `parameters`.

## Steps

1. Copy `src/providers/_template.js` to `src/providers/<name>.js` and implement `complete()`.
2. Register it in `src/providers/index.js` with its model list, key hint, key URL, `origins()` (the API origin patterns Chrome must allow), default `vision`, and a `note` — or `warning` — about how the service handles data.
3. Don't add the origin to `host_permissions`: the settings page requests it at runtime when the analyst saves the provider, so installing OpenTriage never asks for access to services the analyst doesn't use.
4. Add a unit test that feeds a recorded response through your adapter.
5. Document any data-handling differences in the README.

## Quality bar

OpenTriage relies on the model following tool schemas precisely and keeping page content separate from instructions. Before proposing a provider as a default, run the end-to-end test and a few real investigations, and check that it uses `propose_memory` only for analyst-stated facts and respects denied approvals.
