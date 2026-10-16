# Adding a model provider

OpenTriage ships with Anthropic (Claude). Providers are small adapters; adding one does not touch the agent.

## Contract

```js
createXProvider({ apiKey, model, fetchImpl }) → {
  id, model,
  async complete({ system, messages, tools, maxTokens, signal })
    → { content: Block[], stopReason, usage }
}
```

The agent speaks the Anthropic Messages format internally:

- `messages`: `{ role: 'user' | 'assistant', content: string | Block[] }`
- `Block`: `{ type: 'text', text }` · `{ type: 'tool_use', id, name, input }` · `{ type: 'tool_result', tool_use_id, content, is_error? }`
- `tools`: `{ name, description, input_schema }` (JSON Schema)
- `stopReason`: `'tool_use'` when the response contains tool calls, otherwise `'end_turn'` (or `'max_tokens'`).

Your adapter translates requests into the provider's format and responses back. For OpenAI-compatible chat APIs this means mapping `tool_use` ↔ `tool_calls`, `tool_result` ↔ `role: "tool"` messages, and `input_schema` ↔ `parameters`.

## Steps

1. Copy `src/providers/_template.js` to `src/providers/<name>.js` and implement `complete()`.
2. Register it in `src/providers/index.js` with its model list, key hint and key URL.
3. Add the provider's API origin to `host_permissions` in `manifest.json` and to the allowed list in `scripts/check.mjs`. (Self-hosted endpoints can instead be requested as an optional permission at runtime.)
4. Add a unit test that feeds a recorded response through your adapter.
5. Document any data-handling differences in the README.

## Quality bar

OpenTriage relies on the model following tool schemas precisely and keeping page content separate from instructions. Before proposing a provider as a default, run the end-to-end test and a few real investigations, and check that it uses `propose_memory` only for analyst-stated facts and respects denied approvals.
