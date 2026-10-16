// Model provider registry.
//
// Every provider implements:
//
//   async complete({ system, messages, tools, maxTokens, signal })
//     -> { content: Block[], stopReason: 'end_turn' | 'tool_use' | 'max_tokens' | string, usage }
//
// The internal message format is the Anthropic Messages format (text,
// tool_use and tool_result blocks). Providers for other APIs translate to and
// from it. See docs/adding-a-provider.md.

import { createAnthropicProvider, ANTHROPIC_MODELS } from './anthropic.js';

export const PROVIDERS = {
  anthropic: {
    id: 'anthropic',
    name: 'Anthropic (Claude)',
    models: ANTHROPIC_MODELS,
    keyHint: 'sk-ant-…',
    keyUrl: 'https://console.anthropic.com/settings/keys',
    create: createAnthropicProvider,
  },
};

export function getProvider(id, options) {
  const p = PROVIDERS[id];
  if (!p) throw new Error(`Unknown provider "${id}"`);
  return p.create(options);
}
