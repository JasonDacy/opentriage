// Model provider registry.
//
// Every provider implements:
//
//   async complete({ system, messages, tools, maxTokens, signal })
//     -> { content: Block[], stopReason: 'end_turn' | 'tool_use' | 'max_tokens' | string, usage }
//
// and exposes `vision` (false when the model can't take images; the agent then
// drops screenshot tools). The internal message format is the Anthropic
// Messages format (text, tool_use and tool_result blocks). Providers for other
// APIs translate to and from it. See docs/adding-a-provider.md.

import { createAnthropicProvider, ANTHROPIC_MODELS } from './anthropic.js';
import { createOpenAIProvider, OPENAI_MODELS } from './openai.js';
import { createGeminiProvider, GEMINI_MODELS } from './gemini.js';
import { createCompatibleProvider, LOCAL_PRESETS, normaliseBaseUrl } from './compatible.js';
import { originPattern } from './common.js';

export { LOCAL_PRESETS };

export const PROVIDERS = {
  anthropic: {
    id: 'anthropic',
    name: 'Anthropic (Claude)',
    models: ANTHROPIC_MODELS,
    keyHint: 'sk-ant-…',
    keyUrl: 'https://console.anthropic.com/settings/keys',
    origins: () => ['https://api.anthropic.com/*'],
    vision: true,
    note: 'Commercial API terms: Anthropic does not train on API data by default.',
    create: createAnthropicProvider,
  },
  openai: {
    id: 'openai',
    name: 'OpenAI (GPT)',
    models: OPENAI_MODELS,
    keyHint: 'sk-…',
    keyUrl: 'https://platform.openai.com/api-keys',
    origins: () => ['https://api.openai.com/*'],
    vision: true,
    note: 'API terms: OpenAI does not train on API data by default and may keep it for up to 30 days for abuse monitoring. OpenTriage sends requests with store=false.',
    create: createOpenAIProvider,
  },
  gemini: {
    id: 'gemini',
    name: 'Google (Gemini)',
    models: GEMINI_MODELS,
    keyHint: 'AIza…',
    keyUrl: 'https://aistudio.google.com/apikey',
    origins: () => ['https://generativelanguage.googleapis.com/*'],
    vision: true,
    warning:
      "Free tier warning: on the Gemini API's free (unpaid) tier, Google may use what you send to improve its products, and human reviewers may read it. Use a key from a billing-enabled project before investigating real alerts.",
    create: createGeminiProvider,
  },
  compatible: {
    id: 'compatible',
    name: 'Local or OpenAI-compatible server',
    models: [],
    keyHint: 'optional for local servers',
    keyUrl: '',
    keyOptional: true,
    needsBaseUrl: true,
    origins: (s) => [originPattern(normaliseBaseUrl(s?.baseUrl))].filter(Boolean),
    vision: false,
    note: 'Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, Groq, Azure OpenAI and other servers with an OpenAI-style /chat/completions endpoint. A local server keeps alert data on your machine. Pick a model that supports tool calling, and give it a large context window (at least 32k tokens).',
    create: createCompatibleProvider,
  },
};

/** The origins every provider might call, so settings can tell them apart from console sites. */
export function isModelOrigin(pattern, settings) {
  return Object.values(PROVIDERS).some((p) => p.origins(settings).includes(pattern));
}

/** Whether the provider's model takes images, given the analyst's setting (null = provider default). */
export function visionFor(id, settings) {
  const p = PROVIDERS[id];
  if (!p) return false;
  const o = settings?.visionOverride?.[id];
  return typeof o === 'boolean' ? o : p.vision;
}

export function getProvider(id, options) {
  const p = PROVIDERS[id];
  if (!p) throw new Error(`Unknown provider "${id}"`);
  return p.create(options);
}

/** Storage key for a provider's API key (Anthropic keeps the original key name). */
export const apiKeyName = (base, id) => (id === 'anthropic' ? base : `${base}.${id}`);
