import { KEYS } from './storage.js';

export const DEFAULT_SETTINGS = {
  provider: 'anthropic',
  model: 'claude-sonnet-5-5',
  // Local or OpenAI-compatible server (provider 'compatible').
  baseUrl: '',
  authStyle: 'bearer', // or 'api-key' (Azure OpenAI)
  // Per-provider override of whether the model accepts images: { [providerId]: boolean }.
  visionOverride: {},
  maxSteps: 40,
  maxTokens: 4096,
  // 'strict'    — every click and every typed submit needs approval
  // 'standard'  — clicks that look state-changing need approval (default)
  approvalMode: 'standard',
  // 'simulated' — DOM events (default, no extra permission)
  // 'trusted'   — real input via Chrome's debugger (trusted-input build only)
  inputMode: 'simulated',
  // Origins of the analyst's own tools, where typing indicators doesn't need approval.
  internalOrigins: [],
  // Store the API key only for this browser session (cleared when Chrome closes).
  sessionOnlyKey: false,
  // Mask email addresses in page content before it is sent to the model.
  maskEmails: false,
  // Origins the agent may navigate to without asking. Populated as the
  // analyst grants site access; never shipped with defaults.
  trustedOrigins: [],
  // IOC enrichment sources. URL templates use {ioc}. Disabled by default
  // because opening them sends the indicator to that third party.
  enrichmentSources: [
    { id: 'virustotal', name: 'VirusTotal', url: 'https://www.virustotal.com/gui/search/{ioc}', types: ['hash', 'ip', 'domain', 'url'], enabled: false },
    { id: 'abuseipdb', name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/check/{ioc}', types: ['ip'], enabled: false },
    { id: 'talos', name: 'Cisco Talos', url: 'https://talosintelligence.com/reputation_center/lookup?search={ioc}', types: ['ip', 'domain'], enabled: false },
    { id: 'shodan', name: 'Shodan', url: 'https://www.shodan.io/host/{ioc}', types: ['ip'], enabled: false },
  ],
  disabledProfiles: [],
};

export async function loadSettings(storage) {
  const saved = (await storage.get(KEYS.settings, {})) || {};
  return { ...DEFAULT_SETTINGS, ...saved };
}

export async function saveSettings(storage, patch) {
  const current = await loadSettings(storage);
  const next = { ...current, ...patch };
  await storage.set(KEYS.settings, next);
  return next;
}
