// The agent loop: model call → tool calls → results → model call, until the
// model ends its turn, the analyst stops it, or the step budget runs out.

import { uid } from '../lib/storage.js';
import { TOOL_DEFS, createToolRunner } from './tools.js';

// Models that can't see images get no screenshot-based tools.
const VISION_TOOLS = new Set(['screenshot', 'click_at']);
const TEXT_ONLY_TOOL_DEFS = TOOL_DEFS.filter((t) => !VISION_TOOLS.has(t.name));
import { buildSystemPrompt, buildTurnContext } from './prompt.js';

const KEEP_FULL_RESULTS = 8;
const KEEP_IMAGES = 2;
const compacted = new WeakSet();

/** Shrink old tool results (and drop old screenshots) so long investigations stay within context and cost limits. */
export function compactHistory(messages) {
  let seen = 0;
  let images = 0;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m.role !== 'user' || !Array.isArray(m.content)) continue;
    for (const b of m.content) {
      if (b.type !== 'tool_result') continue;
      if (Array.isArray(b.content)) {
        if (!b.content.some((c) => c.type === 'image')) continue;
        images++;
        if (images > KEEP_IMAGES) {
          b.content = b.content.map((c) => (c.type === 'image' ? { type: 'text', text: '[older screenshot removed to save context; take a new one if needed]' } : c));
        }
        continue;
      }
      if (typeof b.content !== 'string') continue;
      seen++;
      if (seen > KEEP_FULL_RESULTS && b.content.length > 1500 && !compacted.has(b)) {
        b.content = b.content.slice(0, 1200) + '\n…[older tool output elided to save context; re-run the tool if you need it again]';
        compacted.add(b);
      }
    }
  }
}

// 'reasoning' holds other providers' replayable reasoning (e.g. OpenAI encrypted reasoning items).
const THINKING = new Set(['thinking', 'redacted_thinking', 'reasoning']);

/**
 * Remove reasoning blocks from earlier, completed assistant turns. They are
 * only required for the assistant turn that is still mid tool-use, and older
 * ones can be rejected if anything about the conversation changed.
 */
export function stripOldThinking(messages, { all = false } = {}) {
  let lastAssistant = -1;
  if (!all) {
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === 'assistant') {
        // Keep the latest assistant turn only if it is still waiting on tool results.
        const next = messages[i + 1];
        const pendingTools = Array.isArray(messages[i].content) && messages[i].content.some((b) => b.type === 'tool_use') && next && next.role === 'user' && i + 1 === messages.length - 1;
        lastAssistant = pendingTools ? i : -1;
        break;
      }
    }
  }
  let removed = 0;
  messages.forEach((m, i) => {
    if (m.role !== 'assistant' || !Array.isArray(m.content) || i === lastAssistant) return;
    const kept = m.content.filter((b) => !THINKING.has(b.type));
    removed += m.content.length - kept.length;
    m.content = kept.length ? kept : [{ type: 'text', text: '(no text)' }];
  });
  return removed;
}

/**
 * Every tool_use must be answered by a tool_result in the very next message,
 * or the model API rejects the whole conversation. If a turn was interrupted
 * (an error, a stop, a cut-off response), answer the dangling calls so the
 * conversation can carry on. Returns the number of results added.
 */
export function repairToolPairs(messages) {
  let added = 0;
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (m.role !== 'assistant' || !Array.isArray(m.content)) continue;
    const ids = m.content.filter((b) => b.type === 'tool_use').map((b) => b.id);
    if (!ids.length) continue;
    let next = messages[i + 1];
    if (!next || next.role !== 'user') {
      if (!next) break; // the call is about to be run
      next = { role: 'user', content: [] };
      messages.splice(i + 1, 0, next);
    }
    if (!Array.isArray(next.content)) next.content = [{ type: 'text', text: next.content }];
    const answered = new Set(next.content.filter((b) => b.type === 'tool_result').map((b) => b.tool_use_id));
    const missing = ids.filter((id) => !answered.has(id));
    if (!missing.length) continue;
    next.content = [
      ...missing.map((id) => ({ type: 'tool_result', tool_use_id: id, content: 'Not run: the previous turn was interrupted before this call completed.', is_error: true })),
      ...next.content,
    ];
    added += missing.length;
  }
  return added;
}

const isThinkingError = (e) => e && (e.status === 400 || /\(400\)/.test(e.message || '')) && /thinking|signature/i.test(e.message || '');

/**
 * Create a conversation session. The same session keeps its message history
 * across analyst turns so follow-ups ("now draft the playbook") have context.
 *
 * deps: { provider, browser, settings, memory, library, audit, knowledge,
 *         approve, proposeMemory, presentPlaybook, onEvent, customTemplate }
 */
export function createSession(deps) {
  const run = {
    id: uid('run'),
    pageTexts: [],
    analystTexts: [],
    activeTabId: null,
    customTemplate: deps.customTemplate || null,
  };
  const messages = [];
  let controller = null;
  let busy = false;
  let system = null; // frozen for the whole conversation (see prompt.js)
  let startFacts = null; // id -> fact text at conversation start

  const emit = (type, data = {}) => deps.onEvent?.({ type, ...data });

  const tools = createToolRunner({
    browser: deps.browser,
    settings: deps.settings,
    library: deps.library,
    memory: deps.memory,
    cases: deps.cases,
    onCase: (c) => emit('case', { case: c }),
    audit: deps.audit,
    knowledge: deps.knowledge,
    run,
    approve: deps.approve,
    proposeMemory: deps.proposeMemory,
    presentPlaybook: deps.presentPlaybook,
    onStatus: (text) => emit('status', { text }),
  });

  async function sessionState() {
    const sessionTabs = await deps.browser.listTabs();
    let tab = sessionTabs.find((t) => t.id === run.activeTabId);
    if (!tab) {
      tab = sessionTabs.find((t) => t.active) || sessionTabs[0] || null;
      run.activeTabId = tab ? tab.id : null;
    }
    return { sessionTabs, tab };
  }

  async function buildSystemOnce(tab) {
    if (system) return system;
    const k = await deps.knowledge.load();
    const profile = await deps.knowledge.matchProfile({ url: tab?.url, title: tab?.title }, deps.settings.disabledProfiles || []);
    run.initialProfileId = profile.id;
    const facts = await deps.memory.all();
    startFacts = new Map(facts.map((f) => [f.id, f.fact]));
    emit('context', { profile: profile.name, facts: facts.length, url: tab?.url || '' });
    system = buildSystemPrompt({ methodology: k.methodology, profile, facts, customTemplate: run.customTemplate, activeUrl: tab?.url || '' });
    return system;
  }

  async function factChanges() {
    const now = await deps.memory.all();
    const newFacts = now.filter((f) => startFacts.get(f.id) !== f.fact);
    const ids = new Set(now.map((f) => f.id));
    const removedFacts = [...startFacts.keys()].filter((id) => !ids.has(id)).length;
    return { newFacts, removedFacts, facts: now };
  }

  async function complete(sys) {
    const req = { system: sys, messages, tools: deps.provider.vision === false ? TEXT_ONLY_TOOL_DEFS : TOOL_DEFS, maxTokens: Math.max(deps.settings.maxTokens || 0, 8192), signal: controller.signal };
    try {
      return await deps.provider.complete(req);
    } catch (e) {
      // Belt and braces: if the API still objects to a reasoning block, drop them all and retry once.
      if (!isThinkingError(e)) throw e;
      stripOldThinking(messages, { all: true });
      await deps.audit.log({ type: 'run.retry', runId: run.id, reason: 'thinking-block' });
      return deps.provider.complete(req);
    }
  }

  return {
    id: run.id,
    get busy() {
      return busy;
    },
    get messages() {
      return messages;
    },

    stop() {
      controller?.abort();
    },

    /**
     * Send an analyst message and run until the model finishes.
     * `untrustedContext` (e.g. a selection from the page) is wrapped separately.
     */
    async send(text, { mode = 'chat', untrustedContext = null, targetTabId = null } = {}) {
      if (busy) throw new Error('Already running');
      if (Number.isInteger(targetTabId)) run.activeTabId = targetTabId;
      busy = true;
      controller = new AbortController();
      run.analystTexts.push(text);
      try {
        const { sessionTabs, tab } = await sessionState();
        const sys = await buildSystemOnce(tab);
        const { newFacts, removedFacts, facts } = await factChanges();
        const content = [{ type: 'text', text }];
        if (untrustedContext) {
          run.pageTexts.push(untrustedContext.text);
          content.push({ type: 'text', text: untrustedContext.wrapped });
        }
        content.push({ type: 'text', text: buildTurnContext({ mode, sessionTabs, targetTabId: run.activeTabId, newFacts, removedFacts, facts }) });
        stripOldThinking(messages);
        const last = messages[messages.length - 1];
        if (last && last.role === 'user') last.content = [...(Array.isArray(last.content) ? last.content : [{ type: 'text', text: last.content }]), ...content];
        else messages.push({ role: 'user', content });
        await deps.audit.log({ type: 'run.message', runId: run.id, mode, chars: text.length });

        const maxSteps = mode === 'queue' ? Math.max(deps.settings.maxSteps || 40, 200) : deps.settings.maxSteps || 40;
        for (let step = 0; step < maxSteps; step++) {
          emit('thinking', { step });
          compactHistory(messages);
          const repaired = repairToolPairs(messages);
          if (repaired) await deps.audit.log({ type: 'run.repair', runId: run.id, results: repaired });
          const res = await complete(sys);
          messages.push({ role: 'assistant', content: res.content });
          emit('usage', { usage: res.usage });

          for (const block of res.content) {
            if (block.type === 'text' && block.text.trim()) emit('assistant', { text: block.text, final: res.stopReason !== 'tool_use' });
          }

          const calls = res.content.filter((b) => b.type === 'tool_use');
          if (!calls.length) {
            if (res.stopReason === 'max_tokens') emit('status', { text: 'The response hit the length limit. Ask OpenTriage to continue.' });
            break;
          }
          if (res.stopReason !== 'tool_use') {
            // The response was cut off (or ended oddly) mid tool call: the input may be incomplete, so don't run it.
            const why = res.stopReason === 'max_tokens'
              ? 'Not run: your response hit the length limit before this tool call was complete. Retry it with a shorter input (for long content, split it into smaller steps).'
              : `Not run: the response ended (${res.stopReason || 'unknown reason'}) before this tool call could be made. Retry it if it is still needed.`;
            messages.push({ role: 'user', content: calls.map((c) => ({ type: 'tool_result', tool_use_id: c.id, content: why, is_error: true })) });
            await deps.audit.log({ type: 'run.cutoff', runId: run.id, stopReason: res.stopReason, calls: calls.length });
            continue;
          }

          const results = [];
          for (const call of calls) {
            if (controller.signal.aborted) {
              results.push({ type: 'tool_result', tool_use_id: call.id, content: 'Stopped by the analyst.', is_error: true });
              continue;
            }
            let r;
            try {
              emit('tool', { name: call.name, input: call.input });
              r = await tools.run(call.name, call.input);
              const preview = typeof r.content === 'string' ? r.content : (r.content || []).filter((c) => c.type === 'text').map((c) => c.text).join(' ');
              emit('tool_result', { name: call.name, isError: r.isError, preview: preview.slice(0, 300) });
            } catch (e) {
              r = r || { isError: true, content: `Tool error: ${e.message || e}` };
            }
            results.push({ type: 'tool_result', tool_use_id: call.id, content: r.content, ...(r.isError ? { is_error: true } : {}) });
          }
          messages.push({ role: 'user', content: results });
          if (controller.signal.aborted) {
            emit('status', { text: 'Stopped.' });
            break;
          }
          if (step === maxSteps - 1) emit('status', { text: `Reached the ${maxSteps}-step limit. Send "continue" to keep going.` });
        }
      } catch (e) {
        if (e.name === 'AbortError') emit('status', { text: 'Stopped.' });
        else emit('error', { text: e.message || String(e) });
      } finally {
        await deps.browser.release?.().catch?.(() => {});
        busy = false;
        controller = null;
        emit('idle');
      }
    },
  };
}
