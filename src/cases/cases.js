// Local case history: one record per alert OpenTriage worked on, written by
// the agent's record_case tool. Used for the queue progress view, weekly
// summaries and CSV export. Stored only in this browser.

import { KEYS, uid } from '../lib/storage.js';

export const CASE_ACTIONS = ['closed', 'held', 'skipped', 'escalated', 'in_progress'];
const MAX_CASES = 5000;

export function createCases(storage, audit) {
  async function all() {
    return (await storage.get(KEYS.cases, [])) || [];
  }
  return {
    all,
    async record(c) {
      const list = await all();
      const now = new Date().toISOString();
      const key = `${c.console || ''}|${c.alert_id}`.toLowerCase();
      const i = list.findIndex((x) => x.key === key);
      const rec = {
        id: i >= 0 ? list[i].id : uid('case'),
        key,
        alertId: String(c.alert_id).slice(0, 120),
        title: String(c.title || '').slice(0, 300),
        console: String(c.console || '').slice(0, 80),
        verdict: c.verdict || 'Undetermined',
        confidence: c.confidence || '',
        action: CASE_ACTIONS.includes(c.action) ? c.action : 'held',
        reason: String(c.reason || '').slice(0, 600),
        playbook: String(c.playbook || '').slice(0, 200),
        ownerRole: String(c.owner_role || '').slice(0, 200),
        mitre: (c.mitre || []).slice(0, 10).map(String),
        createdAt: i >= 0 ? list[i].createdAt : now,
        updatedAt: now,
      };
      if (i >= 0) list[i] = rec;
      else list.push(rec);
      while (list.length > MAX_CASES) list.shift();
      await storage.set(KEYS.cases, list);
      await audit?.log({ type: 'case.record', alertId: rec.alertId, action: rec.action, verdict: rec.verdict });
      return rec;
    },
    async since(days = 7) {
      const cutoff = Date.now() - days * 86400000;
      return (await all()).filter((c) => Date.parse(c.updatedAt) >= cutoff);
    },
    async clear() {
      await storage.set(KEYS.cases, []);
      await audit?.log({ type: 'case.clear' });
    },
    async toCsv() {
      const cols = ['updatedAt', 'console', 'alertId', 'title', 'ownerRole', 'verdict', 'confidence', 'action', 'reason', 'playbook', 'mitre'];
      const esc = (v) => {
        const s = Array.isArray(v) ? v.join('; ') : String(v ?? '');
        // Neutralise spreadsheet formula injection from alert titles.
        const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
        return /[",\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
      };
      return [cols.join(','), ...(await all()).map((c) => cols.map((k) => esc(c[k])).join(','))].join('\n');
    },
  };
}

/** Counts used in summaries. */
export function summarise(cases) {
  const by = (k) => cases.reduce((m, c) => ((m[c[k]] = (m[c[k]] || 0) + 1), m), {});
  return { total: cases.length, byAction: by('action'), byVerdict: by('verdict'), byConsole: by('console') };
}
