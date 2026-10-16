import { chromeStorage, KEYS } from '../lib/storage.js';
import { loadSettings, saveSettings } from '../lib/settings.js';
import { createAudit } from '../lib/audit.js';
import { wrapUntrusted } from '../lib/security.js';
import { createMemory, CATEGORIES } from '../memory/memory.js';
import { createLibrary } from '../playbooks/library.js';
import { createCases } from '../cases/cases.js';
import { toMarkdown, toHtml } from '../playbooks/render.js';
import { playbookTitle } from '../playbooks/template.js';
import { createKnowledge, extensionReader } from '../knowledge/loader.js';
import { chromeBrowser } from '../agent/browser.js';
import { createSession } from '../agent/agent.js';
import { getProvider } from '../providers/index.js';
import { renderMarkdown } from './markdown.js';

const $ = (id) => document.getElementById(id);
const storage = chromeStorage('local');
const audit = createAudit(storage);
const memory = createMemory(storage, audit);
const library = createLibrary(storage, audit);
const cases = createCases(storage, audit);
const knowledge = createKnowledge(extensionReader());
const params = new URLSearchParams(location.search);
const pinned = Number(params.get('tab')) || null;
const popout = params.get('popout') === '1';
const browser = chromeBrowser({ pinnedTabId: pinned, popout, inputMode: () => settings?.inputMode || 'simulated' });
if (popout) document.title = 'OpenTriage';

let settings = null;
let session = null;
let statusEl = null;
let pendingSelection = null;

// ---------- small DOM helpers ----------
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

function append(node) {
  $('empty')?.remove();
  const log = $('log');
  const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 120;
  log.append(node);
  if (nearBottom || node.classList.contains('card') || node.classList.contains('user')) node.scrollIntoView({ block: 'end' });
  return node;
}

function wireCodeCopy(root) {
  root.querySelectorAll('.copy-code').forEach((b) =>
    b.addEventListener('click', () => {
      navigator.clipboard.writeText(b.nextElementSibling.innerText);
      b.textContent = 'Copied';
      setTimeout(() => (b.textContent = 'Copy'), 1200);
    }),
  );
}

function download(name, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || 'playbook';

function setStatus(text) {
  if (!text) {
    statusEl?.remove();
    statusEl = null;
    return;
  }
  if (!statusEl) statusEl = append(el('div', { class: 'status' }, el('span', { class: 'spinner' }), el('span')));
  statusEl.lastChild.textContent = text;
  $('log').append(statusEl);
}

function notice(text, kind = '') {
  return append(el('div', { class: `notice ${kind}` }, text));
}

// ---------- session tabs ----------
// The session is the "OpenTriage" tab group. Rows below mirror it; the analyst
// can also drag tabs in and out of the group in Chrome's tab strip.
let current = null; // { tab, inSession, missing }
let targetTabId = null;
const candidateInfo = new Map(); // tabId -> missing origins (precomputed so permission prompts stay inside the click gesture)

async function frameOrigins(tabId) {
  try {
    const frames = (await chrome.webNavigation.getAllFrames({ tabId })) || [];
    return [...new Set(frames.map((f) => f.url).filter((u) => /^https:/.test(u)).map((u) => new URL(u).origin))];
  } catch {
    return [];
  }
}

async function missingOrigins(tab) {
  if (!tab || !/^https:/.test(tab.url || '')) return [];
  const origins = [...new Set([new URL(tab.url).origin, ...(await frameOrigins(tab.id))])];
  const missing = [];
  for (const o of origins) if (!(await chrome.permissions.contains({ origins: [o + '/*'] }))) missing.push(o);
  return missing;
}

/** Ask for site access. Call this first in a click handler, before any other await. */
async function requestAccess(origins) {
  if (!origins.length) return true;
  const granted = await chrome.permissions.request({ origins: origins.map((o) => o + '/*') });
  if (granted) {
    settings = await saveSettings(storage, { trustedOrigins: [...new Set([...(settings.trustedOrigins || []), ...origins])] });
    await audit.log({ type: 'access.grant', origins });
  }
  return granted;
}

async function addTabToSession(tabId, missing) {
  await requestAccess(missing || []); // optional: the tab is added even if access is declined
  await browser.addToSession(tabId);
  await audit.log({ type: 'session.add', tabId });
  if (!targetTabId) targetTabId = tabId;
  refreshSession();
}

const hostOf = (url) => {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
};

let refreshTimer = null;
function refreshSession() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(renderSession, 150);
}

async function renderSession() {
  const tabs = await browser.listTabs();
  if (targetTabId && !tabs.some((t) => t.id === targetTabId)) targetTabId = null;
  const active = await browser.activeTab();
  if (!targetTabId && tabs.length) targetTabId = (tabs.find((t) => active && t.id === active.id) || tabs[0]).id;
  $('tabCount').textContent = String(tabs.length);
  applyCollapse(tabs.length);
  const tgt = tabs.find((t) => t.id === targetTabId);
  $('targetSummary').textContent = tgt ? `· target: ${tgt.title || hostOf(tgt.url)}` : '';

  const rows = [];
  for (const t of tabs) {
    const missing = await missingOrigins(t);
    const profile = await knowledge.matchProfile({ url: t.url, title: t.title }, settings.disabledProfiles);
    const readable = /^https:/.test(t.url) && !missing.includes(new URL(t.url).origin);
    const row = el(
      'div',
      { class: 'tab-row' + (t.id === targetTabId ? ' target' : ''), 'data-tab': String(t.id) },
      el('span', { class: 'dot ' + (readable && !missing.length ? 'ok' : 'no'), title: readable ? (missing.length ? `Embedded frames not readable: ${missing.join(', ')}` : 'Readable') : 'No site access' }),
      el('span', { class: 'title', title: `${t.title}\n${t.url}\nClick to make this the target tab`, onclick: () => { targetTabId = t.id; renderSession(); } }, t.title || hostOf(t.url), el('small', {}, hostOf(t.url))),
      profile.id === 'generic' ? el('span') : el('span', { class: 'pill' }, profile.name),
      missing.length ? el('button', { title: missing.join('\n'), onclick: async () => { await requestAccess(missing); refreshSession(); } }, 'Grant access') : el('span'),
      el('button', { class: 'x', title: 'Remove from session (the tab stays open)', onclick: async () => { await browser.session.remove(t.id); await audit.log({ type: 'session.remove', tabId: t.id }); refreshSession(); } }, '×'),
    );
    rows.push(row);
  }
  $('tabList').replaceChildren(...(rows.length ? rows : [el('div', { class: 'none' }, 'No tabs yet. Open an alert and click "+ Current" — or just click "Investigate".')]));

  // Current tab button
  const inSession = !!active && tabs.some((t) => t.id === active.id);
  const addable = !!active && /^https?:/.test(active.url || '');
  current = active ? { tab: active, inSession, missing: addable && !inSession ? await missingOrigins(active) : [] } : null;
  const btn = $('addCurrent');
  btn.disabled = !addable || inSession;
  btn.textContent = inSession ? '✓ In session' : '+ Current';
  btn.title = inSession ? 'The tab you are looking at is already in the session' : 'Add the tab you are looking at to the OpenTriage tab group';

  // Other tabs menu
  const cands = await browser.session.candidates();
  candidateInfo.clear();
  for (const c of cands) candidateInfo.set(c.id, await missingOrigins(c));
  $('addList').replaceChildren(
    ...(cands.length
      ? cands.map((c) =>
          el('button', {
            onclick: async () => {
              $('addMenu').open = false;
              await addTabToSession(c.id, candidateInfo.get(c.id) || []);
            },
          }, c.title || hostOf(c.url), el('small', {}, c.url)),
        )
      : [el('div', { class: 'empty-note' }, 'No other web tabs open.')]),
  );
}

// Collapsed by default once the list gets long; the analyst's choice is remembered.
function collapsePref() {
  try {
    return localStorage.getItem('ot.tabsCollapsed');
  } catch {
    return null;
  }
}
function applyCollapse(count) {
  const pref = collapsePref();
  const collapsed = pref === null ? count > 3 : pref === '1';
  $('sessionBar').classList.toggle('collapsed', collapsed && count > 0);
  $('tabsToggle').setAttribute('aria-expanded', String(!(collapsed && count > 0)));
}
$('tabsToggle').addEventListener('click', () => {
  const next = !$('sessionBar').classList.contains('collapsed');
  try {
    localStorage.setItem('ot.tabsCollapsed', next ? '1' : '0');
  } catch {
    /* ignore */
  }
  $('sessionBar').classList.toggle('collapsed', next);
  $('tabsToggle').setAttribute('aria-expanded', String(!next));
});

$('popOut').addEventListener('click', async () => {
  await chrome.windows.create({ url: chrome.runtime.getURL('src/ui/sidepanel.html?popout=1'), type: 'popup', width: 560, height: Math.min(1000, (screen.availHeight || 900) - 40) });
});
if (popout) $('popOut').classList.add('hidden');

$('addCurrent').addEventListener('click', () => {
  if (!current || current.inSession) return;
  addTabToSession(current.tab.id, current.missing);
});

chrome.tabs.onActivated.addListener(refreshSession);
chrome.tabs.onRemoved.addListener(refreshSession);
chrome.tabs.onAttached.addListener(refreshSession);
chrome.tabs.onUpdated.addListener((id, info) => {
  if (info.status === 'complete' || 'groupId' in info || info.title) refreshSession();
});
chrome.tabGroups.onUpdated.addListener(refreshSession);
chrome.tabGroups.onRemoved.addListener(refreshSession);
chrome.permissions.onAdded.addListener(refreshSession);
chrome.permissions.onRemoved.addListener(refreshSession);

// ---------- analyst cards ----------
function approve(req) {
  return new Promise((resolve) => {
    const needs = (req.needsOrigins || []).filter(Boolean);
    const trust = el('input', { type: 'checkbox' });
    const markInternal = el('input', { type: 'checkbox' });
    const preview = req.preview
      ? el('pre', { class: 'approval-preview' + (req.previewKind === 'diff' ? ' diff' : '') }, ...String(req.preview).split('\n').map((l) => el('span', { class: l.startsWith('+ ') ? 'add' : l.startsWith('- ') ? 'del' : '' }, l + '\n')))
      : null;
    const note = el('input', { type: 'text', placeholder: 'Optional note for OpenTriage (e.g. why you denied it)' });
    const card = el(
      'div',
      { class: 'card approval' },
      el('h4', {}, '⚠ Approval needed: ', req.title),
      el('div', { class: 'kv' }, el('span', {}, 'Why'), el('span', {}, req.detail || '—'), el('span', {}, 'Target'), el('span', {}, req.target || '—'), el('span', {}, 'Flagged'), el('span', {}, req.reason || '—')),
      preview,
      needs.length && req.kind !== 'lookup' ? el('label', { class: 'check' }, trust, `Trust ${needs.join(', ')} for future navigation`) : null,
      req.shareOrigin ? el('label', { class: 'check' }, markInternal, `${req.shareOrigin} is one of our own tools — don't ask again`) : null,
      note,
    );
    const done = (approved) => {
      card.classList.add('done');
      card.querySelectorAll('button,input').forEach((b) => (b.disabled = true));
      card.append(el('div', { class: 'muted' }, approved ? 'Approved' : 'Denied'));
      resolve({ approved, note: note.value.trim() });
    };
    const yes = el('button', {
      class: 'primary',
      'data-kind': req.kind,
      onclick: async () => {
        if (req.shareOrigin && markInternal.checked) {
          settings = await saveSettings(storage, { internalOrigins: [...new Set([...(settings.internalOrigins || []), req.shareOrigin])] });
          await audit.log({ type: 'settings.internalOrigin', origin: req.shareOrigin });
        }
        if (req.needsAllUrls) {
          const granted = await chrome.permissions.request({ origins: ['<all_urls>'] });
          await audit.log({ type: 'access.screenshots', granted });
          return done(granted);
        }
        if (needs.length) {
          const granted = await chrome.permissions.request({ origins: needs.map((o) => o + '/*') });
          if (!granted) return done(false);
          if (trust.checked) settings = await saveSettings(storage, { trustedOrigins: [...new Set([...(settings.trustedOrigins || []), ...needs])] });
        }
        done(true);
      },
    }, 'Approve');
    const no = el('button', { onclick: () => done(false) }, 'Deny');
    if (req.kind === 'publish') card.classList.add('publish');
    card.append(el('div', { class: 'row' }, yes, no));
    setStatus(null);
    append(card);
    yes.focus();
  });
}

function proposeMemory(p) {
  return new Promise((resolve) => {
    const text = el('textarea', { rows: 3 });
    text.value = p.fact;
    const cat = el('select', {}, Object.entries(CATEGORIES).map(([k, d]) => el('option', { value: k, title: d, selected: k === p.category }, k.replace(/_/g, ' '))));
    const card = el(
      'div',
      { class: 'card memory' },
      el('h4', {}, 'Remember this about your environment?'),
      p.provenance?.tainted
        ? el('div', { class: 'taint' }, el('strong', {}, 'Careful: '), 'this closely matches text OpenTriage read from a web page during this investigation, not something you typed. Alert data can be written by an attacker. Save it only if you know it is true.')
        : null,
      p.note ? el('div', { class: 'muted' }, p.note) : null,
      text,
      el('div', { class: 'row' }, el('span', { class: 'muted' }, 'Category'), cat),
    );
    const done = (saved, fact, reason) => {
      card.classList.add('done');
      card.querySelectorAll('button,textarea,select').forEach((b) => (b.disabled = true));
      card.append(el('div', { class: 'muted' }, saved ? 'Saved to environment memory' : 'Not saved'));
      resolve({ saved, fact, reason });
    };
    card.append(
      el(
        'div',
        { class: 'row' },
        el('button', {
          class: 'primary',
          onclick: async () => {
            try {
              const item = await memory.add({ fact: text.value, category: cat.value, source: 'approved-proposal', note: p.note });
              refreshMemoryPill();
              done(true, item.fact);
            } catch (e) {
              notice(e.message, 'error');
            }
          },
        }, 'Save'),
        el('button', { onclick: () => done(false, null, 'the analyst discarded it') }, 'Discard'),
      ),
    );
    setStatus(null);
    append(card);
  });
}

function presentPlaybook(d) {
  return new Promise((resolve) => {
    const md = d.kind === 'structured' ? toMarkdown(d.playbook) : d.markdown;
    const title = d.kind === 'structured' ? playbookTitle(d.playbook) : (md.match(/^#\s+(.+)$/m) || [, 'Playbook'])[1];
    const preview = el('div', { class: 'preview msg assistant' });
    preview.innerHTML = renderMarkdown(md);
    wireCodeCopy(preview);
    const feedback = el('input', { type: 'text', placeholder: 'What should change?' });
    const card = el(
      'div',
      { class: 'card' },
      el('h4', {}, d.updateId ? 'Playbook update ready: ' : 'Playbook draft ready: ', title),
      el('div', { class: 'muted' }, `Passed ${d.kind === 'structured' ? 'template' : 'custom-template'} validation.`),
      d.validation.warnings.length ? el('ul', { class: 'issues' }, d.validation.warnings.map((w) => el('li', { class: 'warn' }, `${w.field}: ${w.message}`))) : null,
      el('details', { open: true }, el('summary', {}, 'Preview'), preview),
    );
    const exports = el(
      'div',
      { class: 'row hidden' },
      el('button', { onclick: () => navigator.clipboard.writeText(md) }, 'Copy Markdown'),
      el('button', { onclick: () => download(`${slug(title)}.md`, md, 'text/markdown') }, 'Download .md'),
      d.kind === 'structured' ? el('button', { onclick: () => download(`${slug(title)}.html`, toHtml(d.playbook), 'text/html') }, 'Download .html') : null,
    );
    const finish = (result, label) => {
      card.querySelectorAll('.decide button, .decide input').forEach((b) => (b.disabled = true));
      card.append(el('div', { class: 'muted' }, label));
      resolve(result);
    };
    card.append(
      el(
        'div',
        { class: 'row decide' },
        el('button', {
          class: 'primary',
          onclick: async () => {
            const entry = await library.save({ playbook: d.playbook, markdown: d.markdown, id: d.updateId });
            exports.classList.remove('hidden');
            finish({ saved: true, id: entry.id }, 'Saved to the playbook library.');
          },
        }, d.updateId ? 'Save update' : 'Save to library'),
        el('button', { onclick: () => feedback.value.trim() ? finish({ saved: false, feedback: feedback.value.trim() }, 'Changes requested.') : feedback.focus() }, 'Request changes'),
        el('button', { onclick: () => finish({ saved: false }, 'Discarded.') }, 'Discard'),
      ),
      el('div', { class: 'decide' }, feedback),
      exports,
    );
    setStatus(null);
    append(card);
  });
}

// ---------- conversation ----------
function onEvent(e) {
  switch (e.type) {
    case 'thinking':
      setStatus(e.step ? 'Working…' : 'Thinking…');
      break;
    case 'context':
      break;
    case 'assistant': {
      setStatus(null);
      const m = el('div', { class: 'msg assistant' });
      m.innerHTML = renderMarkdown(e.text);
      wireCodeCopy(m);
      if (e.final) {
        m.append(
          el('div', { class: 'tools' },
            el('button', { class: 'ghost', onclick: () => navigator.clipboard.writeText(e.text) }, 'Copy'),
            el('button', { class: 'ghost', onclick: () => download(`opentriage-report-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')}.md`, e.text, 'text/markdown') }, 'Download'),
          ),
        );
      }
      append(m);
      break;
    }
    case 'tool': {
      const label = describeTool(e.name, e.input);
      append(el('div', { class: 'event' }, el('span', {}, '›'), el('span', { class: 'name' }, e.name), el('span', {}, label)));
      setStatus('Working…');
      break;
    }
    case 'tool_result':
      if (e.isError) append(el('div', { class: 'event err' }, el('span', {}, '✕'), el('span', {}, e.preview.slice(0, 200))));
      break;
    case 'status':
      setStatus(null);
      notice(e.text, 'warn');
      break;
    case 'error':
      setStatus(null);
      notice(e.text, 'error');
      break;
    case 'case':
      renderQueueCard(e.case);
      break;
    case 'idle':
      setStatus(null);
      setBusy(false);
      queueCard = null;
      break;
  }
}

// ---------- queue progress ----------
let queueCard = null;
const queueRows = new Map();
function renderQueueCard(c) {
  if (!queueCard) {
    queueRows.clear();
    queueCard = append(el('div', { class: 'card queue' }, el('h4', {}, 'Queue progress'), el('div', { class: 'counts muted' }), el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ...['Alert', 'Detection', 'Verdict', 'Outcome'].map((h) => el('th', {}, h)))), el('tbody')))));
  }
  queueRows.set(c.key, c);
  const tbody = queueCard.querySelector('tbody');
  tbody.replaceChildren(
    ...[...queueRows.values()].map((r) =>
      el('tr', { title: `${r.reason}${r.ownerRole ? '\nOwner role: ' + r.ownerRole : ''}` }, el('td', {}, r.alertId), el('td', {}, r.title), el('td', {}, `${r.verdict}${r.confidence ? ' · ' + r.confidence : ''}`), el('td', {}, el('span', { class: `outcome ${r.action}` }, r.action))),
    ),
  );
  const counts = {};
  for (const r of queueRows.values()) counts[r.action] = (counts[r.action] || 0) + 1;
  queueCard.querySelector('.counts').textContent = Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(' · ');
  $('log').append(queueCard);
}

function describeTool(name, input = {}) {
  switch (name) {
    case 'get_page_snapshot': return 'reading the page';
    case 'find_text': return `searching for "${input.query}"`;
    case 'click':
    case 'click_at': return input.purpose || input.ref || '';
    case 'screenshot': return 'looking at the page';
    case 'press_key': return input.key === ' ' ? 'Space' : input.key;
    case 'list_tabs': return 'checking session tabs';
    case 'wiki_search': return input.title || input.text || '';
    case 'wiki_get_page': return `page ${input.page_id}`;
    case 'wiki_create_page': return input.title || '';
    case 'wiki_update_page': return input.change_summary || `page ${input.page_id}`;
    case 'wiki_append_table_row': return `page ${input.page_id}`;
    case 'wiki_sort_children':
    case 'wiki_list_children': return `under ${input.parent_id}`;
    case 'record_case': return `${input.alert_id}: ${input.action}`;
    case 'get_case_history': return `last ${input.days || 7} days`;
    case 'type_text': return input.submit ? 'typing and submitting' : 'typing';
    case 'navigate':
    case 'open_tab': return input.url;
    case 'lookup_ioc': return input.ioc;
    case 'search_playbooks': return input.query;
    case 'propose_memory': return 'proposing an environment fact';
    case 'draft_playbook': return 'validating playbook draft';
    default: return '';
  }
}

function setBusy(b) {
  $('send').classList.toggle('hidden', b);
  $('stop').classList.toggle('hidden', !b);
  document.querySelectorAll('#actions button').forEach((x) => (x.disabled = b));
}

async function apiKey() {
  const area = settings.sessionOnlyKey ? chromeStorage('session') : storage;
  return area.get(KEYS.apiKey, '');
}

async function ensureSession() {
  if (session) return session;
  const key = await apiKey();
  if (!key) {
    const n = notice('Add your model API key in Settings to start. ');
    n.append(el('button', { onclick: () => chrome.runtime.openOptionsPage() }, 'Open settings'));
    return null;
  }
  const provider = getProvider(settings.provider, { apiKey: key, model: settings.model });
  session = createSession({
    provider,
    browser,
    settings,
    memory,
    library,
    cases,
    audit,
    knowledge,
    approve,
    proposeMemory,
    presentPlaybook,
    onEvent,
    customTemplate: (await storage.get(KEYS.customTemplate, null)) || null,
  });
  return session;
}

async function send(text, mode = 'chat', untrusted = null) {
  text = text.trim();
  if (!text) return;
  const s = await ensureSession();
  if (!s) return;
  if (s.busy) return;
  append(el('div', { class: 'msg user' }, text));
  setBusy(true);
  await s.send(text, { mode, untrustedContext: untrusted, targetTabId });
}

$('send').addEventListener('click', () => {
  const t = $('input').value;
  $('input').value = '';
  send(t, 'chat');
});
$('input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    $('send').click();
  }
});
$('stop').addEventListener('click', () => session?.stop());
$('newChat').addEventListener('click', () => {
  if (session?.busy) return;
  session = null;
  $('log').replaceChildren(el('div', { class: 'notice' }, 'New conversation. Environment memory and playbooks carry over.'));
});
$('openOptions').addEventListener('click', () => chrome.runtime.openOptionsPage());

$('actInvestigate').addEventListener('click', async () => {
  // Investigating the page you're looking at puts it in the session (asking for site access in the same click).
  if (current && !current.inSession && /^https?:/.test(current.tab.url || '')) await addTabToSession(current.tab.id, current.missing);
  if (current) targetTabId = current.tab.id;
  renderSession();
  send('Investigate the alert or incident on my current tab.', 'investigate');
});
$('actSetup').addEventListener('click', () => send('Let\'s set up my environment. Interview me.', 'setup'));
$('actQueue').addEventListener('click', async () => {
  if (current && !current.inSession && /^https?:/.test(current.tab.url || '')) await addTabToSession(current.tab.id, current.missing);
  if (current) targetTabId = current.tab.id;
  renderSession();
  send('Work the alert queue on my current tab.', 'queue');
});
$('actSummary').addEventListener('click', () => send('Summarise my cases from the last 7 days.', 'summary'));
$('actPlaybook').addEventListener('click', () => send('Draft an IR playbook for this detection. Check the library for an existing one first.', 'playbook'));
$('actSelection').addEventListener('click', () => {
  if (!pendingSelection) return;
  const sel = pendingSelection;
  pendingSelection = null;
  chrome.storage.session.remove('ot.pendingSelection');
  $('actSelection').classList.add('hidden');
  send('Investigate the text I selected on the page.', 'investigate', { text: sel.text, wrapped: wrapUntrusted(sel.text, { source: sel.url, kind: 'analyst selection' }) });
});

async function checkSelection() {
  const { 'ot.pendingSelection': sel } = await chrome.storage.session.get('ot.pendingSelection');
  if (sel && Date.now() - sel.at < 10 * 60 * 1000) {
    pendingSelection = sel;
    $('selectionPreview').textContent = sel.text.slice(0, 60) + (sel.text.length > 60 ? '…' : '');
    $('actSelection').classList.remove('hidden');
  }
}

async function refreshMemoryPill() {
  const n = (await memory.all()).length;
  $('memoryPill').textContent = `${n} fact${n === 1 ? '' : 's'}`;
}

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'local' && changes[KEYS.settings]) {
    const next = await loadSettings(storage);
    Object.assign(settings, next); // the live session reads this object
    refreshSession();
  }
  if (area === 'local' && changes[KEYS.memory]) refreshMemoryPill();
  if ((changes[KEYS.apiKey] || changes[KEYS.apiKey + '.changed'] || changes[KEYS.customTemplate]) && !session?.busy) session = null;
  if (area === 'session' && changes['ot.pendingSelection']) checkSelection();
});

(async function init() {
  settings = await loadSettings(storage);
  await renderSession();
  await refreshMemoryPill();
  await checkSelection();
  if (!(await apiKey())) {
    const n = notice('Welcome. Add your model API key in Settings to get started. ');
    n.append(el('button', { onclick: () => chrome.runtime.openOptionsPage() }, 'Open settings'));
  } else if (!(await memory.all()).length) {
    notice('Tip: run "Set up environment" once so OpenTriage learns how your organisation works. You can also import a team environment file in Settings.');
  }
})();
