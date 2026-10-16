import { chromeStorage, KEYS } from '../lib/storage.js';
import { loadSettings, saveSettings, DEFAULT_SETTINGS } from '../lib/settings.js';
import { createAudit } from '../lib/audit.js';
import { createMemory, CATEGORIES } from '../memory/memory.js';
import { createLibrary } from '../playbooks/library.js';
import { createCases } from '../cases/cases.js';
import { validatePlaybook } from '../playbooks/validator.js';
import { blankPlaybook, SECTIONS } from '../playbooks/template.js';
import { toHtml } from '../playbooks/render.js';
import { createKnowledge, extensionReader } from '../knowledge/loader.js';
import { PROVIDERS, getProvider } from '../providers/index.js';

const $ = (id) => document.getElementById(id);
const storage = chromeStorage('local');
const audit = createAudit(storage);
const memory = createMemory(storage, audit);
const library = createLibrary(storage, audit);
const cases = createCases(storage, audit);
const knowledge = createKnowledge(extensionReader());
let settings;
let editingId = null;

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

function toast(text) {
  const t = el('div', { class: 'toast' }, text);
  document.body.append(t);
  setTimeout(() => t.remove(), 2200);
}

function download(name, text, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
const today = () => new Date().toISOString().slice(0, 10);

// ---------- tabs ----------
$('tabs').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-tab]');
  if (!b) return;
  document.querySelectorAll('#tabs button').forEach((x) => x.classList.toggle('active', x === b));
  document.querySelectorAll('[data-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== b.dataset.tab));
  const fn = { cases: renderCases, safety: renderOrigins, environment: renderMemory, playbooks: renderPlaybooks, audit: renderAudit, enrichment: renderSources, profiles: renderProfiles }[b.dataset.tab];
  fn?.();
});

// ---------- general ----------
function keyArea() {
  return $('sessionOnlyKey').checked ? chromeStorage('session') : storage;
}

function renderModels() {
  const p = PROVIDERS[$('provider').value];
  $('model').replaceChildren(...p.models.map((m) => el('option', { value: m.id, selected: m.id === settings.model }, m.name)));
  $('keyHint').replaceChildren('Format ', el('code', {}, p.keyHint), '. Create one at ', el('a', { href: p.keyUrl, target: '_blank', rel: 'noopener' }, p.keyUrl));
}

async function loadGeneral() {
  $('provider').replaceChildren(...Object.values(PROVIDERS).map((p) => el('option', { value: p.id, selected: p.id === settings.provider }, p.name)));
  renderModels();
  $('sessionOnlyKey').checked = !!settings.sessionOnlyKey;
  $('apiKey').value = (await keyArea().get(KEYS.apiKey, '')) || '';
  $('maxSteps').value = settings.maxSteps;
}

$('provider').addEventListener('change', renderModels);
$('saveGeneral').addEventListener('click', async () => {
  const sessionOnly = $('sessionOnlyKey').checked;
  const key = $('apiKey').value.trim();
  // Keep the key in exactly one place.
  await storage.remove(KEYS.apiKey);
  await chromeStorage('session').remove(KEYS.apiKey);
  if (key) await (sessionOnly ? chromeStorage('session') : storage).set(KEYS.apiKey, key);
  settings = await saveSettings(storage, {
    provider: $('provider').value,
    model: $('model').value,
    sessionOnlyKey: sessionOnly,
    maxSteps: Math.max(5, Math.min(150, Number($('maxSteps').value) || DEFAULT_SETTINGS.maxSteps)),
  });
  // Nudge open side panels to rebuild their session with the new key.
  await storage.set(KEYS.apiKey + '.changed', Date.now());
  toast('Saved');
});

$('testKey').addEventListener('click', async () => {
  const btn = $('testKey');
  btn.disabled = true;
  btn.textContent = 'Testing…';
  try {
    const p = getProvider($('provider').value, { apiKey: $('apiKey').value.trim(), model: $('model').value });
    const r = await p.complete({ system: 'Reply with the single word OK.', messages: [{ role: 'user', content: 'ping' }], tools: [], maxTokens: 10 });
    toast(r.content.some((b) => b.type === 'text') ? 'Connection works' : 'Unexpected response');
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test connection';
  }
});

// ---------- safety ----------
async function loadSafety() {
  $('approvalMode').value = settings.approvalMode;
  $('maskEmails').checked = !!settings.maskEmails;
  const hasDebugger = !!chrome.debugger;
  $('inputMode').value = hasDebugger ? settings.inputMode : 'simulated';
  $('inputMode').querySelector('option[value=trusted]').disabled = !hasDebugger;
  $('inputModeHint').textContent = hasDebugger
    ? 'Trusted mode works with consoles that ignore simulated clicks. While OpenTriage is acting, Chrome shows a "started debugging this browser" bar; it detaches when each turn ends.'
    : 'Trusted mode needs the "trusted input" build of OpenTriage (it adds Chrome\'s debugger permission, which Chrome does not allow to be optional). See the README.';
  renderInternal();
}
$('saveInput').addEventListener('click', async () => {
  settings = await saveSettings(storage, { inputMode: $('inputMode').value });
  await audit.log({ type: 'settings.inputMode', mode: settings.inputMode });
  toast('Saved');
});
function renderInternal() {
  const list = settings.internalOrigins || [];
  $('internalList').replaceChildren(
    ...(list.length
      ? list.map((o) =>
          el('div', { class: 'item' }, el('code', {}, o), el('div', { class: 'btns' }, el('button', {
            class: 'danger',
            onclick: async () => {
              settings = await saveSettings(storage, { internalOrigins: (settings.internalOrigins || []).filter((x) => x !== o) });
              renderInternal();
            },
          }, 'Remove'))),
        )
      : [el('div', { class: 'muted' }, 'None yet.')]),
  );
}

async function renderCases() {
  const list = (await cases.all()).slice().reverse();
  $('casesCount').textContent = `${list.length} case${list.length === 1 ? '' : 's'}`;
  $('casesTable').querySelector('tbody').replaceChildren(
    ...list.slice(0, 500).map((c) =>
      el('tr', {}, el('td', {}, c.updatedAt.slice(0, 16).replace('T', ' ')), el('td', {}, c.console), el('td', {}, c.alertId), el('td', {}, c.title), el('td', {}, `${c.verdict}${c.confidence ? ' · ' + c.confidence : ''}`), el('td', {}, c.action), el('td', {}, c.reason)),
    ),
  );
}
$('casesExport').addEventListener('click', async () => download(`opentriage-cases-${today()}.csv`, await cases.toCsv(), 'text/csv'));
$('casesClear').addEventListener('click', async () => {
  if (!confirm('Clear the case history in this browser?')) return;
  await cases.clear();
  renderCases();
});
$('saveSafety').addEventListener('click', async () => {
  settings = await saveSettings(storage, { approvalMode: $('approvalMode').value, maskEmails: $('maskEmails').checked });
  toast('Saved');
});

async function renderScreenshots() {
  const on = await chrome.permissions.contains({ origins: ['<all_urls>'] });
  $('shotStatus').textContent = on ? 'Screenshots are allowed.' : 'Screenshots are off.';
  $('shotToggle').textContent = on ? 'Turn off' : 'Allow screenshots';
  $('shotToggle').className = on ? 'danger' : 'primary';
}
$('shotToggle').addEventListener('click', async () => {
  const on = await chrome.permissions.contains({ origins: ['<all_urls>'] });
  const changed = on ? await chrome.permissions.remove({ origins: ['<all_urls>'] }) : await chrome.permissions.request({ origins: ['<all_urls>'] });
  await audit.log({ type: on ? 'access.screenshots.revoke' : 'access.screenshots', changed });
  renderScreenshots();
  renderOrigins();
});

async function renderOrigins() {
  renderScreenshots();
  const perms = await chrome.permissions.getAll();
  const granted = (perms.origins || []).filter((o) => o !== 'https://api.anthropic.com/*' && o !== '<all_urls>').map((o) => o.replace(/\/\*$/, ''));
  const all = [...new Set([...granted, ...(settings.trustedOrigins || [])])].sort();
  const list = $('origins');
  if (!all.length) return list.replaceChildren(el('div', { class: 'muted' }, 'No sites yet. Use "Grant access to this site" in the side panel.'));
  list.replaceChildren(
    ...all.map((o) =>
      el(
        'div',
        { class: 'item' },
        el('div', {}, el('code', {}, o), el('div', { class: 'meta' }, [granted.includes(o) ? 'can read' : 'no read access', (settings.trustedOrigins || []).includes(o) ? 'trusted for navigation' : ''].filter(Boolean).join(' · '))),
        el('div', { class: 'btns' }, el('button', {
          class: 'danger',
          onclick: async () => {
            await chrome.permissions.remove({ origins: [o + '/*'] });
            settings = await saveSettings(storage, { trustedOrigins: (settings.trustedOrigins || []).filter((x) => x !== o) });
            await audit.log({ type: 'access.revoke', origin: o });
            renderOrigins();
          },
        }, 'Revoke')),
      ),
    ),
  );
}

// ---------- enrichment ----------
const TYPES = ['hash', 'ip', 'domain', 'url'];
function renderSources() {
  $('srcTypes').replaceChildren(...TYPES.map((t) => el('label', { class: 'check', style: 'display:flex;gap:4px' }, el('input', { type: 'checkbox', value: t }), t)));
  $('sources').replaceChildren(
    ...(settings.enrichmentSources || []).map((s, i) =>
      el(
        'div',
        { class: 'item' },
        el('div', {}, el('strong', {}, s.name), ' ', ...(s.types || []).map((t) => el('span', { class: 'tag' }, t)), el('div', { class: 'meta' }, el('code', {}, s.url))),
        el(
          'div',
          { class: 'btns' },
          el('label', { class: 'check', style: 'display:flex;gap:4px;align-items:center' }, el('input', {
            type: 'checkbox',
            checked: s.enabled,
            onchange: async (e) => {
              const next = settings.enrichmentSources.map((x, j) => (j === i ? { ...x, enabled: e.target.checked } : x));
              settings = await saveSettings(storage, { enrichmentSources: next });
              toast(e.target.checked ? `${s.name} enabled` : `${s.name} disabled`);
            },
          }), 'Enabled'),
          el('button', {
            class: 'danger',
            onclick: async () => {
              settings = await saveSettings(storage, { enrichmentSources: settings.enrichmentSources.filter((_, j) => j !== i) });
              renderSources();
            },
          }, 'Remove'),
        ),
      ),
    ),
  );
}
$('addSource').addEventListener('click', async () => {
  const name = $('srcName').value.trim();
  const url = $('srcUrl').value.trim();
  const types = [...$('srcTypes').querySelectorAll('input:checked')].map((i) => i.value);
  if (!name || !/^https:\/\/.+\{ioc\}/.test(url) || !types.length) return toast('Name, an https URL containing {ioc}, and at least one type are required');
  settings = await saveSettings(storage, { enrichmentSources: [...settings.enrichmentSources, { id: slug(name), name, url, types, enabled: true }] });
  $('srcName').value = '';
  $('srcUrl').value = '';
  renderSources();
});

// ---------- environment memory ----------
$('memCat').replaceChildren(...Object.entries(CATEGORIES).map(([k, d]) => el('option', { value: k, title: d }, `${k.replace(/_/g, ' ')} — ${d}`)));

async function renderMemory() {
  const facts = await memory.all();
  const list = $('memList');
  if (!facts.length) return list.replaceChildren(el('div', { class: 'muted' }, 'Nothing learned yet. Run "Set up environment" from the side panel, add facts below, or import a team file.'));
  const groups = {};
  for (const f of facts) (groups[f.category] ||= []).push(f);
  list.replaceChildren(
    ...Object.keys(CATEGORIES)
      .filter((c) => groups[c])
      .flatMap((c) => [
        el('h3', { style: 'margin:10px 0 2px;font-size:13px' }, c.replace(/_/g, ' '), ' ', el('span', { class: 'muted', style: 'font-weight:400' }, `— ${CATEGORIES[c]}`)),
        ...groups[c].map((f) => {
          const text = el('textarea', { rows: 2, 'aria-label': 'Environment fact' });
          text.value = f.fact;
          let saved = f.fact;
          // Save and Cancel appear only once the fact has been edited.
          const save = el('button', { class: 'primary hidden' }, 'Save');
          const cancel = el('button', { class: 'hidden' }, 'Cancel');
          const status = el('span', { class: 'meta' }, `${f.source} · ${f.createdAt.slice(0, 10)}${f.note ? ' · ' + f.note : ''}`);
          const dirty = () => {
            const changed = text.value !== saved;
            save.classList.toggle('hidden', !changed);
            cancel.classList.toggle('hidden', !changed);
          };
          text.addEventListener('input', dirty);
          save.addEventListener('click', async () => {
            const updated = await memory.update(f.id, { fact: text.value });
            saved = updated.fact;
            text.value = saved;
            dirty();
            toast('Saved');
          });
          cancel.addEventListener('click', () => {
            text.value = saved;
            dirty();
          });
          return el(
            'div',
            { class: 'item' },
            el('div', {}, text, el('div', {}, status)),
            el('div', { class: 'btns' }, save, cancel, el('button', { class: 'danger', onclick: async () => { if (confirm('Delete this fact?')) { await memory.remove(f.id); renderMemory(); } } }, 'Delete')),
          );
        }),
      ]),
  );
}
$('memAdd').addEventListener('click', async () => {
  try {
    await memory.add({ fact: $('memFact').value, category: $('memCat').value, source: 'analyst' });
    $('memFact').value = '';
    renderMemory();
  } catch (e) {
    toast(e.message);
  }
});
$('memExport').addEventListener('click', async () => download(`opentriage-environment-${today()}.json`, await memory.exportJson()));
$('memImport').addEventListener('click', () => $('memFile').click());
$('memFile').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    toast(`Imported ${await memory.importJson(await f.text())} facts`);
    renderMemory();
  } catch (err) {
    toast(err.message);
  }
  e.target.value = '';
});
$('memClear').addEventListener('click', async () => {
  if (!confirm('Delete every environment fact in this browser? Export first if you want a copy.')) return;
  await memory.clear();
  renderMemory();
});

// ---------- playbooks ----------
async function renderPlaybooks() {
  const all = await library.all();
  $('pbCount').textContent = `${all.length} playbook${all.length === 1 ? '' : 's'}`;
  $('pbList').replaceChildren(
    ...(all.length
      ? all.map((p) =>
          el(
            'div',
            { class: 'item' },
            el(
              'div',
              {},
              el('strong', {}, p.title),
              el(
                'div',
                { class: 'meta' },
                [p.format === 'structured' ? 'built-in template' : 'custom template', p.playbook?.determination?.classification, p.playbook?.nextReviewDue ? `review due ${p.playbook.nextReviewDue}` : '', `updated ${p.updatedAt.slice(0, 10)}`].filter(Boolean).join(' · '),
              ),
            ),
            el(
              'div',
              { class: 'btns' },
              p.format === 'structured' ? el('button', { onclick: () => openEditor(p) }, 'Edit') : null,
              el('button', { onclick: () => download(`${slug(p.title)}.md`, p.markdown, 'text/markdown') }, '.md'),
              p.playbook ? el('button', { onclick: () => download(`${slug(p.title)}.html`, toHtml(p.playbook), 'text/html') }, '.html') : null,
              el('button', { class: 'danger', onclick: async () => { if (confirm(`Delete "${p.title}"?`)) { await library.remove(p.id); renderPlaybooks(); } } }, 'Delete'),
            ),
          ),
        )
      : [el('div', { class: 'muted' }, 'No playbooks yet. After an investigation, choose "Draft a playbook" in the side panel.')]),
  );
  const cov = await library.coverage();
  $('coverage').replaceChildren(
    ...(Object.keys(cov).length
      ? Object.entries(cov)
          .sort()
          .map(([t, titles]) => el('div', { class: 'item' }, el('div', {}, el('strong', {}, t), el('div', { class: 'meta' }, titles.join(' · '))), el('span', { class: 'tag' }, String(titles.length))))
      : [el('div', { class: 'muted' }, 'Coverage appears once structured playbooks are saved.')]),
  );
  $('customTemplate').value = (await storage.get(KEYS.customTemplate, '')) || '';
}

function openEditor(entry) {
  editingId = entry?.id || null;
  $('pbEditor').value = JSON.stringify(entry?.playbook || blankPlaybook(today()), null, 2);
  $('pbIssues').replaceChildren();
  $('pbEditorSection').classList.remove('hidden');
  $('pbEditorSection').scrollIntoView({ behavior: 'smooth' });
}

async function runValidation() {
  let pb;
  try {
    pb = JSON.parse($('pbEditor').value);
  } catch (e) {
    $('pbIssues').replaceChildren(el('li', {}, `Not valid JSON: ${e.message}`));
    return null;
  }
  const existing = (await library.all()).filter((p) => p.id !== editingId);
  const r = validatePlaybook(pb, { today: today(), existing });
  $('pbIssues').replaceChildren(
    ...r.errors.map((e) => el('li', {}, `${e.field}: ${e.message}`)),
    ...r.warnings.map((w) => el('li', { class: 'warn' }, `${w.field}: ${w.message}`)),
    ...(r.ok && !r.warnings.length ? [el('li', { style: 'color:var(--ok)' }, 'Passes validation')] : []),
  );
  return r.ok ? pb : null;
}

$('pbNew').addEventListener('click', () => openEditor(null));
$('pbCancel').addEventListener('click', () => $('pbEditorSection').classList.add('hidden'));
$('pbValidate').addEventListener('click', runValidation);
$('pbSave').addEventListener('click', async () => {
  const pb = await runValidation();
  if (!pb) return toast('Fix the errors first');
  await library.save({ playbook: pb, id: editingId });
  $('pbEditorSection').classList.add('hidden');
  toast('Saved');
  renderPlaybooks();
});
$('pbExport').addEventListener('click', async () => download(`opentriage-playbooks-${today()}.json`, await library.exportJson()));
$('pbImport').addEventListener('click', () => $('pbFile').click());
$('pbFile').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    toast(`Imported ${await library.importJson(await f.text())} playbooks`);
    renderPlaybooks();
  } catch (err) {
    toast(err.message);
  }
  e.target.value = '';
});
$('saveTemplate').addEventListener('click', async () => {
  const t = $('customTemplate').value.trim();
  if (!t) return toast('Paste a template, or choose "Use built-in template"');
  if (!/^#{1,3}\s/m.test(t)) return toast('The template needs Markdown headings (#, ##, ###)');
  await storage.set(KEYS.customTemplate, t);
  await audit.log({ type: 'template.set', chars: t.length });
  toast('Template saved. New conversations will use it.');
});
$('clearTemplate').addEventListener('click', async () => {
  await storage.remove(KEYS.customTemplate);
  $('customTemplate').value = '';
  await audit.log({ type: 'template.clear' });
  toast('Using the built-in template');
});
$('downloadBuiltin').addEventListener('click', () => {
  const md = [
    '# <Detection name>',
    '',
    ...SECTIONS.flatMap((s) => [`## ${s.n}. ${s.title}`, ...(s.subsections || []).map((sub, i) => `### ${s.n}.${i + 1} ${sub}`), '']),
  ].join('\n');
  download('opentriage-playbook-template.md', md, 'text/markdown');
});

// ---------- profiles ----------
async function renderProfiles() {
  const profiles = await knowledge.listProfiles();
  $('profiles').replaceChildren(
    ...profiles.map((p) =>
      el(
        'div',
        { class: 'item' },
        el('div', {}, el('strong', {}, p.name), el('div', { class: 'meta' }, (p.hosts || []).map((h) => h.replace(/\\\./g, '.').replace(/[\^$]/g, '')).join(' · ') || 'matched by page title')),
        el('label', { class: 'check', style: 'display:flex;gap:4px;align-items:center' }, el('input', {
          type: 'checkbox',
          checked: !(settings.disabledProfiles || []).includes(p.id),
          onchange: async (e) => {
            const set = new Set(settings.disabledProfiles || []);
            e.target.checked ? set.delete(p.id) : set.add(p.id);
            settings = await saveSettings(storage, { disabledProfiles: [...set] });
          },
        }), 'Enabled'),
      ),
    ),
  );
}

// ---------- audit ----------
async function renderAudit() {
  const log = await audit.list();
  $('auditLog').textContent = log.length ? log.slice().reverse().map((l) => JSON.stringify(l)).join('\n') : 'No entries yet.';
}
$('auditExport').addEventListener('click', async () => download(`opentriage-audit-${today()}.json`, JSON.stringify(await audit.list(), null, 2)));
$('auditClear').addEventListener('click', async () => {
  if (!confirm('Clear the audit log?')) return;
  await audit.clear();
  renderAudit();
});

(async function init() {
  settings = await loadSettings(storage);
  $('version').textContent = 'v' + chrome.runtime.getManifest().version;
  await loadGeneral();
  await loadSafety();
  const openHashTab = () => {
    const tab = location.hash.slice(1);
    if (tab) document.querySelector(`#tabs button[data-tab="${tab}"]`)?.click();
  };
  window.addEventListener('hashchange', openHashTab);
  openHashTab();
})();
