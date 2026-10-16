// Render structured playbooks to Markdown (GitHub, wikis, tickets) and to
// standalone HTML (pastes cleanly into Confluence, SharePoint, Notion, Word).

import { SECTIONS, playbookTitle } from './template.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
const fence = (s, lang = '') => {
  const body = String(s ?? '').replace(/```/g, "'''");
  return '```' + lang + '\n' + body + '\n```';
};

function mdTable(headers, rows) {
  if (!rows.length) return '_None recorded._';
  return [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`)].join('\n');
}

export function toMarkdown(pb) {
  const f = pb.findings || {};
  const s = (n) => `${n}. ${SECTIONS[n - 1].title}`;
  const out = [];
  out.push(`# ${playbookTitle(pb)}`);
  out.push('', `## ${s(1)}`, '');
  out.push(
    mdTable(
      ['Field', 'Value'],
      [
        ['Detection name', pb.detectionName],
        ...(pb.variant ? [['Variant', pb.variant]] : []),
        ['Platforms', (pb.platforms || []).join(', ')],
        ['Detection source', pb.detectionSource || ''],
        ['OS / scope', pb.osScope || ''],
        ['Default severity', pb.defaultSeverity],
        ['MITRE ATT&CK', (pb.mitre || []).map((m) => `${m.tactic} — ${m.techniqueId} ${m.techniqueName}`).join('<br>')],
        ['Owner', pb.ownerRole || ''],
        ['Next review due', pb.nextReviewDue],
      ],
    ),
  );
  out.push('');
  out.push('**Reference cases**');
  out.push('');
  out.push(mdTable(['Case ID', 'Date', 'Host', 'Outcome'], (pb.referenceCases || []).map((c) => [c.id, c.date, c.host || '', c.outcome])));
  out.push('', `## ${s(2)}`, '', fence(pb.decisionFlow));
  out.push('', `## ${s(3)}`, '');
  out.push('### 3.1 IOCs Identified', '', mdTable(['Type', 'Indicator', 'Context'], (f.iocs || []).map((i) => [i.type, '`' + i.value + '`', i.context || ''])));
  out.push('', '### 3.2 Attack Chain Summary', '', f.attackChain || '');
  out.push('', '### 3.3 Affected Assets', '', mdTable(['Asset', 'Owner role', 'Notes'], (f.affectedAssets || []).map((a) => [a.asset, a.role || '', a.notes || ''])));
  out.push('', '### 3.4 Threat Intel Corroboration', '', f.threatIntel || '');
  out.push('', '### 3.5 Overall Confidence Assessment', '', `**${f.confidence?.level || ''}** — ${f.confidence?.rationale || ''}`);
  if ((f.huntQueries || []).length) {
    out.push('', '### 3.6 Hunting and Validation Queries');
    for (const q of f.huntQueries) out.push('', `**${q.language}**${q.description ? ' — ' + q.description : ''}`, '', fence(q.query, q.language.toLowerCase()));
  }
  out.push('', `## ${s(4)}`, '', mdTable(['Condition', 'Severity'], (pb.severityMatrix || []).map((r) => [r.condition, `**${r.severity}**`])));
  out.push('', `## ${s(5)}`, '');
  out.push(`> **Determination: ${pb.determination?.classification || ''}**`);
  out.push('>');
  out.push(`> ${(pb.determination?.rationale || '').replace(/\n/g, '\n> ')}`);
  if (pb.determination?.closureComment) out.push('', '**Closure comment template**', '', fence(pb.determination.closureComment));
  out.push('', `## ${s(6)}`, '', fence(pb.responseFlow));
  out.push('', `## ${s(7)}`, '');
  if (pb.postIncident?.notes) out.push(pb.postIncident.notes, '');
  if (pb.postIncident?.tuning) out.push(`**Tuning recommendation:** ${pb.postIncident.tuning}`, '');
  if (!pb.postIncident?.notes && !pb.postIncident?.tuning) out.push('_None yet._', '');
  out.push(`## ${s(8)}`, '', mdTable(['Date', 'Reviewer role', 'Change'], (pb.reviewHistory || []).map((r) => [r.date, r.reviewerRole || '', r.change])));
  out.push('', `**Next review due:** ${pb.nextReviewDue}`);
  if ((pb.related || []).length) out.push('', `**Related playbooks:** ${pb.related.join(', ')}`);
  out.push('');
  return out.join('\n');
}

function htmlTable(headers, rows) {
  if (!rows.length) return '<p><em>None recorded.</em></p>';
  return `<table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

const SEV_COLOR = { Critical: '#7a0b0b', High: '#c62828', Medium: '#b26a00', Low: '#1565c0', Informational: '#546e7a' };
const badge = (sev) => `<span style="display:inline-block;padding:1px 8px;border-radius:3px;background:${SEV_COLOR[sev] || '#546e7a'};color:#fff;font-weight:600;font-size:12px">${esc(sev)}</span>`;

export function toHtml(pb) {
  const f = pb.findings || {};
  const h = (n) => `${n}. ${esc(SECTIONS[n - 1].title)}`;
  const pre = (s) => `<pre><code>${esc(s)}</code></pre>`;
  const parts = [];
  parts.push(`<h1>${esc(playbookTitle(pb))}</h1>`);
  parts.push(`<h2>${h(1)}</h2>`);
  parts.push(
    htmlTable(
      ['Field', 'Value'],
      [
        ['Detection name', esc(pb.detectionName)],
        ...(pb.variant ? [['Variant', esc(pb.variant)]] : []),
        ['Platforms', esc((pb.platforms || []).join(', '))],
        ['Detection source', esc(pb.detectionSource || '')],
        ['OS / scope', esc(pb.osScope || '')],
        ['Default severity', badge(pb.defaultSeverity)],
        ['MITRE ATT&CK', (pb.mitre || []).map((m) => `${esc(m.tactic)} — <a href="https://attack.mitre.org/techniques/${esc(m.techniqueId.replace('.', '/'))}/">${esc(m.techniqueId)}</a> ${esc(m.techniqueName)}`).join('<br>')],
        ['Owner', esc(pb.ownerRole || '')],
        ['Next review due', esc(pb.nextReviewDue)],
      ].map(([k, v]) => [esc(k), v]),
    ),
  );
  parts.push('<h3>Reference cases</h3>');
  parts.push(htmlTable(['Case ID', 'Date', 'Host', 'Outcome'], (pb.referenceCases || []).map((c) => [esc(c.id), esc(c.date), esc(c.host || ''), esc(c.outcome)])));
  parts.push(`<h2>${h(2)}</h2>${pre(pb.decisionFlow)}`);
  parts.push(`<h2>${h(3)}</h2>`);
  parts.push('<h3>3.1 IOCs Identified</h3>' + htmlTable(['Type', 'Indicator', 'Context'], (f.iocs || []).map((i) => [esc(i.type), `<code>${esc(i.value)}</code>`, esc(i.context || '')])));
  parts.push(`<h3>3.2 Attack Chain Summary</h3><p>${esc(f.attackChain || '').replace(/\n/g, '<br>')}</p>`);
  parts.push('<h3>3.3 Affected Assets</h3>' + htmlTable(['Asset', 'Owner role', 'Notes'], (f.affectedAssets || []).map((a) => [esc(a.asset), esc(a.role || ''), esc(a.notes || '')])));
  parts.push(`<h3>3.4 Threat Intel Corroboration</h3><p>${esc(f.threatIntel || '').replace(/\n/g, '<br>')}</p>`);
  parts.push(`<h3>3.5 Overall Confidence Assessment</h3><p>${badge(f.confidence?.level || '')} ${esc(f.confidence?.rationale || '')}</p>`);
  if ((f.huntQueries || []).length) {
    parts.push('<h3>3.6 Hunting and Validation Queries</h3>');
    for (const q of f.huntQueries) parts.push(`<p><strong>${esc(q.language)}</strong>${q.description ? ' — ' + esc(q.description) : ''}</p>${pre(q.query)}`);
  }
  parts.push(`<h2>${h(4)}</h2>` + htmlTable(['Condition', 'Severity'], (pb.severityMatrix || []).map((r) => [esc(r.condition), badge(r.severity)])));
  parts.push(
    `<h2>${h(5)}</h2><div style="border-left:4px solid #1565c0;background:#e8f0fe;padding:8px 12px;margin:8px 0"><p><strong>Determination: ${esc(pb.determination?.classification || '')}</strong></p><p>${esc(pb.determination?.rationale || '').replace(/\n/g, '<br>')}</p></div>`,
  );
  if (pb.determination?.closureComment) parts.push(`<p><strong>Closure comment template</strong></p>${pre(pb.determination.closureComment)}`);
  parts.push(`<h2>${h(6)}</h2>${pre(pb.responseFlow)}`);
  parts.push(`<h2>${h(7)}</h2>`);
  if (pb.postIncident?.notes) parts.push(`<p>${esc(pb.postIncident.notes).replace(/\n/g, '<br>')}</p>`);
  if (pb.postIncident?.tuning) parts.push(`<p><strong>Tuning recommendation:</strong> ${esc(pb.postIncident.tuning)}</p>`);
  if (!pb.postIncident?.notes && !pb.postIncident?.tuning) parts.push('<p><em>None yet.</em></p>');
  parts.push(`<h2>${h(8)}</h2>` + htmlTable(['Date', 'Reviewer role', 'Change'], (pb.reviewHistory || []).map((r) => [esc(r.date), esc(r.reviewerRole || ''), esc(r.change)])));
  parts.push(`<p><strong>Next review due:</strong> ${esc(pb.nextReviewDue)}</p>`);
  if ((pb.related || []).length) parts.push(`<p><strong>Related playbooks:</strong> ${esc(pb.related.join(', '))}</p>`);

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(playbookTitle(pb))}</title><style>body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1f2328}table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f6f8fa}pre{background:#f6f8fa;padding:10px;border-radius:4px;overflow:auto}code{font:12px/1.4 ui-monospace,Consolas,monospace}</style></head><body>${parts.join('\n')}</body></html>`;
}
