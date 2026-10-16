// Confluence storage-format helpers: render playbooks to storage XHTML,
// extract plain text (for hygiene checks and diffs), append table rows, and
// sort keys for page trees. Pure functions — unit-tested in Node.

import { SECTIONS, playbookTitle } from '../playbooks/template.js';

export const escapeXml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);

const cdata = (s) => `<![CDATA[${String(s ?? '').replace(/]]>/g, ']]]]><![CDATA[>')}]]>`;

export function codeMacro(code, language = '') {
  const lang = String(language || '').toLowerCase().replace(/[^a-z0-9#+-]/g, '');
  return `<ac:structured-macro ac:name="code">${lang ? `<ac:parameter ac:name="language">${escapeXml(lang)}</ac:parameter>` : ''}<ac:plain-text-body>${cdata(code)}</ac:plain-text-body></ac:structured-macro>`;
}

const STATUS_COLOUR = { Critical: 'Red', High: 'Red', Medium: 'Yellow', Low: 'Blue', Informational: 'Grey' };
export function statusMacro(title, colour = STATUS_COLOUR[title] || 'Grey') {
  return `<ac:structured-macro ac:name="status"><ac:parameter ac:name="colour">${escapeXml(colour)}</ac:parameter><ac:parameter ac:name="title">${escapeXml(title)}</ac:parameter></ac:structured-macro>`;
}

export function panelMacro(kind, innerStorage) {
  return `<ac:structured-macro ac:name="${kind === 'warning' ? 'warning' : kind === 'info' ? 'info' : 'note'}"><ac:rich-text-body>${innerStorage}</ac:rich-text-body></ac:structured-macro>`;
}

export function pageLink(pageTitle, text = pageTitle) {
  return `<ac:link><ri:page ri:content-title="${escapeXml(pageTitle)}" /><ac:plain-text-link-body>${cdata(text)}</ac:plain-text-link-body></ac:link>`;
}

const p = (s) => `<p>${escapeXml(s).replace(/\n/g, '<br />')}</p>`;

function table(headers, rows) {
  if (!rows.length) return '<p><em>None recorded.</em></p>';
  return `<table><tbody><tr>${headers.map((h) => `<th><p>${escapeXml(h)}</p></th>`).join('')}</tr>${rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;
}

/** Render a structured playbook as Confluence storage format. */
export function toStorage(pb) {
  const f = pb.findings || {};
  const h1 = (n) => `<h1>${n}. ${escapeXml(SECTIONS[n - 1].title)}</h1>`;
  const out = [];
  out.push(h1(1));
  out.push(
    table(
      ['Field', 'Value'],
      [
        ['Detection name', p(pb.detectionName)],
        ...(pb.variant ? [['Variant', p(pb.variant)]] : []),
        ['Platforms', p((pb.platforms || []).join(', '))],
        ['Detection source', p(pb.detectionSource || '')],
        ['OS / scope', p(pb.osScope || '')],
        ['Default severity', `<p>${statusMacro(pb.defaultSeverity)}</p>`],
        ['MITRE ATT&CK', (pb.mitre || []).map((m) => p(`${m.tactic} — ${m.techniqueId} ${m.techniqueName}`)).join('')],
        ['Owner', p(pb.ownerRole || '')],
        ['Next review due', p(pb.nextReviewDue)],
      ].map(([k, v]) => [p(k), v]),
    ),
  );
  out.push('<h2>Reference cases</h2>');
  out.push(table(['Case ID', 'Date', 'Host', 'Outcome'], (pb.referenceCases || []).map((c) => [p(c.id), p(c.date), p(c.host || ''), p(c.outcome)])));
  out.push(h1(2), codeMacro(pb.decisionFlow));
  out.push(h1(3));
  out.push('<h2>IOCs Identified</h2>', table(['Type', 'Indicator', 'Context'], (f.iocs || []).map((i) => [p(i.type), `<p><code>${escapeXml(i.value)}</code></p>`, p(i.context || '')])));
  out.push('<h2>Attack Chain Summary</h2>', p(f.attackChain || ''));
  out.push('<h2>Affected Assets</h2>', table(['Asset', 'Owner role', 'Notes'], (f.affectedAssets || []).map((a) => [p(a.asset), p(a.role || ''), p(a.notes || '')])));
  out.push('<h2>Threat Intel Corroboration</h2>', p(f.threatIntel || ''));
  out.push('<h2>Overall Confidence Assessment</h2>', `<p>${statusMacro(f.confidence?.level || '', { High: 'Green', Medium: 'Yellow', Low: 'Red' }[f.confidence?.level] || 'Grey')} ${escapeXml(f.confidence?.rationale || '')}</p>`);
  if ((f.huntQueries || []).length) {
    out.push('<h2>Hunting and Validation Queries</h2>');
    for (const q of f.huntQueries) out.push(p(`${q.language}${q.description ? ' — ' + q.description : ''}`), codeMacro(q.query, q.language));
  }
  out.push(h1(4), table(['Condition', 'Severity'], (pb.severityMatrix || []).map((r) => [p(r.condition), `<p>${statusMacro(r.severity)}</p>`])));
  out.push(h1(5), panelMacro('note', `<p><strong>Determination: ${escapeXml(pb.determination?.classification || '')}</strong></p>${p(pb.determination?.rationale || '')}`));
  if (pb.determination?.closureComment) out.push('<p><strong>Closure comment template</strong></p>', codeMacro(pb.determination.closureComment));
  out.push(h1(6), codeMacro(pb.responseFlow));
  out.push(h1(7));
  if (pb.postIncident?.notes) out.push(p(pb.postIncident.notes));
  if (pb.postIncident?.tuning) out.push(`<p><strong>Tuning recommendation:</strong> ${escapeXml(pb.postIncident.tuning)}</p>`);
  if (!pb.postIncident?.notes && !pb.postIncident?.tuning) out.push('<p><em>None yet.</em></p>');
  out.push(h1(8), table(['Date', 'Reviewer role', 'Change'], (pb.reviewHistory || []).map((r) => [p(r.date), p(r.reviewerRole || ''), p(r.change)])));
  out.push(`<p><strong>Next review due:</strong> ${escapeXml(pb.nextReviewDue)}</p>`);
  if ((pb.related || []).length) out.push(`<p><strong>Related playbooks:</strong> ${pb.related.map((t) => pageLink(t)).join(', ')}</p>`);
  return out.join('');
}

export function storageTitle(pb) {
  return playbookTitle(pb);
}

/** Minimal Markdown → storage conversion for playbooks written in an organisation's own template. */
export function markdownToStorage(md) {
  const lines = String(md || '').replace(/\r\n/g, '\n').split('\n');
  const out = [];
  let i = 0;
  const inline = (s) =>
    escapeXml(s)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  while (i < lines.length) {
    const line = lines[i];
    const fence = line.match(/^```(\w*)/);
    if (fence) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(codeMacro(buf.join('\n'), fence[1]));
      continue;
    }
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`);
      i++;
      continue;
    }
    if (/^\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const row = (l) => l.trim().replace(/^\||\|$/g, '').split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
      const head = row(line);
      i += 2;
      const body = [];
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) body.push(row(lines[i++]));
      out.push(`<table><tbody><tr>${head.map((c) => `<th><p>${inline(c)}</p></th>`).join('')}</tr>${body.map((r) => `<tr>${r.map((c) => `<td><p>${inline(c)}</p></td>`).join('')}</tr>`).join('')}</tbody></table>`);
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*[-*]\s+/, ''));
      out.push(`<ul>${items.map((t) => `<li><p>${inline(t)}</p></li>`).join('')}</ul>`);
      continue;
    }
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*\d+[.)]\s+/, ''));
      out.push(`<ol>${items.map((t) => `<li><p>${inline(t)}</p></li>`).join('')}</ol>`);
      continue;
    }
    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
      out.push(panelMacro('info', buf.map((b) => `<p>${inline(b)}</p>`).join('')));
      continue;
    }
    if (!line.trim()) {
      i++;
      continue;
    }
    out.push(`<p>${inline(line)}</p>`);
    i++;
  }
  return out.join('');
}

/** Plain text of a storage document, one block per line. Code bodies are kept. */
export function storageToText(storage) {
  return String(storage || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (m, c) => c.replace(/</g, '‹').replace(/>/g, '›'))
    .replace(/<ac:parameter[^>]*ac:name="(colour|language)"[^>]*>[\s\S]*?<\/ac:parameter>/g, '')
    .replace(/<\/p>\s*(<\/t[hd]>)/gi, '$1')
    .replace(/<(br)\s*\/?>/gi, '\n')
    .replace(/<\/(p|h[1-6]|tr|li|th|td|ac:plain-text-body|ac:parameter)>/gi, (m, t) => (/^t[hd]$/i.test(t) ? ' | ' : '\n'))
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;|&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/ \| *\n/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Line diff of two texts (LCS). Returns [{op: '+'|'-'|' ', line}]. */
export function lineDiff(a, b, maxLines = 4000) {
  const x = String(a).split('\n').slice(0, maxLines);
  const y = String(b).split('\n').slice(0, maxLines);
  const n = x.length;
  const m = y.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: ' ', line: x[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ op: '-', line: x[i++] });
    else out.push({ op: '+', line: y[j++] });
  }
  while (i < n) out.push({ op: '-', line: x[i++] });
  while (j < m) out.push({ op: '+', line: y[j++] });
  return out;
}

/** Compact diff summary: changed lines with one line of context, capped. */
export function diffSummary(a, b, { context = 1, max = 60 } = {}) {
  const d = lineDiff(a, b);
  const keep = new Set();
  d.forEach((e, idx) => {
    if (e.op !== ' ') for (let k = idx - context; k <= idx + context; k++) keep.add(k);
  });
  const lines = [];
  let last = -2;
  for (let idx = 0; idx < d.length && lines.length < max; idx++) {
    if (!keep.has(idx)) continue;
    if (idx !== last + 1 && lines.length) lines.push('…');
    lines.push(`${d[idx].op} ${d[idx].line}`);
    last = idx;
  }
  const added = d.filter((e) => e.op === '+').length;
  const removed = d.filter((e) => e.op === '-').length;
  return { text: lines.join('\n'), added, removed };
}

function cellStorage(cell) {
  if (cell && typeof cell === 'object') {
    if (cell.link_page_title) return `<p>${pageLink(cell.link_page_title, cell.text || cell.link_page_title)}</p>`;
    if (cell.status) return `<p>${statusMacro(cell.status, cell.colour)}</p>`;
    return `<p>${escapeXml(cell.text ?? '')}</p>`;
  }
  return `<p>${escapeXml(cell ?? '')}</p>`;
}

/**
 * Append a row to the first table whose header row contains `headerContains`
 * (case-insensitive). Returns { storage, columns } or throws.
 */
export function appendTableRow(storage, headerContains, cells) {
  const src = String(storage || '');
  const re = /<table[\s\S]*?<\/table>/g;
  let m;
  const needle = String(headerContains || '').toLowerCase();
  while ((m = re.exec(src))) {
    const tbl = m[0];
    const firstRow = (tbl.match(/<tr[\s\S]*?<\/tr>/) || [''])[0];
    if (needle && !storageToText(firstRow).toLowerCase().includes(needle)) continue;
    const columns = (firstRow.match(/<t[hd][\s>]/g) || []).length;
    if (cells.length !== columns) throw new Error(`That table has ${columns} columns (${storageToText(firstRow).replace(/\s*\|\s*$/, '')}); you supplied ${cells.length} cells.`);
    const row = `<tr>${cells.map((c) => `<td>${cellStorage(c)}</td>`).join('')}</tr>`;
    const closeIdx = tbl.lastIndexOf('</tbody>') >= 0 ? tbl.lastIndexOf('</tbody>') : tbl.lastIndexOf('</table>');
    const updated = tbl.slice(0, closeIdx) + row + tbl.slice(closeIdx);
    return { storage: src.slice(0, m.index) + updated + src.slice(m.index + tbl.length), columns };
  }
  throw new Error(`No table on the page has a header row containing "${headerContains}".`);
}

/** Sort key for page trees: ignore bracket characters and leading punctuation, case-insensitive. */
export function sortKey(title) {
  return String(title || '')
    .replace(/[[\](){}]/g, '')
    .replace(/^[^A-Za-z0-9]+/, '')
    .trim()
    .toLowerCase();
}

/**
 * Plan the minimal sequence of moves to put `current` (array of {id,title})
 * into sortKey order. Returns { desired, moves: [{id, position: 'before'|'after', targetId}] }.
 */
export function planSort(current) {
  const desired = [...current].sort((a, b) => sortKey(a.title).localeCompare(sortKey(b.title), undefined, { numeric: true, sensitivity: 'base' }) || a.title.localeCompare(b.title));
  const order = current.map((c) => c.id);
  const moves = [];
  const moveTo = (id, idx) => {
    order.splice(order.indexOf(id), 1);
    order.splice(idx, 0, id);
  };
  desired.forEach((d, i) => {
    if (order[i] === d.id) return;
    if (i === 0) {
      moves.push({ id: d.id, position: 'before', targetId: order[0] });
      moveTo(d.id, 0);
    } else {
      moves.push({ id: d.id, position: 'after', targetId: desired[i - 1].id });
      moveTo(d.id, i);
    }
  });
  return { desired, moves };
}

/** Pairs that are out of order (should be empty after a sort). */
export function inversions(list) {
  const bad = [];
  for (let i = 1; i < list.length; i++) {
    if (sortKey(list[i - 1].title).localeCompare(sortKey(list[i].title), undefined, { numeric: true, sensitivity: 'base' }) > 0) bad.push([list[i - 1].title, list[i].title]);
  }
  return bad;
}
