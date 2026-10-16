// Playbook quality checks. The agent sees these results and must fix every
// error before a playbook can be saved; the analyst sees them on the draft card.

import { CLASSIFICATIONS, SEVERITIES, CONFIDENCE } from './template.js';
import { isDefanged } from '../lib/ioc.js';

const PLACEHOLDER = /\[(?:insert|add|tbd|todo|placeholder|name|hostname|date|fill|xxx|your)[^\]]*\]|\bTBD\b|\bTODO\b|\bworking title\b|\bnot captured\b|\bconfirm hostname\b|\blorem ipsum\b|<\s*(?:insert|placeholder)[^>]*>/i;
// Usernames inside paths. "[account]" is the accepted redaction.
const USER_PATH = /(?:[A-Za-z]:\\Users\\(?!\[account\]|Public\\|Default\\|All Users\\)[^\\\s"']+|\/Users\/(?!\[account\]|Shared\/)[^/\s"']+|\/home\/(?!\[account\])[^/\s"']+|\\\\Users\\(?!\[account\])[^\\\s]+)/;
const SHORT_NAME = /\b[A-Z]{2,6}~\d\b/; // 8.3 short names leak usernames too
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const RELATIVE_DATE = /\b(?:in|after|within)\s+\d+\s+(?:day|week|month)s?\b|\+\d+\s*d(?:ays?)?\b|\bnext (?:week|month|quarter)\b/i;
const TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;

function walkStrings(obj, path = '', out = []) {
  if (typeof obj === 'string') out.push([path, obj]);
  else if (Array.isArray(obj)) obj.forEach((v, i) => walkStrings(v, `${path}[${i}]`, out));
  else if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) walkStrings(v, path ? `${path}.${k}` : k, out);
  return out;
}

function validDate(s) {
  return ISO_DATE.test(s) && !Number.isNaN(Date.parse(s));
}

/**
 * Validate a structured playbook.
 * @returns {{ok: boolean, errors: Array, warnings: Array}}
 */
export function validatePlaybook(pb, { today = new Date().toISOString().slice(0, 10), existing = [] } = {}) {
  const errors = [];
  const warnings = [];
  const err = (field, message) => errors.push({ field, message });
  const warn = (field, message) => warnings.push({ field, message });

  if (!pb || typeof pb !== 'object') return { ok: false, errors: [{ field: '', message: 'Playbook is empty' }], warnings };

  // Section 1 — metadata
  if (!pb.detectionName || pb.detectionName.trim().length < 3) err('detectionName', 'Detection name is required. Use the exact rule/model name the console shows.');
  if (pb.detectionName && /^(trojan|pua|hacktool|backdoor|ransom|worm|riskware|adware)[.:/]/i.test(pb.detectionName)) {
    err('detectionName', 'This looks like a malware/signature name, not a detection rule name. Key the playbook on the detection that raised the alert.');
  }
  if (!Array.isArray(pb.platforms) || !pb.platforms.length) err('platforms', 'List at least one console where this detection appears.');
  if (!Array.isArray(pb.mitre) || !pb.mitre.length) err('mitre', 'Map at least one MITRE ATT&CK technique.');
  (pb.mitre || []).forEach((m, i) => {
    if (!TECHNIQUE.test(m.techniqueId || '')) err(`mitre[${i}].techniqueId`, `"${m.techniqueId}" is not a technique ID like T1059 or T1059.001.`);
    if (!m.tactic) err(`mitre[${i}].tactic`, 'Tactic is required.');
  });
  if (!SEVERITIES.includes(pb.defaultSeverity)) err('defaultSeverity', `Severity must be one of ${SEVERITIES.join(', ')}.`);
  if (!Array.isArray(pb.referenceCases) || !pb.referenceCases.length) err('referenceCases', 'Add at least one reference case (incident or alert ID, date, outcome) from the records.');
  (pb.referenceCases || []).forEach((c, i) => {
    if (!c.id) err(`referenceCases[${i}].id`, 'Case ID is required.');
    if (!validDate(c.date || '')) err(`referenceCases[${i}].date`, 'Case date must be YYYY-MM-DD.');
    if (!CLASSIFICATIONS.includes(c.outcome)) err(`referenceCases[${i}].outcome`, `Outcome must be one of ${CLASSIFICATIONS.join(', ')}.`);
  });
  if (pb.ownerRole && /^[A-Z][a-z]+ [A-Z][a-z]+$/.test(pb.ownerRole.trim())) warn('ownerRole', 'Owner looks like a person\'s name. Use a team or role.');

  // Sections 2 and 6 — flows
  if (!pb.decisionFlow || pb.decisionFlow.trim().split('\n').length < 3) err('decisionFlow', 'Decision flow needs at least three lines of branching logic.');
  if (pb.decisionFlow && !CLASSIFICATIONS.some((c) => pb.decisionFlow.includes(c))) warn('decisionFlow', 'Decision branches should end in a classification (True Positive, Benign True Positive, False Positive).');
  if (!pb.responseFlow || pb.responseFlow.trim().split('\n').length < 3) err('responseFlow', 'Response flow needs at least three steps.');

  // Section 3 — findings
  const f = pb.findings || {};
  if (!Array.isArray(f.iocs)) err('findings.iocs', 'IOC list is required (use an empty list only if the detection has no indicators).');
  (f.iocs || []).forEach((ioc, i) => {
    if (['ip', 'domain', 'url', 'email'].includes(ioc.type) && !isDefanged(ioc.value || '')) {
      err(`findings.iocs[${i}].value`, `Defang ${ioc.type} indicators (hxxp, [.], [@]): ${ioc.value}`);
    }
  });
  if (!f.attackChain || f.attackChain.trim().length < 40) err('findings.attackChain', 'Attack chain summary is missing or too short.');
  if (!Array.isArray(f.affectedAssets) || !f.affectedAssets.length) err('findings.affectedAssets', 'List the affected asset(s) by hostname, with the owner described by role.');
  if (!f.threatIntel) err('findings.threatIntel', 'Record threat-intel corroboration, or state that none was found and where you looked.');
  if (!f.confidence || !CONFIDENCE.includes(f.confidence.level)) err('findings.confidence.level', `Confidence must be ${CONFIDENCE.join(', ')}.`);
  if (f.confidence && !f.confidence.rationale) err('findings.confidence.rationale', 'Explain the confidence level.');

  // Section 4 — severity matrix
  if (!Array.isArray(pb.severityMatrix) || pb.severityMatrix.length < 2) err('severityMatrix', 'Severity matrix needs at least two rows (conditions that raise or lower severity).');
  (pb.severityMatrix || []).forEach((r, i) => {
    if (!SEVERITIES.includes(r.severity)) err(`severityMatrix[${i}].severity`, `Severity must be one of ${SEVERITIES.join(', ')}.`);
  });

  // Section 5 — determination
  const d = pb.determination || {};
  if (!CLASSIFICATIONS.includes(d.classification)) err('determination.classification', `Classification must be one of ${CLASSIFICATIONS.join(', ')}.`);
  if (!d.rationale || d.rationale.trim().length < 30) err('determination.rationale', 'Explain why — the evidence that supports the classification.');

  // Section 7 — post-incident
  if (!pb.postIncident || (!pb.postIncident.notes && !pb.postIncident.tuning)) warn('postIncident', 'Add post-incident notes or a tuning recommendation.');

  // Section 8 — review history
  if (!Array.isArray(pb.reviewHistory) || !pb.reviewHistory.length) err('reviewHistory', 'Add at least one review history row.');
  (pb.reviewHistory || []).forEach((r, i) => {
    if (!validDate(r.date || '')) err(`reviewHistory[${i}].date`, 'Review dates must be YYYY-MM-DD.');
  });
  if (!validDate(pb.nextReviewDue || '')) err('nextReviewDue', 'Next review due must be an absolute date YYYY-MM-DD, not an offset.');
  else if (pb.nextReviewDue <= today) warn('nextReviewDue', 'Next review due is not in the future.');

  // Whole-document hygiene
  for (const [path, s] of walkStrings(pb)) {
    if (PLACEHOLDER.test(s)) err(path, `Placeholder text left in: "${s.match(PLACEHOLDER)[0]}". Fill it from records or say exactly what is missing and where it will come from.`);
    if (USER_PATH.test(s)) err(path, `Username in a path: "${s.match(USER_PATH)[0]}". Replace the user folder with [account].`);
    if (SHORT_NAME.test(s)) warn(path, `Possible 8.3 short name ("${s.match(SHORT_NAME)[0]}") — these can expose usernames.`);
    if (EMAIL.test(s) && !/\[@\]/.test(s)) err(path, 'Email address present. Describe people by role; defang sender addresses used as IOCs.');
    if (RELATIVE_DATE.test(s) && /date|due|review/i.test(path)) err(path, 'Use absolute dates (YYYY-MM-DD), not offsets.');
  }

  // Library coverage
  const key = (pb.detectionName || '').trim().toLowerCase();
  const sameDetection = existing.filter((e) => (e.playbook?.detectionName || '').trim().toLowerCase() === key && (e.playbook?.variant || '') === (pb.variant || ''));
  if (key && sameDetection.length && !pb._replacing) {
    warn('detectionName', `A playbook for "${pb.detectionName}"${pb.variant ? ` (${pb.variant})` : ''} already exists. Add a reference case to it, or set "variant" if the decision logic differs.`);
  }

  return { ok: errors.length === 0, errors, warnings };
}

/** Hygiene-only checks for playbooks written in an organisation's own Markdown template. */
export function validateMarkdownPlaybook(md, { requiredHeadings = [] } = {}) {
  const errors = [];
  const warnings = [];
  const lines = String(md || '').split('\n');
  lines.forEach((line, i) => {
    const at = `line ${i + 1}`;
    if (PLACEHOLDER.test(line)) errors.push({ field: at, message: `Placeholder text: "${line.match(PLACEHOLDER)[0]}"` });
    if (USER_PATH.test(line)) errors.push({ field: at, message: `Username in a path: "${line.match(USER_PATH)[0]}"` });
    if (EMAIL.test(line) && !/\[@\]/.test(line)) errors.push({ field: at, message: 'Email address present.' });
  });
  for (const h of requiredHeadings) {
    if (!lines.some((l) => /^#{1,6}\s/.test(l) && l.toLowerCase().includes(h.toLowerCase()))) {
      errors.push({ field: 'structure', message: `Missing heading from the template: "${h}"` });
    }
  }
  if (!/\d{4}-\d{2}-\d{2}/.test(md)) warnings.push({ field: 'dates', message: 'No absolute dates found. Review dates should be YYYY-MM-DD.' });
  return { ok: errors.length === 0, errors, warnings };
}

/** Pull the headings out of an organisation's Markdown template. */
export function templateHeadings(md) {
  return String(md || '')
    .split('\n')
    .filter((l) => /^#{1,3}\s/.test(l))
    .map((l) => l.replace(/^#{1,3}\s+/, '').replace(/^\d+[.)]\s*/, '').trim())
    .filter(Boolean);
}

/** Hygiene-only checks for free text (used for wiki pages): placeholders, usernames in paths, emails. */
export function hygieneCheck(text, { label = 'line' } = {}) {
  const errors = [];
  String(text || '')
    .split('\n')
    .forEach((line, i) => {
      const at = `${label} ${i + 1}`;
      if (PLACEHOLDER.test(line)) errors.push({ field: at, message: `Placeholder text: "${line.match(PLACEHOLDER)[0]}"` });
      if (USER_PATH.test(line)) errors.push({ field: at, message: `Username in a path: "${line.match(USER_PATH)[0]}" — use [account]` });
      if (EMAIL.test(line) && !/\[@\]/.test(line)) errors.push({ field: at, message: 'Email address present — describe people by role, defang sender addresses used as IOCs.' });
    });
  return errors;
}
