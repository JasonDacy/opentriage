// The built-in IR playbook template.
//
// Eight numbered sections, keyed on the detection (rule / model) name so the
// playbook library works as a coverage map: one detection, one playbook,
// variants cross-linked. Environments that already have their own template
// can load it in Options; see docs/playbook-standard.md.

export const CLASSIFICATIONS = ['True Positive', 'Benign True Positive', 'False Positive', 'Undetermined'];
export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
export const CONFIDENCE = ['High', 'Medium', 'Low'];
export const IOC_TYPES = ['hash', 'ip', 'domain', 'url', 'email', 'file', 'path', 'registry', 'process', 'command', 'other'];

export const SECTIONS = [
  { n: 1, key: 'metadata', title: 'Alert Metadata' },
  { n: 2, key: 'decisionFlow', title: 'Investigation Decision Flow' },
  {
    n: 3,
    key: 'findings',
    title: 'Investigation Findings',
    subsections: ['IOCs Identified', 'Attack Chain Summary', 'Affected Assets', 'Threat Intel Corroboration', 'Overall Confidence Assessment', 'Hunting and Validation Queries'],
  },
  { n: 4, key: 'severityMatrix', title: 'Severity Matrix' },
  { n: 5, key: 'determination', title: 'Analyst Determination' },
  { n: 6, key: 'responseFlow', title: 'Response Steps Flow' },
  { n: 7, key: 'postIncident', title: 'Post-Incident Notes' },
  { n: 8, key: 'reviewHistory', title: 'Review History' },
];

/** JSON Schema given to the model as the draft_playbook tool input. */
export const PLAYBOOK_SCHEMA = {
  type: 'object',
  required: ['detectionName', 'platforms', 'mitre', 'defaultSeverity', 'referenceCases', 'decisionFlow', 'findings', 'severityMatrix', 'determination', 'responseFlow', 'reviewHistory', 'nextReviewDue'],
  properties: {
    detectionName: { type: 'string', description: 'Exact detection / rule / model name as the console shows it. This is the playbook key. Never a malware family name, a filter name or a working title.' },
    variant: { type: 'string', description: 'Optional. Set only when this is a variant of an existing playbook for the same detection with different decision logic, e.g. "macOS, credential access".' },
    platforms: { type: 'array', items: { type: 'string' }, description: 'Consoles where the detection appears, e.g. ["Microsoft Sentinel", "CrowdStrike Falcon"].' },
    detectionSource: { type: 'string', description: 'Product or sensor that raises it (EDR, email gateway, identity, cloud).' },
    osScope: { type: 'string', description: 'Windows, macOS, Linux, cloud, identity, network or mixed.' },
    mitre: {
      type: 'array',
      items: { type: 'object', required: ['tactic', 'techniqueId', 'techniqueName'], properties: { tactic: { type: 'string' }, techniqueId: { type: 'string' }, techniqueName: { type: 'string' } } },
    },
    defaultSeverity: { type: 'string', enum: SEVERITIES },
    referenceCases: {
      type: 'array',
      description: 'Real cases this playbook is built from: incident or alert IDs, dates (YYYY-MM-DD) and outcomes.',
      items: { type: 'object', required: ['id', 'date', 'outcome'], properties: { id: { type: 'string' }, date: { type: 'string' }, outcome: { type: 'string', enum: CLASSIFICATIONS }, host: { type: 'string', description: 'Hostname as recorded in the alert (not a username).' } } },
    },
    ownerRole: { type: 'string', description: 'Owning team or role, never a person\'s name.' },
    decisionFlow: { type: 'string', description: 'Decision tree as plain text (rendered in a code block). Branches end in a classification.' },
    findings: {
      type: 'object',
      required: ['iocs', 'attackChain', 'affectedAssets', 'threatIntel', 'confidence'],
      properties: {
        iocs: { type: 'array', items: { type: 'object', required: ['type', 'value'], properties: { type: { type: 'string', enum: IOC_TYPES }, value: { type: 'string', description: 'Defanged for URLs, domains, IPs and emails.' }, context: { type: 'string' } } } },
        attackChain: { type: 'string' },
        affectedAssets: { type: 'array', items: { type: 'object', required: ['asset'], properties: { asset: { type: 'string' }, role: { type: 'string', description: 'Owner described by role, e.g. "developer workstation".' }, notes: { type: 'string' } } } },
        threatIntel: { type: 'string' },
        confidence: { type: 'object', required: ['level', 'rationale'], properties: { level: { type: 'string', enum: CONFIDENCE }, rationale: { type: 'string' } } },
        huntQueries: { type: 'array', items: { type: 'object', required: ['language', 'query'], properties: { language: { type: 'string', description: 'KQL, SPL, CQL, EQL, SQL, etc.' }, description: { type: 'string' }, query: { type: 'string' } } } },
      },
    },
    severityMatrix: { type: 'array', items: { type: 'object', required: ['condition', 'severity'], properties: { condition: { type: 'string' }, severity: { type: 'string', enum: SEVERITIES } } } },
    determination: {
      type: 'object',
      required: ['classification', 'rationale'],
      properties: { classification: { type: 'string', enum: CLASSIFICATIONS }, rationale: { type: 'string' }, closureComment: { type: 'string', description: 'Template closure comment analysts can reuse.' } },
    },
    responseFlow: { type: 'string', description: 'Response steps as plain text (rendered in a code block), including who to notify and when to escalate.' },
    postIncident: { type: 'object', properties: { notes: { type: 'string' }, tuning: { type: 'string', description: 'Detection tuning recommendation. Rule tuning is the durable fix.' } } },
    reviewHistory: { type: 'array', items: { type: 'object', required: ['date', 'change'], properties: { date: { type: 'string' }, reviewerRole: { type: 'string' }, change: { type: 'string' } } } },
    nextReviewDue: { type: 'string', description: 'Absolute date YYYY-MM-DD, default 90 days after the last review.' },
    related: { type: 'array', items: { type: 'string' }, description: 'Detection names of related playbooks or variants.' },
  },
};

export function playbookTitle(pb) {
  return pb.variant ? `${pb.detectionName} — ${pb.variant}` : pb.detectionName;
}

/** Blank skeleton analysts can fill by hand from the options page. */
export function blankPlaybook(today = new Date().toISOString().slice(0, 10)) {
  const due = new Date(Date.parse(today) + 90 * 86400000).toISOString().slice(0, 10);
  return {
    detectionName: '',
    platforms: [],
    detectionSource: '',
    osScope: '',
    mitre: [],
    defaultSeverity: 'Medium',
    referenceCases: [],
    ownerRole: '',
    decisionFlow: '',
    findings: { iocs: [], attackChain: '', affectedAssets: [], threatIntel: '', confidence: { level: 'Medium', rationale: '' }, huntQueries: [] },
    severityMatrix: [],
    determination: { classification: 'Undetermined', rationale: '', closureComment: '' },
    responseFlow: '',
    postIncident: { notes: '', tuning: '' },
    reviewHistory: [{ date: today, reviewerRole: '', change: 'Created' }],
    nextReviewDue: due,
    related: [],
  };
}
