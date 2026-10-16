// A complete, valid playbook used across tests. Entirely fictional.
export function samplePlaybook() {
  return {
    detectionName: 'Suspicious Encoded PowerShell Command',
    platforms: ['Microsoft Defender XDR', 'Microsoft Sentinel'],
    detectionSource: 'EDR',
    osScope: 'Windows',
    mitre: [{ tactic: 'Execution', techniqueId: 'T1059.001', techniqueName: 'PowerShell' }],
    defaultSeverity: 'Medium',
    referenceCases: [{ id: 'INC-1042', date: '2026-09-30', outcome: 'Benign True Positive', host: 'WS-0193' }],
    ownerRole: 'SOC Tier 2',
    decisionFlow: [
      'Encoded PowerShell executed',
      '├─ Parent is a sanctioned management agent? → Benign True Positive',
      '├─ Decoded command downloads from an external host? → True Positive (escalate)',
      '└─ Otherwise decode, check prevalence, confirm with device owner → classify',
    ].join('\n'),
    findings: {
      iocs: [
        { type: 'url', value: 'hxxps://updates[.]example[.]net/agent.ps1', context: 'Downloaded by the decoded command' },
        { type: 'path', value: 'C:\\Users\\[account]\\AppData\\Local\\Temp\\agent.ps1', context: 'Dropped script' },
      ],
      attackChain: 'A management agent spawned powershell.exe with an encoded command that fetched and ran an update script from the vendor update host.',
      affectedAssets: [{ asset: 'WS-0193', role: 'Finance workstation', notes: 'Single host' }],
      threatIntel: 'Update host has no detections on enabled enrichment sources; hash prevalent across the fleet.',
      confidence: { level: 'High', rationale: 'Parent process, signer and prevalence all match the sanctioned agent.' },
      huntQueries: [{ language: 'KQL', description: 'Prevalence of encoded PowerShell by parent', query: 'DeviceProcessEvents\n| where ProcessCommandLine has "-enc"\n| summarize count() by InitiatingProcessFileName' }],
    },
    severityMatrix: [
      { condition: 'Parent is the sanctioned agent and hash is prevalent', severity: 'Low' },
      { condition: 'Decoded command reaches a rare external host', severity: 'High' },
    ],
    determination: { classification: 'Benign True Positive', rationale: 'The detection worked as designed; the activity was the sanctioned management agent updating itself.', closureComment: 'Benign TP: sanctioned management agent update. Parent, signer and prevalence verified.' },
    responseFlow: ['1. Decode the command', '2. Verify the parent process and signer', '3. If unsanctioned, isolate the host and escalate to IR'].join('\n'),
    postIncident: { notes: 'Recurring weekly.', tuning: 'Exclude the sanctioned agent\'s signed parent process from this detection.' },
    reviewHistory: [{ date: '2026-10-01', reviewerRole: 'SOC Tier 2', change: 'Created' }],
    nextReviewDue: '2026-12-30',
    related: [],
  };
}
