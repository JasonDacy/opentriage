---
id: microsoft-defender-xdr
name: Microsoft Defender XDR
---
# Microsoft Defender XDR (Defender portal)

Community-maintained hints. Consoles change; trust what is on the page over this file.

**Incidents & alerts.** Incidents correlate alerts across endpoint, identity, email and cloud apps. The incident page shows an attack story, alerts, assets (devices, users, mailboxes, apps), evidence and response, and investigations. Each alert has its own page with an alert story / process tree — this is where command lines, parent processes and file details live. The alert title is the detection name to key playbooks on; note the detection source (EDR, Defender for Identity, Defender for Office 365, Defender for Cloud Apps, custom detection).

**Device page.** Timeline of events on the device, logged-on users, exposure level and risk, and response actions.

**Classifying.** Alerts and incidents take a classification and a determination:
- True positive → True Positive
- Informational, expected activity (e.g. security test, line-of-business application, confirmed activity) → Benign True Positive
- False positive → False Positive
- Not set → Undetermined

**Query language: KQL (Advanced hunting).** Useful tables: `AlertInfo`, `AlertEvidence`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `CloudAppEvents`. Advanced hunting usually covers about 30 days.

```kql
AlertInfo
| where Timestamp > ago(30d)
| where Title == "<detection name>"
| join kind=inner AlertEvidence on AlertId
| summarize Alerts=dcount(AlertId), Devices=make_set(DeviceName, 50) by Title
```

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 == "<sha256>"
| summarize Devices=dcount(DeviceId), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by FileName, FolderPath
```

**State-changing controls** (approval required): classify/resolve, assign, isolate device, restrict app execution, run antivirus scan, collect investigation package, live response, stop and quarantine file, add indicator, disable user, block URL/file, release from quarantine, create custom detection.
