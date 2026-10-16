---
id: microsoft-sentinel
name: Microsoft Sentinel
---
# Microsoft Sentinel

Community-maintained hints. Consoles change; trust what is on the page over this file.

**Where it runs.** The Azure portal (Sentinel blade inside a Log Analytics workspace) and, for workspaces onboarded to unified security operations, the Microsoft Defender portal. The Azure portal renders much of Sentinel inside iframes from other Microsoft origins; if the snapshot reports blocked frames, the analyst needs to grant those origins.

**Incidents.** Threat management → Incidents. An incident groups one or more alerts and shows severity, status (New, Active, Closed), owner, the analytics rule that created it, entities, and a timeline. Open the incident's full details to see alerts, entities and comments. The analytics rule name is the detection name to key playbooks on. Alerts that come from another product (for example an XDR or EDR connector) often carry a link back to that product's alert — follow it for richer evidence.

**Closing.** Closing asks for a classification and a comment. Classifications map as:
- True Positive – suspicious activity → True Positive
- Benign Positive – suspicious but expected → Benign True Positive
- False Positive – incorrect alert logic / incorrect data → False Positive
- Undetermined → Undetermined

**Query language: KQL.** Run queries in Logs. Useful tables, when the matching connectors are enabled: `SecurityIncident`, `SecurityAlert`, `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`, `SecurityEvent`, `Syslog`, `CommonSecurityLog`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `OfficeActivity`, `AzureActivity`.

```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName == "<detection name>"
| summarize count(), make_set(CompromisedEntity, 50) by bin(TimeGenerated, 1d)
```

```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| where Title has "<detection name>"
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, Status, Classification, ClassificationReason, Owner, ClosedTime
```

The incident grid typically shows a limited time window; use `SecurityIncident` for history.

**State-changing controls** (approval required): change status, change owner, change severity, add or edit comments, run playbooks/automation, create tasks, run or save analytics rules, save queries.
