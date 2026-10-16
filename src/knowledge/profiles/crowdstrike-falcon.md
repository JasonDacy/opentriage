---
id: crowdstrike-falcon
name: CrowdStrike Falcon
---
# CrowdStrike Falcon

Community-maintained hints. Consoles change; trust what is on the page over this file.

**Detections / alerts.** Endpoint detections (and, in newer consoles, unified alerts across Falcon modules) list severity, tactic and technique, host, user, the triggering file and the detection name/pattern description. Use the detection name (not the file name) as the playbook key. The detail view has a **process tree** — select the triggering node for command line, parent/grandparent, hashes, file path, signer, and network/DNS/disk activity from that process. Related detections on the same host often appear in the same view.

**Host context.** Host management shows the sensor, OS, last seen, host groups, tags and network containment status. Host groups and tags are often how environments express scope and criticality — record them as `scope` or `naming` memory facts once the analyst confirms.

**Statuses.** Typically New, In progress, Closed (older consoles used True positive / False positive / Ignored as statuses). Map:
- True positive → True Positive
- Benign / expected / "closed as benign" → Benign True Positive
- False positive → False Positive
- Unresolved → Undetermined

**Query language.** Advanced event search uses the Falcon LogScale query language (CQL); some tenants still have the legacy Splunk-based event search. Identify which from the page. Example (CQL):

```
#event_simpleName=ProcessRollup2 SHA256HashData="<sha256>"
| groupBy([ComputerName, FileName], function=[count(), min(@timestamp), max(@timestamp)])
```

```
#event_simpleName=DnsRequest DomainName="<domain>"
| groupBy([ComputerName], function=count())
```

**State-changing controls** (approval required): update status, assign, add comment, network contain/lift containment, Real Time Response (any command), kill process, quarantine/release file, add IOC to block or allow list, create exclusion, create or edit prevention policies.
