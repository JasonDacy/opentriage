---
id: splunk-es
name: Splunk Enterprise Security
---
# Splunk Enterprise Security

Community-maintained hints. Consoles change; trust what is on the page over this file.

**Which ES.** ES 7.x uses **Incident Review** with notable events. ES 8.x reorganises triage around an analyst queue of **findings** (and finding groups) and **investigations**. Identify the version from the page before navigating.

**The alert record.** Each notable event or finding shows the correlation search / detection name (use this as the playbook key), urgency, status, owner, security domain, and the fields that triggered it (`src`, `dest`, `user`, `process`, `file_hash`, etc.). Expand the row or open details for drilldown searches, risk events (risk-based alerting) and the contributing events. Asset and identity enrichment (`src_category`, `dest_priority`, `user_bunit`, etc.) comes from the Assets & Identities framework — if it is populated, it answers the owner and criticality questions; record that as an `asset_lookup` memory fact.

**Status and disposition.** Statuses are typically New, In Progress, Pending, Resolved, Closed (customisable). Dispositions often include true positive, benign positive and false positive variants — map them to True Positive / Benign True Positive / False Positive / Undetermined, and record any local custom statuses as `closure` memory facts.

**Query language: SPL.** Run searches in the search app. Examples:

```spl
index=notable search_name="<detection name>" earliest=-30d
| stats count values(dest) as dest values(user) as user by status_label, disposition
```

```spl
| tstats summariesonly=true count min(_time) as first max(_time) as last
  from datamodel=Endpoint.Processes
  where Processes.process_hash="<sha256>"
  by Processes.dest Processes.process_name Processes.process
```

```spl
| tstats summariesonly=true count from datamodel=Network_Traffic
  where All_Traffic.dest_ip="<ip>" by All_Traffic.src_ip All_Traffic.dest_port
```

Index names and data models are environment-specific; ask the analyst and record them as `consoles` memory facts.

**State-changing controls** (approval required): edit status/urgency/owner/disposition, add comments, run adaptive response actions, create or edit investigations, suppress notables, edit correlation searches, save searches or reports.
