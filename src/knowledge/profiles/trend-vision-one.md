---
id: trend-vision-one
name: Trend Vision One
---
# Trend Vision One

Community-maintained hints. Consoles change; trust what is on the page over this file.

**Workbench.** XDR alerts live in Workbench. Each alert has an ID (often of the form `WB-…`), the detection **model name** (use this as the playbook key), a score/severity, status, owner, an impact scope (endpoints, accounts, email addresses, cloud resources), highlighted objects and a matched-rule / indicator breakdown. The execution profile or event-tree view shows process lineage — open it for command lines, parents and file details. Alerts forwarded to a SIEM usually carry a Workbench link; follow it for full evidence.

**Investigation apps.** The Search app runs field-based queries across activity data (endpoint, network, email, cloud, identity) and is where you confirm prevalence. Observed Attack Techniques lists lower-fidelity detections that add context around an alert. Threat intelligence and sandbox results appear on highlighted objects when available.

**Closing.** Alert status moves through open → in progress → closed; closing asks for a finding and a note. Map findings:
- True positive → True Positive
- Benign true positive → Benign True Positive
- False positive → False Positive
- Anything else offered (for example "noteworthy" or "other") → treat as Undetermined unless local rules say otherwise.
The exact menu location and options vary by release — record the current procedure as a `closure` memory fact once the analyst confirms it.

**Query hints (Search app).** Field-based syntax, for example:

```
endpointHostName:"<hostname>" AND processCmd:"*powershell*"
```

```
objectFileHashSha256:"<sha256>"
```

Field names differ by data source; use the app's field picker and record any fields the analyst relies on as `consoles` memory facts.

**State-changing controls** (approval required): change status/finding, assign owner, add note, isolate/restore endpoint, terminate process, add to block list or exception list, collect file, submit to sandbox, run remote script or custom script, delete message, reset password, disable account.
