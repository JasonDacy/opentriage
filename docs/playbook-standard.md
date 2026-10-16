# Playbook standard

OpenTriage turns investigations into IR playbooks so the next analyst who sees the same detection makes the same, well-reasoned decision faster. The library doubles as a coverage map: one detection, one playbook, variants cross-linked.

## The built-in template

| # | Section | What goes in it |
|---|---|---|
| 1 | **Alert Metadata** | Detection name (the key), variant, platforms, detection source, OS/scope, default severity, MITRE ATT&CK, owning team/role, reference cases (ID, date, host, outcome) |
| 2 | **Investigation Decision Flow** | Plain-text decision tree; every branch ends in a classification or action |
| 3 | **Investigation Findings** | 3.1 IOCs Identified · 3.2 Attack Chain Summary · 3.3 Affected Assets · 3.4 Threat Intel Corroboration · 3.5 Overall Confidence Assessment · 3.6 Hunting and Validation Queries |
| 4 | **Severity Matrix** | Conditions that raise or lower severity |
| 5 | **Analyst Determination** | Classification, rationale, reusable closure comment |
| 6 | **Response Steps Flow** | Plain-text response steps, notifications, escalation |
| 7 | **Post-Incident Notes** | Lessons, recurrence, **tuning recommendation** |
| 8 | **Review History** | Dated review rows and an absolute next-review date |

Classifications: **True Positive**, **Benign True Positive**, **False Positive**, **Undetermined**.

## Rules the validator enforces

1. **Key on the detection name** exactly as the console shows it (rule, analytic or model name). Malware/signature names (`Trojan.…`, `PUA.…`) are rejected.
2. **At least one reference case** from real records, with an ID, a `YYYY-MM-DD` date and an outcome.
3. **Valid ATT&CK technique IDs** (`T1059`, `T1059.001`).
4. **No placeholders** — `[insert…]`, `TBD`, `TODO`, "working title", "not captured". If something is genuinely unknown, say what is missing and where it will come from.
5. **No usernames**, including inside paths (`C:\Users\<name>`, `/Users/<name>`, `/home/<name>`) — use `[account]`. 8.3 short names are flagged. No email addresses; describe people by role.
6. **Defanged indicators** for IPs, domains, URLs and emails.
7. **Absolute dates** — next review due is a date, not "in 90 days".
8. **Decision and response flows** have real branching (three or more lines).
9. **Severity matrix** has at least two rows.
10. **Duplicates are flagged** — the same detection (and variant) already in the library produces a warning, so the agent adds a reference case instead of creating a second page.

## Merge, variant or new

- Same detection, same decision logic → add a reference case to the existing playbook.
- Same detection, different decision logic (for example a different OS or technique) → a **variant**, titled `<Detection> — <variant>`, cross-referenced in `related`.
- No playbook for the detection → a new one.

## Using your organisation's template

Paste your template's Markdown into **Settings → Playbooks → Organisation template**. OpenTriage will then write playbooks in your structure and the validator checks that every heading in your template is present, plus the hygiene rules above (placeholders, usernames, emails, dates). Clear the template to return to the built-in one.

## Exporting

Every playbook can be downloaded as Markdown (wikis, Git, tickets) or as standalone HTML (pastes cleanly into Confluence, SharePoint, Notion or Word). The whole library exports as JSON for sharing with your team.
