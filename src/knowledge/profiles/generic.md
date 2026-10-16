---
id: generic
name: Unknown or custom console
---
# Working in a console without a profile

No platform profile matched this page. Work it out from the page itself:

- **Find the alert record.** Look for a title, an ID (often a GUID or a prefixed number), severity, status, assignee and timestamps. Detail panes often open as drawers or side panels — snapshot after opening one.
- **Find the entities.** Hosts, users, IPs, processes and files are usually in an "Entities", "Evidence", "Assets", "Observables" or "Artifacts" section, or in a raw-event / JSON view. Raw JSON is the most reliable source of exact values.
- **Find the timeline.** "Timeline", "Events", "Activity", "History" or "Process tree" views show what happened around the alert.
- **Find the query feature.** Most consoles have a search or hunting page. Identify the query language from its syntax hints (KQL, SPL, Lucene/KQL-Elastic, EQL, SQL, YARA-L, vendor-specific).
- **Find the closure controls**, but do not use them without approval. Note which classifications the console offers and map them to True Positive / Benign True Positive / False Positive / Undetermined.

Once you understand how this console works, propose one or two memory facts about it (category `consoles`) so the next investigation starts faster — for example, where entities live or how the alert links to another console. Phrase them as questions in the `note` field for the analyst to confirm.
