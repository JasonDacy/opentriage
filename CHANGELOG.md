# Changelog

## Unreleased

- **Clearer enrichment-source errors.** Adding a source now names every field that still needs fixing instead of one generic message, and a URL copied from the address bar with `%7Bioc%7D` is accepted as `{ioc}`.

## 0.4.0 — 2026-10-16

- **Choose your model.** New providers alongside Anthropic (Claude):
  - **OpenAI** (GPT-6 and GPT-5.6 families) through the Responses API, stateless (`store=false`), replaying encrypted reasoning between tool calls.
  - **Google Gemini** (Gemini 3.x) through `generateContent`, with thought signatures preserved for function calling. The settings page warns that the free tier lets Google use submitted data.
  - **Local or OpenAI-compatible servers** — Ollama, LM Studio, llama.cpp, vLLM, OpenRouter, Groq, Azure OpenAI — with one-click URL presets, **Load models from server**, optional key and Azure-style `api-key` header.
- Each provider keeps its own API key. Chrome asks for access to a provider's API the first time you save it; nothing new is requested at install.
- **Text-only models**: untick *This model accepts images* and OpenTriage drops screenshot and click-by-position tools and reads pages as text.
- **Other model ID…** lets you use any model a provider offers, not just the listed ones.
- Clear errors for rejected keys, unknown models, an unreachable local server, and Ollama's extension-origin block.


## 0.3.3 — 2026-10-16

- **Team builds.** `npm run package[:trusted] -- --env <exported environment file> --team <name>` bundles a team's environment facts into the extension. Facts load automatically on install; a newer team build updates them, removing facts the team dropped but keeping anything the analyst edited or added. Team builds are written only to `dist/` (git-ignored) and are clearly labelled "<TEAM> team build".

## 0.3.2 — 2026-10-16

- Environment memory: Save and Cancel appear only after a fact is edited (imported and approved facts are already saved); each fact box grows to show the full text; deleting asks for confirmation.

## 0.3.1 — 2026-10-16

- **Owner and role lookup is now mandatory.** Every investigation and queue turn carries a required-steps checklist: look up each in-scope device's owner and the owner's role with the methods in environment memory — or, if none is recorded, stop and ask the analyst where to look. Reports gain an "Owner & role" table with the source of each answer; `record_case` records the owner's role (role only).
- Teams can bootstrap environment memory from a prepared file (Settings → Environment memory → Import) instead of teaching facts one by one.

## 0.3.0 — 2026-10-16

- **Confluence publishing.** New `wiki_*` tools run as the analyst inside their signed-in Confluence tab (no stored credentials): search, read, list a page tree, create pages (from a saved playbook — with status lozenges, note panel and code macros — or from the team's own template page), update pages with a diff, append index-table rows, and sort a page tree alphabetically (ignoring brackets) with verification. Every write needs approval; new content must pass hygiene checks; edits require a fresh read and refuse large accidental deletions.
- **Queue mode** (Queue button): lists the queue, skips out-of-scope alerts, investigates one at a time, requests closure only for playbook-backed, high-confidence BTP/FP cases (each closure still approved), holds the rest with a reason, and ends with a summary table. Live queue-progress card.
- **Case history** (`record_case`, `get_case_history`): local per-alert outcomes, **Summary** button for weekly summaries, Settings → Case history with CSV export (formula-injection safe).
- **Trusted input** (optional "trusted input" build): real mouse and keyboard through Chrome's debugger for consoles that ignore simulated events, including first-level iframes; screenshots via the debugger too. Off by default; Chrome shows its debugging bar only while OpenTriage is acting. `npm run package:trusted`.
- **Indicator sharing gate.** Typing an indicator into a site, or putting one in a URL, asks first unless the site is one of the analyst's own tools; well-known external services (VirusTotal, Shodan, …) always ask. Private IPs never trigger it. "One of our own tools" is remembered (Settings → Safety).
- Compact action row; publish previews render tables readably.

## 0.2.2 — 2026-10-16

- **More room for the conversation.** The session tab list collapses to one line (auto-collapsed above three tabs; remembers your choice) and scrolls when expanded; action buttons are one compact row; labels no longer wrap in a narrow panel; "Unknown console" pills are hidden.
- **Pop-out window** (⧉): open OpenTriage in its own resizable window. "Current tab" there means the active tab of your last-used browser window.
- Fixed a horizontal scrollbar in the conversation; narrow tables wrap by word.

## 0.2.1 — 2026-10-16

- **Fix:** follow-up messages could fail with `400 … Invalid signature in thinking block … system prompt differs`. The system prompt is now built once per conversation and never changes; the task, session tabs and newly approved facts travel in a context note on each analyst message. Reasoning blocks from completed turns are dropped, and a thinking-signature error is retried once without them.
- **Fix:** the agent could say no playbook existed when the team keeps playbooks outside OpenTriage (e.g. a wiki). New `playbook_location` environment fact; the agent checks the local library *and* the recorded location, and asks the analyst where playbooks live instead of concluding none exist. The setup interview now asks for it.

## 0.2.0 — 2026-10-16

- **Session tabs.** An investigation now works across an "OpenTriage" Chrome tab group. Add tabs from the side panel ("+ Add current tab", "Add tab ▾"), the right-click menu, or by dragging them into the group. The agent can only see and act on tabs in the group; tabs it opens join the group. "Investigate this page" adds the current tab automatically.
- **Screenshots** (`screenshot` tool) so the agent can see process trees, graphs and icon-only controls. Optional one-time Chrome permission, requested in-flow or from Settings → Safety.
- **Click by position** (`click_at`) and **key presses** (`press_key`), with the same approval gating as other actions. Position clicks require a fresh screenshot after any page change.
- Per-tab console detection: the right platform profile is supplied the first time the agent reads each kind of console in a session.
- Older screenshots are dropped from context automatically.

## 0.1.0 — 2026-10-16

First public version.

- Side-panel agent that investigates the alert on the current tab across any SIEM/XDR console, including embedded frames.
- Platform profiles: Microsoft Sentinel, Microsoft Defender XDR, Trend Vision One, Splunk Enterprise Security, CrowdStrike Falcon; generic fallback for everything else.
- Environment memory learned from the analyst (setup interview, corrections), with approval and page-provenance warnings; team import/export.
- Approval gates for state-changing clicks, submissions, new origins and indicator lookups; strict mode.
- IR playbooks: eight-section template, validator, local library keyed on detection name, MITRE coverage view, Markdown/HTML export, optional organisation template.
- Indicator extraction and defanging; optional enrichment sources (off by default).
- Local audit log.
- Anthropic provider with a pluggable provider interface.
