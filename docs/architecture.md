# Architecture

## Components

| Path | Responsibility |
|---|---|
| `manifest.json` | Manifest V3. Side panel, on-demand scripting, optional per-site host access. |
| `src/background/service-worker.js` | Opens the side panel; "Investigate selection" context menu. Nothing else. |
| `src/ui/sidepanel.*` | The analyst's workspace: conversation, approval / memory / playbook cards, site access. **The agent runs here.** |
| `src/ui/options.*` | Settings, environment memory, playbook library and editor, enrichment sources, profiles, audit log. |
| `src/agent/agent.js` | The loop: model call → tool calls → results, with stop, step budget and history compaction. |
| `src/agent/tools.js` | Tool schemas given to the model and their implementations, with risk gating. |
| `src/agent/prompt.js` | Assembles the system prompt from methodology, profile, memory and template mode. |
| `src/agent/browser.js` | Chrome adapter: session tabs, frames, snapshots, screenshots, clicks (by ref or position), keys, typing, navigation. |
| `src/agent/session-tabs.js` | The session = the "OpenTriage" tab group: add, remove, list, membership checks, candidates. Shared by the side panel and the service worker. |
| `src/content/page-functions.js` | Self-contained functions injected into console frames (snapshot, click, type, scroll). |
| `src/agent/wiki-tools.js`, `src/wiki/*` | Confluence client (runs in the signed-in tab), storage-format rendering, table-row insertion, diffs, page-tree sort planning. |
| `src/agent/trusted-input.js` | Optional real input and screenshots through `chrome.debugger` (trusted-input build). |
| `src/cases/cases.js` | Local case history, summaries, CSV export. |
| `src/lib/security.js` | Untrusted-content wrapping, action classification, memory provenance check, injection heuristic. |
| `src/lib/ioc.js` | Indicator extraction, defang/refang, type detection. |
| `src/memory/memory.js` | Environment memory store, categories, import/export, prompt rendering. |
| `src/playbooks/*` | Template, validator, Markdown/HTML renderers, local library. |
| `src/knowledge/*` | Methodology and platform profiles (Markdown) plus the loader and profile matcher. |
| `src/providers/*` | Model provider registry; Anthropic implementation; template for others. |

## Why the agent runs in the side panel, not the service worker

MV3 service workers are suspended when idle. An investigation regularly waits minutes for the analyst to approve something, and a suspended worker would lose the run. The side panel is an extension page with the same `chrome.*` APIs, it is open whenever the analyst is working, and it can show approval prompts directly. Closing the panel stops the run — which is also the safest behaviour.

## Reading pages

`get_page_snapshot` enumerates every frame in the tab (`chrome.webNavigation.getAllFrames`) and injects `snapshotFrame` into each frame OpenTriage has access to. Each frame returns visible text (including open shadow roots) and up to 250 visible interactive elements, which are tagged in the DOM with `data-ot-ref`. Refs are presented to the model as `frameId:ref` so a later click targets the right frame. Frames without access are reported by origin so the analyst can grant them.

## Session tabs

The investigation session is a Chrome tab group titled **OpenTriage**. The group id is kept in `chrome.storage.session` (and re-adopted by title if lost), and membership is always read live from Chrome, so tabs the analyst drags in or out are picked up immediately. Every tab-taking tool resolves its target through `targetTab()`, which refuses tabs outside the group. `open_tab` puts new tabs in the group.

## Screenshots

`chrome.tabs.captureVisibleTab` only captures the active tab of a window, so a background session tab is activated briefly and the analyst's previous tab restored. Images are downscaled to at most 1280×1600 JPEG. The result tells the model the screenshot-to-CSS-pixel ratio; `click_at` converts back and hit-tests with `elementFromPoint` (through open shadow roots) before classifying and clicking. Any page-changing action invalidates the last screenshot for that tab. Only the two most recent screenshots stay in context.

## Confluence

Requests are executed in a Confluence session tab with `chrome.scripting.executeScript`, so `fetch` is same-origin and carries the analyst's session cookie; no tokens are stored. Endpoints: v2 `pages` (get/create/update), `spaces`, `pages|folders/{id}/direct-children`; v1 CQL `content/search` and `content/{id}/move/{position}/{target}`. Writes are optimistic-locked on the page version the agent last read.

## Gating

```
model wants to …           check                                  result
────────────────────────   ────────────────────────────────────   ─────────────────
read / search / extract    none                                   runs
navigate / open tab        origin in trustedOrigins and https?    runs, else approval
click / click_at           classifyAction(element label/role)     runs, else approval
press_key Enter/Space      classifyAction(focused element)        runs, else approval
screenshot                 all-sites permission held?             runs, else one-time approval
type / navigate with IOC   own-tools origin and not external?     runs, else approval
wiki create/update/row/sort  always                               approval with preview/diff
type + submit              search/filter box?                     runs, else approval
lookup indicator           private IP? source enabled?            always approval
propose memory             provenanceCheck → card                 analyst saves or not
draft playbook             validator → card                       analyst saves or not
```

## Prompt assembly

```
methodology.md                  (generic, versioned with the code)
+ today's date
+ matched platform profile      (vendor-public)
+ environment facts             (analyst-approved, local)
+ playbook template mode        (built-in or organisation Markdown)
+ task for this conversation    (investigate | setup | playbook | chat)
```

The system prompt is marked for prompt caching, so long investigations pay for it once.

## Context management

Snapshots are large. The agent keeps the eight most recent tool results in full and trims older ones to a short prefix with a note that the tool can be re-run. Each snapshot is capped at 30k characters per frame and 60k per tool result.

## Storage keys (`chrome.storage.local`)

| Key | Contents |
|---|---|
| `ot.settings` | Provider, model, approval mode, trusted origins, enrichment sources, disabled profiles |
| `ot.apiKey` | API key (in `chrome.storage.session` instead when "session only" is on) |
| `ot.memory` | Environment facts |
| `ot.playbooks` | Playbook library |
| `ot.customTemplate` | Organisation playbook template (Markdown) |
| `ot.audit` | Audit log (last 2,000 entries) |
