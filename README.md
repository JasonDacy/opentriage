<p align="center"><img src="icons/logo256.png" width="96" alt=""></p>

<h1 align="center">OpenTriage</h1>

<p align="center"><strong>An AI investigation assistant for SOC analysts that lives in your browser.</strong><br>
Works in any SIEM or XDR console · learns your environment locally · never changes anything without your approval.</p>

---

OpenTriage is a Chrome extension that sits in the side panel next to your consoles. Open an alert, click **Investigate**, and it reads the alert, follows links into your other tools, extracts and (optionally) enriches indicators, checks your playbook library, and hands you a decision-ready write-up: verdict, evidence, entities, defanged IOCs, MITRE ATT&CK mapping, hunting queries in the console's own language, and a draft closure comment.

It ships with **no knowledge of any particular organisation**. Everything specific to your environment — naming conventions, where device owners are looked up, which tools are sanctioned, how alerts are closed — is learned from you, approved by you, and stored only in your browser.

<p align="center">
  <img src="docs/images/approval.png" width="260" alt="Approval card before a state-changing click">
  <img src="docs/images/memory-warning.png" width="260" alt="Warning on a memory proposal copied from alert data">
  <img src="docs/images/playbook-draft.png" width="260" alt="Validated playbook draft ready to save">
</p>

## Highlights

- **Works across your tabs, like a teammate at your shoulder.** Put the consoles for an investigation — SIEM incident, XDR workbench, EDR host page, asset inventory, threat intel — in the OpenTriage tab group, and the agent moves between them. It can't see or touch anything outside the group.
- **Sees the page, not just its text.** Optional screenshots let it read process trees, graphs and icon-only buttons, and click by position when it has to.
- **Vendor-neutral.** It reads whatever console is on screen. Platform profiles give it a head start on Microsoft Sentinel, Microsoft Defender XDR, Trend Vision One, Splunk Enterprise Security and CrowdStrike Falcon; anything else is handled by reading the page.
- **Learns your environment, safely.** A short setup interview, plus learning from your corrections. The agent can only *propose* facts; you approve each one. Proposals that look copied from alert data are flagged, because alert data can be written by an attacker.
- **Human-approved actions.** Reading is free. Clicks that look state-changing (close, resolve, isolate, block, save, submit…), navigation to new sites, and every indicator lookup stop and wait for you.
- **Publishes to Confluence.** Creates and updates playbook pages, adds index rows and keeps the page tree sorted — as you, in your signed-in tab, with a preview or diff to approve for every change.
- **Works your queue.** Queue mode investigates alert by alert, closes only what a playbook and high confidence support (with your approval), holds the rest with a reason, and keeps a local case history for weekly summaries.
- **Playbooks built in.** Turn an investigation into an IR playbook with an eight-section template, automatic quality checks (no usernames, no placeholders, defanged IOCs, absolute review dates, valid ATT&CK IDs) and a local library keyed on detection name — or use your organisation's own template.
- **Asks before indicators leave.** Typing a hash, IP or domain into an external site (or a URL) asks first; your own tools can be remembered.
- **Prompt-injection aware.** Page content is wrapped and labelled as untrusted, instruction-like text in alerts is flagged as a finding, and memory can never be written from page content.
- **Auditable.** Every tool call, approval decision, memory change and playbook change is logged locally and exportable.
- **Bring your own model key.** Claude by default, with a pluggable provider interface.

> **Need more room?** Drag the side panel's left edge to widen it, collapse the tab list with **▸ Tabs**, or click **⧉** to pop OpenTriage out into its own resizable window.

## Install (developer mode)

1. Download or clone this repository.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and choose the repository folder.
3. Pin OpenTriage and click its icon to open the side panel.
4. Open **Settings → Model**, paste an [Anthropic API key](https://console.anthropic.com/settings/keys), click **Test connection**, then **Save**.

Works in Chrome 116+ and other Chromium browsers with the side panel API (Edge, Brave).

### Team builds

To roll OpenTriage out to a team with your environment already learned, export environment memory (**Settings → Environment memory → Export**) and build:

```bash
npm run package:trusted -- --env team-environment.json --team soc
# → dist/opentriage-soc-trusted/ and dist/opentriage-soc-trusted-<version>.zip
```

Teammates install that build and start with every fact. Ship a new team build to update the facts; anything an analyst edited or added themselves is kept. Team builds contain internal details — share them only inside your organisation, and never commit the environment file (it is git-ignored).

### Standard and trusted-input builds

Some consoles ignore simulated clicks. The **trusted input** build (`npm run package:trusted` → `dist/opentriage-trusted/`) adds Chrome's `debugger` permission so OpenTriage can use a real mouse and keyboard. Chrome doesn't allow that permission to be optional, so it's a separate build with an extra install warning. Trusted input stays off until you choose it in **Settings → Safety → Input mode**, and Chrome shows its "debugging this browser" bar only while OpenTriage is acting.

> Some organisations block extensions that aren't from the Chrome Web Store. Your IT team can allow it by extension ID or push it through managed policy.

## First run

1. Click **Set up environment** and answer the interview. Approve the facts you want remembered.
2. Open an alert in your console and click **Investigate**. The tab joins the OpenTriage tab group and Chrome asks for access to that site (and its embedded frames — this matters for consoles like the Azure portal).
3. Add any other consoles the investigation needs: **+ Current**, **Add ▾**, right-click → *Add this tab to the OpenTriage session*, or drag the tab into the group.
4. The first time the agent wants a screenshot, approve the one-time Chrome permission (or turn it on in **Settings → Safety**).

Teams can share what they've learned: **Settings → Environment memory → Export** produces a JSON file colleagues can import. Treat that file as internal — it describes your environment.

## How it works

```
┌────────────────────────── Side panel ──────────────────────────┐
│  Agent loop ── model provider (your key)                        │
│     │                                                           │
│     ├─ read tools ─────── page snapshot (all frames), find text, │
│     │                     extract IOCs, search playbooks         │
│     ├─ navigate tools ─── trusted origins free; others approved  │
│     ├─ interact tools ─── state-changing clicks approved         │
│     └─ learn tools ────── memory + playbooks: always approved    │
│                                                                 │
│  System prompt = methodology + platform profile                 │
│                + environment memory (local) + playbook template │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Ships in the repo? | What it holds |
|---|---|---|
| Methodology | Yes | How to investigate: scoping, evidence, enrichment, classification, reporting, playbook rules |
| Platform profiles | Yes | Vendor-public hints: where fields live, closure options, query language examples |
| Environment memory | **No** — browser only | Your naming, scope, lookups, sanctioned tools, closure and escalation rules |
| Playbook library | **No** — browser only | Your team's playbooks, exportable as JSON / Markdown / HTML |

More detail: [docs/architecture.md](docs/architecture.md) · [docs/threat-model.md](docs/threat-model.md) · [docs/playbook-standard.md](docs/playbook-standard.md)

## Data handling

- Page content you investigate is sent to your model provider using **your** API key. Check that this is permitted by your organisation's data-handling policy before using OpenTriage on production consoles.
- Nothing is sent to the OpenTriage authors. There is no telemetry.
- Environment memory, playbooks, settings and the audit log stay in `chrome.storage.local`. The API key can be kept in session storage only (cleared when Chrome closes).
- Optional: mask email addresses before content is sent to the model (**Settings → Safety**).
- Indicator enrichment sources are off by default; each lookup asks first and private IPs are never sent.

## Contributing

Platform profiles for more consoles, model providers, and better page reading are the most useful contributions. See [CONTRIBUTING.md](CONTRIBUTING.md). Before opening a pull request:

```bash
npm test          # unit tests (no dependencies)
npm run check     # keeps secrets and organisation-specific data out of the repo
python tests/e2e/e2e.py   # optional: drives the real extension in Chromium with a mocked model
```

Add your own organisation's terms to a local `.opentriage-denylist` (git-ignored) and `npm run check` will make sure none of them ever land in a commit.

## Status

**v0.3 — experimental.** Everything here is covered by unit tests and by browser tests that drive the real extension in Chromium against mock consoles, a mock Confluence and a scripted model. Testing against live SIEM/XDR consoles with a live model is just beginning, so expect rough edges — particularly with heavily virtualised grids, canvas-rendered UIs and consoles that ignore simulated input (try the trusted-input build). Keep approvals on, review what it proposes, and please report what breaks.

Known limitations:
- Anthropic (Claude) is the only model provider so far; others plug in through `src/providers/` (see [docs/adding-a-provider.md](docs/adding-a-provider.md)).
- Trusted input targets the top page and first-level iframes; deeper frames fall back to simulated input.
- Confluence publishing targets Confluence Cloud.

## License

[MIT](LICENSE)
