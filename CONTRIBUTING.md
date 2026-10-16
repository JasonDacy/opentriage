# Contributing

Thanks for helping. OpenTriage is built by and for SOC analysts.

## The one rule

**Nothing organisation-specific goes in this repository.** No company names in examples, internal hostnames, tenant or workspace IDs, wiki page IDs, colleagues' names, real alert data or screenshots from real consoles. OpenTriage learns those things at runtime. Use `example.com`, documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and fictional hostnames.

`npm run check` enforces the common cases. Put your own organisation's terms in a local `.opentriage-denylist` file (one term or `/regex/` per line; it is git-ignored) and the check will catch them too.

## Good first contributions

- **Platform profiles** for more consoles (Elastic Security, Google SecOps, QRadar, SentinelOne, Palo Alto Cortex XDR/XSIAM, Sumo Logic, Rapid7, Wazuh…). See [docs/writing-a-platform-profile.md](docs/writing-a-platform-profile.md).
- **Model providers.** See [docs/adding-a-provider.md](docs/adding-a-provider.md).
- **Page reading** improvements for virtualised grids, canvas UIs and closed shadow DOM.
- **Safety** — better state-change detection, injection test cases.

## Development

```bash
npm test                     # unit tests, no dependencies (Node 20+)
npm run check                # hygiene check
python tests/e2e/e2e.py      # optional end-to-end run in Chromium (pip install playwright; playwright install chromium)
npm run package              # dist/opentriage-<version>.zip
```

Load the folder unpacked at `chrome://extensions` to try changes; click the reload icon on the extension card after editing.

## Pull requests

- Keep changes focused and include tests for behaviour changes.
- Anything that loosens a safety gate needs a clear rationale in the PR description and a test showing what stays protected.
- Update `CHANGELOG.md`.
