# Security policy

OpenTriage operates inside security consoles with the analyst's privileges, so we treat its own security as a first-class feature. The design is described in [docs/threat-model.md](docs/threat-model.md).

## Safety guarantees

These hold in every configuration and are covered by tests:

1. **Read-only by default.** Clicks that look state-changing, form submissions, navigation to untrusted origins and indicator lookups require the analyst's approval.
2. **No memory from page content.** The model can only propose environment facts; the analyst saves them. Proposals that resemble page text are flagged.
3. **Page content is labelled untrusted** and cannot break out of its wrapper.
4. **No blanket site access.** Access is granted per origin by the analyst and can be revoked.
5. **No telemetry.** Data goes only to the model provider the analyst configures.
6. **Everything is logged** locally for the analyst's review.
7. **Indicators don't leave silently.** Sending a public indicator to a site that isn't one of the analyst's own tools needs approval.
8. **Wiki changes are previewed.** Every Confluence write shows a preview or diff and needs approval.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting (**Security → Report a vulnerability** on this repository). Include:

- what an attacker controls (for example a field in an alert) and what they can achieve;
- a minimal reproduction, ideally a page like `tests/e2e/site/index.html`;
- the browser version and OpenTriage version.

Prompt-injection bypasses that lead to an unapproved state change, a memory write, or data leaving the browser to a destination the analyst did not approve are in scope and especially welcome.

## Supported versions

Only the latest release receives fixes.
