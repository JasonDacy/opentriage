# Writing a platform profile

A profile is a short Markdown file of **vendor-public** hints that helps OpenTriage get oriented in a console: where the alert record and entities are, which closure options exist and how they map to the four classifications, the console's query language with one or two examples, and which controls change state.

## Rules

- **Public knowledge only.** Nothing that identifies an organisation: no tenant IDs, workspace names, internal hostnames, custom field names, team names or screenshots from a real environment. Those are environment facts the analyst teaches OpenTriage locally.
- **Describe, don't script.** Consoles change. Explain where things usually are and what they are called; do not hard-code CSS selectors or click paths. The agent reads the live page and trusts it over the profile.
- **List the state-changing controls.** It helps the model explain what an approval will do.
- **Keep it short** — around 300–600 words. It is in every system prompt for that console.

## Steps

1. Create `src/knowledge/profiles/<id>.md`:

   ```markdown
   ---
   id: <id>
   name: <Display name>
   ---
   # <Display name>

   Community-maintained hints. Consoles change; trust what is on the page over this file.

   **The alert record.** …
   **Closing.** … (map to True Positive / Benign True Positive / False Positive / Undetermined)
   **Query language: …** with one or two examples using <placeholders>
   **State-changing controls** (approval required): …
   ```

2. Register it in `src/knowledge/profiles/index.json` with host regexes for the vendor's public SaaS domains and, for self-hosted products, page-title hints:

   ```json
   { "id": "<id>", "name": "<Display name>", "file": "<id>.md", "hosts": ["^console\\.vendor\\.com$"], "titleHints": ["product name"] }
   ```

3. Add a case to the "profile matching" test in `tests/agent.test.mjs`.
4. Run `npm test && npm run check`.
