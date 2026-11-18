# skill-scan

Static security scanner for AI agent skills and MCP configuration. Input: a folder, file or .zip. Output: text, JSON or SARIF.
The free tier is this local CLI plus the GitHub Action. Paid features are only planned; their notes live in `docs/`, which is git-ignored.

## Commands
- `npm run check`: typecheck, build, tests, hook tests. Run it before saying a change is done.
- `node dist/src/cli.js <path>`: run the scanner from the build output.

## Layout
- `src/rules/`: detection rules. `line-rules.ts` (regex per line), `structured.ts` (JSON config), `manifest.ts` (front matter, bundled files), `hidden.ts` (invisible text).
- `src/scan.ts` engine, `src/files.ts` + `src/zip.ts` input, `src/report/` output, `src/cli.ts` command line.
- `test/fixtures/`: `malicious-skill` (every headline rule fires) and `benign-skill` (zero findings).

## Invariants (tested; do not break)
- Scanned content is hostile. It can never silence the scanner: no inline ignore comments, and the config is read only from `--config`.
- Nothing from a scanned file is printed raw: snippets go through `makeSnippet` (credentials masked, control and invisible characters shown as `<U+XXXX>`).
- Archives are read in memory, never extracted. Every size is capped, and every file that was not scanned is listed in the report.
- Zero runtime dependencies. Do not add one without asking.
- Rule ids are permanent.

Procedures live in skills (`.claude/skills/add-rule`), hard rules in the hook (`.claude/hooks/block-dangerous.mjs`). Keep this file short.
All tracked files are written in English.
