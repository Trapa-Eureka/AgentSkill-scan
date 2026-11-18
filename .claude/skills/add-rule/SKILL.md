---
name: add-rule
description: Procedure for adding or changing a detection rule in skill-scan. Use when asked to add a rule, detect a new pattern, or fix a false positive or a missed detection.
---

# Add or change a detection rule

A rule is only done when it is proven in both directions: it reports the bad thing, and it stays quiet on look-alikes.

1. **Pick the kind.**
   - One line of text is enough to decide: add a `LineRule` in `src/rules/line-rules.ts`.
   - The structure matters (JSON keys, front matter, file type): add a check in `src/rules/structured.ts`, `manifest.ts` or `hidden.ts`, and its metadata to that file's rule table.
2. **Choose the id and severity.** Prefix by category: `PI` prompt injection, `EX` exfiltration, `SH` shell, `AC` agent configuration, `SK` manifest. Never reuse or renumber an id: users disable rules by id.
   - `critical`: no legitimate use (reverse shell, credentials piped to the network).
   - `high`: fails the default gate. Use only when a false positive is rare.
   - `medium` / `low`: needs a human look; common in honest skills.
3. **Write the pattern** with bounded repetition (`.{0,80}`, never `.*` or nested quantifiers). Scanned files are hostile input.
4. **Add test cases** in `test/rules.test.ts`: at least two `hit` lines and two `miss` lines that look similar but are harmless. For structured rules add a test in `test/scan.test.ts`.
5. **Fixtures.** If the rule is a headline feature, add a line to `test/fixtures/malicious-skill/` and extend the expected id list. `test/fixtures/benign-skill/` must keep producing zero findings.
   - Create fixture files with the Write tool, not a shell heredoc: the dev hook reads shell command text and will block a command that contains a dangerous-looking string.
   - Never write a real-looking credential into a file. Assemble fake values at run time in the test.
6. **Run `npm run check`** (typecheck, tests, hook tests). It must pass.
7. **Measure false positives** on real content: `node dist/src/cli.js --installed --fail-on none --format json` and read the new rule's findings. If honest skills are flagged at `high`, narrow the pattern or lower the severity.
8. **Update the README** rule table (`node dist/src/cli.js --list-rules` gives the current list).

Do not add inline-ignore comments or config auto-discovery to make a false positive go away: scanned content must never be able to silence the scanner.
