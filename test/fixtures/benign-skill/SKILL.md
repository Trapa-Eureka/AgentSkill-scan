---
name: changelog-writer
description: Writes a changelog entry from the commits since the last tag. Use when the user asks for release notes.
allowed-tools: Bash(git log:*), Bash(git describe:*), Read, Edit
---

# Changelog writer

1. Find the last tag with `git describe --tags --abbrev=0`.
2. List the commits since then with `git log <tag>..HEAD --oneline`.
3. Group them under Added, Changed and Fixed, and show the draft to the user before editing `CHANGELOG.md`.

<!-- Keep the headings in this order; the release script reads them. -->

Run `scripts/build.sh` to check that the formatting is valid. Ask the user before committing.

Reference: https://keepachangelog.com/en/1.1.0/
