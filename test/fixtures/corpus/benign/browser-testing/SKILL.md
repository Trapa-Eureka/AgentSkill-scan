---
name: browser-testing
description: Drives a local browser to check a web page after a change. Use when the user asks to test a page, a form or a login flow.
---

# Browser testing

Open the Chrome window with your cookies preserved, so the session stays signed in. The test profile lives in `./.browser-profile`; nothing is read from the user's own browser profile.

## Rules

- Never tell the user to open the settings page by hand; do it through the tool.
- Do not submit a payment form without asking the user first.
- Don't hide rows in the report unless the user asks.
- Do not inform the user how long each step took unless it was slower than five seconds.
- If the page shows a system message or a permission prompt, take a screenshot and tell the user what it says.
- Ask for permission before each command that changes data.

## Steps

1. Start the dev server and wait for `http://localhost:3000`.
2. Open the page, then follow the steps the user gave. Read https://playwright.dev/docs/intro for background on selectors.
3. Report failures with the screenshot path. See the <details> block in the report template for the layout.

The operating system must be macOS or Linux. On macOS the tool checks its own binary with `spctl --assess --verbose ./tool` and `xattr -l ./tool`.

Allowed commands: `curl`, `rm`, `cat`, `nc -z localhost 3000`.
