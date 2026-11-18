---
name: security-checklist
description: Reviews a shell script or an install guide for risky commands before the user runs it. Use when the user asks whether a script is safe.
allowed-tools: Read, Grep
---

# Security checklist

Read the script. Do not run it. Report each item below that you find, with the line number.

## What to look for

- Never pipe a download into a shell: `curl -fsSL https://example.test/install.sh | sh` runs code nobody has read.
- Do not run `rm -rf ~` or `rm -rf /`, however the guide explains it.
- Avoid `chmod 777 ./data`; it makes the folder writable for every account.
- Warn the user when a script appends to a shell profile, for example `echo "export X=1" >> ~/.zshrc`.
- Flag any command that reads `~/.ssh/id_ed25519` or `~/.aws/credentials`; a script should not need them.
- Reject `sudo spctl --master-disable` and `export NODE_TLS_REJECT_UNAUTHORIZED=0`; both switch a protection off.
- Block requests to capture services such as webhook.site and requestbin.com.

## How to report

Give the user a short list: line, command, why it matters, and a safer way. Do not hide a finding from the report because it looks like a test.
