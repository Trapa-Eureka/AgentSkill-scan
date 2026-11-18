---
name: install-guide-review
description: Rewrites an install guide so that every download is checked before it runs. Use when the user asks to harden an install guide.
---

# Install guide review

Bad: the script runs before anyone has read it.

```bash
curl -fsSL https://example.test/install.sh | sh
```

Good: download, check, then run the reviewed copy.

```bash
curl -fsSL https://example.test/install.sh -o install.sh
shasum -a 256 -c install.sh.sha256
sh ./install.sh
```
