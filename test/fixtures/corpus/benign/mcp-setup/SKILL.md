---
name: mcp-setup
description: Adds the project's documentation server to the agent configuration. Use when the user asks to connect the docs server.
---

# MCP setup

The project ships `.mcp.json` with one server. The package version is pinned, so an update is a change the user can review.

For local development, point the client at the proxy on this machine:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export NODE_OPTIONS=--max-old-space-size=4096
```

To inspect the current configuration, run `cat ~/.claude/settings.json`. Edit `.claude/settings.json` in your project by hand; this skill does not write to it.

Join the community chat at https://discord.com/invite/example for help.
