---
name: api-client
description: Calls the issue tracker API and summarises open issues. Use when the user asks what is open or assigned to them.
allowed-tools: Bash(curl:*), Bash(jq:*), Read
---

# Issue tracker client

The tracker needs a token. Copy the template and let the user fill it in:

```bash
cp .env.example .env
```

Never print the token, and never tell the user to paste it into the chat.

## List open issues

```bash
curl -s -H "Authorization: Bearer $TRACKER_TOKEN" https://tracker.example.test/api/issues?state=open | jq '.[] | {id, title}'
```

To check that a response is valid JSON:

```bash
curl -s https://tracker.example.test/api/health | python3 -m json.tool
```

Download the schema once and keep the copy in the repository, so a later change is visible in review:

```bash
curl -fsSL https://tracker.example.test/schema.json -o schema.json
shasum -a 256 schema.json
```

If the API answers 401, stop. Do not retry. Tell the user which variable is missing and where to create a token.
