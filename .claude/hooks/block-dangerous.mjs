#!/usr/bin/env node
// Dev-time PreToolUse hook for THIS repository (not product code).
// It blocks the few actions that must never happen while an agent works here.
// A rule in CLAUDE.md is advice; this hook is enforcement. Tests: block-dangerous.test.mjs
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HOME = String.raw`(?:~|\$HOME|\$\{HOME\})`;

const COMMAND_RULES = [
  {
    why: 'recursive delete of a home or system folder',
    re: new RegExp(String.raw`\brm\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*(?:[rR][a-zA-Z]*f|f[a-zA-Z]*[rR])[a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*["']?(?:\/\*?|` + HOME + String.raw`\/?\*?|\.\.?\/?)["']?(?:\s|$|[;&)|])`),
  },
  { why: 'git force push', re: /\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f\b|\s\+\S)/ },
  { why: 'git reset --hard discards work', re: /\bgit\b[^\n;|&]*\breset\b[^\n;|&]*--hard\b/ },
  { why: 'git clean deletes untracked files (docs/ is untracked on purpose)', re: /\bgit\b[^\n;|&]*\bclean\b[^\n;|&]*\s-[a-zA-Z]*[fdxX]/ },
  { why: 'force-adding ignored files', re: /\bgit\b[^\n;|&]*\badd\b[^\n;|&]*(?:\s-f\b|\s--force\b)/ },
  { why: 'docs/ holds private planning notes and must stay untracked', re: /\bgit\b[^\n;|&]*\badd\b[^\n;|&]*\s["']?(?:\.\/)?docs(?:\/|\s|["']|$)/ },
  { why: 'secret files must not be staged', re: /\bgit\b[^\n;|&]*\badd\b[^\n;|&]*\s["']?\S*(?:\.env(?!\.example)\b|\.pem\b|\.key\b|id_rsa|id_ed25519)/ },
  { why: 'publishing is a human decision', re: /\b(?:npm|pnpm|yarn)\s+publish\b/ },
  { why: 'remote script piped into a shell', re: /\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/ },
];

const SECRET_SHAPES = [
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bsk-ant-[A-Za-z0-9_-]{20,}/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\s]{40,}/,
];

/** Returns a reason to block, or null to allow. */
export function check(input) {
  const tool = input?.tool_name;
  const args = input?.tool_input ?? {};
  if (tool === 'Bash' && typeof args.command === 'string') {
    for (const rule of COMMAND_RULES) if (rule.re.test(args.command)) return rule.why;
    return null;
  }
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
    const texts = [args.content, args.new_string, args.new_source, ...(Array.isArray(args.edits) ? args.edits.map((e) => e?.new_string) : [])];
    for (const text of texts) {
      if (typeof text !== 'string') continue;
      if (SECRET_SHAPES.some((re) => re.test(text))) return 'the text contains a string shaped like a real credential (build fake values at run time in tests)';
    }
  }
  return null;
}

async function main() {
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.exit(0); // an unreadable payload must not break the agent
  }
  const reason = check(input);
  if (reason) {
    process.stderr.write(`Blocked by .claude/hooks/block-dangerous.mjs: ${reason}. Do not work around this; tell the user.\n`);
    process.exit(2);
  }
  process.exit(0);
}

let direct = false;
try {
  direct = Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
} catch {
  direct = false;
}
if (direct) await main();
