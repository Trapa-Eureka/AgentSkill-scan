import type { Finding, RuleMeta } from '../types.js';
import { makeSnippet } from '../sanitize.js';

export const AC_RULES: Record<string, RuleMeta> = {
  AC001: {
    id: 'AC001',
    title: 'MCP server runs an unpinned package',
    category: 'agent-config',
    severity: 'medium',
    description: 'The server is started with npx/uvx/dlx without an exact version, so whatever is published under that name tomorrow runs with your permissions.',
    remediation: 'Pin an exact version you have reviewed, for example `package@1.2.3`.',
  },
  AC002: {
    id: 'AC002',
    title: 'MCP server started through a shell',
    category: 'agent-config',
    severity: 'medium',
    description: 'The server command is an inline shell script, which can do anything before (or instead of) starting a server.',
    remediation: 'Read the whole script. Prefer a direct command with arguments.',
  },
  AC003: {
    id: 'AC003',
    title: 'Credential written into agent configuration',
    category: 'agent-config',
    severity: 'medium',
    description: 'A key, token or password is stored as a literal value in a configuration file that is shared with the skill.',
    remediation: 'Reference an environment variable instead, and revoke the value if it is real.',
  },
  AC004: {
    id: 'AC004',
    title: 'Remote MCP server without TLS',
    category: 'agent-config',
    severity: 'medium',
    description: 'The server URL uses plain http to a host that is not this machine, so tool calls and results can be read or changed in transit.',
    remediation: 'Use https, or a server on localhost.',
  },
  AC005: {
    id: 'AC005',
    title: 'Approval prompts switched off by configuration',
    category: 'agent-config',
    severity: 'high',
    description: 'The configuration approves tools automatically: auto-approved MCP tools, every project MCP server enabled, unrestricted shell permission, or bypass mode.',
    remediation: 'Remove the setting. Approvals should be granted by the user, one tool at a time.',
  },
  AC006: {
    id: 'AC006',
    title: 'Hook command shipped in configuration',
    category: 'agent-config',
    severity: 'medium',
    description: 'A hook runs a shell command automatically on agent events, without a prompt, once the configuration is installed.',
    remediation: 'Read the command and decide whether it should run on every event.',
  },
};

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function isObject(value: Json | undefined): value is { [key: string]: Json } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function strings(value: Json | undefined): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)$/i;
const SECRET_NAME = /(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTHORIZATION)/i;
const PLACEHOLDER = /^(?:|\$\{?[A-Za-z0-9_:.-]+\}?|<[^>]*>|\{\{[^}]*\}\}|.*(?:your|example|placeholder|changeme|change-me|xxx+|\.\.\.|todo|redacted|dummy).*)$/i;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'powershell', 'pwsh']);
const BROAD_PERMISSION = /^(?:\*|Bash|Bash\(\s*\*?\s*\)|Bash\(\s*:\*\s*\))$/;

function baseCommand(command: string): string {
  const base = command.split(/[\\/]/).pop() ?? command;
  return base.replace(/\.(?:cmd|exe|bat)$/i, '').toLowerCase();
}

function firstPackage(args: string[], valueFlags: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (valueFlags.includes(arg)) return args[i + 1];
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return undefined;
}

/** Returns the package that a launcher command would download without an exact version. */
export function unpinnedPackage(command: string, args: string[]): string | undefined {
  const base = baseCommand(command);
  let pkg: string | undefined;
  let python = false;
  if (base === 'npx' || base === 'bunx') pkg = firstPackage(args, ['-p', '--package']);
  else if ((base === 'pnpm' || base === 'yarn' || base === 'bun') && (args[0] === 'dlx' || args[0] === 'x')) pkg = firstPackage(args.slice(1), ['-p', '--package']);
  else if (base === 'uvx') {
    pkg = firstPackage(args, ['--from']);
    python = true;
  } else if (base === 'pipx' && args[0] === 'run') {
    pkg = firstPackage(args.slice(1), ['--spec']);
    python = true;
  } else if (base === 'uv' && args[0] === 'tool' && args[1] === 'run') {
    pkg = firstPackage(args.slice(2), ['--from']);
    python = true;
  }
  if (!pkg) return undefined;
  if (/^[./~]/.test(pkg) || pkg.includes('://') || pkg.startsWith('git+')) return undefined;
  if (python) return /(?:==|@)\d/.test(pkg) ? undefined : pkg;
  const at = pkg.lastIndexOf('@');
  if (at > 0 && /^\d/.test(pkg.slice(at + 1))) return undefined;
  return pkg;
}

class Reporter {
  readonly findings: Finding[] = [];
  private readonly lines: string[];

  constructor(
    private readonly file: string,
    content: string,
  ) {
    this.lines = content.split(/\r?\n/);
  }

  /** Reports at the first line that contains one of the needles, in order of preference. */
  add(ruleId: string, message: string, needles: string[]): void {
    const meta = AC_RULES[ruleId];
    if (!meta) return;
    let line = 1;
    let column = 1;
    for (const needle of needles) {
      if (!needle) continue;
      const index = this.lines.findIndex((text) => text.includes(needle));
      if (index >= 0) {
        line = index + 1;
        column = (this.lines[index] ?? '').indexOf(needle) + 1;
        break;
      }
    }
    this.findings.push({
      ruleId: meta.id,
      title: meta.title,
      category: meta.category,
      severity: meta.severity,
      message,
      file: this.file,
      line,
      column,
      snippet: makeSnippet(this.lines[line - 1] ?? '', column - 1),
    });
  }
}

function checkServer(name: string, server: { [key: string]: Json }, report: Reporter): void {
  const key = JSON.stringify(name);
  const command = typeof server.command === 'string' ? server.command : '';
  const args = strings(server.args);

  if (command) {
    const pkg = unpinnedPackage(command, args);
    if (pkg) report.add('AC001', `MCP server ${key} downloads "${pkg}" without an exact version.`, [JSON.stringify(pkg), key]);
    const inline = args.some((a) => /^(?:-c|\/c|-Command|-EncodedCommand)$/i.test(a));
    if ((SHELLS.has(baseCommand(command)) && inline) || /[|;&`]|\$\(/.test(command)) {
      report.add('AC002', `MCP server ${key} is started by an inline shell script.`, [JSON.stringify(command), key]);
    }
  }

  const url = typeof server.url === 'string' ? server.url : '';
  if (url.startsWith('http://')) {
    let host = '';
    try {
      host = new URL(url).hostname;
    } catch {
      host = '';
    }
    if (!LOCAL_HOST.test(host)) report.add('AC004', `MCP server ${key} is reached over plain http (${host || 'unparsable host'}).`, [JSON.stringify(url), key]);
  }

  for (const field of ['env', 'headers'] as const) {
    const bag = server[field];
    if (!isObject(bag)) continue;
    for (const [envName, value] of Object.entries(bag)) {
      if (typeof value !== 'string' || !SECRET_NAME.test(envName)) continue;
      const bare = value.replace(/^(?:Bearer|Basic|token)\s+/i, '');
      if (bare.length < 8 || PLACEHOLDER.test(bare)) continue;
      report.add('AC003', `MCP server ${key} has a literal value for ${JSON.stringify(envName)}.`, [JSON.stringify(envName), key]);
    }
  }

  for (const field of ['autoApprove', 'alwaysAllow']) {
    if (strings(server[field]).length > 0 || server[field] === true) {
      report.add('AC005', `MCP server ${key} pre-approves tools with "${field}".`, [`"${field}"`, key]);
    }
  }
}

function checkHooks(hooks: { [key: string]: Json }, report: Reporter): void {
  const visit = (value: Json | undefined, event: string): void => {
    if (Array.isArray(value)) value.forEach((v) => visit(v, event));
    else if (isObject(value)) {
      if (typeof value.command === 'string' && (value.type === undefined || value.type === 'command')) {
        report.add('AC006', `A ${event} hook runs a command automatically.`, [JSON.stringify(value.command), '"command"']);
      }
      if (Array.isArray(value.hooks)) visit(value.hooks, event);
    }
  };
  for (const [event, value] of Object.entries(hooks)) visit(value, event);
}

/** Structured checks for JSON files: MCP server definitions, agent settings and hook definitions. */
export function checkJsonConfig(file: string, content: string): Finding[] {
  let root: Json;
  try {
    root = JSON.parse(content) as Json;
  } catch {
    return [];
  }
  if (!isObject(root)) return [];
  const report = new Reporter(file, content);

  const serverMaps: Json[] = [root.mcpServers ?? null];
  if (isObject(root.mcp)) serverMaps.push(root.mcp.servers ?? null);
  if (/(?:^|\/)mcp\.json$/i.test(file)) serverMaps.push(root.servers ?? null);
  for (const map of serverMaps) {
    if (!isObject(map)) continue;
    for (const [name, server] of Object.entries(map)) {
      if (isObject(server)) checkServer(name, server, report);
    }
  }

  if (root.enableAllProjectMcpServers === true) {
    report.add('AC005', 'Every MCP server defined in the project is enabled without asking.', ['"enableAllProjectMcpServers"']);
  }
  if (root.skipDangerousModePermissionPrompt === true) {
    report.add('AC005', 'The warning for dangerous mode is switched off.', ['"skipDangerousModePermissionPrompt"']);
  }
  if (isObject(root.permissions)) {
    if (root.permissions.defaultMode === 'bypassPermissions') {
      report.add('AC005', 'The default permission mode skips every approval prompt.', ['"bypassPermissions"']);
    }
    for (const entry of strings(root.permissions.allow)) {
      if (BROAD_PERMISSION.test(entry.trim())) {
        report.add('AC005', `The allow list grants ${JSON.stringify(entry)}, which permits any shell command.`, [JSON.stringify(entry), '"allow"']);
      }
    }
  }
  if (isObject(root.hooks)) checkHooks(root.hooks, report);

  return report.findings;
}
