#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EMPTY_CONFIG, isSeverity, severityRank, type ScanConfig, type Severity } from './types.js';
import { loadConfig } from './config.js';
import { applyBaseline, createBaseline, formatBaseline, loadBaseline } from './baseline.js';
import { scanTargets } from './scan.js';
import { ALL_RULES, ruleById } from './rules/index.js';
import { formatRule, formatText } from './report/text.js';
import { formatJson } from './report/json.js';
import { formatSarif } from './report/sarif.js';

const HELP = `skill-scan: static security scanner for AI agent skills and MCP configuration

Usage
  skill-scan [options] [path ...]

  A path is a folder, a single file, or a .zip / .skill archive. Default: the current folder.

Options
  --installed             also scan the skills and agent configuration already on this machine
                          (~/.claude/skills, agents, commands; ./.claude; ./.mcp.json; ...)
  --format <name>         text (default), json or sarif
  --output <file>         write the report to a file instead of the terminal
  --fail-on <severity>    exit with code 1 when a finding is at least this severe:
                          low, medium, high (default), critical, or none
  --min-severity <sev>    list only findings at least this severe in the text report (default: low)
  --config <file>         JSON file with "disable", "severity" and "exclude" (never auto-discovered)
  --baseline <file>       findings recorded in this file are known: they are not listed and do
                          not fail the run (never auto-discovered)
  --write-baseline <file> record the current findings as the baseline, then exit with code 0
  --list-rules            print every rule and exit
  --explain <rule id>     print what a rule means and what to do about it, then exit
  --no-color              plain text output
  -v, --version           print the version
  -h, --help              print this help

Exit codes
  0  nothing at or above --fail-on      1  findings at or above --fail-on      2  usage or read error
`;

class UsageError extends Error {}

function version(): string {
  const file = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../package.json');
  try {
    return String((JSON.parse(readFileSync(file, 'utf8')) as { version?: unknown }).version ?? '0.0.0');
  } catch {
    return '0.0.0';
  }
}

function installedTargets(cwd: string): string[] {
  const home = homedir();
  const candidates = [
    path.join(home, '.claude', 'skills'),
    path.join(home, '.claude', 'agents'),
    path.join(home, '.claude', 'commands'),
    path.join(home, '.codex', 'skills'),
    path.join(home, '.agents', 'skills'),
    path.join(cwd, '.claude'),
    path.join(cwd, '.agents'),
    path.join(cwd, '.mcp.json'),
    path.join(cwd, '.cursor', 'mcp.json'),
    path.join(cwd, '.vscode', 'mcp.json'),
  ];
  return candidates.filter((candidate) => existsSync(candidate));
}

interface Options {
  targets: string[];
  installed: boolean;
  format: 'text' | 'json' | 'sarif';
  output?: string;
  failOn: Severity | 'none';
  minSeverity: Severity;
  config?: string;
  baseline?: string;
  writeBaseline?: string;
  color: boolean;
}

function parseArgs(argv: string[]): Options | 'help' | 'version' | 'rules' | { explain: string } {
  const options: Options = { targets: [], installed: false, format: 'text', failOn: 'high', minSeverity: 'low', color: true };
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i] as string;
    let inline: string | undefined;
    if (arg.startsWith('--') && arg.includes('=')) {
      inline = arg.slice(arg.indexOf('=') + 1);
      arg = arg.slice(0, arg.indexOf('='));
    }
    const value = (): string => {
      const next = inline ?? argv[++i];
      if (next === undefined) throw new UsageError(`${arg} needs a value`);
      return next;
    };
    switch (arg) {
      case '-h':
      case '--help':
        return 'help';
      case '-v':
      case '--version':
        return 'version';
      case '--list-rules':
        return 'rules';
      case '--explain':
        return { explain: value() };
      case '--installed':
        options.installed = true;
        break;
      case '--no-color':
        options.color = false;
        break;
      case '--format': {
        const format = value();
        if (format !== 'text' && format !== 'json' && format !== 'sarif') throw new UsageError(`unknown format "${format}" (use text, json or sarif)`);
        options.format = format;
        break;
      }
      case '--output':
        options.output = value();
        break;
      case '--config':
        options.config = value();
        break;
      case '--baseline':
        options.baseline = value();
        break;
      case '--write-baseline':
        options.writeBaseline = value();
        break;
      case '--fail-on': {
        const level = value();
        if (level !== 'none' && !isSeverity(level)) throw new UsageError(`unknown severity "${level}" for --fail-on`);
        options.failOn = level;
        break;
      }
      case '--min-severity': {
        const level = value();
        if (!isSeverity(level)) throw new UsageError(`unknown severity "${level}" for --min-severity`);
        options.minSeverity = level;
        break;
      }
      case '--':
        options.targets.push(...argv.slice(i + 1));
        i = argv.length;
        break;
      default:
        if (arg.startsWith('-')) throw new UsageError(`unknown option ${arg}`);
        options.targets.push(arg);
    }
  }
  return options;
}

function listRules(): string {
  const rows = ALL_RULES.map((rule) => `${rule.id}  ${rule.severity.padEnd(8)}  ${rule.category.padEnd(16)}  ${rule.title}`);
  return ['ID     SEVERITY  CATEGORY          TITLE', ...rows].join('\n') + '\n';
}

export function main(argv: string[], cwd = process.cwd()): number {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`skill-scan: ${(error as Error).message}\nRun skill-scan --help for usage.\n`);
    return 2;
  }
  if (parsed === 'help') {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed === 'version') {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  if (parsed === 'rules') {
    process.stdout.write(listRules());
    return 0;
  }
  if ('explain' in parsed) {
    const rule = ruleById(parsed.explain.toUpperCase());
    if (!rule) {
      process.stderr.write(`skill-scan: unknown rule "${parsed.explain}". Run skill-scan --list-rules to see every rule.\n`);
      return 2;
    }
    process.stdout.write(formatRule(rule));
    return 0;
  }

  const options = parsed;
  try {
    const config: ScanConfig = options.config ? loadConfig(path.resolve(cwd, options.config)) : EMPTY_CONFIG;
    const targets = [...options.targets, ...(options.installed ? installedTargets(cwd) : [])];
    if (targets.length === 0) {
      if (options.installed) throw new Error('--installed found no skill or agent configuration on this machine');
      targets.push('.');
    }
    const result = scanTargets(targets, { cwd, config });

    if (options.writeBaseline) {
      const baseline = createBaseline(result.findings);
      writeFileSync(path.resolve(cwd, options.writeBaseline), formatBaseline(baseline));
      process.stderr.write(`skill-scan: recorded ${result.findings.length} finding(s) as the baseline in ${options.writeBaseline}\n`);
      return 0;
    }
    if (options.baseline) {
      const applied = applyBaseline(result.findings, loadBaseline(path.resolve(cwd, options.baseline)));
      result.findings = applied.findings;
      result.baseline = { known: applied.known, stale: applied.stale };
    }

    const useColor = options.color && !options.output && process.stdout.isTTY === true && !process.env.NO_COLOR;
    const report =
      options.format === 'json'
        ? formatJson(result, version())
        : options.format === 'sarif'
          ? formatSarif(result, version())
          : formatText(result, { color: useColor, minSeverity: options.minSeverity });
    if (options.output) {
      writeFileSync(path.resolve(cwd, options.output), report);
      const known = result.baseline ? ` (${result.baseline.known} known from the baseline)` : '';
      process.stderr.write(`skill-scan: ${result.findings.length} finding(s)${known} in ${result.filesScanned} file(s); report written to ${options.output}\n`);
    } else process.stdout.write(report);

    if (options.failOn === 'none') return 0;
    const threshold = severityRank(options.failOn);
    return result.findings.some((f) => !f.baseline && severityRank(f.severity) >= threshold) ? 1 : 0;
  } catch (error) {
    process.stderr.write(`skill-scan: ${(error as Error).message}\n`);
    return 2;
  }
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : '';
let self = fileURLToPath(import.meta.url);
let invokedReal = invoked;
try {
  // npm and npx start the CLI through a symbolic link in node_modules/.bin.
  const { realpathSync } = await import('node:fs');
  invokedReal = realpathSync(invoked);
  self = realpathSync(self);
} catch {
  // keep the unresolved paths
}
if (invokedReal === self) process.exitCode = main(process.argv.slice(2));
