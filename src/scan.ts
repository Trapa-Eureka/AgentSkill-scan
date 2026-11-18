import { EMPTY_CONFIG, SEVERITIES, severityRank, type Finding, type ScanConfig, type ScanFile, type ScanResult, type Severity } from './types.js';
import { collectTarget } from './files.js';
import { globToRegExp } from './config.js';
import { makeSnippet } from './sanitize.js';
import { LINE_RULES } from './rules/line-rules.js';
import { checkHiddenUnicode, checkHtmlComments } from './rules/hidden.js';
import { checkJsonConfig } from './rules/structured.js';
import { checkManifest, manifestFinding, opaqueKind } from './rules/manifest.js';

const DOC_EXTENSION = /\.(?:md|mdx|markdown|mdc|txt|rst)$/i;
const MAX_LINE_LENGTH = 20000;
const MAX_CONTINUATION_LINES = 30;

/** A line that reads like a warning about the command, not an instruction to run it. */
const CAUTIONARY =
  /\b(?:never|do not|don't|dont|avoid|must not|should not|shouldn't|refuse|block(?:s|ed|ing)?|warn(?:s|ing)?|forbidden|prohibit(?:s|ed)?|dangerous|malicious|instead of|flag(?:s|ged)?|detect(?:s|ed)?|reject(?:s|ed)?)\b|금지|하지\s*마|위험/i;

interface LogicalLine {
  /** 1-based number of the first physical line. */
  line: number;
  text: string;
  /** Length of the first physical line, to tell whether a match starts on it. */
  firstLength: number;
}

/** Joins shell continuation lines (a trailing backslash) so a command split over lines is seen whole. */
function logicalLines(lines: string[]): LogicalLine[] {
  const out: LogicalLine[] = [];
  for (let i = 0; i < lines.length; i++) {
    let text = lines[i] ?? '';
    const start = i;
    const firstLength = text.length;
    let joined = 0;
    while (/(?:^|[^\\])(?:\\\\)*\\$/.test(text) && i + 1 < lines.length && joined < MAX_CONTINUATION_LINES) {
      text = `${text.slice(0, -1)} ${(lines[i + 1] ?? '').trimStart()}`;
      i++;
      joined++;
    }
    out.push({ line: start + 1, text: text.length > MAX_LINE_LENGTH ? text.slice(0, MAX_LINE_LENGTH) : text, firstLength });
  }
  return out;
}

/** For each physical line of a Markdown file: is it inside a fenced code block? */
function fencedLines(lines: string[]): boolean[] {
  const out: boolean[] = [];
  let fence: string | null = null;
  for (const text of lines) {
    const marker = /^\s{0,3}(`{3,}|~{3,})/.exec(text)?.[1];
    if (marker && fence === null) {
      fence = marker[0] as string;
      out.push(true);
    } else if (marker && fence !== null && marker[0] === fence) {
      fence = null;
      out.push(true);
    } else out.push(fence !== null);
  }
  return out;
}

function lower(severity: Severity): Severity {
  return SEVERITIES[Math.max(0, severityRank(severity) - 1)] as Severity;
}

function isBinary(bytes: Buffer): boolean {
  return bytes.subarray(0, 8000).includes(0);
}

/** Runs every rule against one file. */
export function scanFile(file: ScanFile): Finding[] {
  const opaque = opaqueKind(file.path, file.bytes);
  if (opaque) return [manifestFinding('SK003', file.path, 1, `Bundled ${opaque}: its content was not scanned.`)];
  if (isBinary(file.bytes)) return [];

  let content = file.bytes.toString('utf8');
  if (content.charCodeAt(0) === 0xfeff) content = content.slice(1);
  const lines = content.split(/\r?\n/);
  const isDoc = DOC_EXTENSION.test(file.path);
  const fenced = isDoc ? fencedLines(lines) : [];
  const findings: Finding[] = [];

  for (const logical of logicalLines(lines)) {
    for (const rule of LINE_RULES) {
      for (const pattern of rule.patterns) {
        const match = pattern.exec(logical.text);
        if (!match) continue;
        const cautionary = Boolean(rule.cautionaryDowngrade) && isDoc && !fenced[logical.line - 1] && CAUTIONARY.test(logical.text);
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          category: rule.category,
          severity: cautionary ? lower(rule.severity) : rule.severity,
          message: cautionary ? `${rule.description} (The line reads like a warning, so the severity was lowered one level.)` : rule.description,
          file: file.path,
          line: logical.line,
          column: match.index < logical.firstLength ? match.index + 1 : 1,
          snippet: makeSnippet(logical.text, match.index),
          ...(cautionary ? { cautionary: true } : {}),
        });
        break; // one finding per rule per line
      }
    }
  }

  findings.push(...checkHiddenUnicode(file.path, lines));
  if (isDoc) {
    findings.push(...checkHtmlComments(file.path, content));
    findings.push(...checkManifest(file.path, lines));
  }
  if (/\.json$/i.test(file.path)) findings.push(...checkJsonConfig(file.path, content));
  return findings;
}

export interface ScanOptions {
  cwd?: string;
  config?: ScanConfig;
}

function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId),
  );
}

/** Scans folders, single files and .zip/.skill archives. Throws when a target cannot be read. */
export function scanTargets(targets: string[], options: ScanOptions = {}): ScanResult {
  const cwd = options.cwd ?? process.cwd();
  const config = options.config ?? EMPTY_CONFIG;
  const excluded = config.exclude.map(globToRegExp);
  const isExcluded = (file: string): boolean => excluded.some((re) => re.test(file));
  const result: ScanResult = { targets, filesScanned: 0, skipped: [], findings: [] };
  const seen = new Set<string>();

  for (const target of targets) {
    const collected = collectTarget(target, cwd);
    result.skipped.push(...collected.skipped);
    result.findings.push(...collected.findings.filter((f) => !isExcluded(f.file)));
    for (const file of collected.files) {
      if (seen.has(file.path) || isExcluded(file.path)) continue;
      seen.add(file.path);
      result.filesScanned++;
      result.findings.push(...scanFile(file));
    }
  }

  result.findings = sortFindings(
    result.findings
      .filter((f) => !config.disable.includes(f.ruleId))
      .map((f) => {
        const override = config.severity[f.ruleId];
        return override ? { ...f, severity: override } : f;
      }),
  );
  return result;
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
