import { SEVERITIES, severityRank, type Finding, type ScanResult, type Severity } from '../types.js';
import { countBySeverity } from '../scan.js';

const COLORS: Record<Severity, string> = { critical: '\u001b[1;35m', high: '\u001b[1;31m', medium: '\u001b[33m', low: '\u001b[36m' };
const RESET = '\u001b[0m';
const DIM = '\u001b[2m';
const BOLD = '\u001b[1m';

export interface TextOptions {
  color: boolean;
  /** Findings below this severity are counted but not listed. */
  minSeverity: Severity;
}

export function formatText(result: ScanResult, options: TextOptions): string {
  const paint = (code: string, text: string): string => (options.color ? `${code}${text}${RESET}` : text);
  const fresh = result.findings.filter((f) => !f.baseline);
  const shown = fresh.filter((f) => severityRank(f.severity) >= severityRank(options.minSeverity));
  const lines: string[] = [];

  const byFile = new Map<string, Finding[]>();
  for (const f of shown) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
  for (const [file, findings] of byFile) {
    lines.push(paint(BOLD, file));
    for (const f of findings) {
      lines.push(`  ${paint(COLORS[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.ruleId}  ${f.title}  ${paint(DIM, `${f.line}:${f.column}`)}`);
      lines.push(`           ${f.message}`);
      if (f.snippet) lines.push(paint(DIM, `           > ${f.snippet}`));
    }
    lines.push('');
  }

  const counts = countBySeverity(fresh);
  const summary = [...SEVERITIES].reverse().map((s) => `${counts[s]} ${s}`).join(', ');
  lines.push(`${result.filesScanned} file(s) scanned, ${fresh.length} ${result.baseline ? 'new ' : ''}finding(s): ${summary}`);
  if (result.baseline) {
    lines.push(`${result.baseline.known} known finding(s) match the baseline and are not listed.`);
    if (result.baseline.stale > 0) lines.push(`${result.baseline.stale} baseline entr(y/ies) no longer match anything; refresh the file with --write-baseline.`);
  }
  const hidden = fresh.length - shown.length;
  if (hidden > 0) lines.push(`${hidden} finding(s) below "${options.minSeverity}" are not listed (see --min-severity).`);
  if (result.skipped.length > 0) {
    lines.push(`${result.skipped.length} file(s) were NOT scanned:`);
    for (const s of result.skipped.slice(0, 20)) lines.push(`  ${s.path}: ${s.reason}`);
    if (result.skipped.length > 20) lines.push(`  ... and ${result.skipped.length - 20} more (use --format json for the full list)`);
  }
  if (result.findings.length === 0) lines.push('No known risky pattern was found. This is not proof that the content is safe.');
  else if (fresh.length === 0) lines.push('Nothing new since the baseline.');
  return lines.join('\n') + '\n';
}
