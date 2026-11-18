import { SEVERITIES, severityRank, type ScanResult, type Severity } from '../types.js';
import { countBySeverity } from '../scan.js';
import { ruleById } from '../rules/index.js';

/** A pull request comment holds 65,536 characters; keep the table well below that. */
const MAX_ROWS = 50;
const MAX_SKIPPED = 20;

export interface MarkdownOptions {
  /** Findings below this severity are counted but not listed. */
  minSeverity: Severity;
}

/**
 * Text from a scanned file goes into a code span and nowhere else. Inside a code span Markdown
 * renders no HTML, no links, no images and no @mentions, so hostile content cannot change the page
 * the report is posted on. A backtick would end the span and a pipe would end the table cell, so
 * both are replaced.
 */
function code(text: string): string {
  const safe = text.replace(/`/g, "'").replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').trim();
  return safe ? `\`${safe}\`` : '';
}

/** Markdown for a pull request comment or a GitHub Actions job summary. */
export function formatMarkdown(result: ScanResult, options: MarkdownOptions): string {
  const fresh = result.findings.filter((f) => !f.baseline);
  const listed = fresh.filter((f) => severityRank(f.severity) >= severityRank(options.minSeverity));
  const ordered = [...listed].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const rows = ordered.slice(0, MAX_ROWS);
  const counts = countBySeverity(fresh);
  const summary = [...SEVERITIES].reverse().map((s) => `${counts[s]} ${s}`).join(', ');
  const lines: string[] = ['## skill-scan', ''];

  lines.push(`**${fresh.length} ${result.baseline ? 'new ' : ''}finding(s)** in ${result.filesScanned} file(s): ${summary}`);
  if (result.baseline) {
    lines.push('', `${result.baseline.known} known finding(s) match the baseline and are not listed.`);
    if (result.baseline.stale > 0) lines.push(`${result.baseline.stale} baseline entr(y/ies) no longer match anything; refresh the file with \`--write-baseline\`.`);
  }

  if (rows.length > 0) {
    lines.push('', '| Severity | Rule | Location | Text |', '|---|---|---|---|');
    for (const f of rows) {
      lines.push(`| ${f.severity}${f.cautionary ? ' (warning text)' : ''} | ${f.ruleId} ${f.title} | ${code(`${f.file}:${f.line}`)} | ${code(f.snippet)} |`);
    }
  }
  const notListed = fresh.length - rows.length;
  if (notListed > 0) {
    const below = fresh.length - listed.length;
    const reasons = [below > 0 ? `${below} below "${options.minSeverity}"` : '', listed.length > MAX_ROWS ? `the table is limited to ${MAX_ROWS} rows` : ''].filter(Boolean);
    lines.push('', `${notListed} more finding(s) are not listed (${reasons.join('; ')}). The JSON or SARIF report has all of them.`);
  }

  const ruleIds = [...new Set(rows.map((f) => f.ruleId))].sort();
  if (ruleIds.length > 0) {
    lines.push('', '<details>', '<summary>What to do</summary>', '');
    for (const id of ruleIds) {
      const rule = ruleById(id);
      if (rule) lines.push(`- **${rule.id} ${rule.title}**: ${rule.remediation}`);
    }
    lines.push('', '</details>');
  }

  if (result.skipped.length > 0) {
    lines.push('', `**${result.skipped.length} file(s) were not scanned:**`, '');
    for (const s of result.skipped.slice(0, MAX_SKIPPED)) lines.push(`- ${code(s.path)}: ${s.reason}`);
    if (result.skipped.length > MAX_SKIPPED) lines.push(`- ... and ${result.skipped.length - MAX_SKIPPED} more`);
  }

  if (result.findings.length === 0) lines.push('', 'No known risky pattern was found. This is not proof that the content is safe.');
  else if (fresh.length === 0) lines.push('', 'Nothing new since the baseline.');
  return lines.join('\n') + '\n';
}
