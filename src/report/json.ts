import type { ScanResult } from '../types.js';
import { countBySeverity } from '../scan.js';

export function formatJson(result: ScanResult, version: string): string {
  return (
    JSON.stringify(
      {
        tool: 'skill-scan',
        version,
        targets: result.targets,
        summary: { filesScanned: result.filesScanned, findings: result.findings.length, bySeverity: countBySeverity(result.findings), skipped: result.skipped.length },
        findings: result.findings,
        skipped: result.skipped,
      },
      null,
      2,
    ) + '\n'
  );
}
