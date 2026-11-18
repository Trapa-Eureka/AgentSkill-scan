import type { ScanResult } from '../types.js';
import { countBySeverity } from '../scan.js';
import { ruleById } from '../rules/index.js';

export function formatJson(result: ScanResult, version: string): string {
  return (
    JSON.stringify(
      {
        tool: 'skill-scan',
        version,
        targets: result.targets,
        summary: {
          filesScanned: result.filesScanned,
          findings: result.findings.length,
          bySeverity: countBySeverity(result.findings),
          skipped: result.skipped.length,
          ...(result.baseline ? { baseline: { ...result.baseline, new: result.findings.filter((f) => !f.baseline).length } } : {}),
        },
        findings: result.findings.map((f) => ({ ...f, remediation: ruleById(f.ruleId)?.remediation ?? '' })),
        skipped: result.skipped,
      },
      null,
      2,
    ) + '\n'
  );
}
