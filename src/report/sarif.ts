import { createHash } from 'node:crypto';
import type { ScanResult, Severity } from '../types.js';
import { ALL_RULES } from '../rules/index.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
// GitHub code scanning reads this number to show its own critical/high/medium/low label.
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.0', low: '2.0' };

/** SARIF 2.1.0, the format GitHub code scanning and most security dashboards accept. */
export function formatSarif(result: ScanResult, version: string): string {
  const rules = ALL_RULES.map((rule) => ({
    id: rule.id,
    name: rule.title.replace(/[^A-Za-z0-9]+(.)?/g, (_, next: string | undefined) => (next ? next.toUpperCase() : '')),
    shortDescription: { text: rule.title },
    fullDescription: { text: rule.description },
    help: { text: rule.remediation },
    defaultConfiguration: { level: LEVEL[rule.severity] },
    properties: { tags: ['security', rule.category], 'security-severity': SECURITY_SEVERITY[rule.severity] },
  }));

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ALL_RULES.findIndex((rule) => rule.id === f.ruleId),
    level: LEVEL[f.severity],
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: encodeURI(f.file) },
          region: { startLine: f.line, startColumn: f.column, ...(f.snippet ? { snippet: { text: f.snippet } } : {}) },
        },
      },
    ],
    partialFingerprints: {
      'skillScan/v1': createHash('sha256').update(`${f.ruleId}\n${f.file}\n${f.snippet}`).digest('hex').slice(0, 32),
    },
    properties: { severity: f.severity, 'security-severity': SECURITY_SEVERITY[f.severity], category: f.category },
  }));

  return (
    JSON.stringify(
      {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'skill-scan', version, informationUri: 'https://github.com/Trapa-Eureka/AgentSkill-scan', rules } },
            results,
          },
        ],
      },
      null,
      2,
    ) + '\n'
  );
}
