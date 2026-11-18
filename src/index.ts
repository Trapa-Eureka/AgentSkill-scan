export { scanTargets, scanFile, countBySeverity, type ScanOptions } from './scan.js';
export { loadConfig } from './config.js';
export { applyBaseline, createBaseline, fingerprint, loadBaseline, type Baseline, type BaselineEntry } from './baseline.js';
export { ALL_RULES, ruleById } from './rules/index.js';
export { formatRule, formatText } from './report/text.js';
export { formatJson } from './report/json.js';
export { formatSarif } from './report/sarif.js';
export { formatMarkdown } from './report/markdown.js';
export * from './types.js';
