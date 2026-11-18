export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

export type Category = 'prompt-injection' | 'exfiltration' | 'shell' | 'agent-config' | 'manifest';

/** What every rule has, whether it is a line pattern or a structured check. */
export interface RuleMeta {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  remediation: string;
}

/** A rule that is matched against one (logical) line of text. */
export interface LineRule extends RuleMeta {
  patterns: RegExp[];
  /**
   * When true, a match in the prose of a document (outside a fenced code block) on a line that
   * reads like a warning ("never run ...") is reported one severity level lower.
   */
  cautionaryDowngrade?: boolean;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  message: string;
  /** Display path, forward slashes, control characters made visible. */
  file: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** The offending text, redacted and made safe to print. */
  snippet: string;
  /** True when the severity was lowered because the line reads like a warning. */
  cautionary?: boolean;
  /** True when the finding matches an entry of the baseline given with `--baseline`. */
  baseline?: boolean;
}

export interface ScanFile {
  /** Display path (see Finding.file). */
  path: string;
  bytes: Buffer;
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface ScanResult {
  targets: string[];
  filesScanned: number;
  skipped: SkippedFile[];
  findings: Finding[];
  /** Present when a baseline was applied. */
  baseline?: { known: number; stale: number };
}

export interface ScanConfig {
  /** Rule ids that are switched off. */
  disable: string[];
  /** Per-rule severity overrides. */
  severity: Record<string, Severity>;
  /** Glob patterns (matched against the display path) of files that are not scanned. */
  exclude: string[];
}

export const EMPTY_CONFIG: ScanConfig = { disable: [], severity: {}, exclude: [] };
