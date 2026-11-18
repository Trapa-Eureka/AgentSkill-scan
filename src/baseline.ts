import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Finding } from './types.js';

/**
 * A baseline is the list of findings a team has already looked at. With `--baseline`, those are
 * still reported as known, but only findings that are NOT in the baseline fail the run.
 *
 * Like the policy file, a baseline is read only from the path the user names. It is never
 * discovered inside the scanned folder.
 */
export interface BaselineEntry {
  fingerprint: string;
  /** For the person reviewing the baseline file; not used for matching. */
  ruleId: string;
  file: string;
  /** How many identical findings (same rule, file and text) are accepted. */
  count: number;
}

export interface Baseline {
  tool: 'skill-scan';
  baselineVersion: 1;
  findings: BaselineEntry[];
}

/**
 * Identifies a finding by rule, file and offending text, not by line number, so that adding or
 * removing lines elsewhere in the file does not turn a known finding into a new one.
 */
export function fingerprint(finding: Finding): string {
  return createHash('sha256').update(`${finding.ruleId}\n${finding.file}\n${finding.snippet}`).digest('hex').slice(0, 32);
}

export function createBaseline(findings: Finding[]): Baseline {
  const entries = new Map<string, BaselineEntry>();
  for (const f of findings) {
    const id = fingerprint(f);
    const entry = entries.get(id);
    if (entry) entry.count++;
    else entries.set(id, { fingerprint: id, ruleId: f.ruleId, file: f.file, count: 1 });
  }
  const sorted = [...entries.values()].sort(
    (a, b) => a.file.localeCompare(b.file) || a.ruleId.localeCompare(b.ruleId) || a.fingerprint.localeCompare(b.fingerprint),
  );
  return { tool: 'skill-scan', baselineVersion: 1, findings: sorted };
}

export function formatBaseline(baseline: Baseline): string {
  return JSON.stringify(baseline, null, 2) + '\n';
}

export function loadBaseline(file: string): Baseline {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read baseline ${file}: ${(error as Error).message}`);
  }
  const input = raw as Partial<Baseline> | null;
  if (typeof input !== 'object' || input === null || input.tool !== 'skill-scan' || input.baselineVersion !== 1 || !Array.isArray(input.findings)) {
    throw new Error(`baseline ${file} is not a skill-scan baseline (create one with --write-baseline)`);
  }
  for (const entry of input.findings as Partial<BaselineEntry>[]) {
    const valid =
      typeof entry === 'object' &&
      entry !== null &&
      typeof entry.fingerprint === 'string' &&
      /^[0-9a-f]{32}$/.test(entry.fingerprint) &&
      Number.isInteger(entry.count) &&
      (entry.count as number) >= 1;
    if (!valid) throw new Error(`baseline ${file} has an invalid entry`);
  }
  return input as Baseline;
}

export interface BaselineResult {
  /** The same findings, with `baseline: true` on those the baseline accepts. */
  findings: Finding[];
  known: number;
  /** Baseline entries that no longer match anything: fixed, or the text changed. */
  stale: number;
}

export function applyBaseline(findings: Finding[], baseline: Baseline): BaselineResult {
  const remaining = new Map<string, number>();
  for (const entry of baseline.findings) remaining.set(entry.fingerprint, (remaining.get(entry.fingerprint) ?? 0) + entry.count);
  let known = 0;
  const marked = findings.map((f) => {
    const id = fingerprint(f);
    const left = remaining.get(id) ?? 0;
    if (left <= 0) return f;
    remaining.set(id, left - 1);
    known++;
    return { ...f, baseline: true };
  });
  let stale = 0;
  for (const left of remaining.values()) stale += left;
  return { findings: marked, known, stale };
}
