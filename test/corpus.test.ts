import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { FIXTURES } from './helpers.js';
import { scanTargets } from '../src/scan.js';
import { severityRank } from '../src/types.js';

/**
 * Regression corpus. Every finding in it is recorded in expected.json, so a rule change that adds a
 * false positive or loses a detection fails here and has to be looked at.
 *
 *   benign/                  honest skills: nothing may reach the default gate (high)
 *   known-false-positives/   honest text the scanner still reports at high; kept so the limit stays visible
 *   hostile/                 attacks dressed up as honest text: each sample must still fail the gate
 *
 * After an intended change: UPDATE_CORPUS=1 npm test, then read the diff of expected.json.
 */
const CORPUS = path.join(FIXTURES, 'corpus');
const EXPECTED = path.join(CORPUS, 'expected.json');
const CATEGORIES = ['benign', 'known-false-positives', 'hostile'] as const;
const GATE = severityRank('high');

type Recorded = Record<string, string[]>;

/** sample ("benign/api-client") -> findings as "file:line ruleId severity", in report order. */
function scanCorpus(): Recorded {
  const out: Recorded = {};
  for (const category of CATEGORIES) {
    const samples = readdirSync(path.join(CORPUS, category), { withFileTypes: true }).filter((entry) => entry.isDirectory());
    for (const sample of samples.map((entry) => entry.name).sort()) {
      const name = `${category}/${sample}`;
      const result = scanTargets([name], { cwd: CORPUS });
      assert.deepEqual(result.skipped, [], `${name}: every file must be scanned`);
      out[name] = result.findings.map((f) => `${f.file.slice(name.length + 1)}:${f.line} ${f.ruleId} ${f.severity}${f.cautionary ? ' (warning text)' : ''}`);
    }
  }
  return out;
}

function reachesGate(findings: string[]): boolean {
  return findings.some((line) => severityRank(line.split(' ')[2] as 'low') >= GATE);
}

const actual = scanCorpus();
if (process.env.UPDATE_CORPUS === '1') writeFileSync(EXPECTED, `${JSON.stringify(actual, null, 2)}\n`);

test('corpus: findings are exactly the recorded ones', () => {
  const expected = JSON.parse(readFileSync(EXPECTED, 'utf8')) as Recorded;
  assert.deepEqual(
    actual,
    expected,
    'The corpus findings changed. If the change is intended, run UPDATE_CORPUS=1 npm test and review the diff of test/fixtures/corpus/expected.json.',
  );
});

test('corpus: an honest skill never fails the default gate', () => {
  const samples = Object.entries(actual).filter(([name]) => name.startsWith('benign/'));
  assert.ok(samples.length >= 5);
  for (const [name, findings] of samples) {
    assert.ok(!reachesGate(findings), `${name} is honest but would fail --fail-on high: ${findings.join(', ')}`);
  }
});

test('corpus: an attack dressed up as honest text still fails the default gate', () => {
  const samples = Object.entries(actual).filter(([name]) => name.startsWith('hostile/'));
  assert.ok(samples.length >= 4);
  for (const [name, findings] of samples) assert.ok(reachesGate(findings), `${name} is hostile but would pass --fail-on high`);
});

test('corpus: a known false positive is moved to benign/ once it is fixed', () => {
  for (const [name, findings] of Object.entries(actual).filter(([sample]) => sample.startsWith('known-false-positives/'))) {
    assert.ok(reachesGate(findings), `${name} no longer fails the gate: move it to benign/`);
  }
});
