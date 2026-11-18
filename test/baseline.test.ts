import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { CLI, FIXTURES, tempDir } from './helpers.js';
import { applyBaseline, createBaseline } from '../src/baseline.js';
import { scanTargets } from '../src/scan.js';

function run(args: string[], cwd: string): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

const PIPE = fixtureLine('SKILL.md', 17); // the remote-script line of the malicious fixture
const WIPE = fixtureLine('scripts/setup.sh', 12); // its destructive line

function fixtureLine(file: string, line: number): string {
  return readFileSync(path.join(FIXTURES, 'malicious-skill', file), 'utf8').split('\n')[line - 1] as string;
}

test('known findings pass, a new finding fails, and line shifts do not matter', () => {
  const dir = tempDir({ 'run.sh': `${PIPE}\n` });
  assert.equal(run(['.'], dir).code, 1);

  const written = run(['.', '--write-baseline', 'baseline.json'], dir);
  assert.equal(written.code, 0, 'recording a baseline never fails the run');
  assert.match(written.stderr, /recorded 1 finding/);

  const known = run(['run.sh', '--baseline', 'baseline.json'], dir);
  assert.equal(known.code, 0);
  assert.match(known.stdout, /0 new finding\(s\)/);
  assert.match(known.stdout, /1 known finding\(s\) match the baseline/);
  assert.doesNotMatch(known.stdout, /SH001/);

  writeFileSync(path.join(dir, 'run.sh'), `#!/bin/sh\n# moved down\n\n${PIPE}\n`);
  assert.equal(run(['run.sh', '--baseline', 'baseline.json'], dir).code, 0, 'the same text on another line is still known');

  writeFileSync(path.join(dir, 'run.sh'), `${PIPE}\n${WIPE}\n`);
  const fresh = run(['run.sh', '--baseline', 'baseline.json'], dir);
  assert.equal(fresh.code, 1);
  assert.match(fresh.stdout, /SH002/);
  assert.doesNotMatch(fresh.stdout, /SH001/);
  assert.match(fresh.stdout, /1 new finding\(s\)/);
});

test('a second copy of a known line is new, and fixed entries are reported as stale', () => {
  const dir = tempDir({ 'run.sh': `${PIPE}\n` });
  run(['run.sh', '--write-baseline', 'baseline.json'], dir);

  writeFileSync(path.join(dir, 'run.sh'), `${PIPE}\n${PIPE}\n`);
  const twice = run(['run.sh', '--baseline', 'baseline.json', '--format', 'json'], dir);
  assert.equal(twice.code, 1);
  assert.deepEqual(JSON.parse(twice.stdout).summary.baseline, { known: 1, stale: 0, new: 1 });

  writeFileSync(path.join(dir, 'run.sh'), 'echo fixed\n');
  const fixed = run(['run.sh', '--baseline', 'baseline.json'], dir);
  assert.equal(fixed.code, 0);
  assert.match(fixed.stdout, /1 baseline entr\(y\/ies\) no longer match/);
});

test('a baseline is used only when named, and a wrong file is an error', () => {
  const dir = tempDir({ 'run.sh': `${PIPE}\n` });
  run(['.', '--write-baseline', 'skill-scan.baseline.json'], dir);
  assert.equal(run(['run.sh'], dir).code, 1, 'a baseline lying in the folder must not be picked up');

  writeFileSync(path.join(dir, 'other.json'), '{"findings":[]}');
  const wrong = run(['run.sh', '--baseline', 'other.json'], dir);
  assert.equal(wrong.code, 2);
  assert.match(wrong.stderr, /not a skill-scan baseline/);
  assert.equal(run(['run.sh', '--baseline', 'missing.json'], dir).code, 2);
  writeFileSync(path.join(dir, 'bad.json'), '{"tool":"skill-scan","baselineVersion":1,"findings":[{"fingerprint":"x","count":1}]}');
  assert.equal(run(['run.sh', '--baseline', 'bad.json'], dir).code, 2);
});

test('the baseline file holds no text from the scanned files, and SARIF marks new and known', () => {
  const dir = tempDir();
  const target = path.join(FIXTURES, 'malicious-skill');
  const all = scanTargets([target], { cwd: dir }).findings; // paths are part of the fingerprint, so scan from the same folder
  const baseline = createBaseline(all);
  assert.equal(baseline.findings.reduce((sum, e) => sum + e.count, 0), all.length);
  for (const entry of baseline.findings) assert.deepEqual(Object.keys(entry).sort(), ['count', 'file', 'fingerprint', 'ruleId']);

  const partial = { ...baseline, findings: baseline.findings.filter((e) => e.ruleId !== 'SH004') };
  const applied = applyBaseline(all, partial);
  assert.equal(applied.findings.filter((f) => !f.baseline).map((f) => f.ruleId).join(), 'SH004');

  writeFileSync(path.join(dir, 'b.json'), JSON.stringify(partial));
  const sarif = JSON.parse(run([target, '--baseline', 'b.json', '--format', 'sarif'], dir).stdout);
  const states = sarif.runs[0].results.map((r: { ruleId: string; baselineState: string }) => `${r.ruleId}:${r.baselineState}`);
  assert.ok(states.includes('SH004:new'));
  assert.equal(states.filter((s: string) => s.endsWith(':new')).length, 1);
});
