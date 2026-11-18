import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { CLI, REPO, tempDir } from './helpers.js';
import { scanTargets } from '../src/scan.js';

function run(args: string[], cwd: string, env: Record<string, string> = {}): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', ...env } });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

test('the bundled skill passes its own scanner', () => {
  const result = scanTargets([path.join(REPO, 'skills')]);
  assert.equal(result.filesScanned, 1);
  assert.deepEqual(result.findings.map((f) => `${f.ruleId} ${f.file}:${f.line}`), []);
});

test('--install-skill writes a skill whose command really runs this scanner', () => {
  const dir = tempDir();
  const installed = run(['--install-skill', 'project'], dir);
  assert.equal(installed.code, 0);
  const file = path.join(dir, '.claude', 'skills', 'skill-scan', 'SKILL.md');
  assert.ok(installed.stdout.includes(file) || installed.stdout.includes('skill-scan/SKILL.md'));

  const text = readFileSync(file, 'utf8');
  assert.match(text, /^---\nname: skill-scan\ndescription: /);
  assert.ok(!text.includes('{{'), 'no placeholder is left in the installed skill');
  const command = /^\s*(node "[^"\n]+") <path> --format json/m.exec(text)?.[1];
  assert.ok(command, 'the installed skill names the command to run');
  const cli = JSON.parse(command.slice('node '.length)) as string;
  assert.ok(path.isAbsolute(cli) && existsSync(cli));

  writeFileSync(path.join(dir, 'run.sh'), 'chmod 777 ./x\n');
  const scan = spawnSync(process.execPath, [cli, 'run.sh', '--format', 'json', '--fail-on', 'none'], { cwd: dir, encoding: 'utf8' });
  assert.equal(scan.status, 0);
  const report = JSON.parse(scan.stdout);
  assert.equal(report.findings[0].ruleId, 'SH006');
  assert.ok(report.findings[0].remediation, 'the fields the skill tells the agent to read exist');
  assert.ok(Array.isArray(report.skipped) && report.summary.bySeverity);

  assert.deepEqual(scanTargets(['.claude'], { cwd: dir }).findings, [], 'the installed skill is clean too');
  assert.equal(run(['--install-skill', 'project'], dir).code, 0, 'installing again updates it');
});

test('--install-skill user goes to the home folder, a path goes where it says', () => {
  const home = tempDir();
  const dir = tempDir();
  assert.equal(run(['--install-skill', 'user'], dir, { HOME: home, USERPROFILE: home }).code, 0);
  assert.ok(existsSync(path.join(home, '.claude', 'skills', 'skill-scan', 'SKILL.md')));
  assert.equal(run(['--install-skill', 'agent/skills'], dir).code, 0);
  assert.ok(existsSync(path.join(dir, 'agent', 'skills', 'skill-scan', 'SKILL.md')));
  assert.equal(run(['--install-skill'], dir).code, 2);
});

test('--install-skill never overwrites a file that is not its own', () => {
  const dir = tempDir();
  const file = path.join(dir, '.claude', 'skills', 'skill-scan', 'SKILL.md');
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, '---\nname: something-else\n---\nmine\n');
  const result = run(['--install-skill', 'project'], dir);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /left untouched/);
  assert.equal(readFileSync(file, 'utf8'), '---\nname: something-else\n---\nmine\n');
});
