import { lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import type { Finding, ScanFile, SkippedFile } from './types.js';
import { visible } from './sanitize.js';
import { manifestFinding } from './rules/manifest.js';
import { readZip } from './zip.js';

export const LIMITS = {
  /** Larger files are listed as skipped, never silently ignored. */
  maxFileBytes: 2 * 1024 * 1024,
  maxFiles: 5000,
  maxTotalBytes: 64 * 1024 * 1024,
  maxArchiveBytes: 200 * 1024 * 1024,
};

const SKIPPED_DIRECTORIES = new Set(['.git', 'node_modules']);

export interface Collected {
  files: ScanFile[];
  skipped: SkippedFile[];
  /** Findings about the structure itself (paths and links), not about file content. */
  findings: Finding[];
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

function displayPath(abs: string, cwd: string): string {
  const rel = path.relative(cwd, abs);
  if (rel === '') return '.';
  return visible(toPosix(rel.startsWith('..') || path.isAbsolute(rel) ? abs : rel));
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function collectDirectory(root: string, cwd: string, out: Collected): void {
  const realRoot = realpathSync(root);
  const stack = [root];
  let total = 0;
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    const names = readdirSync(dir).sort();
    for (const name of names) {
      const abs = path.join(dir, name);
      const shown = displayPath(abs, cwd);
      const info = lstatSync(abs);
      if (info.isSymbolicLink()) {
        let target: string;
        try {
          target = realpathSync(abs);
        } catch {
          out.skipped.push({ path: shown, reason: 'broken symbolic link' });
          continue;
        }
        if (isInside(realRoot, target)) out.skipped.push({ path: shown, reason: 'symbolic link (the target is scanned at its own path)' });
        else out.findings.push(manifestFinding('SK005', shown, 1, 'A symbolic link points outside the scanned folder; its target was not scanned.', `-> ${readlinkSync(abs)}`));
        continue;
      }
      if (info.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(name)) stack.push(abs);
        continue;
      }
      if (!info.isFile()) continue;
      if (out.files.length >= LIMITS.maxFiles) {
        out.skipped.push({ path: displayPath(root, cwd), reason: `more than ${LIMITS.maxFiles} files; the rest were not scanned` });
        return;
      }
      if (info.size > LIMITS.maxFileBytes) {
        out.skipped.push({ path: shown, reason: `larger than ${LIMITS.maxFileBytes} bytes` });
        continue;
      }
      if (total + info.size > LIMITS.maxTotalBytes) {
        out.skipped.push({ path: displayPath(root, cwd), reason: 'total size limit reached; the rest were not scanned' });
        return;
      }
      total += info.size;
      out.files.push({ path: shown, bytes: readFileSync(abs) });
    }
  }
}

function escapesArchive(name: string): boolean {
  return /^(?:[\\/]|[A-Za-z]:)/.test(name) || name.split(/[\\/]/).includes('..');
}

function collectArchive(file: string, cwd: string, out: Collected): void {
  const shownArchive = displayPath(file, cwd);
  const entries = readZip(readFileSync(file), {
    maxEntries: LIMITS.maxFiles,
    maxEntryBytes: LIMITS.maxFileBytes,
    maxTotalBytes: LIMITS.maxTotalBytes,
  });
  for (const entry of entries) {
    const shown = `${shownArchive}!/${visible(entry.name.replace(/\\/g, '/'))}`;
    if (escapesArchive(entry.name)) {
      out.findings.push(manifestFinding('SK004', shown, 1, 'An archive entry has a path that leaves the folder it is extracted into.', entry.name));
    }
    if (entry.symlink) {
      const target = entry.data ? entry.data.toString('utf8') : '';
      if (target === '' || escapesArchive(target)) {
        out.findings.push(manifestFinding('SK004', shown, 1, 'An archive entry is a symbolic link that points outside the skill folder.', `-> ${target}`));
      } else out.skipped.push({ path: shown, reason: 'symbolic link inside the archive' });
      continue;
    }
    if (entry.data) out.files.push({ path: shown, bytes: entry.data });
    else out.skipped.push({ path: shown, reason: entry.skipped ?? 'not read' });
  }
}

function looksLikeZip(file: string): boolean {
  if (/\.(?:zip|skill)$/i.test(file)) return true;
  return false;
}

/** Reads one target (a folder, a single file, or a .zip/.skill archive) into memory. */
export function collectTarget(target: string, cwd: string): Collected {
  const abs = path.resolve(cwd, target);
  const out: Collected = { files: [], skipped: [], findings: [] };
  let info;
  try {
    info = statSync(abs);
  } catch {
    throw new Error(`cannot read ${target}: no such file or folder`);
  }
  if (info.isDirectory()) collectDirectory(abs, cwd, out);
  else if (looksLikeZip(abs)) {
    if (info.size > LIMITS.maxArchiveBytes) throw new Error(`${target} is larger than ${LIMITS.maxArchiveBytes} bytes`);
    try {
      collectArchive(abs, cwd, out);
    } catch (error) {
      throw new Error(`cannot read ${target}: ${(error as Error).message}`);
    }
  } else if (info.size > LIMITS.maxFileBytes) out.skipped.push({ path: displayPath(abs, cwd), reason: `larger than ${LIMITS.maxFileBytes} bytes` });
  else out.files.push({ path: displayPath(abs, cwd), bytes: readFileSync(abs) });
  return out;
}
