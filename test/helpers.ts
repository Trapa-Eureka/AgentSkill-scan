import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';
import { scanFile } from '../src/scan.js';
import type { Finding } from '../src/types.js';

/** dist/test -> repository root */
export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const FIXTURES = path.join(REPO, 'test', 'fixtures');
export const CLI = path.join(REPO, 'dist', 'src', 'cli.js');

export function scanText(file: string, text: string): Finding[] {
  return scanFile({ path: file, bytes: Buffer.from(text, 'utf8') });
}

export function ids(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.ruleId))].sort();
}

export function tempDir(files: Record<string, string | Buffer> = {}): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'skill-scan-test-'));
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(dir, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
  return dir;
}

function crc32(data: Buffer): number {
  let crc = ~0;
  for (const byte of data) {
    crc ^= byte;
    for (let k = 0; k < 8; k++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return ~crc >>> 0;
}

export interface ZipInput {
  name: string;
  data: string | Buffer;
  deflate?: boolean;
  /** Unix mode, e.g. 0o120777 for a symbolic link. */
  mode?: number;
}

/** Builds a zip archive in memory, including entries no ordinary tool would write. */
export function makeZip(inputs: ZipInput[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const input of inputs) {
    const raw = Buffer.isBuffer(input.data) ? input.data : Buffer.from(input.data, 'utf8');
    const body = input.deflate ? deflateRawSync(raw) : raw;
    const name = Buffer.from(input.name, 'utf8');
    const method = input.deflate ? 8 : 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc32(raw), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32(raw), 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(((input.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(inputs.length, 8);
  end.writeUInt16LE(inputs.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
