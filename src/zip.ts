import { inflateRawSync } from 'node:zlib';

/**
 * A minimal, read-only ZIP reader. It never writes to disk, so a hostile entry name cannot place a
 * file anywhere, and every size is capped, so a "zip bomb" cannot exhaust memory.
 */
export interface ZipEntry {
  name: string;
  /** Present when the entry was read. */
  data?: Buffer;
  /** Present when the entry was not read, with the reason. */
  skipped?: string;
  symlink: boolean;
}

export interface ZipLimits {
  maxEntries: number;
  maxEntryBytes: number;
  maxTotalBytes: number;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;

export function readZip(buf: Buffer, limits: ZipLimits): ZipEntry[] {
  let eocd = -1;
  const lowest = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= lowest; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIGNATURE) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip archive (no end-of-central-directory record)');

  const count = buf.readUInt16LE(eocd + 10);
  const directoryOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || directoryOffset === 0xffffffff) throw new Error('ZIP64 archives are not supported');
  if (count > limits.maxEntries) throw new Error(`archive has ${count} entries (limit ${limits.maxEntries})`);

  const entries: ZipEntry[] = [];
  let total = 0;
  let pos = directoryOffset;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > buf.length || buf.readUInt32LE(pos) !== CENTRAL_SIGNATURE) throw new Error('corrupt zip archive (bad central directory)');
    const flags = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const nameLength = buf.readUInt16LE(pos + 28);
    const extraLength = buf.readUInt16LE(pos + 30);
    const commentLength = buf.readUInt16LE(pos + 32);
    const externalAttributes = buf.readUInt32LE(pos + 38);
    const localOffset = buf.readUInt32LE(pos + 42);
    if (pos + 46 + nameLength > buf.length) throw new Error('corrupt zip archive (truncated entry name)');
    const name = buf.toString('utf8', pos + 46, pos + 46 + nameLength);
    pos += 46 + nameLength + extraLength + commentLength;

    if (name.endsWith('/')) continue;
    const symlink = ((externalAttributes >>> 16) & 0o170000) === 0o120000;
    const entry: ZipEntry = { name, symlink };
    entries.push(entry);

    if (flags & 0x1) {
      entry.skipped = 'encrypted entry';
      continue;
    }
    if (method !== 0 && method !== 8) {
      entry.skipped = `unsupported compression method ${method}`;
      continue;
    }
    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) {
      entry.skipped = 'corrupt local header';
      continue;
    }
    const start = localOffset + 30 + buf.readUInt16LE(localOffset + 26) + buf.readUInt16LE(localOffset + 28);
    if (start + compressedSize > buf.length) {
      entry.skipped = 'truncated data';
      continue;
    }
    if (total >= limits.maxTotalBytes) {
      entry.skipped = 'archive size limit reached';
      continue;
    }
    const raw = buf.subarray(start, start + compressedSize);
    let data: Buffer;
    if (method === 0) {
      if (raw.length > limits.maxEntryBytes) {
        entry.skipped = 'file too large';
        continue;
      }
      data = Buffer.from(raw);
    } else {
      try {
        data = inflateRawSync(raw, { maxOutputLength: limits.maxEntryBytes });
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        entry.skipped = code === 'ERR_BUFFER_TOO_LARGE' ? 'file too large' : 'could not be decompressed';
        continue;
      }
    }
    total += data.length;
    entry.data = data;
  }
  return entries;
}
