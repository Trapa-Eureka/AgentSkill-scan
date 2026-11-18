import { redactSecrets } from './rules/secrets.js';

// Control characters, and Unicode characters that are invisible or reorder text.
const UNSAFE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u200B-\u200F\u2028-\u202E\u2060-\u2069\uFEFF]|[\u{E0000}-\u{E007F}]/gu;

/**
 * Makes untrusted text safe to print: a scanned file (or a file name inside an archive) could carry
 * terminal escape sequences or invisible characters, so they are shown as `<U+XXXX>` instead.
 */
export function visible(text: string): string {
  return text.replace(/\t/g, ' ').replace(UNSAFE, (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return `<U+${code.toString(16).toUpperCase().padStart(4, '0')}>`;
  });
}

const SNIPPET_BEFORE = 60;
const SNIPPET_LENGTH = 200;

/** The part of a line around a match: credentials masked, unsafe characters made visible. */
export function makeSnippet(line: string, index: number): string {
  const redacted = redactSecrets(line);
  const start = Math.max(0, index - SNIPPET_BEFORE);
  const end = Math.min(redacted.length, start + SNIPPET_LENGTH);
  const body = visible(redacted.slice(start, end)).trim();
  return (start > 0 ? '…' : '') + body + (end < redacted.length ? '…' : '');
}
