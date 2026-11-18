/**
 * Shapes of well-known credentials. Used twice: to report a credential that is committed inside a
 * skill (rule EX005), and to redact every snippet before it is printed or written to a report.
 */
export const SECRET_PATTERNS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bsk-ant-[A-Za-z0-9_-]{20,}/,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}/,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/,
];

/** Replaces every credential-shaped run with a same-length mask, so column numbers stay valid. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    const global = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    out = out.replace(global, (match) => match.slice(0, 4) + '*'.repeat(Math.max(0, match.length - 4)));
  }
  return out;
}
