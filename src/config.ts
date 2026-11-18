import { readFileSync } from 'node:fs';
import { isSeverity, type ScanConfig, type Severity } from './types.js';
import { ruleById } from './rules/index.js';

/**
 * The configuration is read only from the file the user names with `--config`. It is never
 * discovered inside the scanned folder and there are no inline "ignore" comments: the content being
 * scanned is untrusted, and it must not be able to switch its own findings off.
 */
export function loadConfig(file: string): ScanConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`cannot read config ${file}: ${(error as Error).message}`);
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error(`config ${file} must be a JSON object`);
  const input = raw as Record<string, unknown>;
  const known = ['disable', 'severity', 'exclude', '$schema'];
  for (const key of Object.keys(input)) {
    if (!known.includes(key)) throw new Error(`config ${file}: unknown key "${key}"`);
  }

  const stringList = (key: string): string[] => {
    const value = input[key];
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) throw new Error(`config ${file}: "${key}" must be a list of strings`);
    return value as string[];
  };

  const disable = stringList('disable');
  const severity: Record<string, Severity> = {};
  const overrides = input.severity ?? {};
  if (typeof overrides !== 'object' || overrides === null || Array.isArray(overrides)) throw new Error(`config ${file}: "severity" must be an object`);
  for (const [id, value] of Object.entries(overrides)) {
    if (!isSeverity(value)) throw new Error(`config ${file}: severity of ${id} must be low, medium, high or critical`);
    severity[id] = value;
  }
  for (const id of [...disable, ...Object.keys(severity)]) {
    if (!ruleById(id)) throw new Error(`config ${file}: unknown rule "${id}"`);
  }
  return { disable, severity, exclude: stringList('exclude') };
}

/** `*` matches inside one path segment, `**` across segments, `?` one character. */
export function globToRegExp(glob: string): RegExp {
  let source = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i] as string;
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') {
          i++;
          source += '(?:.*/)?';
        } else source += '.*';
      } else source += '[^/]*';
    } else if (ch === '?') source += '[^/]';
    else source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${source}$`);
}
