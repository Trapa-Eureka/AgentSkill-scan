import type { Finding, RuleMeta } from '../types.js';
import { makeSnippet } from '../sanitize.js';

export const SK_RULES: Record<string, RuleMeta> = {
  SK001: {
    id: 'SK001',
    title: 'Skill manifest incomplete',
    category: 'manifest',
    severity: 'low',
    description: 'SKILL.md has no front matter, or it lacks `name` or `description`. The agent decides when to load a skill from these fields.',
    remediation: 'Add front matter with `name` and `description`.',
  },
  SK002: {
    id: 'SK002',
    title: 'Unrestricted tool grant',
    category: 'manifest',
    severity: 'low',
    description: '`allowed-tools` grants every tool or an unrestricted shell, so commands in this skill run without a prompt.',
    remediation: 'List only the specific commands the skill needs, for example `Bash(git status:*)`.',
  },
  SK003: {
    id: 'SK003',
    title: 'Bundled file that cannot be inspected',
    category: 'manifest',
    severity: 'medium',
    description: 'A compiled executable, library or nested archive is shipped with the skill. Static rules cannot read it.',
    remediation: 'Ask for the source, or inspect the file with a tool made for that format before running it.',
  },
  SK004: {
    id: 'SK004',
    title: 'Path escapes the skill folder',
    category: 'manifest',
    severity: 'high',
    description: 'An archive entry (a path or a symbolic link) points outside the skill folder, which can overwrite or expose files elsewhere when the skill is installed or read.',
    remediation: 'Do not extract the archive with a tool that follows such paths. Remove the entry or link.',
  },
  SK005: {
    id: 'SK005',
    title: 'Symbolic link leaves the scanned folder',
    category: 'manifest',
    severity: 'medium',
    description: 'A symbolic link on disk points outside the folder being scanned. Its target was not scanned, and an agent that follows it reads files from elsewhere.',
    remediation: 'Check where the link points. Scan the target separately if it is another skill; remove the link if it points at private files.',
  },
};

export function manifestFinding(ruleId: string, file: string, line: number, message: string, snippet = ''): Finding {
  const meta = SK_RULES[ruleId] as RuleMeta;
  return {
    ruleId: meta.id,
    title: meta.title,
    category: meta.category,
    severity: meta.severity,
    message,
    file,
    line,
    column: 1,
    snippet: makeSnippet(snippet, 0),
  };
}

interface Field {
  value: string;
  line: number;
}

/** A small reader for the flat `key: value` front matter that skills use. Not a YAML parser. */
export function parseFrontmatter(lines: string[]): Map<string, Field> | null {
  if ((lines[0] ?? '').trim() !== '---') return null;
  const end = lines.findIndex((text, i) => i > 0 && /^(?:---|\.\.\.)\s*$/.test(text));
  if (end < 0) return null;
  const fields = new Map<string, Field>();
  let current: string | null = null;
  for (let i = 1; i < end; i++) {
    const text = lines[i] ?? '';
    const top = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(text);
    if (top) {
      current = (top[1] ?? '').toLowerCase();
      const raw = (top[2] ?? '').trim();
      fields.set(current, { value: /^[|>][+-]?$/.test(raw) ? '' : raw, line: i + 1 });
    } else if (current && /^\s+\S/.test(text)) {
      const field = fields.get(current) as Field;
      const item = text.trim().replace(/^-\s+/, '');
      field.value = field.value ? `${field.value}, ${item}` : item;
    }
  }
  return fields;
}

function splitTools(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of value.replace(/^\[|\]$/g, '')) {
    if (ch === '(') depth++;
    if (ch === ')') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      out.push(current);
      current = '';
    } else current += ch;
  }
  out.push(current);
  return out.map((tool) => tool.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
}

const BROAD_TOOL = /^(?:\*|Bash|Bash\(\s*\*?\s*\)|Bash\(\s*:\*\s*\))$/;

export function checkManifest(file: string, lines: string[]): Finding[] {
  const out: Finding[] = [];
  const isSkill = /(?:^|\/)SKILL\.md$/i.test(file);
  const fields = parseFrontmatter(lines);

  if (isSkill) {
    if (!fields) out.push(manifestFinding('SK001', file, 1, 'SKILL.md has no front matter.', lines[0] ?? ''));
    else {
      const missing = ['name', 'description'].filter((key) => !fields.get(key)?.value);
      if (missing.length > 0) out.push(manifestFinding('SK001', file, 1, `SKILL.md front matter is missing: ${missing.join(', ')}.`));
    }
  }

  const tools = fields?.get('allowed-tools');
  if (tools) {
    const broad = splitTools(tools.value).filter((tool) => BROAD_TOOL.test(tool));
    if (broad.length > 0) {
      out.push(manifestFinding('SK002', file, tools.line, `allowed-tools grants ${broad.join(', ')} with no restriction.`, lines[tools.line - 1] ?? ''));
    }
  }
  return out;
}

const OPAQUE_EXTENSION = /\.(?:exe|dll|dylib|so|node|jar|class|pyc|pyo|wasm|bin|zip|tar|gz|tgz|bz2|xz|7z|rar|dmg|pkg|msi|deb|rpm|skill)$/i;

/** Compiled code or a nested archive, judged from the first bytes and the extension. */
export function opaqueKind(path: string, bytes: Buffer): string | null {
  if (bytes.length >= 4) {
    const magic = bytes.readUInt32BE(0);
    if (magic === 0x7f454c46) return 'ELF executable';
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(magic)) return 'Mach-O or Java binary';
    if (magic === 0x0061736d) return 'WebAssembly module';
    if (magic === 0x504b0304) return 'nested zip archive';
    if (bytes.readUInt16BE(0) === 0x4d5a) return 'Windows executable';
    if (bytes.readUInt16BE(0) === 0x1f8b) return 'gzip archive';
  }
  const ext = OPAQUE_EXTENSION.exec(path);
  return ext ? `${ext[0].toLowerCase()} file` : null;
}
