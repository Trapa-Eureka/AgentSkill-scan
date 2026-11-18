import type { Finding, RuleMeta } from '../types.js';
import { makeSnippet, visible } from '../sanitize.js';

export const PI004: RuleMeta = {
  id: 'PI004',
  title: 'Hidden Unicode characters',
  category: 'prompt-injection',
  severity: 'high',
  description:
    'Invisible Unicode (tag characters, bidirectional overrides, runs of zero-width characters). A person reviewing the file does not see this text, but the model reads it.',
  remediation: 'Delete the invisible characters and read what they spelled out.',
};

export const PI005: RuleMeta = {
  id: 'PI005',
  title: 'Instructions inside an HTML comment',
  category: 'prompt-injection',
  severity: 'medium',
  description: 'An HTML comment is not shown when Markdown is rendered, but the agent reads it. This one addresses the agent or carries a command.',
  remediation: 'Read the comment in the raw file. Remove it if it gives the agent instructions.',
};

const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/u;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const ZERO_WIDTH = /[\u200B\u2060-\u2064\uFEFF]/g;
const ZERO_WIDTH_THRESHOLD = 4;

function decodeTags(run: string): string {
  let out = '';
  for (const ch of run) {
    const code = (ch.codePointAt(0) ?? 0) - 0xe0000;
    if (code >= 0x20 && code < 0x7f) out += String.fromCharCode(code);
  }
  return out;
}

function finding(meta: RuleMeta, file: string, line: number, column: number, message: string, text: string): Finding {
  return {
    ruleId: meta.id,
    title: meta.title,
    category: meta.category,
    severity: meta.severity,
    message,
    file,
    line,
    column,
    snippet: makeSnippet(text, Math.max(0, column - 1)),
  };
}

/** `lines` must already have a leading byte-order mark removed. */
export function checkHiddenUnicode(file: string, lines: string[]): Finding[] {
  const out: Finding[] = [];
  lines.forEach((text, i) => {
    const tags = TAG_CHARS.exec(text);
    if (tags) {
      const decoded = decodeTags(tags[0]);
      const said = decoded ? ` It decodes to: "${visible(decoded).slice(0, 160)}"` : '';
      out.push(finding(PI004, file, i + 1, tags.index + 1, `Unicode tag characters hide text from a human reader.${said}`, text));
      return;
    }
    const bidi = BIDI.exec(text);
    if (bidi) {
      out.push(finding(PI004, file, i + 1, bidi.index + 1, 'A bidirectional control character changes the order in which this line is displayed.', text));
      return;
    }
    const zero = text.match(ZERO_WIDTH);
    if (zero && zero.length >= ZERO_WIDTH_THRESHOLD) {
      const column = text.search(/[\u200B\u2060-\u2064\uFEFF]/) + 1;
      out.push(finding(PI004, file, i + 1, column, `${zero.length} zero-width characters on one line, which can encode hidden data.`, text));
    }
  });
  return out;
}

const COMMENT = /<!--([\s\S]{0,4000}?)-->/g;
const ADDRESSES_AGENT =
  /\b(?:you (?:must|should|are|will|have to)|ignore (?:the|all|any|previous|prior)|system prompt|do not (?:tell|mention|reveal)|don't (?:tell|mention|reveal)|(?:assistant|claude|agent|ai|model)\s*[:,]|(?:run|execute)\b.{0,40}\b(?:command|script|shell|bash)|\bcurl\s+\S|\bwget\s+\S|send\b.{0,60}\bhttps?:)/i;

export function checkHtmlComments(file: string, content: string): Finding[] {
  const out: Finding[] = [];
  for (const match of content.matchAll(COMMENT)) {
    const body = match[1] ?? '';
    if (!ADDRESSES_AGENT.test(body)) continue;
    const before = content.slice(0, match.index);
    const line = before.split('\n').length;
    const column = match.index - (before.lastIndexOf('\n') + 1) + 1;
    out.push({
      ruleId: PI005.id,
      title: PI005.title,
      category: PI005.category,
      severity: PI005.severity,
      message: 'A comment that is invisible in rendered Markdown gives the agent instructions.',
      file,
      line,
      column,
      snippet: makeSnippet(match[0].replace(/\s+/g, ' '), 0),
    });
  }
  return out;
}
