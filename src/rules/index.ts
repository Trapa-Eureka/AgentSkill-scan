import type { RuleMeta } from '../types.js';
import { LINE_RULES } from './line-rules.js';
import { PI004, PI005 } from './hidden.js';
import { AC_RULES } from './structured.js';
import { SK_RULES } from './manifest.js';

/** Every rule the scanner knows, sorted by id. This list drives `--list-rules` and the SARIF rule table. */
export const ALL_RULES: RuleMeta[] = [
  ...LINE_RULES.map(({ id, title, category, severity, description, remediation }) => ({ id, title, category, severity, description, remediation })),
  PI004,
  PI005,
  ...Object.values(AC_RULES),
  ...Object.values(SK_RULES),
].sort((a, b) => a.id.localeCompare(b.id));

export function ruleById(id: string): RuleMeta | undefined {
  return ALL_RULES.find((rule) => rule.id === id);
}
