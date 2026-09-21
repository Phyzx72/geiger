// What a skill actually says. A skill is instructions an agent loads and
// follows, so its text is the payload — a name in a directory listing tells
// you nothing. Read-only: frontmatter, a steering-text scan, and credential
// shapes. The body is never copied into a report.
import { j, exists, isDir, listDir, readText } from './util/fsx.js';
import { scanText } from './redact.js';
import { STEERING_TEXT, RISKY_COMMANDS, notesFor } from './patterns.js';

const BODY_CAP = 200_000; // a playbook that large is already a finding in itself
const DESC_CAP = 140;

/** The instruction file of a skill directory, or the skill file itself. */
function skillFile(path) {
  if (!isDir(path)) return /\.(md|markdown)$/i.test(path) && exists(path) ? path : null;
  for (const name of ['SKILL.md', 'skill.md', 'README.md', 'AGENT.md', 'AGENTS.md']) {
    if (exists(j(path, name))) return j(path, name);
  }
  const md = listDir(path).find((n) => /\.(md|markdown)$/i.test(n));
  return md ? j(path, md) : null;
}

/**
 * YAML frontmatter `description:` (or `name:`). Handles a plain or quoted
 * value and the folded block scalars (`description: >`) that real skills use —
 * without them the value reads as a bare ">".
 */
export function frontmatterField(text, field) {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(String(text || ''));
  if (!fm) return null;
  const lines = fm[1].split(/\r?\n/);
  const at = lines.findIndex((l) => new RegExp('^' + field + ':', 'i').test(l));
  if (at === -1) return null;
  let value = lines[at].slice(lines[at].indexOf(':') + 1).trim();
  if (value === '>' || value === '|' || value === '>-' || value === '|-') {
    const folded = [];
    for (let i = at + 1; i < lines.length && /^\s+\S/.test(lines[i]); i++) folded.push(lines[i].trim());
    value = folded.join(' ');
  }
  value = value.replace(/^["']|["']$/g, '').trim();
  return value ? value.slice(0, DESC_CAP) : null;
}

/**
 * Inspect one skill. Returns { file, description, notes, secrets } — notes are
 * plain-language flags, secrets are shape-only.
 */
export function inspectSkill(path) {
  const file = skillFile(path);
  if (!file) {
    return {
      file: null, description: null, secrets: [],
      notes: ['no instruction file here — the directory may hold nested skills, which are not read'],
    };
  }
  const text = (readText(file) || '').slice(0, BODY_CAP);
  const description = frontmatterField(text, 'description');
  const notes = [];
  if (description) notes.push('says: ' + description);
  for (const n of notesFor(text, STEERING_TEXT)) notes.push('instruction text ' + n);
  for (const n of notesFor(text, RISKY_COMMANDS)) notes.push('contains a command that ' + n);
  const secrets = scanText(text).map((shape) => ({ key: '(in skill text)', shape, file }));
  return { file, description, notes, secrets };
}
