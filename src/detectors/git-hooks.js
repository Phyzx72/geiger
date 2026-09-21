// Git hooks and merge drivers: commands git runs by itself, with no prompt and
// no model in the loop — the same standing execution as an agent hook, and a
// place agent tooling now installs itself (graph rebuilds, lint, telemetry).
// Only the directories geiger was pointed at are read; nothing is executed.
import { j, isDir, exists, listDir, readText } from '../util/fsx.js';
import { scanText } from '../redact.js';
import { RISKY_COMMANDS, notesFor } from '../patterns.js';

const MAX_HOOKS = 20;
const CMD_CAP = 160;

/** Resolve a repo's git dir, following the `gitdir:` pointer of a worktree. */
function gitDir(projectDir) {
  const p = j(projectDir, '.git');
  if (isDir(p)) return p;
  const text = readText(p);
  const m = text && /^gitdir:\s*(.+)$/m.exec(text);
  const target = m && m[1].trim();
  return target && isDir(target) ? target : null;
}

/** Minimal git-config reader: section names plus the keys we care about. */
export function parseGitConfig(text) {
  const out = { hooksPath: null, mergeDrivers: [] };
  let section = '';
  let sub = '';
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const head = /^\[\s*([A-Za-z0-9.-]+)\s*(?:"([^"]*)")?\s*\]$/.exec(line);
    if (head) { section = head[1].toLowerCase(); sub = head[2] || ''; continue; }
    const kv = /^([A-Za-z0-9-]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const value = kv[2].trim();
    if (section === 'core' && key === 'hookspath') out.hooksPath = value;
    if (section === 'merge' && key === 'driver') out.mergeDrivers.push({ name: sub || '(unnamed)', driver: value });
  }
  return out;
}

// Shell keywords and builtins are not the interesting part of a hook. Real
// hooks open with guard clauses and only reach their program dozens of lines
// down, so report the programs it invokes rather than its first line.
const SHELL_WORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'case', 'esac', 'while', 'until', 'for', 'do', 'done',
  'exit', 'return', 'export', 'local', 'set', 'unset', 'shift', 'trap', 'cd', 'echo', 'printf', 'read', 'test',
  'true', 'false', 'continue', 'break', 'getopts', 'let', 'eval', 'exec', 'source', 'umask', 'wait', 'shopt', 'declare', 'function', 'command']);

/** Distinct program names a hook body invokes, in order of appearance. */
export function programsIn(text, cap = 8) {
  const found = [];
  let heredoc = null; // inside `<<PY ... PY` the lines are data, not commands
  let openQuote = null; // ...as are the lines of a multi-line `python -c "..."`
  for (const raw of String(text || '').split(/\r?\n/)) {
    if (heredoc !== null) {
      if (raw.trim() === heredoc) heredoc = null;
      continue;
    }
    if (openQuote !== null) {
      if (raw.includes(openQuote)) openQuote = null;
      continue;
    }
    // A quote still open at end of line means the next lines are its payload.
    let q = null;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];
      if (q) { if (ch === q && raw[i - 1] !== '\\') q = null; continue; }
      if (ch === '"' || ch === "'") q = ch;
      else if (ch === '#' && (i === 0 || /\s/.test(raw[i - 1]))) break;
    }
    openQuote = q;
    const hd = /<<-?\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z_][\w]*))/.exec(raw);
    if (hd) heredoc = hd[1] || hd[2] || hd[3];
    // Strip the comment tail first: splitting on |&; would otherwise turn
    // prose inside a comment into fake "commands".
    const code = raw.replace(/(^|\s)#.*$/, '$1');
    for (const part of code.split(/[|&;]+/)) {
      // Drop redirections (`2>&1`, `>out`) and shell noise before the token.
      const line = part.trim().replace(/^[({\s]+/, '').replace(/^\d*[<>]+\s*/, '');
      if (!line || line.startsWith('#') || line.startsWith('[') || line.startsWith('$')) continue;
      const tok = line.split(/\s+/)[0];
      if (!tok || tok.includes('=') || SHELL_WORDS.has(tok)) continue;
      const name = (tok.replace(/^["']|["']$/g, '').split(/[\\/]/).pop() || '').replace(/\.(exe|cmd|bat)$/i, '');
      // A program name starts with a letter: filters "1" out of `2>&1`.
      if (!name || !/^[A-Za-z_][\w.-]*$/.test(name) || SHELL_WORDS.has(name)) continue;
      if (!found.includes(name)) found.push(name);
      if (found.length >= cap) return found;
    }
  }
  return found;
}

export default {
  id: 'git-hooks',
  name: 'Git hooks & merge drivers',
  run(ctx) {
    const out = [];
    const dirs = (ctx.paths && ctx.paths.length ? ctx.paths : [ctx.cwd]).filter(Boolean);
    const seen = new Set();
    for (const dir of dirs) {
      const gd = gitDir(dir);
      if (!gd || seen.has(gd)) continue;
      seen.add(gd);

      const cfg = parseGitConfig(readText(j(gd, 'config')));
      const hooksDir = cfg.hooksPath
        ? (isDir(cfg.hooksPath) ? cfg.hooksPath : j(dir, cfg.hooksPath))
        : j(gd, 'hooks');

      // Hooks: git ships .sample files that never run — those are not findings.
      const names = isDir(hooksDir) ? listDir(hooksDir).filter((n) => !n.endsWith('.sample')) : [];
      const live = names.filter((n) => exists(j(hooksDir, n))).slice(0, MAX_HOOKS);
      if (live.length) {
        const notes = ['git runs these itself on commit, checkout, push and merge — no prompt, no approval'];
        const secrets = [];
        if (cfg.hooksPath) notes.push('core.hooksPath redirects hooks to ' + hooksDir + ' — they live outside this repo');
        for (const n of live) {
          const body = readText(j(hooksDir, n)) || '';
          const progs = programsIn(body);
          if (progs.length) notes.push(`${n}: runs ${progs.join(', ')}`);
          const marker = /Installed by:\s*([^\n]{1,60})/i.exec(body);
          if (marker) notes.push(`${n}: installed by ${marker[1].trim()}`);
          for (const risky of notesFor(body, RISKY_COMMANDS)) notes.push(`${n}: ${risky}`);
          for (const shape of scanText(body)) secrets.push({ key: '(in hook body)', shape, file: j(hooksDir, n) });
        }
        out.push({
          detector: 'git-hooks', kind: 'hook', name: `git hooks (${dir}): ${live.join(', ')}`,
          origin: { type: 'local', ref: hooksDir },
          exposures: secrets.length ? ['EXECUTES', 'HOLDS-SECRETS'] : ['EXECUTES'],
          evidence: [{ file: hooksDir, note: 'git hook scripts' }],
          secrets,
          notes,
        });
      }

      // Merge drivers run a command while git merges a file.
      for (const d of cfg.mergeDrivers.slice(0, MAX_HOOKS)) {
        out.push({
          detector: 'git-hooks', kind: 'config', name: `git merge driver "${d.name}" (${dir})`,
          origin: { type: 'local', ref: j(gd, 'config') },
          exposures: ['EXECUTES'],
          evidence: [{ file: j(gd, 'config'), note: 'command git runs when merging a matching file' }],
          notes: [
            'runs during any merge of the paths that select it in .gitattributes',
            'driver: ' + String(d.driver).slice(0, CMD_CAP),
            ...notesFor(d.driver, RISKY_COMMANDS),
          ],
        });
      }
    }
    return out;
  },
};
