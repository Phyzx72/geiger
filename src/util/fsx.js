// Read-only filesystem helpers. Geiger never writes outside its own --out file.
import fs from 'node:fs';
import path from 'node:path';

/**
 * Read a file as UTF-8, or null. Never throws. A leading byte-order mark is
 * dropped: Notepad, older Visual Studio and PowerShell 5.1 write one by
 * default, and JSON.parse rejects it — a BOM'd config must not become an
 * invisible one.
 */
export function readText(file) {
  try { return stripBom(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function stripBom(text) {
  return typeof text === 'string' ? text.replace(/^\uFEFF/, '') : text;
}

/** True if a path exists. Never throws. */
export function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

/** List directory entries (names), or []. Never throws. */
export function listDir(p) {
  try { return fs.readdirSync(p); } catch { return []; }
}

/** True if path is a directory. Never throws. */
export function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

/**
 * Tolerant JSON parse: strips // and / * * / comments and trailing commas
 * (agent configs in the wild are frequently JSON-with-comments).
 * Returns { value, error } — never throws.
 */
export function parseJsonTolerant(text) {
  if (text == null) return { value: null, error: 'missing' };
  text = stripBom(text);
  try {
    return { value: JSON.parse(text), error: null };
  } catch {
    try {
      const stripped = text
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:"'])\/\/[^\n]*/g, '$1')
        .replace(/,\s*([}\]])/g, '$1');
      return { value: JSON.parse(stripped), error: null };
    } catch (e2) {
      try {
        // Hand-edited Windows configs often contain lone backslashes in
        // paths. Escape any backslash that does not begin a valid JSON
        // escape sequence, then retry.
        const fixedSlashes = text.replace(/\\(?![\\/"bfnrtu])/g, '\\\\');
        return { value: JSON.parse(fixedSlashes), error: null };
      } catch {
        return { value: null, error: parseErrorLabel(e2) };
      }
    }
  }
}

/**
 * A parse-error label that carries a location, never content. V8's
 * "Unexpected token" messages quote the text around the error — in a config,
 * that can be part of a credential value, so the message text itself must
 * never reach a report.
 */
function parseErrorLabel(e) {
  const msg = String((e && e.message) || '');
  const lc = /line (\d+) column (\d+)/.exec(msg);
  if (lc) return `unparseable JSON (line ${lc[1]}, column ${lc[2]})`;
  const pos = /at position (\d+)/.exec(msg);
  return pos ? `unparseable JSON (byte ${pos[1]})` : 'unparseable JSON';
}

/** Read + tolerant-parse a JSON file. Returns { value, error, file }. */
export function readJson(file) {
  const text = readText(file);
  if (text == null || text.trim() === '') return { value: null, error: 'missing', file };
  const r = parseJsonTolerant(text);
  return { value: r.value, error: r.error, file };
}

/** Join that tolerates null segments. */
export function j(...parts) {
  return path.join(...parts.filter(Boolean));
}
