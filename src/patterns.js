// Shape patterns for text that geiger reads but cannot execute: hook bodies,
// skill instructions, agent playbooks. A hit means "worth opening by hand",
// never "malicious" — geiger reports position and shape, never verdicts.

/** Commands whose shape is hostile regardless of who wrote them. */
export const RISKY_COMMANDS = [
  { id: 'download-pipe-shell', note: 'downloads something and pipes it straight into a shell', re: /\b(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n|]{0,200}\|\s*(sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)\b/i },
  { id: 'base64-exec', note: 'decodes a base64 payload before running it', re: /(-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{16,}|FromBase64String|\bbase64\s+(-d|--decode|-D)\b)/i },
  { id: 'raw-ip-endpoint', note: 'contacts a bare IP address instead of a named host', re: /\bhttps?:\/\/(?!127\.|0\.0\.0\.0|localhost)(\d{1,3}\.){3}\d{1,3}(:\d+)?/i },
  { id: 'credential-file-read', note: 'reads a credential file (SSH key, AWS credentials, /etc/shadow)', re: /(\.ssh[\\/]id_(rsa|ed25519|ecdsa|dsa)\b|\.aws[\\/]credentials\b|\/etc\/(shadow|sudoers)\b)/i },
  { id: 'history-rewrite', note: 'rewrites git history or force-pushes', re: /\bgit\s+(push\s+[^\n]*--force(-with-lease)?\b|filter-branch\b|reset\s+--hard\b)/i },
];

/**
 * Instruction text that steers an agent rather than informing it. These live
 * in skills, rules files and playbooks — the prompt-injection surface that no
 * config field describes.
 */
export const STEERING_TEXT = [
  { id: 'override-instructions', note: 'tells the agent to ignore or override its previous instructions', re: /\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|system)\b[^.\n]{0,20}\b(instruction|prompt|rule|message)/i },
  { id: 'hide-from-user', note: 'tells the agent to act without telling the user', re: /\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|show|reveal)\b[^.\n]{0,20}\b(the )?user/i },
  { id: 'exfiltration', note: 'mentions sending local content to an outside destination', re: /\bexfiltrat|\b(send|upload|post)\b[^.\n]{0,40}\b(\.env|credential|secret|api[_-]?key|token|private key)\b/i },
  { id: 'bypass-approval', note: 'mentions bypassing approval or permission prompts', re: /\b(bypass|skip|suppress|auto[- ]?approve)\b[^.\n]{0,30}\b(approval|permission|confirmation|prompt|review)\b/i },
];

/** Match `text` against a pattern list. Returns the notes that fired. */
export function notesFor(text, patterns) {
  const out = [];
  if (typeof text !== 'string' || !text) return out;
  for (const p of patterns) if (p.re.test(text)) out.push(p.note);
  return out;
}
