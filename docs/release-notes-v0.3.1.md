# v0.3.1 — security fix: BOM-prefixed configs no longer vanish from reports

Upgrade recommended for anyone using `--strict` or `--diff` as a drift alarm.

## Fixed: configs starting with a byte-order mark were silently skipped

A JSON config whose first bytes were a UTF-8 byte-order mark (BOM) failed to
parse. Notepad, older Visual Studio and PowerShell 5.1 write one by default,
so hand-edited configs on Windows were affected.

- MCP configs in project and host locations (Cursor, Claude Desktop,
  Windsurf, VS Code and others) showed a single "unparseable config" line
  with no exposures. Servers that could execute code or held credentials were
  not reported, and `--strict` exited 0.
- Worse: the global Claude Code config, Claude Code settings (hooks and the
  API-key helper), Cursor and Gemini CLI hook files, and the Claude Code
  plugin list dropped parse errors entirely. A BOM made their servers and
  hooks disappear without any trace.
- As a result the drift alarm could be bypassed: a new hook added in a
  BOM-prefixed settings file produced "no drift — this machine matches the
  baseline" and exit 0.

The BOM is now stripped when a file is read, so these configs parse normally.
Separately, every reader that used to drop a parse error now reports the file
as an "unparseable config" finding instead of skipping it.

## Fixed: parse errors could copy part of a credential into reports

When a config was malformed right next to a credential without a recognizable
shape, the parser's error message could carry up to about ten characters of
the value into the `--json` and `--html` reports (not the terminal). Parse
errors are now labeled by line and column only, with no file content.

## Changed: unparseable configs are shape-scanned

A config that exists but cannot be parsed is now scanned for credential
shapes like any partially parseable format (HOLDS-SECRETS when found), and
the finding says when the file appears to declare MCP servers or hooks. The
README's limitations section is corrected to match.

## Credit

The BOM issue was reported privately, with an exact reproduction, by an
independent researcher who runs verification passes on security tooling.
Thank you. The error-message leak and the wider silent-drop cases were found
while fixing it.

Tests added for all of the above. Read-only, no telemetry, secrets by shape
only — unchanged, and now enforced on the parse-error path too.
