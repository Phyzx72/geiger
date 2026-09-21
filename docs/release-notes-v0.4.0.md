# v0.4.0 — git hooks, and reading what a skill actually says

Two surfaces that a config-only inventory kept missing.

## Git hooks and merge drivers

Git runs `.git/hooks` scripts itself on commit, checkout, push and merge — no
prompt, no approval, no model in the loop. That is the same standing execution
as an agent hook, and agent tooling now installs itself there (graph rebuilds,
lint passes, telemetry). Geiger now reports, for every directory you scan:

- **Live hooks**, with the programs each one invokes. Git's `*.sample` files
  never run and are not findings.
- **`core.hooksPath` redirects**, which move hooks outside the repo entirely.
- **Merge drivers** (`[merge "x"] driver = ...`), a command git runs while
  merging any file that selects it in `.gitattributes`.
- **Hostile shapes** in a hook body: downloading and piping into a shell,
  base64-decoding a payload before running it, contacting a bare IP address,
  reading an SSH key or AWS credentials, rewriting git history. Plus any
  credential shape found in the body.

Reading the programs rather than the first line matters: real hooks open with
a dozen guard clauses and only reach their program much later. The reader skips
comments, heredoc bodies, multi-line `python -c "..."` payloads and
redirections, so it reports `git, python, sed` and not shell noise or the
identifiers of embedded code.

## Skills are instructions, so read the instructions

Before, a skill was a name in a directory listing. A skill is text an agent
loads and follows, which makes the text the payload. Geiger now reports, per
skill and subagent definition:

- its **description**, including the folded `description: >` form real skills
  use (reading line one yields a useless `>`),
- **instruction text** that tries to override the agent's previous
  instructions, hide work from you, mention exfiltration, or bypass approval,
- **commands with a hostile shape** in the body, using the same list as hooks,
- **credential shapes**, reported by shape and never by value.

Project-level `.claude/skills` is covered alongside the user profile.

## Honest labels, unchanged

A flagged line means "open this by hand", never "this is malicious". The flags
are heuristics and a carefully written hostile file will not trip them — the
README says so. Nothing geiger reads is ever executed, git hooks included.

Every new path ships with tests, including a benign twin so a pattern cannot
start false-positiving silently, and unit tests for the hook program reader and
the git-config reader. Verified against a real toolchain install rather than
fixtures alone.
