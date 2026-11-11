# Hermes Security Skills

Three Hermes skills plus a shared SQLite CLI that tracks security candidates, their evidence and the
review state of every file in scope. Python 3.10+, Git. No external Python dependencies.

Not a vulnerability scanner: it decides *what* has been reviewed and refuses to call a review valid
while anything is open. The reading of the code is the agent's job.

## Install

```bash
bash scripts/install.sh
```

It copies the CLI to `~/.hermes/security-tools/security_matrix.py` and the three skills to
`~/.hermes/skills/software-development/`. Override with `HERMES_SECURITY_TOOLS` and
`HERMES_SKILLS_DIR`.

The skills invoke the CLI by that absolute path on purpose: Hermes does not export
`HERMES_SKILL_DIR` to the shell, so a path relative to the skill directory works in one layout and
breaks in every other one.

## Use

```bash
SM=~/.hermes/security-tools/security_matrix.py

python3 $SM --repo /path/to/project scan --mode incremental   # changed files + untracked
python3 $SM --repo /path/to/project scan --mode full          # whole tree, explicit request only
python3 $SM --repo /path/to/project scan --base origin/main   # compare against a committed baseline
python3 $SM --repo /path/to/project status                    # JSON: coverage + review validity (read-only)
python3 $SM --repo /path/to/project check                     # exit 0 when committable, 1 when not
```

`scan` only prepares the scope; **the agent must inspect every path returned** and then record what it
found:

```bash
python3 $SM --repo . finding --path A.cs --symbol A.Run \
  --title "..." --severity high --description "..." --evidence "A.cs:42 ..." --actor scanner-agent
python3 $SM --repo . scope-reviewed --run 1 --path A.cs --actor scanner-agent
python3 $SM --repo . transition SEC-ABCDEF123456 --status confirmed --actor verifier-agent --note "..."
```

Scope covers `.cs .csproj .json .config .yml .yaml .razor .cshtml .ts .tsx .js .mjs .cjs .vue .sh
.ps1 .sql .html`. Machine-written paths (EF `Migrations/`, `*.Designer.cs`, lockfiles, `bin`, `obj`,
`node_modules`) are skipped; `scan --include-generated` opts them back in. Each new `scan` supersedes
the previous run's unreviewed entries, so a file left unread in run *N* does not block run *N+1*
forever — but nothing in the tool can tell you the file was read, which is why `status` reports the
count instead of assuming it.

Artifacts written into the target repo: `SECURITY_MATRIX.md`, `.security/REMEDIATION_STATUS.md`,
`.security/FINAL_SECURITY_REVIEW.md`, `.security/security.db`. Keep `.security/` out of Git (the
shipped `.gitignore` covers this repository only) unless you deliberately want the database in
history.

## Automatic integration

```bash
bash scripts/install-hook.sh /path/to/project
```

The hook **blocks a commit unless the security review is valid** for the tree being committed; it
performs no analysis. Its body is one call — `security_matrix.py check` — which is read-only by
construction: a command that answers "is this committable?" must not rewrite the tree in the middle of
a commit. `status` is read-only too; the documents (`SECURITY_MATRIX.md`,
`.security/REMEDIATION_STATUS.md`, `.security/FINAL_SECURITY_REVIEW.md`) are written by the commands
that change state (`scan`, `finding`, `transition`, `scope-reviewed`, `review`). Two behaviours worth knowing before you install it:

- **A review is consumed by the commit it covers.** The validity check is tied to the Git HEAD and to
  the source hashes in scope, so committing moves HEAD and the next commit needs a new review. That is
  the point — but it means one review pass per commit, not one per session.
- Hooks can be bypassed with `git commit --no-verify`; enforce the gate in CI for a real guarantee.

Add the instructions from `templates/AGENTS.security.md` to a project's `AGENTS.md` so development
agents run the scanner after each task.

## Limitations

- An empty findings list is **not** a clean audit. Read `status`: the gate is only as good as the
  `scope-reviewed` marks somebody actually earned.
- Findings are keyed to file + symbol + title and carry the file's SHA-256, so any edit to a file
  reopens the findings recorded against it. File granularity, not function granularity.
- The state machine refuses a `review --status passed` while any finding is unresolved or any scope
  entry is pending. `accepted_risk` does not count as resolved in this version.
- Independent assignment (a different agent to confirm, to fix, to verify) is a workflow contract
  between skills, not something the CLI can enforce.

See `TEST-REPORT.md` for the verification run that produced this version, including the defects that
were fixed here and the ones still open.
