# Hermes Security Skills

Three Hermes skills plus a shared SQLite CLI that tracks security candidates, their evidence and the
review state of every file in scope. Python 3.10+, Git. No external Python dependencies.

Not a vulnerability scanner: it decides *what* has been reviewed and refuses to call a review valid
while anything is open. The reading of the code is the agent's job.

## Install

```bash
bash scripts/install.sh                                  # shared skills dir
bash scripts/install.sh --profile code-orchestrator      # shared dir + that profile's skills dir
```

It copies the CLI to `~/.hermes/security-tools/security_matrix.py` and the three skills to
`~/.hermes/skills/software-development/`. Override with `HERMES_SECURITY_TOOLS` and
`HERMES_SKILLS_DIR`.

**Name the profile you actually run.** A profile with its own `skills/` directory shadows the shared
one, so installing only to `~/.hermes/skills` leaves that profile loading the previous version while
the installer reports success. `--profile` (or `HERMES_PROFILE`) writes both and prints each
destination.

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

`scan` only prepares the scope. It is the **scout** pass that decides what is worth reading, because
reading everything is how an audit becomes arbitrary:

```bash
# scout: name a target, say who can reach it and why it matters
python3 $SM --repo . target-add --title "Upload path" \
  --path src/api/uploads.py --path src/api/storage.py \
  --reachability user --relevance "writes caller-named files to disk" \
  --priority high --actor scout-agent

# analyst: read that target, record candidates against it, then close it
python3 $SM --repo . finding --path A.cs --symbol A.Run \
  --title "..." --severity high --description "..." --evidence "A.cs:42 ..." \
  --target T-XXXXXXXX --actor scanner-agent
python3 $SM --repo . target-close T-XXXXXXXX --status audited --actor scanner-agent \
  --note "read Upload, ApplyUploadAsync, SaveAsync; sinks checked"
```

This two-pass split is the lesson from OpenAI's Linux kernel sweep (`a-thousand-fewer-paths-to-root`
on openai.com): 40M lines → 5,034 audit targets (~7% of the code) for $3,426, then 2,308 candidates
for $316,549, then a triage agent that *reproduced* 74.7% of them before anyone called them bugs. The
selection step is 1% of the cost and decides the quality of everything after it. The concrete
heuristics for this stack — reachability table, relevance triggers, sizing, worked example — are in
`skills/hermes-security-scanner/references/scout-playbook.md`; the mechanics for turning an external
hardening checklist into a gap table (edge headers, CSP hashes, `security.txt`, certificate checks) are
in `skills/hermes-security-scanner/references/web-hardening.md`.

An open target blocks a passing review exactly like an unreviewed file does, and `dismissed` needs a
reason that names the missing link.

A candidate is a claim. It becomes `confirmed` only when the remediator reproduces it in a sandbox and
puts the request and the observed output in the note:

```bash
python3 $SM --repo . transition SEC-ABCDEF123456 --status confirmed --actor verifier-agent \
  --note "repro: POST ... -> 500, file left on disk (ls)"
python3 $SM --repo . scope-reviewed --run 1 --path A.cs --actor scanner-agent
python3 $SM --repo . scope-reviewed --run 1 --all --actor scanner-agent   # every pending path of that run
python3 $SM --repo . check                                               # read-only gate: exit 0 committable, 1 blocked
python3 $SM --repo . transition SEC-ABCDEF123456 --status confirmed --actor verifier-agent --note "..."
```

Scope covers `.cs .csproj .json .config .yml .yaml .razor .cshtml .ts .tsx .js .mjs .cjs .vue .sh
.ps1 .sql .html .py .pyi .toml .ini`. Skipped by default:

- **caches and tool state** — `bin`, `obj`, `node_modules`, `__pycache__`, `.venv`, `venv`,
  `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `site-packages`, `dist`, `build`;
- **generated trees** — EF `Migrations/`, `*.Designer.cs`, `alembic/versions/`, lockfiles;
- **`tests/`, `test/`, `__tests__/`, `spec/`** — test trees do not ship, so they are not attack surface.
  On the 400-file Python project this was measured against, `tests/` was 269 files: a scope that large
  is one nobody reads.

`scan --include-tests` opts the test tree back in (audit fixtures: a committed secret, a credential
baked into a sample) and `scan --include-generated` re-adds the generated trees. Each new `scan` supersedes
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

The CHANGELOG records what each release fixed and why, including the defects found by running the tool
on real repositories.
