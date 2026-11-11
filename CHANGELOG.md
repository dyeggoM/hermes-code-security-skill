# Changelog

## v0.1.3 — a scope you can clear in one call, and the two rules that bite first

From driving the tool on `InventoryManagementContainers` (28 changed paths in one run).

- `scope-reviewed --all`: marks every pending path of a run in one command. Clearing a 28-path scope
  was 28 invocations of a CLI with a `--path` that has to be typed exactly; a single mistyped path left
  the gate blocked with no way to see which one without reading `status`. `--path` still works, the two
  are mutually exclusive, and a second `--all` with nothing pending exits 2 instead of pretending.
- The scanner skill now states the two sequencing rules that cost a cycle in practice: **a scan
  invalidates the recorded review** (scope digest plus source hashes), and **a finding is reopened by
  any later edit to its file** — so scan after the last edit and record `fixed_pending_verification`
  after the last edit to the file, not before.
- **The installer now installs into a named profile.** A profile with its own `skills/` directory
  shadows `~/.hermes/skills`, so `install.sh` reported success while the profile kept loading the old
  copy — measured: the shared tree was 0.1.3 and the active profile still served 0.1.2. `--profile
  NAME` (or `HERMES_PROFILE`) writes both locations and prints each one; without it the behaviour is
  unchanged.
- Tests: 12 cases, adding the `--all` path (three files, one call, review passes; the second call is an
  error).

## v0.1.2 — a gate that cannot corrupt the commit it guards

- New `check` command: read-only release gate. Exit 0 when the review is valid for the current HEAD and
  the tree, 1 when not, with a one-line reason on stderr (`--json` for machines, `--quiet` for silence).
  This is the fix for D-6: the pre-commit hook used to run `status`, which rewrote `SECURITY_MATRIX.md`
  and `.security/` *during* the commit — modifying the worktree after staging is exactly how a gate
  corrupts what it is guarding.
- `status` is now read-only too, and no longer creates `.security/` on a clone that never ran a scan. The
  three documents are written only by the commands that change state.
- `install-hook.sh` installs a three-line hook that execs `check`; a missing CLI now warns and allows the
  commit instead of blocking everything (a local tool that is not installed must not stop work — the
  same rule the inventory hook follows).
- Tests: 11 cases, adding read-only assertions for `check` and `status`, the HEAD-moved block, the
  source-hash-moved block and the `--json` payload.

## v0.1.1 — fixes from the first real run

Everything here comes from `TEST-REPORT.md`; the defect ids match it.

### Install
- **D-1** `scripts/install.sh` replaces the README recipe. The old one could never work: Hermes does
  not export `HERMES_SKILL_DIR`, so every documented command failed with `unbound variable`, and
  `ln -sfn ~/.hermes/security-tools ~/.hermes/shared` nested a symlink inside Hermes' own
  `~/.hermes/shared` instead of creating the expected path. The installer copies the CLI to
  `~/.hermes/security-tools/` and the skills to `skills/software-development/` (overridable via
  `HERMES_SECURITY_TOOLS` / `HERMES_SKILLS_DIR`).
- The three `SKILL.md` files now call `~/.hermes/security-tools/security_matrix.py` by absolute path.
- **D-7** Skills installed under a category directory register as `software-development` instead of
  `category: null`.

### Scope accounting
- **D-2** A new `scan` marks the previous run's outstanding entries `superseded`; `pending` counts only
  rows still awaiting review. Before this, the gate deadlocked: a path listed in run 1 stayed pending
  forever, and a file dirty across two scans was counted twice.
- `scope-reviewed` now only accepts a pending entry of the run named, and says why when it refuses
  (already reviewed, superseded, or not in that run).
- **D-3** Scope covers `.ts .tsx .js .mjs .cjs .vue .sh .ps1 .sql .html` (55 more files on the
  reference repo) and skips machine-written paths — EF `Migrations/`, `*.Designer.cs`, `*.g.cs`,
  lockfiles, `node_modules`. `--include-generated` opts them back in. On the reference repo that is
  98 paths instead of 58, with 0 lockfiles and 0 migrations instead of 2 and 15.

### Correctness
- **D-5** Recording a finding that already exists is an error instead of a silent no-op that still
  wrote an event claiming a transition nobody made.
- **D-4** The hook prints one line saying *why* it blocked — no review recorded / review recorded for
  a different HEAD / last review failed / N findings and M entries open / hashes changed — plus the
  `status` command, instead of an `AssertionError` traceback. It also tolerates a relocated CLI via
  `SECURITY_MATRIX_CLI`.
- `status` gained `head`, `latest_review` and `review_applies_to_head`, which is what makes that
  message possible.

### Tests
`tests/test_smoke.py` grows from 1 to 6 cases: the original workflow, illegal transitions and
path containment, duplicate rejection with no phantom event, supersede-on-rescan, refusal to review a
superseded entry, and the scope matrix including TS/Vue and excluding generated files.

## v0.1 — prototype

Initial three-skill layout (scanner / remediator / validator) with the SQLite finding matrix, the
state machine, the generated review documents and the optional pre-commit gate.
