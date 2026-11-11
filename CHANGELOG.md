# Changelog

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
