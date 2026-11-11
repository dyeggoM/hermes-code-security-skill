# Test report — v0.1 as received

Date: 2026-11-11
Host: Linux 6.1, Python 3.13
Target repo: `InventoryManagementContainers` @ `211a4ca` (branch `docs/docs-truth-pass`), .NET 9 API + EF Core/SQLite + Quasar PWA.
Method: installed v0.1 exactly as its README says, ran the CLI, the shipped smoke test and the Git hook, and drove a real review of the current code. No source file was modified.

## Verdict

The state machine, the evidence trail and the release gate work. The install path and two scope-accounting defects do not. Details below; every failing item was reproduced, not inferred.

## What passed

| Check | Result | Evidence |
|---|---|---|
| `tests/test_smoke.py` | PASS | `python3 -m unittest discover -s tests -v` → `Ran 1 test … OK` |
| Skills register with Hermes | PASS | all three appear in `skills_list` and load through `skill_view` |
| `scan --mode incremental` on a clean tree | PASS | returns `paths: []`, exit 0 |
| `scan --mode full` | PASS | 58 paths on the target repo, `run 2` |
| Findings persist and render | PASS | 7 findings recorded, `SECURITY_MATRIX.md` + `.security/REMEDIATION_STATUS.md` + `.security/FINAL_SECURITY_REVIEW.md` generated with severity ordering |
| Illegal transitions rejected | PASS | `needs_validation → verified_fixed` and `→ integration_verified` both exit 2 with `Invalid transition` |
| Path containment on `finding` | PASS | `--path ../other.cs` → `ERROR: Path outside repository`, exit 2 |
| Gate refuses a pass with work open | PASS | `review --status passed` → `Cannot pass: 7 unresolved, 58 unreviewed scope entries`, exit 2 |
| Gate accepts a failure | PASS | `review --status failed` recorded, exit 0 |
| Source hash invalidation | PASS | findings carry the file SHA-256; a changed file reopens `verified_fixed` findings |
| Pre-commit hook blocks | PASS | commit without a valid review exits 1 |
| Pre-commit hook allows | PASS | `scan` → `scope-reviewed` → `review --status passed` → commit exits 0 |
| Review is scoped to one commit | PASS (by design) | after the allowed commit, HEAD moves and the next commit is blocked again until a new review |

## What failed

### D-1 — Install instructions cannot work (blocks first use)

Two independent faults in the documented install:

1. Every skill command uses `${HERMES_SKILL_DIR}/../../shared/security_matrix.py`. Hermes does not export `HERMES_SKILL_DIR` to the shell (`env | grep HERMES` shows 20 variables, none of them this one), so the documented command fails on the first invocation: `/usr/bin/bash: line 27: HERMES_SKILL_DIR: unbound variable`.
2. `ln -sfn ~/.hermes/security-tools ~/.hermes/shared` assumes `~/.hermes/shared` does not exist. It does — it holds Hermes' own `nous_auth.json`. `ln -sfn` therefore creates `~/.hermes/shared/security-tools` instead of the intended path, so `~/.hermes/shared/security_matrix.py` is still missing while a stray symlink lands in a directory Hermes owns.

Repro: run the three README install lines verbatim, then any skill command.
Worked around during this test by calling `~/.hermes/security-tools/security_matrix.py` directly.

### D-2 — Scope entries accumulate across runs and deadlock the gate

`scan` inserts one row per path per run and `render`/`review` count every row whose status is not `reviewed`, across all runs ever recorded. A path left pending in run *N* still blocks in run *N+4*, and a file that is dirty in two consecutive scans is pending twice.

Repro (clean two-file repo):

```
git commit -qm init                    # A.cs, B.cs
echo 'class A { int x; }' > A.cs  ; scan --mode incremental   # paths: [A.cs]      -> run 1
echo 'class B { int y; }' > B.cs  ; scan --mode incremental   # paths: [A.cs, B.cs] -> run 2
scope-reviewed --run 2 --path B.cs --actor s
review --status passed --reviewer v --note ok
→ ERROR: Cannot pass: 0 unresolved, 2 unreviewed scope entries
```

Both unreviewed entries are run 1's `A.cs` (superseded) and run 2's `A.cs` (same file, counted again). In a real workflow this is a permanent block: the entry for a file can never be cleared after the run that listed it has been superseded.

### D-3 — Coverage misses the whole front end

The extension whitelist is `.cs .csproj .json .config .yml .yaml .razor .cshtml`. On the target repo that is 44 of 117 tracked source files: 49 `imcui/src/**` TypeScript/Vue files, 4 more `.ts`, 2 `.js` and 2 `.sh` are invisible. The previous audit's B-4 finding lived in `imcui/src/services/api.ts`; under this scanner that file cannot even be put in scope. `endpoints.allow-anonymous.txt`, `AGENTS.md` and `.githooks/pre-commit` are likewise out of reach.

At the same time a full scan pulls noise in: 15 of the 58 scope entries are EF migrations plus `.Designer.cs` files, and 2 are `package-lock.json` (13 807 lines total). Roughly 29 % of the review scope on this repo is generated file nobody should read line by line.

### D-4 — The hook reports failure as a traceback

The installed hook pipes `status` into `python3 -c 'assert …'`. When the review is not valid the developer sees:

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
AssertionError: Security review required before commit
```

with no indication of which counter failed and no hint about the next command. Should be a one-line message on stderr naming the unresolved/pending counts and `status`.

### D-5 — Recording a duplicate finding writes a false event

`finding` uses `INSERT OR IGNORE` for the finding row but always inserts an event. Recording the same `path|symbol|title` twice yields one finding and **two** events, the second claiming `a2` moved the finding from nothing to `needs_validation`. The audit trail — the one thing this tool exists to produce — then contains a transition that never happened. Worse, the operator gets the same ID echoed and no warning that nothing was recorded.

Repro: identical `finding` call twice with different `--actor`; `SELECT count(*) FROM findings` = 1, two event rows.

### D-6 — `status` mutates the repository it inspects

`status` (the read-only-looking command, and the one the hook runs) creates `.security/`, rewrites `SECURITY_MATRIX.md` and both status documents at the repo root. On a clean checkout it leaves four untracked paths and a new SQLite database. Nothing ships a `.gitignore` entry for them, so the first commit after a `status` can publish `.security/security.db`.

### D-7 — Skills land uncategorised

`metadata.hermes.category: software-development` in the frontmatter is not honoured; the category comes from the install directory. Copying to `~/.hermes/skills/` (as the README says) yields `category: null` in `skills_list`, so the three skills sit outside `software-development` where every other engineering skill lives.

## Security findings reaffirmed on the target repo

The point of the test: the old audit (`docs/security/2026-11-10-audit.md`, commit `7d12a33`) was re-run against today's code. Auth landed since then, so most findings are genuinely closed — C-1 (no authentication in the pipeline), C-2 (ParentId cycle → stack overflow), A-1 (anonymous destructive delete), A-2 (mass assignment of `Id`/`IsActive`/`UpdatedBy`), A-3 (anonymous log download), M-2 (`DeveloperExceptionPage`), M-4 (`Id` collision 500) all verified closed in the current source.

Seven issues are still real. Recorded in the matrix with file+line evidence, all seven confirmed by re-reading the code at `211a4ca`:

- **SEC-4808052E1D3D (high)** — `AttachmentController.Upload` writes the file to disk before `_repository.Add`, so an item id that does not exist produces a 500 plus an orphan file: no row, no way to delete it through the API. Was M-3, still open; now needs a token, so the reachability dropped from anonymous to `operador`.
- **SEC-050338E3D166 (medium)** — refresh-token reuse is audited but the token family is never revoked: the rotated token from the earlier call stays valid. New, introduced with the auth work.
- **SEC-406552D02254 (medium)** — Development CORS reflects any origin *and* allows credentials, while the refresh token travels in an HttpOnly cookie. Was B-1; `AllowCredentials()` made it worse.
- **SEC-508D6F575945 (medium)** — `LogsController` still concatenates the raw `date` route segment into `Path.Combine` with no whitelist and no containment check. Was M-1; now behind `RequiereAdmin`.
- **SEC-73849A289811 (medium)** — `Auth:Enforce=false` short-circuits all four role policies at runtime, from configuration, with no startup warning and no test asserting production runs with it on.
- **SEC-E87E247C9086 (medium)** — `BaseRepository.Delete` looks the row up through the `IsActive` query filter, so the physical-delete branch is unreachable: `Constants` and `Attachment` deletes leave rows that can never be revived or removed. Was M-6; `ItemController` works around it, the shared path does not.
- **SEC-213501636994 (low)** — stored file extension comes from the client filename unchecked, under a media root that defaults to the API content root. Was B-2; latent, becomes stored XSS the day the folder is served.

Artifacts from the run: `SECURITY_MATRIX.md`, `.security/REMEDIATION_STATUS.md`, `.security/FINAL_SECURITY_REVIEW.md`, `.security/security.db` (copied to the test workspace, removed from the target repo afterwards so its tree is unchanged).

Honest note on the matrix as an artifact: it records the seven candidates and the coverage gap (49 of 58 scope entries unread). It does not claim the repo is clean, and the CLI refuses to pass a review while anything is open — which is the behaviour the design promised.

## Conclusion

Worth putting in Git as v0.1: the model (candidates → independent validation → remediation → independent review, all keyed to Git state and source hashes) is sound and the gates behave. Fix order before the next audit: D-1 and D-2 (block first use and deadlock the gate), then D-3 (coverage), then D-4 … D-7.

---

# Second run — driving the whole loop on a real repository (2026-11-11)

Same target (`InventoryManagementContainers`, uncommitted round on `wip/round-20261111`), but this time
the point was to exercise **scanner → remediator → validator → gate** end to end, not to audit the
installer. Version under test: v0.1.2 installed, v0.1.3 produced from this run.

## What the loop produced

- **Seven candidates recorded and confirmed** in the matrix with file+line evidence (upload before row,
  refresh-token family, CORS, log path, `Auth:Enforce`, `BaseRepository.Delete`, client extension).
  Six were fixed, each with a test in `Testing/SecurityRegressionTests.cs`; the seventh (CORS) turned
  into two startup refusals.
- **The independent validator earned its place**: it re-ran the probes and found three regressions the
  fixer had introduced — the orphan-file bug still alive on the JSON upload route, the log endpoint
  returning 404 for every real file because reader and writer disagreed on the file name, and the hard
  delete turning into a `500` on a parent with live children. All three were fixed and covered by tests
  before the matrix moved to `verified_fixed`. Without a separate validator this round would have
  shipped a "closed" finding that was not closed.

## Defects found in the tooling itself

- **D-8 — the installer reports success while the running profile stays stale.** `install.sh` wrote to
  `~/.hermes/skills/software-development` only. A profile with its own `skills/` directory shadows that
  path, so the active profile kept serving 0.1.2 while the installer printed the 0.1.3 paths. Measured:
  `grep '^version:'` across both trees showed 0.1.2 and 0.1.3 side by side. Fixed with
  `--profile NAME` / `HERMES_PROFILE`, which installs to both and prints every destination.
- **D-9 — clearing a scope is one command per file.** A 28-path run needed 28 invocations of
  `scope-reviewed --path`, and one mistyped path leaves the gate blocked with no hint about which
  entry is still pending. Fixed with `scope-reviewed --run N --all`, which marks every pending entry of
  that run and refuses a second call instead of pretending. Verified on the real 28-path scope.

## Rules the tool cannot enforce, and the skill now states

- **A scan invalidates the last review** (scope digest plus source hashes). Scanning while still
  editing wasted a pass: the review recorded before the scan no longer applied afterwards.
- **A finding is reopened by any later edit to its file** (findings carry the file's SHA-256), so
  `fixed_pending_verification` has to be recorded after the last edit, not before.
- **An empty findings list is not a clean audit.** The first pass recorded zero findings and a passing
  review against this very tree; the same code had seven open issues when it was actually read. The
  gate is only as good as the `scope-reviewed` marks somebody earned, which is why the skill repeats
  the instruction and the README keeps the limitation.

## Verdict

The state machine, the independent-validation handoff and the gate behaved correctly under real use.
Both defects found here were in the wrapper (installer, bookkeeping), not in the model, and both are
fixed in v0.1.3 with tests (12 cases, `Ran 12 tests … OK`).
