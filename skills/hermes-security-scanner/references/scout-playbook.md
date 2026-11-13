# Scout playbook

How to turn a scope of files into a short list of audit targets worth reading, and how to keep the
analyst cheap. Derived from OpenAI's Linux kernel pipeline ("A thousand fewer paths to root",
https://openai.com/index/a-thousand-fewer-paths-to-root/): 40M lines → 5,034 targets (~7%) for
$3,426, then 2,308 candidates for $316,549. The selection step is 1% of the cost and decides the
quality of everything after it.

## The pipeline this supports

| Stage | Who | Artifact | Gate it respects |
|---|---|---|---|
| Discovery — scout | cheap pass over structure | audit targets (`target-add`) | reachability + relevance |
| Discovery — analyst | one target at a time | candidates (`finding --target`) | `target-close` |
| Dynamic validation | remediator, in a sandbox | reproduction: request/test/probe + output | `needs_validation` → `confirmed` or `false_positive` |
| Impact | remediator | severity from the boundary crossed | — |
| Patch | remediator | smallest fix + regression test + variants checked | `fixed_pending_verification` |
| Independent review | validator, different agent | verdict | `review --status passed/failed` |

## Reachability: who can actually reach the code

Read the route/attribute, not the intent. In an ASP.NET Core API the principal is decided per action:

| Evidence in the code | Reachability |
|---|---|
| `[AllowAnonymous]`, or no attribute under a controller without `[Authorize]` | `anonymous` |
| `RequiereLectura` (or `[Authorize]` with no role) | `lector` and up |
| `RequiereEscritura` | `operador` and up |
| `RequiereAdmin` | `admin` and up |
| `RequiereSuperadmin`, impersonation endpoints, user/role management | `superadmin` |
| Background job, startup seeding, migration, interceptor | `process` — runs as the app, no request needed |
| Vue/TS under `imcui/src` | `anonymous` if it ships in the bundle: the browser is the attacker's machine |

### Python (FastAPI, Flask, Django, workers)

| Evidence in the code | Reachability |
|---|---|
| `@app.get/post(...)` or `@router.*` with no `Depends(current_user)` | `anonymous` |
| Route behind `Depends(require_user)` / `@login_required` / `LoginRequiredMixin` | authenticated user |
| `Depends(require_admin)`-style guard, admin blueprint, Django `is_staff`/`is_superuser` | `admin` and up |
| `middleware`, `@app.before_request`, ASGI wrapper | whatever the routes behind it allow — read the routes |
| Celery/RQ task, APScheduler job, `startup`/`lifespan` hook, CLI entry point (`__main__`, `argparse`, Typer) | `process` |
| Alembic migration, seed script, `scripts/*.py` run by ops | `process` — and usually privileged |
| Front-end JS (`app/static/*.js`) | `anonymous`: the browser is the attacker's machine |

In FastAPI the dependency tree is the authorization decision: `Depends(...)` at router level applies to
every path under it, and one route that re-declares its own dependencies escapes the router's guard.
Read the router `include_router(...)` call and the decorator together, not the handler alone.

A target with `superadmin` reachability is a hardening item, not an urgent one: the attacker already
has the keys. Weight the list the same way the kernel pipeline did — unprivileged reachability first.

## Relevance: the triggers that make a file a target

A path is a target when attacker-influenced data meets one of these:

- **Writes to disk** — file name or extension taken from input, path built by concatenation, upload
  without a whitelist, delete that reaches outside a known root.
- **Identity and session** — token minting/validation, refresh rotation, cookie flags, impersonation
  claims, lockout, password or role assignment, seeded accounts.
- **Authorization decisions** — per-action policies, ownership checks, `IgnoreQueryFilters` near an
  authorization check, a route that reuses a base action.
- **Query and command construction** — string-built SQL, `FromSqlRaw`, shell/process start, path
  passed to an interpreter, `Expression` built from input.
- **Deserialization and parsing** — `JsonSerializer` on untrusted shapes, XML, `Type.GetType`, model
  binding into entities (mass assignment).
- **Outbound requests** — URL from input (SSRF), redirect target, webhook.
- **Secrets and configuration** — literal keys, connection strings, `appsettings.*` switches that
  change a security behaviour (`Auth:Enforce`), CORS policies, `AllowedHosts`.
- **Graphs and recursion** — parent/child walks, cycle handling, unbounded fan-out, DTO projection
  that follows relations both ways.
- **Logging and errors** — exception text or file paths returned to a client, log endpoints, audit
  rows that can be forged or skipped.
- **Python-specific sinks** — `pickle.loads`, `yaml.load` without `SafeLoader`, `eval`/`exec`,
  `subprocess` with `shell=True`, `os.system`, Jinja `Template(...).render` on user input,
  `tarfile.extractall` / `zipfile.extractall` (zip-slip), `Path(...)` built from input, `requests` to a
  URL from input (SSRF), `jwt.decode` without `algorithms=[...]` or with `verify=False`,
  `hashlib.md5/sha1` for passwords, `random` for tokens instead of `secrets`, SQL built with f-strings
  or `%`, `sqlite3` with `executescript` on input, framework debug flags (`debug=True`,
  `DEBUG = True`) and default `SECRET_KEY` values.

Conversely, most files are not targets, and saying so is the scout's job: DTO shapes, constants,
styling, presentational Vue components with no data access, generated code, test helpers. That is why
`scan` skips the `tests/` tree by default: on a 400-file Python repo it is 269 of the 400 files, and a
scope that large is one nobody reads. Pass `--include-tests` only when the audit is about fixtures.
The same reasoning drops `alembic/versions/` and EF `Migrations/`: schema history, not request surface.

## Sizing

- One target ≈ one decision surface, and **under ~3,000 lines** for the analyst to hold the whole
  picture: a controller plus the service it calls, not "the whole API layer".
- Same controller with independent actions (a base CRUD controller plus overrides) → split by action
  group when the threat models differ; keep it whole when they share one.
- A whole-file `--path` is fine for a 200-line service; use `path:start-end` when only a region
  matters and say why in `--note`.

## Worked example

```bash
SM=~/.hermes/security-tools/security_matrix.py

# 1. scope
python3 $SM --repo . scan --mode full          # 98 paths on the reference repo

# 2. scout: three targets out of 98 paths, each with the reason it was chosen
python3 $SM --repo . target-add --title "Attachment upload and storage" \
  --path IMCAPI/Controllers/Controllers.cs --path IMCAPI/Services/AttachmentStorage.cs \
  --reachability operador --relevance "writes attacker-named files under the content root" \
  --priority high --actor scout-agent
python3 $SM --repo . target-add --title "Token lifecycle" \
  --path IMCAPI/Controllers/AuthController.cs --path IMCAPI/Services/AuthTokenService.cs \
  --reachability anonymous --relevance "refresh rotation and cookie scope decide session theft" \
  --priority high --actor scout-agent
python3 $SM --repo . target-add --title "Authorization plumbing" --path IMCAPI/Program.cs \
  --reachability process --relevance "policy definitions and the Auth:Enforce switch" \
  --priority medium --actor scout-agent

# 3. analyst: read each one, record candidates against it, then close it
python3 $SM --repo . target-close T-XXXXXXXX --status audited --actor scanner-agent \
  --note "Upload -> ApplyUploadAsync -> SaveAsync; no Exists(itemId) before the write; candidate recorded"
```

## Lessons from the source run that are worth keeping

- **Revalidate before reporting.** During OpenAI's ten-day run, 61 of its own findings were patched
  upstream. A candidate found against an old file is noise: this tool reopens findings whose file
  hash moved, so re-read before you report.
- **A reproduction is the only confirmation.** 74.7% of candidates reproduced; only 3.1% were plain
  analysis errors — the rest needed perks, timing or budget nobody had. Static reasoning alone is
  how a report becomes noise.
- **Verify the path, not the state.** 20 of 200 "successful" kernel exploits had reached their goal
  through a *different* bug. A test that passes after a fix is not proof that *this* fix removed
  *this* trigger — re-run the original probe.
- **Patch with variant analysis.** Generated patches kept missing sibling copies of the same
  defect. Before closing a fix, grep for the same pattern elsewhere in the target.
- **Stop rules save more than they cost.** Unsuccessful exploitation attempts averaged ~10x the cost
  of successful ones. If a reproduction makes no progress after two honest attempts, record what was
  tried and move on instead of burning the budget.
- **Re-evaluate the scaffolding.** A 103-technique library lifted an older model from 76% to 89%
  success and the newer one by 1.5 points. Keep this playbook available, but do not grow it faster
  than the models absorb it.
