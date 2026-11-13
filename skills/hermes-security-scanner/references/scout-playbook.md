# Scout playbook

How to turn a scope of files into a short list of audit targets worth reading, and how to keep the
analyst cheap. Derived from OpenAI's Linux kernel pipeline ("A thousand fewer paths to root",
https://openai.com/index/a-thousand-fewer-paths-to-root/): 40M lines → 5,034 targets (~7%) for
$3,426, then 2,308 candidates for $316,549. The selection step is 1% of the cost and decides the
quality of everything after it.

Nothing here is specific to one codebase. The tables describe *patterns*; map them onto the stack in
front of you and write down the mapping before you start.

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

Use one portable scale, and map the project's own role names onto it — the axis is *privilege*, not
the project's vocabulary:

| Scale | Meaning | Typical names in real projects |
|---|---|---|
| `anonymous` | no credential at all; also anything that ships to a browser | public, guest, unauthenticated |
| `user` | any authenticated principal, lowest privilege | viewer, member, customer, read-only role |
| `privileged` | an admin-shaped role that can change data or configuration | admin, operator, manager, staff |
| `process` | no request reaches it: job, worker, CLI, startup, migration | system, service, cron |

A target with `privileged` reachability is a hardening item, not an urgent one: the attacker already
has the keys. Weight the list the way the kernel pipeline did — unprivileged reachability first, and
`process` targets second only when the process runs with more rights than the caller who can influence
its input.

### .NET / ASP.NET Core

| Evidence in the code | Reachability |
|---|---|
| `[AllowAnonymous]`, or no attribute on an action in a controller without `[Authorize]` | `anonymous` |
| `[Authorize]` with no role, or a policy that only requires authentication | `user` |
| A policy whose assertion checks `IsInRole("admin")`-style membership | `privileged` |
| Superadmin-only policies, impersonation endpoints, user/role management | `privileged` (highest) |
| Background service, `IHostedService`, startup seeding, migration, `SaveChanges` interceptor | `process` |
| TypeScript/Vue/JS under the bundle directory | `anonymous` — the browser is the attacker's machine |

Authorization is per action, not per controller: an inherited action with no attribute is anonymous
even when the class carries `[Authorize]`, and a policy whose assertion returns `true` under a
configuration flag is a role check that can be switched off.

### Python (FastAPI, Flask, Django, workers)

| Evidence in the code | Reachability |
|---|---|
| `@app.get/post(...)` or `@router.*` with no `Depends(current_user)` | `anonymous` |
| Route behind `Depends(require_user)` / `@login_required` / `LoginRequiredMixin` | `user` |
| `Depends(require_admin)`-style guard, admin blueprint, Django `is_staff`/`is_superuser` | `privileged` |
| `middleware`, `@app.before_request`, ASGI wrapper | whatever the routes behind it allow — read the routes |
| Celery/RQ task, APScheduler job, `startup`/`lifespan` hook, CLI entry point (`__main__`, `argparse`, Typer) | `process` |
| Alembic migration, seed script, ops script under `scripts/` | `process` — and usually privileged |
| Front-end JS (`static/`, `templates/` with inline script) | `anonymous` |

In FastAPI the dependency tree is the authorization decision: `Depends(...)` declared at router level
applies to every path under it, and one route that re-declares its own dependencies escapes the
router's guard. Read the `include_router(...)` call and the decorator together, not the handler alone.

### Node / TypeScript (Express, Nest, Next.js)

| Evidence in the code | Reachability |
|---|---|
| `app.get/post(...)`, `@Get()/@Post()` with no guard, a Next route handler with no session check | `anonymous` |
| `requireAuth` middleware mounted per route, `@UseGuards(AuthGuard)`, `getServerSession` | `user` |
| Role guard, `@Roles('admin')`, `authorize('admin')` middleware | `privileged` |
| Middleware mounted at app level | applies to everything routed after it — check the order |
| Queue consumer, cron script, `instrumentation.ts`, build/seed script | `process` |

## Relevance: the triggers that make a file a target

A path is a target when attacker-influenced data meets one of these:

- **Writes to disk** — file name or extension taken from input, path built by concatenation, upload
  without a whitelist, delete that reaches outside a known root.
- **Identity and session** — token minting/validation, refresh rotation, cookie flags, impersonation
  claims, lockout, password or role assignment, seeded accounts.
- **Authorization decisions** — per-action policies, ownership checks, a query filter that hides a row
  from the check that protects it, a route that reuses a base action.
- **Query and command construction** — string-built SQL, raw-SQL helpers (`FromSqlRaw`, `text()`,
  `cursor.execute` with formatting), shell/process start, path passed to an interpreter, expressions
  built from input.
- **Deserialization and parsing** — untrusted shapes into object mappers, XML, type resolution by
  name, model binding straight into entities (mass assignment).
- **Outbound requests** — URL from input (SSRF), redirect target, webhook delivery.
- **Secrets and configuration** — literal keys, connection strings, a configuration switch that
  changes a security behaviour, CORS policies, allowed hosts, debug flags.
- **Graphs and recursion** — parent/child walks, cycle handling, unbounded fan-out, DTO/projection
  that follows relations in both directions.
- **Logging and errors** — exception text or file paths returned to a client, log endpoints, audit
  rows that can be forged or skipped.
- **Language-specific sinks.** Python: `pickle.loads`, `yaml.load` without `SafeLoader`, `eval`/`exec`,
  `subprocess` with `shell=True`, `os.system`, Jinja `Template(...).render` on user input,
  `tarfile/zipfile.extractall` (zip-slip), `Path(...)` built from input, `requests` to a URL from input,
  `jwt.decode` without `algorithms=[...]` or with `verify=False`, `hashlib.md5/sha1` for passwords,
  `random` for tokens instead of `secrets`, SQL built with f-strings or `%`. .NET: `Process.Start`,
  `Type.GetType`, `BinaryFormatter`, `Assembly.Load`, `FromSqlRaw`, `Path.Combine` on input,
  `Razor`/`Html.Raw`, `JsonSerializer` on untrusted polymorphic shapes. JS: `eval`,
  `new Function`, `child_process.exec`, `innerHTML`, `dangerouslySetInnerHTML`, template engines with
  user templates, `require()`/`import()` of a name from input.

Conversely, most files are not targets, and saying so is the scout's job: DTO shapes, constants,
styling, presentational components with no data access, generated code, test helpers. That is why
`scan` skips the `tests/` tree by default — on one real Python repo the test tree was 269 of 400
files, and a scope that size is a scope nobody reads. Pass `--include-tests` only when the audit is
about fixtures. The same reasoning drops `alembic/versions/` and EF `Migrations/`: schema history, not
request surface.

## Sizing

- One target ≈ one decision surface, and **under ~3,000 lines** for the analyst to hold the whole
  picture: a controller plus the service it calls, not "the whole API layer".
- Same controller with independent actions (a base CRUD controller plus overrides) → split by action
  group when the threat models differ; keep it whole when they share one.
- A whole-file `--path` is fine for a 200-line service; use `path:start-end` when only a region
  matters and say why in `--note`.

## Worked example

Two shapes, the same steps — pick the one that matches the repo.

```bash
SM=~/.hermes/security-tools/security_matrix.py

# 1. scope
python3 $SM --repo . scan --mode full

# 2a. a Python API: three targets out of the returned paths
python3 $SM --repo . target-add --title "Upload path" \
  --path app/api/uploads.py --path app/services/storage.py \
  --reachability user --relevance "writes caller-named files under the content root" \
  --priority high --actor scout-agent
python3 $SM --repo . target-add --title "Session and token lifecycle" \
  --path app/api/auth.py --path app/services/tokens.py \
  --reachability anonymous --relevance "refresh rotation and cookie scope decide session theft" \
  --priority high --actor scout-agent

# 2b. a .NET API: the same two targets in that layout
python3 $SM --repo . target-add --title "Upload path" \
  --path src/Api/Controllers/UploadsController.cs --path src/Api/Services/FileStorage.cs \
  --reachability user --relevance "writes caller-named files under the content root" \
  --priority high --actor scout-agent

# 3. analyst: read each one, record candidates against it, then close it
python3 $SM --repo . target-close T-XXXXXXXX --status audited --actor scanner-agent \
  --note "upload -> storage.save -> write; no existence check before the write; candidate recorded"
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
