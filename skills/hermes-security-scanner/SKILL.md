---
name: hermes-security-scanner
description: Scout audit targets by reachability, then analyse each one and record evidence-backed candidates.
version: 0.3.0
metadata:
  hermes:
    category: software-development
    tags: [security, audit, git, polyglot]
---
# Security Scanner
Two passes, and they are different jobs. **Scout** decides what is worth reading; **Analyst** reads it. Skipping the scout turns a whole repository into an arbitrary, expensive read; skipping the analyst turns a target list into a false sense of coverage. This split is the one OpenAI used to make a 40M-line kernel tractable: 5,034 audit targets covering ~7% of the code, and deep analysis only there.

## Scout — cheap, structural, no deep reading
After a completed code-editing task run `python3 ~/.hermes/security-tools/security_matrix.py --repo . scan --mode incremental` (`--mode full` only on explicit request). It returns *paths*, not targets. Convert them into audit targets, judged on two axes only:

- **Reachability** — who can trigger it. Use this portable scale, and map the project's own role names onto it: `anonymous` (no credential) → `user` (any authenticated principal) → `privileged` (an admin-shaped role) → `process` (no request reaches it: job, CLI, startup, migration). Code no unprivileged principal can reach is not a target, whatever it does.
- **Relevance** — why it matters if it is wrong: auth boundary, file write, path built from input, raw SQL, deserialization, outbound request, token lifetime, log sink, seeded identity.

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . target-add \
  --title "Upload path" --path src/api/uploads.py \
  --reachability user --relevance "writes caller-named files to disk" \
  --priority high --actor scout-agent
```

`references/scout-playbook.md` holds the reachability patterns per stack, the triggers that make a file a target, the sizing rule and a worked example — read it before the first scout pass of an unfamiliar repo. During this pass do not record findings and do not read whole files: a target is a hypothesis about where to look.

## First pass in a repository you have never seen
Four questions, each answered by reading configuration rather than guessing:

1. **What are the entry points?** Route registrations and their decorators/attributes (`app/routes*`, `urls.py`, `Controllers/`, `router.ts`), CLI entry points, queue workers, cron/startup hooks.
2. **What is the role ladder?** The authorization config: policies, `Depends(...)` guards, decorators, middleware, `roles` tables/seeds. Write the project's role names down and their order; use those names in `--reachability`.
3. **What ships to the client?** The bundle directory. Anything that runs in the browser is `anonymous` — the attacker owns that machine.
4. **What is the project's own test command?** Read the manifest (`pyproject.toml`, `package.json`, `*.csproj`, `Makefile`) instead of inventing one; the remediator and validator will be asked for its real output.

## Analyst — one target at a time
For each open target, read that code and the call chain in and out of it, state the threat model (entry point → principal → asset), then look for defects: input validation, authentication, authorization/IDOR, injection, unsafe deserialization, secrets, traversal, SSRF, logging and exception leakage, dependency and configuration risk, trust boundaries. Keep a target under ~3,000 lines; split it with a second `target-add` when it is bigger. Consult `hermes-code-inventory` rather than re-reading files.

Record every concrete candidate tied to its target, then close the target:

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . finding \
  --path src/api/uploads.py --symbol upload_attachment \
  --title "..." --severity high --description "..." --evidence "uploads.py:88 ..." \
  --target T-XXXXXXXX --actor scanner-agent
python3 ~/.hermes/security-tools/security_matrix.py --repo . target-close T-XXXXXXXX \
  --status audited --actor scanner-agent --note "read upload_attachment, save_file, storage; sinks checked"
```

- `dismissed` needs a reason naming the missing link ("no caller-controlled value reaches the path builder"), not a shrug.
- Evidence is `file:line` plus the code or the request that proves the claim. Do not call a candidate confirmed: that word belongs to the remediator and is earned by a reproduction.
- Mark files you actually read with `scope-reviewed --run RUN --path PATH --actor scanner-agent`, or `--all` for a run read in one pass (a 28-file scope is 28 shell calls otherwise, and one typo leaves the gate blocked). The tool cannot tell whether you read them; the review is only as good as those marks.
- Scope is language-agnostic: `.cs .csproj .py .pyi .ts .tsx .js .mjs .cjs .vue .razor .cshtml .sh .ps1 .sql .html .json .yml .yaml .toml .ini .config`. It skips dependency caches and tool state (`bin`, `obj`, `node_modules`, `__pycache__`, `.venv`, `.mypy_cache`, `.pytest_cache`, `dist`, `build`), generated trees (EF `Migrations/`, `*.Designer.cs`, `alembic/versions/`, lockfiles) and the `tests/` tree — **test trees are not attack surface**; `--include-tests` opts them back in when the audit is about fixtures (a committed secret, a credential baked into a sample), and `--include-generated` re-adds the generated trees. Curated `.txt`/`.md` files a repo treats as contracts (allowed-route lists, `AGENTS.md` rules) are out of scope — read them by hand when they gate the review.

## Order of work, and what invalidates it
`scan` → scout targets → analyst findings → close targets → remediator reproduces and fixes → independent validator. `scan` supersedes the previous run's unreviewed entries, invalidates the recorded review (keyed to the scope digest and the source hashes) and reopens findings whose file changed, so run it once the edits for the task are done, not while files are still changing. An open target blocks `review --status passed` exactly like an unreviewed file does.

Automatic behavior is a workflow instruction, NOT a native Hermes completion hook. To enforce it, use the Git gate hook and the project's `AGENTS.md`; do not claim unattended agent execution.
