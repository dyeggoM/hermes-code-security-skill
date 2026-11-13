---
name: hermes-security-scanner
description: Scout audit targets by reachability, then analyse each one and record evidence-backed candidates.
version: 0.4.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    category: software-development
    tags: [security, audit, git, polyglot]
---
# Security Scanner
Two passes, and they are different jobs. **Scout** decides what is worth reading; **Analyst** reads it. Skipping the scout turns a whole repository into an arbitrary, expensive read; skipping the analyst turns a target list into a false sense of coverage. This split is the one OpenAI used to make a 40M-line kernel tractable: 5,034 audit targets covering ~7% of the code, and deep analysis only there.

## When to Use
Load this when a repository, a changed surface, or an external hardening checklist has to become audited findings with evidence. It ends when the candidates are recorded and the targets closed: the remediator reproduces and patches them, the validator gives the independent review.

## Scout — cheap, structural, no deep reading
After a completed code-editing task run `python3 ~/.hermes/security-tools/security_matrix.py --repo . scan --mode incremental` (`--mode full` only on explicit request). It returns *paths*, not targets.

**Check the scan covers the repo's primary language before scouting.** Group the returned paths by extension and look for the language the product is written in: a scan of a Python or TypeScript service that comes back with only JSON, YAML, HTML and shell means the tool's extension list is wrong, not that the repo is small — and every later pass would be theatre over 0% of the code. The list is a hardcoded constant: extend it (with that language's dependency and build directories skipped), re-scan, and confirm the count moved before spending anything on a scout.

Convert the paths into audit targets, judged on two axes only:

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

## When the input is a requirements handout, not a repo
An external checklist — a competitor survey, a compliance matrix, a vendor's hardening guide — is a list of *claims about what should exist*, and it is worth nothing until each item is pinned to the code. Build a gap table before opening a single target: one line per requirement, `requirement → what the code does today (path:line, or the command that prints the live header) → ok / partial / missing`, plus the items unreachable from this workstation (certificate chain, DNS, a header the load balancer adds). Report the `ok` rows too: they prove the remaining list is short and stop the next session re-proposing what exists.

- **Read the requirement literally, and check the layer it lands in.** "HTTPS redirect" means the absolute URL it lands on; "HSTS" means the header on the response the client actually receives; "strict CSP" means no `'unsafe-inline'` in `script-src`. A control that exists in the framework middleware but not in the reverse proxy that serves static files is `partial`, and that split is usually the whole bug: a proxy's own `add_header` in a `location` suppresses every inherited header, so files served from disk leave with none.
- **A requirement can be met more strongly than it asks.** Vendoring a third-party script locally and pinning it with `integrity` beats loading it from a CDN with SRI; mark it `ok` with the deviation named instead of redoing it the literal way.
- **Mark the rows that are decisions, not defects.** A stricter `Referrer-Policy` than the checklist requests, or a `frame-ancestors` value that blocks a future embedding, is the owner's call: put it under a short "pending decision" list with the consequence spelled out.

The mechanics behind those rows — edge headers and their two inheritance traps, the CSP hash recipe, `security.txt`, the data-export endpoint, certificate-check arithmetic — are in `references/web-hardening.md`.

## Analyst — one target at a time
For each open target, read that code and the call chain in and out of it, state the threat model (entry point → principal → asset), then look for defects: input validation, authentication, authorization/IDOR, injection, unsafe deserialization, secrets, traversal, SSRF, logging and exception leakage, dependency and configuration risk, trust boundaries, and any security gate keyed to the literal environment name (`app_env == "production"`) instead of a `production_like` predicate — that gate fails open on the staging box wired to real providers, which is the deployment that gets probed. Keep a target under ~3,000 lines; split it with a second `target-add` when it is bigger. Consult `hermes-code-inventory` rather than re-reading files. When the target list is long, batch it into runs of 6-8 targets ordered by reachability and ask for a per-target status line plus the open targets at the end: one run over a dozen targets in a 30k-line service buys breadth and no depth, and a run that hits its budget mid-target must report the target it stopped on.

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
- **Before proposing to relax a fail-closed behaviour, grep the corpus for the assertions that encode it.** A gate written the strict way on purpose — a docstring that says so, a test named for the design, a comment explaining the trade — is not a defect: the candidate is `false_positive`, the note cites the line that encodes the intent, and the behaviour stays. Relaxing it to satisfy a UX complaint trades a known cost for an unknown hole. The same grep guards the opposite direction: a suggested *tightening* is a hypothesis about precision too, so it is only demonstrated by the corpus green in **both** directions — the motivating bypass blocked and the innocent cases still passing.
- **When a gate keys on a word list, the fix is a shape, not more words.** Every enumerated list is a list the attacker finishes for you: adding the ten synonyms the auditor found buys one round, and the next synonym is the same finding. Anchor the rule to the grammatical or structural form around the value, and keep the existing precision guard (the extra required cue, the unit exclusion). Say that in the finding, or the fix will add eleven words and call it closed.
- **A size or shape check inside a request handler runs after the framework has already read the body.** FastAPI/Starlette resolves `Form(...)`/`Body(...)` before the function body, so a `Content-Length` check there materialises the payload it means to refuse; the fix is middleware that cuts the stream for those paths, with the per-handler check removed rather than duplicated.
- Evidence is `file:line` plus the code or the request that proves the claim. The analyst leaves every candidate in `needs_validation` — the scanner does not get to call its own finding confirmed.
- Most candidates in application code reproduce in the language's own interpreter in one command (call the parser, the render function, the classifier with the payload). Do that during triage: it costs minutes, needs no server or credentials, and it is what separates *likely* from *plausible* before anyone pays for a fix. Do not write `confirmed` yourself, but never route a high-severity fix on reading alone.
- Mark files you actually read with `scope-reviewed --run RUN --path PATH --actor scanner-agent`, or `--all` for a run read in one pass (a 28-file scope is 28 shell calls otherwise, and one typo leaves the gate blocked). The tool cannot tell whether you read them; the review is only as good as those marks.
- Scope is language-agnostic: `.cs .csproj .py .pyi .ts .tsx .js .mjs .cjs .vue .razor .cshtml .sh .ps1 .sql .html .json .yml .yaml .toml .ini .config`. It skips dependency caches and tool state (`bin`, `obj`, `node_modules`, `__pycache__`, `.venv`, `.mypy_cache`, `.pytest_cache`, `dist`, `build`), generated trees (EF `Migrations/`, `*.Designer.cs`, `alembic/versions/`, lockfiles) and the `tests/` tree — **test trees are not attack surface**; `--include-tests` opts them back in when the audit is about fixtures (a committed secret, a credential baked into a sample), and `--include-generated` re-adds the generated trees. Curated `.txt`/`.md` files a repo treats as contracts (allowed-route lists, `AGENTS.md` rules) are out of scope — read them by hand when they gate the review.
- The ledger and its render are artifacts: `.security/` and `SECURITY_MATRIX.md` belong in the repo's `.gitignore` (as do `.code-inventory/` and its rendered document), because the render embeds the reviewed commit and rewrites on every review run.

## Order of work, and what invalidates it
`scan` → scout targets → analyst findings → close targets → remediator reproduces and fixes → independent validator. `scan` supersedes the previous run's unreviewed entries, invalidates the recorded review (keyed to the scope digest and the source hashes) and reopens findings whose file changed, so run it once the edits for the task are done, not while files are still changing. An open target blocks `review --status passed` exactly like an unreviewed file does.

### Ledger transitions, and who moves them
`needs_validation` → `confirmed` → `in_remediation` → `fixed_pending_verification` → `verified_fixed` → `integration_verified`. The chain is enforced, so knowing which link belongs to whom keeps a round from stalling with a dozen findings nobody can close:

- The **analyst** stops at `needs_validation`.
- **Whoever reproduces** it moves it to `confirmed`; an in-interpreter probe is a reproduction and is the cheapest one available.
- `in_remediation` when the fix is assigned; `fixed_pending_verification` when the change is *in the tree and verified by you*, not when someone reports it.
- `verified_fixed` and `integration_verified` belong to the independent validator and the `review` command; `transition` refuses `integration_verified` on purpose.
- A finding whose file changed since verification reopens by itself. Re-read it before re-reporting.
- A partial fix goes to `fixed_pending_verification` with the missing piece named in the note. `false_positive` is for a finding the code disproves (cite the line), `accepted_risk` for a trade the owner made — neither is a place to park work half-done, and `accepted_risk` keeps `review --status passed` refused exactly like an unresolved finding. Collect the lows that are really owner decisions into one list and put it in front of them early: discovering at the end that the gate cannot go green costs the round.

Group candidates by root cause before routing fixes, not by finding id: several gates that fail open for the same predicate are one brief, one test file and one changelog line, and splitting them by id buys four rounds of the same edit.

Automatic behavior is a workflow instruction, NOT a native Hermes completion hook. To enforce it, use the Git gate hook and the project's `AGENTS.md`; do not claim unattended agent execution.
