---
name: hermes-security-scanner
description: Scout audit targets by reachability, then analyse each one and record evidence-backed candidates.
version: 0.2.0
metadata:
  hermes:
    category: software-development
    tags: [security, csharp, audit, git]
---
# Security Scanner
Two passes, and they are different jobs. **Scout** decides what is worth reading; **Analyst** reads it. Skipping the scout turns a whole repository into an arbitrary, expensive read; skipping the analyst turns a target list into a false sense of coverage. This split is the one OpenAI used to make a 40M-line kernel tractable: 5,034 audit targets covering ~7% of the code, and deep analysis only there.

## Scout — cheap, structural, no deep reading
After a completed code-editing task run `python3 ~/.hermes/security-tools/security_matrix.py --repo . scan --mode incremental` (`--mode full` only on explicit request). It returns *paths*, not targets. Convert them into audit targets, judged on two axes only:

- **Reachability** — who can trigger it: `anonymous`, `lector`, `operador`, `admin`, `superadmin`. Code no unprivileged principal can reach is not a target, whatever it does.
- **Relevance** — why it matters if it is wrong: auth boundary, file write, path built from input, raw SQL, deserialization, outbound request, token lifetime, log sink, seeded identity.

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . target-add \
  --title "Attachment upload path" --path IMCAPI/Controllers/Controllers.cs \
  --reachability operador --relevance "writes attacker-named files to disk" \
  --priority high --actor scout-agent
```

`references/scout-playbook.md` holds the reachability table for this stack, the triggers that make a file a target, the sizing rule and a worked example — read it before the first scout pass of a repo. During this pass do not record findings and do not read whole files: a target is a hypothesis about where to look.

## Analyst — one target at a time
For each open target, read that code and the call chain in and out of it, state the threat model (entry point → principal → asset), then look for defects: input validation, authentication, authorization/IDOR, injection, unsafe deserialization, secrets, traversal, SSRF, logging and exception leakage, dependency and configuration risk, trust boundaries. Keep a target under ~3,000 lines; split it with a second `target-add` when it is bigger. Consult `hermes-code-inventory` rather than re-reading files.

Record every concrete candidate tied to its target, then close the target:

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . finding \
  --path IMCAPI/Controllers/Controllers.cs --symbol AttachmentController.Upload \
  --title "..." --severity high --description "..." --evidence "Controllers.cs:357 ..." \
  --target T-XXXXXXXX --actor scanner-agent
python3 ~/.hermes/security-tools/security_matrix.py --repo . target-close T-XXXXXXXX \
  --status audited --actor scanner-agent --note "read Upload, ApplyUploadAsync, SaveAsync; sinks checked"
```

- `dismissed` needs a reason naming the missing link ("no attacker-controlled value reaches `Path.Combine`"), not a shrug.
- Evidence is `file:line` plus the code or the request that proves the claim. Do not call a candidate confirmed: that word belongs to the remediator and is earned by a reproduction.
- Mark files you actually read with `scope-reviewed --run RUN --path PATH --actor scanner-agent`, or `--all` for a run read in one pass (a 28-file scope is 28 shell calls otherwise, and one typo leaves the gate blocked). The tool cannot tell whether you read them; the review is only as good as those marks.
- Scope covers `.cs .csproj .json .config .yml .yaml .razor .cshtml .ts .tsx .js .mjs .cjs .vue .sh .ps1 .sql .html`, skipping EF `Migrations/`, `*.Designer.cs`, lockfiles, `bin`, `obj`, `node_modules` (`--include-generated` opts them back in). Curated `.txt`/`.md` files a repo treats as contracts (allowed-route lists, `AGENTS.md` rules) are out of scope — read them by hand when they gate the review.

## Order of work, and what invalidates it
`scan` → scout targets → analyst findings → close targets → remediator reproduces and fixes → independent validator. `scan` supersedes the previous run's unreviewed entries, invalidates the recorded review (keyed to the scope digest and the source hashes) and reopens findings whose file changed, so run it once the edits for the task are done, not while files are still changing. An open target blocks `review --status passed` exactly like an unreviewed file does.

Automatic behavior is a workflow instruction, NOT a native Hermes completion hook. To enforce it, use the Git gate hook and the project's `AGENTS.md`; do not claim unattended agent execution.
