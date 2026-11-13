---
name: hermes-security-validator
description: Independent final security review that re-runs the reproductions and gates the release.
version: 0.3.0
metadata:
  hermes:
    category: software-development
    tags: [security, validation, integration, polyglot]
---
# Security Validator
Run only when every scope entry was actually read, every audit target is closed, and every finding is `verified_fixed` or `false_positive` (`status` says so; `review --status passed` refuses otherwise). You did not write the fix — that is the point.

## Verify the path, not the state
A green test suite proves the suite passes, not that this fix removed this trigger. For each finding, re-run the reproduction recorded in its note, on a copy of the tree, and confirm it now fails **for the right reason** — without the harness having been adjusted to make it fail. The kernel sweep found 20 of 200 apparently successful exploits had reached their goal through a *different* bug: a result obtained by another route is not evidence for this one.

Then read outward, not just at the diff: the whole affected call chain, the authorization flow it sits in, the data boundaries, the interaction between corrected functions, the regression tests and the configuration the behaviour depends on (`appsettings.*`, policy definitions, cookie flags). Run the project's own suite yourself and keep the raw output: `dotnet build` + `dotnet test` for .NET, `pytest -q` (scope it to the touched modules if the full run is long) + `ruff check` for Python, whatever `scripts.test` declares in `package.json` for the UI. Review the patch as an attacker: can it be bypassed, does it miss a sibling copy of the same defect, does it break a legitimate path?

## Record the verdict
- A new problem → record it as a `finding` tied to its target, then `review --status failed --reviewer <you> --note "<what breaks>"`.
- Everything holds → `python3 ~/.hermes/security-tools/security_matrix.py --repo . review --status passed --reviewer <you> --note "<evidence + raw test summary>"`.
- `… check` gives the same verdict read-only (exit 0 committable, 1 blocked): run it before and after your pass.

Validity is tied to the Git HEAD and to the source hashes in scope, so a passing review covers exactly one commit and dies when HEAD moves — if the code moved after your pass, revalidate before signing. A passing status is an evidence-bounded statement about the files you read, never proof that the code has no vulnerabilities.
