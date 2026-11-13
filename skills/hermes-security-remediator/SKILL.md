---
name: hermes-security-remediator
description: Reproduce security candidates before confirming them, then fix the confirmed ones with regression tests.
version: 0.3.0
metadata:
  hermes:
    category: software-development
    tags: [security, remediation, polyglot]
---
# Security Remediator
Read `SECURITY_MATRIX.md`, `.security/REMEDIATION_STATUS.md` and the audit target each candidate came from. Then **reproduce before believing it**.

## Confirm by reproduction, not by reading
For every `needs_validation` candidate, build the smallest probe that exercises the claimed path and run it: `curl` against a sandbox instance, a focused test, a script. Copy the repo to your own sandbox — its own database file, its own port — never against a tree someone else is working in. Put the request and the observed output in the transition note:

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . transition SEC-XXXXXXXX \
  --status confirmed --actor verifier-agent \
  --note "repro: POST /api/uploads item_id=999999 -F file=@x.bin -> 500 FK; media/999999/x.bin left on disk (ls)"
```

- Reproduced → `confirmed`, with the request and the observed output in the note.
- Not reproduced → `false_positive` with the reason the trigger fails ("the route rejects `%2F` before binding — measured"). A dismissed candidate with evidence is a result, not a failure.
- Cannot drive it inside the budget → leave it `needs_validation` and say what is missing. Two honest attempts with no progress is the stop rule: record what was tried and move on.

## Fix the confirmed ones
Record `in_remediation`, implement the smallest safe fix, and add a regression test that fails before the fix and passes after it. Run the project's own commands, read from its manifest rather than guessed: `dotnet build` + `dotnet test <csproj>` for .NET, `pytest -q <path>::<test>` + `ruff check` + `mypy` (if configured) for Python, whatever `scripts.test` declares in `package.json` for a JS/TS app. Then look for siblings: grep for the same pattern elsewhere in the target before closing — one patched sink is how the variant survives. Keep the diff to the concern; a security change bundled with a refactor cannot be verified.

```bash
python3 ~/.hermes/security-tools/security_matrix.py --repo . transition SEC-XXXXXXXX \
  --status fixed_pending_verification --actor fix-agent \
  --note "guard added at uploads.py:88; test_upload_with_missing_parent_returns_400 green; both write paths audited"
```

Record `fixed_pending_verification` **after** the last edit to that file: findings are keyed to the file's SHA-256, so editing afterwards reopens the finding and your state was a lie.

## Never self-approve
A **different** agent re-runs the probe, reads the fix and records `verified_fixed`, or `reopened` with what still triggers. If you are that second agent, verify the *path*: the original probe must fail now for the right reason, not because the test was adjusted or because another change made it unreachable. Accepted risk needs explicit owner approval and still blocks a clean final review in this version. Put test output and agent identity in every note, and never execute untrusted code outside a sandbox.
