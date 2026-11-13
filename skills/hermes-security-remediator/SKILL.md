---
name: hermes-security-remediator
description: Reproduce security candidates before confirming them, then fix the confirmed ones with regression tests.
version: 0.4.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    category: software-development
    tags: [security, remediation, polyglot]
---
# Security Remediator
Read `SECURITY_MATRIX.md`, `.security/REMEDIATION_STATUS.md` and the audit target each candidate came from. Then **reproduce before believing it**.

## Confirm by reproduction, not by reading
For every `needs_validation` candidate, build the smallest probe that exercises the claimed path and run it: `curl` against a sandbox instance, a focused test, a script, or a direct call into the function from the language's interpreter. Copy the repo to your own sandbox — its own database file, its own port — never against a tree someone else is working in. Put the request and the observed output in the transition note:

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

## Respect the invariants the database enforces
Before accepting a fix that changes a lifecycle or status value, read the schema that guards it: triggers, `CHECK` constraints and (often partial) unique indexes on that table. The brief is a hypothesis; the schema is the contract. Three shapes cost a round trip each and are worth checking by name:

- **Terminal states.** A monotonic-transition trigger admitting only `X → X` makes a supposedly ordinary `expire`/`complete` abort the whole statement — and with it the surrounding transaction, so the endpoint starts failing on the exact path the finding is about. Read the trigger's `WHEN` clause and treat any state it does not list as unreachable, not as an oversight to correct.
- **A second transition list.** If a service method accepts more source states than the trigger does, the method's signature is not permission: narrow the caller to the trigger's set.
- **Uniqueness that forbids the obvious workaround.** A unique key on a "live" row (one active lease/mandate/token per owner) means "expire the old row and create another" is not available; the fix has to make the existing row reusable — gate on the *live* status rather than a local TTL.

When the invariant blocks the requested fix, the design changes, never the constraint: a schema migration on a ledger or a billing table is not a side effect of a security patch. Rewrite the brief around the real contract ("reuse while the provider object is alive" instead of "expire after TTL") and record in the note which constraint forced the shape — otherwise the next reviewer re-proposes the version the schema refuses.

## Dedupe and idempotency keys
A replay finding is usually "fixed" by changing the dedupe key, and that is where the damage happens: the key has to stay **unique per event**, and the field a provider signs is usually not.

- **Signed is not unique.** A webhook signature typically covers the resource id and not the notification id, so keying on the signed value collapses every event for that resource: the approval and the refund of the same payment compute the same key and the second one is swallowed. Losing the refund is worse than the replay the fix was about.
- **The acceptance case is the chain, not the replay.** One test where two different events share a resource and both must be processed, plus one where a replay that changes only the unsigned field must not produce a second grant. A fix that only proves "the replay is deduped" passes while destroying the event stream, and a filtered test run over the module will not show it.
- **When the provider signs no per-event identifier, uniqueness wins and the residual is bounded, not hidden.** Keep the unsigned id as the key, bound the abuse with a rate limit on the endpoint and the ledger's own per-payment idempotency (no double grant is the invariant that matters), record `accepted_risk` naming those two mechanisms, and leave the trade in a test docstring so the next reader sees a decision instead of a regression. Do not reshape a state machine to make a medium finding look closed.

## Never self-approve
A **different** agent re-runs the probe, reads the fix and records `verified_fixed`, or `reopened` with what still triggers. If you are that second agent, verify the *path*: the original probe must fail now for the right reason, not because the test was adjusted or because another change made it unreachable. Accepted risk needs explicit owner approval and still blocks a clean final review in this version. Put test output and agent identity in every note, and never execute untrusted code outside a sandbox.
