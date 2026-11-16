---
name: hermes-security-remediator
description: Reproduce security candidates before confirming them, then fix the confirmed ones with regression tests.
version: 0.4.2
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
python3 $SM --repo . transition SEC-XXXXXXXX \
  --status confirmed --actor verifier-agent \
  --note "repro: POST /api/uploads item_id=999999 -F file=@x.bin -> 500 FK; media/999999/x.bin left on disk (ls)"
```

- Reproduced → `confirmed`, with the request and the observed output in the note.
- Not reproduced → `false_positive` with the reason the trigger fails ("the route rejects `%2F` before binding — measured"). A dismissed candidate with evidence is a result, not a failure.
- Cannot drive it inside the budget → leave it `needs_validation` and say what is missing. Two honest attempts with no progress is the stop rule: record what was tried and move on.

## Fix the confirmed ones
`$SM` is the security matrix CLI that the scanner already set (`SM="${HERMES_SECURITY_TOOLS:-$HOME/.hermes/security-tools}/security_matrix.py"`); set it the same way if you started the session here. Record `in_remediation`, implement the smallest safe fix, and add a regression test that fails before the fix and passes after it. Run the project's own commands, read from its manifest rather than guessed: `dotnet build` + `dotnet test <csproj>` for .NET, `pytest -q <path>::<test>` + `ruff check` + `mypy` (if configured) for Python, whatever `scripts.test` declares in `package.json` for a JS/TS app. Then look for siblings: grep for the same pattern elsewhere in the target before closing — one patched sink is how the variant survives. Keep the diff to the concern; a security change bundled with a refactor cannot be verified.

```bash
python3 $SM --repo . transition SEC-XXXXXXXX \
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

## Gates that only a browser enforces
`curl` proves the route, not the deployment. Two classes of finding live entirely in the browser's rules and survive every server-side test:

- **A method missing from the CORS allow-list.** The server route works, the preflight answers `Access-Control-Allow-Methods` without that verb, and the browser refuses to send the call: the client sees `TypeError: Failed to fetch`, never a status. Probe it as a browser would —`OPTIONS` with `Origin` and `Access-Control-Request-Method`, then read the allow-list — and pin it with a test that takes the verbs from the app's own route table, not from a list typed into the test — ASP.NET `IActionDescriptorCollectionProvider` → `HttpMethodActionConstraint`, FastAPI `app.routes[*].methods`, Express's router stack, Django's `URLResolver` — so a new verb cannot drift out of the policy. Same shape for `Access-Control-Allow-Headers`.
- **A credential the client never sends.** A gate that requires a cookie is enforced by the browser only if the call sets `credentials: 'include'`; a transport that only does so for the refresh endpoint passes every same-origin test and fails in production, where the SPA and the API are different ports. Check the transport, not just the route, and add a test asserting the option on the call that needs it.

Reflecting any origin while allowing credentials is a real exposure on a shared network (a page on the internet reads the API with the tester's cookie). In development reflect loopback and private ranges only, plus the configured list, and say so in a test — the LAN case must keep working, the public one must not.

## When the finding is "this credential cannot be revoked"
A borrowed or delegated token (impersonation, support access, a scoped share link) is unrevocable by construction: the claim says *who*, nothing says whether it is *still allowed*. Hardening the exchange that minted it does not fix that — the token already out there keeps working until it expires, cannot be ended twice-detected, and cannot be paired with its own start event. The fix shape is a row, not another claim:

- **Give the borrow an entity and put its id in the token** — `imp_sid` in the recipe below, whatever name your claims use. One row per borrow: actor, target, started, expires, ended, ended-by. `Impersonate`/`ImpersonateStart`/`ImpersonateEnd` already mean a lifecycle — make it real.
- **Check the row wherever the token is validated**, not in the controllers: the check has to run before authorization, so a closed borrow fails as *unauthenticated* and no route has to remember to look.
- **The end path must not depend on the credential the exchange requires.** If ending the borrow needs the actor's refresh cookie and that cookie is gone (family revoked, account deactivated, another device), the borrow is stuck — the finding you were fixing is still there in a new place. Answer "ended, no token" (`204`) when the proof is absent: the borrow closes, the client falls back to the session it kept aside, and nothing is upgraded. Only the *token handback* needs the proof.
- **Single use falls out of the row**: a second end finds nothing live. Expect the status to move from `403` to `401`, because after revocation the credential dies in authentication, before authorization can answer — update those assertions to the new semantics with a one-line comment saying so. Deleting or loosening them to the old code hides whether revocation works at all.
- **Name the borrow in the audit trail**, on the Start/End pair *and* on any row written while it was live, so "what did this borrow touch" is a query. Pairing is the point: a session id only in `AfterJson` cannot be filtered on.
- **Keep the borrow's own row out of the audit stream.** An interceptor that watches every modified entity turns each state change of your new table into an `Update` row that swamps the pair you actually need; exclude the control table and let the Start/End events carry the meaning.
- **Ship the client half in the same change.** A server gate that the SPA does not satisfy (a cookie it never sends, a `204` it parses as an error) turns the feature's exit button into a refusal and silently loses the closing audit row. Grep the transport and drive the real screen once, not just the route.

See `references/delegation-token-revocation.md` for the concrete entity/claim/validation recipe and the verification matrix.

## After the fix: prove both sides
A gate that only closes the hole can silently break the feature, and the fallback hides it.

- **Bare holder fails, legitimate caller passes.** For a token-borrowing or impersonation finding, run the original probe again (the borrowed credential alone must now be refused) *and* the intended path (the actor's own session must still succeed). A fix verified only in the negative direction leaves the feature dead.
- **The trail still closes.** When the legitimate path writes an audit row, assert the pair exists after the fix. A client that falls back locally clears the UI while the `…End` row stops being written — the feature looks fine and the evidence is gone.
- **Revert the fix to see the test fail.** A regression test written after the fix passes for the wrong reasons more often than not: remove the guard, run it, read the failure message (`these verbs are routed but a browser would refuse them: PATCH` is the shape), restore. If it passes with the guard removed, it is not a regression test.
- **Confirm the running instance is the code under review.** An endpoint that answers `404`, or a feature that behaves like the old version, is usually a server started before the change. Check a marker (a route that only exists after the fix, a response header,  the branch the build came from) before concluding a fix is broken — two of these cost a diagnosis round each.
  Restarting it is where the shell dies by its own hand: `pgrep -f '<script>.sh'` also matches the
  command line that *launches* that script, so a pattern kill issued in the same call terminates the
  agent's own shell mid-command and leaves the service down. Kill in one call (match the listening
  socket, `ss -ltn | grep :PORT`, or the full binary path), start in a second, poll the port in a third.

## Dedupe and idempotency keys
A replay finding is usually "fixed" by changing the dedupe key, and that is where the damage happens: the key has to stay **unique per event**, and the field a provider signs is usually not.

- **Signed is not unique.** A webhook signature typically covers the resource id and not the notification id, so keying on the signed value collapses every event for that resource: the approval and the refund of the same payment compute the same key and the second one is swallowed. Losing the refund is worse than the replay the fix was about.
- **The acceptance case is the chain, not the replay.** One test where two different events share a resource and both must be processed, plus one where a replay that changes only the unsigned field must not produce a second grant. A fix that only proves "the replay is deduped" passes while destroying the event stream, and a filtered test run over the module will not show it.
- **When the provider signs no per-event identifier, uniqueness wins and the residual is bounded, not hidden.** Keep the unsigned id as the key, bound the abuse with a rate limit on the endpoint and the ledger's own per-payment idempotency (no double grant is the invariant that matters), record `accepted_risk` naming those two mechanisms, and leave the trade in a test docstring so the next reader sees a decision instead of a regression. Do not reshape a state machine to make a medium finding look closed.

## Never self-approve
A **different** agent re-runs the probe, reads the fix and records `verified_fixed`, or `reopened` with what still triggers. If you are that second agent, verify the *path*: the original probe must fail now for the right reason, not because the test was adjusted or because another change made it unreachable. Accepted risk needs explicit owner approval and still blocks a clean final review in this version. Put test output and agent identity in every note, and never execute untrusted code outside a sandbox.
