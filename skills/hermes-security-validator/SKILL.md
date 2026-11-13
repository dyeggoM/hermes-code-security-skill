---
name: hermes-security-validator
description: Independent final security review that re-runs the reproductions and gates the release.
version: 0.4.0
author: Hermes Agent
license: MIT
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

## Prove a file out of scope instead of reading it
A full scope always contains files nobody will read line by line — an archived copy of the frontend, an ML training tree, a vendored SDK, generated snapshots. The review counts them, so the choice is between reading them and proving they cannot matter. Prove it one category at a time and put the proof in the note rather than the word "excluded":

- **Not deployed.** Read the server config: if the reverse proxy serves one directory, an archived copy elsewhere never reaches a client.
- **Byte-identical to upstream.** Hash the vendored file and compare with the source it came from; an `integrity` attribute in the HTML is a claim to verify, not evidence.
- **Unreachable from production.** `grep` the app tree for imports of the module: references in comments are not edges. An offline trainer that nothing imports and that binds to loopback is a different trust boundary from the request path.
- **Trivial by construction.** `__init__.py` re-exports, constants, type stubs: skim and say so.

Then `scope-reviewed --run N --all` and state in the note how many were read and how many were covered by which proof. A scope marked reviewed without that breakdown is the same comfort as a green suite.

## Attack the vocabulary, not only the branch
A text gate — a content classifier, an injection detector, a profanity filter — has two parts: the condition that decides, and the lexicon it recognises. A fix almost always lands on the condition (the lookahead, the missing guard, the wrong block type) and leaves the word list untouched, so the recorded reproduction now fails while a one-word substitution still passes. Re-running the reproduction therefore proves the smallest possible thing. Spend the pass on the input surface instead:

- **Vary the lexicon.** Regional and dialectal synonyms, plurals, diminutives, typos, another language, the same idea in digits or homoglyphs. One such sweep over a classifier that had just "passed" produced the only new high of that round: six subject nouns the fix never touched, each a one-line bypass.
- **Vary the shape around it.** Punctuation where the rule expects end-of-clause, an emoji, the cue moved one word later, the clause reordered.
- **Run the inverse sweep in the same pass.** Every widening also loosens precision, so the innocent corpus must be green too: a parent describing their own child, a unit of measure, a comparative ("15 cm smaller"), a business phrase built from the same word. A fix demonstrated only on the cases that motivated it is a hypothesis, not a fix.
- Report it as a new `finding` when the sweep lands, even if the original id was already closed — reusing the closed id hides the fact that the class of defect is still open.

## A fix can buy security with correctness
Anything that decides *is this the same event* or *is this the same person* — a dedupe/idempotency key, a routing table, an identity alias — is where a hardening change breaks the product while every security test stays green. Before signing, pick two legitimate cases that **must** remain distinct and trace both end to end: an approval and its refund on the same payment, the same phone number on two channels, two users with similar identifiers. Read the resulting rows, not the status string:

- A dedupe key moved from an unsigned notification id to a signed resource id collapsed the charge and the refund of the same payment, so the refund came back as a duplicate and never reached the ledger. The attacker path was genuinely closed and every test the fix targeted passed.
- The mechanical check is one query on the inbox/ledger after replaying both events (row count, and the state each event produced). If two events that must differ map to one row, the fix is wrong regardless of what it closed.

When no signed identifier distinguishes two events, the honest verdict is `accepted_risk` with the residual cost named (bounded by the ledger and the rate limit) — not a key that silently drops half the events. `accepted_risk` keeps `review --status passed` refused exactly like an open finding: surface those trades to the owner early instead of discovering at signing time that the gate cannot go green.

## Record the verdict
- A new problem → record it as a `finding` tied to its target, then `review --status failed --reviewer <you> --note "<what breaks>"`.
- Everything holds → `python3 ~/.hermes/security-tools/security_matrix.py --repo . review --status passed --reviewer <you> --note "<evidence + raw test summary>"`.
- `… check` gives the same verdict read-only (exit 0 committable, 1 blocked): run it before and after your pass.

Validity is tied to the Git HEAD and to the source hashes in scope, so a passing review covers exactly one commit and dies when HEAD moves — if the code moved after your pass, revalidate before signing. A passing status is an evidence-bounded statement about the files you read, never proof that the code has no vulnerabilities.
