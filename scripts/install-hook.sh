#!/usr/bin/env bash
# Installs a pre-commit hook that blocks the commit unless the recorded security review is valid
# for the state of the tree being committed. It runs no analysis of its own.
set -euo pipefail
repo="$(git -C "${1:-.}" rev-parse --show-toplevel)"
hook="$repo/.git/hooks/pre-commit"
if [[ -e "$hook" ]]; then echo "Existing hook found; merge manually: $hook" >&2; exit 1; fi
cat > "$hook" <<'EOF'
#!/usr/bin/env bash
# Security review gate. Bypass per commit with: git commit --no-verify
set -uo pipefail
cli="${SECURITY_MATRIX_CLI:-$HOME/.hermes/security-tools/security_matrix.py}"
if [[ ! -f "$cli" ]]; then
  echo "Security gate: CLI not found at $cli (set SECURITY_MATRIX_CLI)" >&2
  exit 1
fi
out="$(python3 "$cli" --repo . status)"
printf '%s' "$out" | CLI="$cli" python3 -c '
import json, os, sys
try:
    state = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit("Security gate: could not read the matrix status")
if state["valid_integration_review"]:
    sys.exit(0)
findings = len(state["findings"])
unreviewed = len(state["unreviewed_scope"])
latest = state.get("latest_review")
if latest is None:
    reason = "no security review has been recorded for this repository"
elif not state.get("review_applies_to_head"):
    reason = "the last review was recorded for commit %s but HEAD is now %s" % (
        latest["commit_sha"][:12], state["head"][:12])
elif latest["status"] != "passed":
    reason = "the last review for this tree was recorded as %s" % latest["status"]
elif findings or unreviewed:
    reason = "%d open finding(s), %d unreviewed scope entr(ies)" % (findings, unreviewed)
else:
    reason = "the review no longer matches the tree (a source hash in scope changed)"
print("Security review required before commit: %s." % reason, file=sys.stderr)
print("  next: python3 %s --repo . status" % os.environ["CLI"], file=sys.stderr)
sys.exit(1)
'
EOF
chmod +x "$hook"
echo "Installed $hook"
