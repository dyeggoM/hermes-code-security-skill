#!/usr/bin/env bash
# Installs a pre-commit hook that blocks the commit unless the recorded security review is valid
# for the state of the tree being committed. It runs no analysis of its own.
#
# The hook body is short on purpose: all the reasoning lives in `security_matrix.py check`, which is
# read-only, so the gate never rewrites the tree in the middle of a commit.
set -euo pipefail
repo="$(git -C "${1:-.}" rev-parse --show-toplevel)"
hook="$repo/.git/hooks/pre-commit"
if [[ -e "$hook" ]]; then echo "Existing hook found; merge manually: $hook" >&2; exit 1; fi
cat > "$hook" <<'EOF'
#!/usr/bin/env bash
# Security review gate — see SECURITY_MATRIX.md. Bypass for one commit: git commit --no-verify
set -u
cli="${SECURITY_MATRIX_CLI:-$HOME/.hermes/security-tools/security_matrix.py}"
if [[ ! -f "$cli" ]]; then
  echo "security gate: CLI not found at $cli (set SECURITY_MATRIX_CLI) — gate skipped" >&2
  exit 0
fi
exec python3 "$cli" --repo . check
EOF
chmod +x "$hook"
echo "Installed $hook"
