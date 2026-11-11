#!/usr/bin/env bash
set -euo pipefail
repo="$(git -C "${1:-.}" rev-parse --show-toplevel)"
hook="$repo/.git/hooks/pre-commit"
if [[ -e "$hook" ]]; then echo "Existing hook found; merge manually: $hook" >&2; exit 1; fi
cat > "$hook" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
python3 "$HOME/.hermes/security-tools/security_matrix.py" --repo . status | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["valid_integration_review"], "Security review required before commit"'
EOF
chmod +x "$hook"
echo "Installed $hook"
