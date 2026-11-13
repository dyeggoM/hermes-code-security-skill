#!/usr/bin/env bash
# Installs the skills and the shared CLI into the Hermes profile.
# The CLI is a standalone program, so the skills call it by absolute path: Hermes does not export
# HERMES_SKILL_DIR to the shell, and a path relative to the skill directory only works for one
# install layout.
#
# Usage:
#   bash scripts/install.sh                          # shared skills dir (~/.hermes/skills)
#   bash scripts/install.sh --profile code-orchestrator
#   HERMES_PROFILE=code-orchestrator bash scripts/install.sh
#
# A profile with its own `skills/` directory shadows the shared one, so installing only to the shared
# directory leaves that profile running an older copy of these skills while reporting success. When a
# profile is named the installer writes both, and prints every destination it touched.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
tools="${HERMES_SECURITY_TOOLS:-$HOME/.hermes/security-tools}"
shared="${HERMES_SKILLS_DIR:-$HOME/.hermes/skills/software-development}"
profile="${HERMES_PROFILE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="${2:-}"; shift 2 ;;
    --profile=*) profile="${1#*=}"; shift ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

targets=("$shared")
if [[ -n "$profile" ]]; then
  targets+=("$HOME/.hermes/profiles/$profile/skills/software-development")
fi

mkdir -p "$tools" "${targets[@]}"
install -m 0755 "$root/shared/security_matrix.py" "$tools/security_matrix.py"

for dest in "${targets[@]}"; do
  for skill in "$root"/skills/*/; do
    name="$(basename "$skill")"
    # Replace, not merge: a stale file left behind by an older version is the drift this installer
    # exists to prevent.
    rm -rf "${dest:?}/$name"
    cp -r "$skill" "$dest/$name"
  done
done

echo "CLI:    $tools/security_matrix.py ($(python3 "$tools/security_matrix.py" version))"
for dest in "${targets[@]}"; do
  echo "Skills: $dest/hermes-security-{scanner,remediator,validator}"
done
echo
echo "Next: python3 $tools/security_matrix.py --repo /path/to/project scan --mode incremental"
echo "Hook: bash $here/install-hook.sh /path/to/project   (see README: the gate is per commit)"
