#!/usr/bin/env bash
# Installs the skills and the shared CLI into the Hermes profile.
# The CLI is a standalone program, so the skills call it by absolute path: Hermes does not export
# HERMES_SKILL_DIR to the shell, and a path relative to the skill directory only works for one
# install layout.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
tools="${HERMES_SECURITY_TOOLS:-$HOME/.hermes/security-tools}"
skills="${HERMES_SKILLS_DIR:-$HOME/.hermes/skills/software-development}"

mkdir -p "$tools" "$skills"
install -m 0755 "$root/shared/security_matrix.py" "$tools/security_matrix.py"

for skill in "$root"/skills/*/; do
  name="$(basename "$skill")"
  rm -rf "${skills:?}/$name"
  cp -r "$skill" "$skills/$name"
done

echo "CLI:    $tools/security_matrix.py"
echo "Skills: $skills/hermes-security-{scanner,remediator,validator}"
echo
echo "Next: python3 $tools/security_matrix.py --repo /path/to/project scan --mode incremental"
echo "Hook: bash $here/install-hook.sh /path/to/project   (see README: the gate is per commit)"
