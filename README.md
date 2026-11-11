# Hermes Security Skills (prototype v0.1)

Three Hermes skills + shared SQLite CLI. Python 3.10+, Git. No external Python dependencies.

## Install

```bash
mkdir -p ~/.hermes/security-tools ~/.hermes/skills
cp shared/security_matrix.py ~/.hermes/security-tools/security_matrix.py
cp -r skills/hermes-security-* ~/.hermes/skills/
# Make skill references resolve in the installed layout:
ln -sfn ~/.hermes/security-tools ~/.hermes/shared
```

Use `python3 ~/.hermes/security-tools/security_matrix.py --repo /path/to/project scan --mode incremental` or `--mode full`. To compare a committed baseline, add `--base <git-ref>`. The scanner command prepares the review scope; the agent must inspect files and record findings.

## Automatic integration

Install the optional Git pre-commit hook with `bash scripts/install-hook.sh /path/to/project`. It **blocks a commit unless the security review is valid**; it does not perform AI analysis. Add `AGENTS.md` instructions from `templates/AGENTS.security.md` to have the development agent run the scanner after each task. Git hooks can be bypassed, so enforce the gate in CI for stronger guarantees.

## Limitations

Prototype, not a vulnerability scanner. SQLite tracks findings and source hashes; actual reasoning, independent agent assignment, regression testing and full audit coverage require Hermes orchestration. Do not interpret an empty matrix as a clean audit. Run `status` to check coverage and final-review validity.
