---
name: hermes-security-remediator
description: Independently validate security candidates and remediate confirmed vulnerabilities with regression tests and tracked states.
version: 0.1.0
metadata:
  hermes:
    category: software-development
    tags: [security, remediation, csharp]
---
# Security Remediator
Read `SECURITY_MATRIX.md` and `.security/REMEDIATION_STATUS.md`. For each `needs_validation` candidate, independently inspect source, caller/callee context and trust boundaries. Reject unsupported candidates with `transition ID --status false_positive --actor verifier-agent --note ...`, or confirm with `--status confirmed`. Do not assume scanner assertions are correct.

For confirmed findings, record `in_remediation`, implement the smallest safe fix and add focused regression/security tests. Run relevant dotnet build/test commands where feasible; never execute untrusted code outside a sandbox. Record `fixed_pending_verification` after implementation. A **different** agent independently checks the fix, tests and potential bypasses, then records `verified_fixed`. If failed, use `reopened`. Every command uses `python3 ${HERMES_SKILL_DIR}/../../shared/security_matrix.py --repo . transition ...` in the installed package layout.

Never self-approve a fix. Record test results and agent identity in transition notes. An accepted risk requires explicit owner approval and blocks clean final review in this version.
