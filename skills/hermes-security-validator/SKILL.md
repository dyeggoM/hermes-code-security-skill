---
name: hermes-security-validator
description: Perform independent final integrated security review after remediation, with release gate tied to Git state and coverage.
version: 0.1.1
metadata:
  hermes:
    category: software-development
    tags: [security, validation, integration]
---
# Security Validator
Run only when all scoped files have been actually reviewed and all findings are `verified_fixed` or `false_positive`. Inspect the entire affected call chain, authentication/authorization flows, data boundaries, interactions between corrected functions, regression tests and relevant configuration. Run safe static checks and tests where available. Do not rely solely on prior agents' reports.

If a new problem appears, record it via scanner `finding` and require remediation; record `review --status failed --reviewer independent-validator --note ...`. If checks pass, run `python3 ~/.hermes/security-tools/security_matrix.py --repo . review --status passed --reviewer independent-validator --note 'Evidence and test summary'`. Review validity is tied to the Git HEAD and tracked source hashes. A passing status is an evidence-bounded review, not proof of zero vulnerabilities.
