# Security workflow for developer agents

After each code-editing task, invoke `hermes-security-scanner` and actually inspect the changed code. Record candidates and mark inspected scope entries reviewed. Use independent agents for confirmation, remediation verification and final integrated validation. Never claim security approval from an empty findings list or from merely running the scan CLI. Use `--mode full` only when explicitly requested. The final security review must be repeated when relevant code changes.
