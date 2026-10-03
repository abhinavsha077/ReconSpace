# Security Policy

## Security & Architecture Principles

ReconSpace is engineered from the ground up to prioritize system safety, operational integrity, and user privacy over reckless automated cleanup.

### 1. Read-Only Core by Design
- The core reconnaissance engine has **no deletion or modification primitives**.
- It does not modify system files, change registry configurations, alter Access Control Lists (ACLs), prune Docker volumes, or unregister WSL distributions.
- Windows collectors utilize non-destructive read operations via CIM, Registry, and standard Windows CLIs (`shell=False` only).

### 2. Local-Only Execution & Zero Telemetry
- ReconSpace makes **no outbound network connections**.
- No telemetry, analytics, pingbacks, or background service reports are sent.
- The optional web dashboard binds strictly to the loopback interface (`127.0.0.1`).
- Every dashboard session generates an ephemeral, cryptographically secure bearer token (`secrets.token_urlsafe`) to prevent unauthorized cross-origin access.

### 3. Strict Boundary Guards for Execution
The optional execution runner (`reconspace.runner`) enforces immutable safety checks:
- **System Protection Boundaries**: Hardcoded rejection of core Windows directories (`System32`, `SysWOW64`, `WinSxS`, system volume information, root drive roots, user profile roots).
- **Scope Restriction**: Only items explicitly categorized as `probably_safe_cleanup` can be selected; `manual_review` or protected items are rejected.
- **Dry-Run by Default**: Actions are simulated unless `--confirm` is provided.
- **Reversible Deletion**: File removal operations are performed via the Win32 Shell API (`SHFileOperationW`) with `FOF_ALLOWUNDO`, sending items to the Windows Recycle Bin rather than permanently deleting them.

### 4. Privacy Redaction
Reports can be exported with automatic best-effort privacy redaction (`--redact`), which automatically scrubs:
- Local usernames and user profile paths
- Machine names and environment host identifiers
- Command-line arguments containing passwords, tokens, API keys, and basic authentication strings

## Reporting a Vulnerability

If you discover a security vulnerability or potential privacy leak in ReconSpace, please report it responsibly:

1. **Do not open a public issue.**
2. Email details of the vulnerability to the project maintainers via GitHub private security advisories or directly to `abhinavsha077`.
3. Provide reproducible steps, expected vs. actual behavior, and affected components.

We take security seriously and will review and respond to valid vulnerability disclosures promptly.
