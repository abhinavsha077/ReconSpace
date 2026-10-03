# Contributing to ReconSpace

Thank you for your interest in improving ReconSpace!

## Core Invariants

When contributing code, you must respect the following core invariants:
1. **Safety First**: Never introduce unconditional destructive operations.
2. **Read-Only Engine**: The core discovery engine and collectors must remain strictly read-only.
3. **No External Network Dependencies**: Do not introduce outbound HTTP calls, telemetry, or remote analytics.
4. **Subprocess Hygiene**: Any subprocess invocation in collectors must use explicit argument lists with `shell=False`.
5. **No Regressions**: All 140 automated tests must pass before opening a pull request.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/abhinavsha077/ReconSpace.git
   cd ReconSpace
   ```

2. Prerequisites:
   - Python 3.11 or newer on Windows.
   - Standard library only (no mandatory third-party runtime dependencies).
   - Optional development tool: `pytest`.

3. Running Tests:
   Always run test commands from the `Source/` directory:
   ```powershell
   cd Source
   python -m pytest tests
   ```

4. Verifying Release Integrity:
   ```powershell
   cd Source
   python build_portable_pyz.py
   python update_release_manifest.py --check
   ```

## Pull Request Guidelines

- Ensure your branch is based on `main`.
- Add tests for any new collectors, classifiers, or query filters.
- Run `verify_reconspace.bat` or `python -m pytest tests` to verify the suite.
- Keep commits focused and provide clear, descriptive commit messages.
