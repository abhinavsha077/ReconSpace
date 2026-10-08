# Code review — Glass & Motion 1.3

Summary: improves the care experience without replacing the audit engine. New motion/storage code are resource modules instead of another inline monolith.

Blocking: none remaining. High: none remaining.

- Correctness: navigatePage's sequence guard prevents stale callbacks from applying an older menu choice. Tab-scoped sessionStorage fixes refresh authentication. Both were browser-tested.
- Readability: removed forced page/import reflows and nested tab entry during page changes. Named motion/storage helpers carry feature state.
- Architecture: packaged shared motion controller, component stylesheet and bounded-evidence visualization; existing exports, detailed tabs and AI preserved.
- Security: explicit six-image allowlist; no general local-file route. Labels use esc(), selected paths use textContent; invalid/nonfinite/negative metadata is ignored. Local API token/CSP boundaries remain.
- Performance: report pages use transform/opacity on the actual layer instead of expensive snapshots. Pointer work is coalesced/cancellable. Folder ancestors use key membership, not an all-pairs scan; eight bubbles maximum.
- Accessibility: keyboard/focus equivalents, OS plus in-app reduced motion, hidden-tab pause, verified readable storage text.

Medium tracked limitation: existing very large report tables are not virtualized; broader inventory-performance work is outside this UI pass. No native/device parity guarantee. Low: 1.2 stylesheet remains the base token layer, with scoped 1.3 overrides.

Verdict: approve for the tested local-browser scope. 165 automated tests passed; evidence and exclusions in care-13-report.md.
