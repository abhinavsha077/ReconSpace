# QA — ReconSpace Glass & Motion 1.3.0

2026-10-05, Windows host, Chromium via Playwright CLI. Skills: imagegen, playwright, archive-qa-report, archive-code-review. Final graphite/icy-blue/mint design; original generated graphics, no MacPaw assets shipped.

| Case | Result | Evidence |
|---|---|---|
| Refresh session recovery | PASS | Reload retained tab-scoped authentication and scan availability |
| Eight primary menu destinations plus Settings | PASS | Before/after real scan; scope form and validation |
| 31 visible report tabs | PASS | Every tab clicked without runtime error |
| Quick audit of Source | PASS | Five real-data review cards; [results](screenshots/care13/care-13-results.png) |
| Portable PYZ and five PNG endpoints | PASS | v1.3.0; all illustrations HTTP 200 |
| App/source sync and extracted ZIP integrity | PASS | Exact current manifests; identical PYZ hashes across Source/App/Releases |
| Export and file-input report import | PASS | Download event; portable import restored five cards |
| Deep scan submission/cancellation | PASS | “Audit cancelled”; [scan](screenshots/care13/care-13-scan.png) |
| Linked map/list focus and drill-down | PASS | Eight bubbles, one selected, two breadcrumb levels; [map](screenshots/care13/care-13-space-lens.png) |
| Non-overlapping hierarchy, malformed metadata | PASS | Node-backed regression in test_care_v13.py |
| Pointer parallax and zoom | PASS | ~2.4°/3° tilt; 105% and reset to 100% |
| App/OS reduced motion | PASS | Reduced mode, zero running animations |
| 390px responsive layout | PASS | scrollWidth=viewport=390; [narrow](screenshots/care13/care-13-mobile-results.png) |
| Invalid root | PASS | Recoverable expected HTTP 400; [validation](screenshots/care13/care-13-invalid-root.png) |
| JS/network main-flow review | PASS | Zero unexpected page errors/HTTP failures |
| Python/API regressions | PASS | 165 tests passed on Windows |

## Motion diagnostics

Initial snapshot-based rapid navigation: p95 66.5ms, 37/240 intervals above 32ms. Report-heavy pages now animate the actual content layer and suppress nested tab-entry animation. A subsequent sequential-navigation sample in the portable UI: p95 17ms, 4/240 above 32ms. Protocols differ: these are diagnostic samples, not a controlled benchmark or native-app/FPS guarantee.

Resolved: lost session on refresh, low-contrast storage labels, duplicate pre-scan headings, old forced zoom/reflow, nested transitions, and stale navigation callbacks. See [review](care-13-review.md) and [defects](care-13-defects.csv).

Release polish also fixes batch launcher's stale block-expanded exit code so command-line launch failures are returned accurately.

## Limits

No full C-drive audit, cleanup/recycle execution, paid/cloud AI, native executable, or cross-browser/device benchmark. This is a local-browser experience, not an exact native CleanMyMac clone. Storage shows bounded retained evidence, not the complete disk tree. Cancellation was exercised with process collection disabled; other Windows collectors may finish/time out before stopping. Missing process/signature inventory remains “No records,” not a fabricated clean-health claim. Private exported JSON is in excluded output/, not the shipped QA package.

[Design/research plan](../CARE_EXPERIENCE_PLAN.md) · [Original artwork prompts/backend](../reconspace/assets/ARTWORK.md)
