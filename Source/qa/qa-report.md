# QA report — ReconSpace Care 1.2.0

Date: 2026-10-05. Windows build host; Chromium driven through the Playwright CLI. Skills: playwright, archive-qa-report, archive-code-review, imagegen. Final graphite palette was visually reviewed after the purple draft was rejected.

| Test case | Result | Evidence |
|---|---|---|
| Root launcher serves v1.2.0 | PASS | Launcher printed 1.2.0; browser displayed version badge |
| Busy/exclusive default-port recovery | PASS | Existing 8765 service left untouched; root launcher chose a free loopback port |
| Portable PYZ loads CSS and generated PNG | PASS | HTTP 200; asset loaded from importlib.resources within archive |
| All nine sidebar routes before scan | PASS | Home, five modules, Reports, AI Advisor, Settings |
| All result module destinations | PASS | Real audit report rendered, not placeholder navigation |
| 31 visible result tabs across seven destinations | PASS | Every tab produced nonempty content |
| Quick audit on Source/examples | PASS | Real engine completed; six review cards displayed |
| Invalid/nonexistent root | PASS | Expected HTTP 400 shown as recoverable inline error |
| Cancellation | PASS with latency note | Deep audit cancelled; scanning UI exited; collector may finish/time out first |
| Export report JSON | PASS | Browser download event and named JSON file |
| Import exported report | PASS | Validated report populated modules and six landing cards |
| Offline AI Advisor | PASS | Heuristic review rendered; no external provider used |
| Keyboard result tabs | PASS | ArrowRight advanced to visible Findings tab |
| Zoom controls | PASS | 105% after zoom-in; reset restores 100% |
| Reduced motion | PASS | Desktop artwork computed animation-name: none |
| 390px narrow layout | PASS | No document horizontal overflow; menu remains horizontally scrollable |
| 1440×900 desktop visual review | PASS | Current screenshots below |
| JavaScript runtime/network review | PASS | No unexpected runtime errors; expected validation 400 excluded |
| Automated unit/API suite | PASS | 163 tests passed on Windows after UI changes |

## Screenshots

- [Welcome](screenshots/welcome.png)
- [Results](screenshots/results.png)
- [Cleanup](screenshots/cleanup.png)
- [Narrow layout](screenshots/narrow.png)

## Limitations

No full C-drive scan, destructive recycle/cleanup execution, paid/cloud AI provider, native executable build, or cross-browser/device benchmark was performed. The interface runs in a local browser; subjective/native CleanMyMac parity and frame-rate performance are not asserted. Long Windows collectors may delay cancellation until their current operation ends.

Expected HTTP 400 was deliberately exercised for invalid-root validation. Chromium's informational password-field-without-form message comes from the existing AI provider controls; no password was supplied. All discovered UI regressions in this pass are recorded as resolved in defects.csv.
