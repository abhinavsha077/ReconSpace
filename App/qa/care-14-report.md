# QA — ReconSpace Guided Care 1.4.0

2026-10-08. Windows host, headed Chromium through Playwright CLI. Skills: playwright, archive-qa-report, archive-code-review. The interaction plan was saved before implementation; the previous 1.3 checkpoint was pushed to GitHub first.

| Case | Result | Evidence |
|---|---|---|
| Module summary and grouped review | PASS | [Summary](screenshots/care14/care-14-summary.png), [review](screenshots/care14/care-14-review.png) |
| Protected cleanup findings | PASS | Zero selectable checkboxes; inspector remains available |
| Cross-category selection | PASS | Safe selection retained after manual/protected category navigation |
| Search, empty state, inspector | PASS | No-match empty state; literal `<script>` fixture title rendered as text |
| Confirmation cancel, download and receipt | PASS | Download event for reconspace-selected-review.md; [receipt](screenshots/care14/care-14-receipt.png) |
| Bounded pagination | PASS | 67 fixture apps rendered as 60 then 7 rows |
| Real module scan | PASS | Quick audit of Source/examples returned to Applications summary |
| Cancellation recovery | PASS | Deep audit cancelled; prior report and selection retained |
| Invalid-root recovery | PASS | Expected HTTP 400; prior report and selection retained |
| Sidebar and advanced navigation | PASS | Nine destinations, 31 advanced tabs, module-summary back paths |
| Home result card | PASS | Direct grouped review rather than a technical hub |
| Full/reduced motion and zoom | PASS | Full-mode navigation exercised; 105% zoom/reset; reduced mode had zero running animations |
| Responsive review | PASS | At 390px viewport, document width 375px: no horizontal overflow; [narrow](screenshots/care14/care-14-narrow.png) |
| Console/network | PASS | Zero unexpected JS/HTTP errors in main-flow checks; expected invalid-root 400 tested separately |
| Automated regressions | PASS | 167 unittest/API/Node-backed tests |
| Portable PYZ runtime | PASS | Same fixture-to-real-scan flow and all 31 tabs, v1.4.0 |
| App/source/release packaging | PASS | Identical PYZ hashes; App and extracted complete ZIP pass manifest verification |

Scripts: verify-care14.js, verify-navigation14.js, verify-recovery14.js. Summary/review/receipt/narrow screenshots use explicitly synthetic UI data, not cleaned-space claims or a user's private report. Real scan checks inventory the Windows host and only read the selected filesystem root. Cloud AI is disabled for QA.

Resolved during review: search field sizing, left-aligned item titles, redundant summary banner, service path display, scan-return URL mismatch, and restoration after backend failure. A test-only timeout was traced to opening a new server without its session-token launch URL; authenticated runs passed.

## Limits

Not an exact native CleanMyMac clone or a measured native-animation/FPS parity claim. No destructive cleanup, uninstall, registry mutation, cloud AI call or full C-drive audit. The new selected-item action exports a review document only. Selection is tab-memory state, not durable across refresh. Windows collector cancellation can wait for the active collector to finish/time out. Large report search is linear; rendered manager rows are bounded to 60 per page.

[Researched plan](../CARE_FLOW_PLAN.md) · [Five-axis review](care-14-review.md)
