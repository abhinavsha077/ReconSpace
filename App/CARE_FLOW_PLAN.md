# Guided Care experience — 1.4 plan

2026-10-08. Preserve the approved graphite/blue/mint visual system and original icons. GitHub prerequisite completed first: 0d93471454eb7806ce084a565585203f08b14306 on main.

## Research

- [Current Smart Care](https://macpaw.com/support/cleanmymac/knowledgebase/smart-care), updated August 11, 2026: overview tiles, Review into details, explicit task selection, then action.
- [Applications](https://macpaw.com/support/cleanmymac/knowledgebase/uninstaller), updated September 17, 2026: module introduction → scan → summary → grouped manager → select → action → completion. Start Over asks for confirmation.
- [Smart Cleanup](https://macpaw.com/support/cleanmymac/knowledgebase/smart-cleanup), updated September 30, 2026: useful categorized suggestions before exhaustive manual browsing.

Inference for ReconSpace: the remaining deficit is interaction architecture, not another palette or illustration pass. Technical tabs are an advanced surface, not the default consumer experience. No copied product screenshots ship.

## Flow

Module introduction → compact scope/depth setup → read-only scan spotlight → module summary → category sidebar + searchable item list + detail inspector → selected-item confirmation → review-plan receipt.

Smart Audit keeps its current five result tiles. Their Review action opens the relevant grouped manager directly. Sidebar module navigation opens a concise summary. Every nested screen has a clear Back action. A separate Advanced evidence action preserves existing hubs, tabs, filters and exports.

## Per-module categories

| Module | Guided groups |
|---|---|
| Cleanup | Lower-risk review, Manual review, Protected/intentional findings |
| Protection | Signature evidence, Startup indicators, Permissions |
| Performance | Running processes, Startup entries, Services |
| Applications | Installed apps, Related footprints |
| My Clutter | Duplicate groups, Large files, Folders |

All counts come from the real report. Missing inventory is an explicit empty state, never a clean-health assertion. Selected items are review requests, not removal authorization. Protected findings are inspectable but not selectable for the plan. No combined “space recovered” claim: estimates overlap.

## State and implementation

- Shared care-flow.js owns guided categories, filters, bounded 60-row pages, item inspection, selected review items and receipt.
- New report resets selections; cancellation/failure must not destroy a prior report or review state.
- Module-initiated scans return to that module when the scan view is still foreground. Navigating elsewhere during scanning must not be overridden unexpectedly.
- Re-scan confirms scope and that successful replacement resets current review selections. Cancellation restores the prior report.
- Scope setup explains that filesystem data follows the root while host application/process/persistence inventory can cover the wider host. Underlying engine remains a shared audit, not a fabricated independent scanner.
- Native dialog semantics, Escape, labels, keyboard item inspection, visible focus, OS/app reduced motion and existing motion controller. Preserve private review state in memory only.
- Selected-item export is Markdown, PLAN ONLY / NO EXECUTION. Receipt says prepared, not files cleaned. Browser determines download/save location.

## Acceptance

Test real scan from a module, correct return destination, summary-to-category review, search, selection retention, details, protected-item guard, confirmation/cancel, receipt/export, rescan/cancel recovery, direct result-tile Review, advanced tabs/Back, empty states and 390px layouts. Check console/network errors, run regressions, code-review five axes, synchronize App and build/verify 1.4 portable and ZIP. No destructive cleanup or cloud AI call during this UI pass.
