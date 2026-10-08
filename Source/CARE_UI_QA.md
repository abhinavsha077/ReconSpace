# ReconSpace Care UI 1.2.0

Latest build: 1.3.0. See [the current QA report](qa/care-13-report.md) and [experience plan](CARE_EXPERIENCE_PLAN.md). The details below are preserved historical 1.2 evidence.

The Care UI is implemented in `reconspace/webapp.py` and the shared `reconspace/assets/care.css` resource. Original local artwork is documented in `reconspace/assets/ARTWORK.md`. The final palette is graphite, icy blue, and mint, following the user's rejection of purple.

See [the QA report](qa/qa-report.md), [case summary](qa/test-summary.json), and [resolved defect log](qa/defects.csv).

The runnable `App` copy and portable PYZ include the same styles, artwork, and navigation code. The root `run_reconspace.bat` calls `App/run_reconspace.bat`. Restart an already-open server/browser session to load the rebuilt UI.

## Design basis

The welcome → scan → review structure was informed by the official [CleanMyMac Smart Care interface](https://macpaw.com/support/cleanmymac/knowledgebase/smart-care). The implementation retains ReconSpace's actual audit and review behavior; it does not copy MacPaw artwork or claim to perform CleanMyMac's operations. Reduced motion follows the same accessibility principle described by [MacPaw](https://macpaw.com/news/cleanmymac-accessibility-features).

## Code review

The archive-code-review skill was applied across correctness, architecture, readability, security, and performance. Resolved findings: scan submission/status race; early stop-action availability; rejected View Transition promise during rapid navigation; hidden-tab keyboard focus; imported-report landing refresh; cross-module evidence links; inaccessible root shortcut controls; stale packaged artwork/styles.

No outstanding blocking finding was identified in the UI patch. Existing audit/AI/execution code was preserved. No destructive cleanup or cloud AI request was made during QA. Native-app performance equivalence to CleanMyMac was not measured and is not claimed.
