# Care Experience 1.3 — complete research and implementation plan

Date: 2026-10-05. Goal: a coherent, graphic-led care experience, not another palette-only dashboard restyle. Keep graphite, icy blue and mint; no purple. Preserve the actual Windows audit engine and user edits.

## Research and direction

- [MacPaw's design rationale](https://macpaw.com/news/cleanmymac-got-the-red-dot-award): subtle 3D parallax, purposeful micro-animation, interactive hover, fewer competing controls. The [Apple silicon design article](https://macpaw.com/news/cleanmymac-support-apple-silicon) describes simplified shapes and glass-like icons. These are design references, not timing specifications.
- [Current Smart Care](https://macpaw.com/support/cleanmymac/knowledgebase/smart-care): focused start, sequential scan, overview tiles, then review. ReconSpace has the states but not yet a unified graphic/motion story.
- [Space Lens](https://macpaw.com/support/cleanmymac/knowledgebase/space-lens-results): spatial storage graphic and list highlight the same item. Breadcrumbs preserve exploration context. ReconSpace retains a bounded top-directory inventory; do not pretend it contains the complete filesystem tree.
- [Accessibility](https://macpaw.com/news/cleanmymac-accessibility-features): system reduced-motion support. Also expose an explicit in-app motion setting.

## Design system and screen plan

1. **Shell:** neutral graphite window, animated sidebar selection marker, more readable type, compact contextual tools. Maintain all nine routes and keyboard focus.
2. **Original art family:** transparent sculptural storage disc, shield, gauge, application stack and folder. Consistent glass/metal materials, icy-blue/mint/champagne accents. Reuse the objects in welcome, scanning, result tiles and module detail. Keep crisp vector navigation icons. Package all images locally.
3. **Landing:** focused centerpiece with layered orbital accents, atmospheric lighting, subtle pointer parallax, one primary Scan action, and a five-module dock. Scope adjustment remains secondary.
4. **Scanning:** central object changes with the real engine phase; cross-faded artwork, orbit, phase badges and live counters. No fabricated progress or findings. Retain cancellation and collector-latency explanation.
5. **Results:** art-led review tiles arrive in a bounded stagger. Clearly label missing evidence and separate non-additive candidates. No invented security/health score.
6. **Module pages:** unify duplicate headings, use the module graphic/identity as the lead, and make exports/evidence controls secondary. Preserve detailed tables, filters, plans, import/export and AI controls.
7. **Storage exploration:** responsive bubble map paired with retained top-folder list; synchronized hover/focus, selected-item details, bounded-inventory disclosure. Bubble area reflects bytes. Drill only into retained evidence; offer the existing folder view otherwise.

## Motion specification

| Interaction | Motion | Guardrail |
|---|---|---|
| Page change | short directional zoom/fade and marker glide | one page transition, no stacked page animations |
| Graphic/card arrival | opacity + 12px translation stagger | bounded objects; cancel stale animations |
| Hero pointer | gentle parallax and lighting response | coalesced requestAnimationFrame; no touch/reduced-motion tilt |
| Scan phase | crossfade/scale object and progress badges | driven by actual phase changes |
| Storage selection | bubble emphasis and linked list/details | keyboard equivalent, read-only |
| Controls | small press/lift | transform/opacity, no layout loop |

Targets: 160–220ms controls, 320–460ms stages, ≤70ms stagger. These are our targets, not measured MacPaw internals. Respect system reduced motion plus Full/Reduced setting; pause ambient motion in hidden tabs. Avoid animated blur, fake progress, perpetual JavaScript particle rendering, or unexpected audio.

## Implementation and verification order

1. Research and save this full plan.
2. Generate, inspect and document the five-object artwork family.
3. Implement a shared motion controller, shell/landing, scan-stage changes, art-led results and module presentation.
4. Implement linked storage visualization from real retained report data.
5. Iterate desktop/narrow screenshots. Verify menus, result tabs, scan, cancellation, invalid roots, imports/exports and motion settings. Check unexpected JS/network errors and sample frame pacing without claiming universal native FPS parity.
6. Run automated regressions; review correctness, security and performance; version/sync App; build PYZ/ZIP and verify manifests and launcher. Recoverably archive previous builds.

Acceptance: these features must work in the shipped app, not only source. Record untested cases and defects in QA. Do not claim exact native CleanMyMac parity; visual similarity is subjective. No destructive cleanup or cloud AI call is needed for this UI work.
