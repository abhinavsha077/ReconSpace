# Native Windows Acceptance Checklist — ReconSpace 0.4

ReconSpace does not perform these steps automatically. Use a disposable/test machine first where possible.

## Package and source

1. Extract the release ZIP into a normal user-writable folder.
2. Verify the published SHA-256 hashes.
3. Run `verify_reconspace.bat` as a normal user.
4. Confirm all source tests and built-in rule validation pass.
5. Run `py -3 -m reconspace doctor --root C:\ --pretty`.

## Normal-user scan

6. Run a Quick C: audit and export JSON.
7. Validate it with `validate-report`.
8. Run a Deep C: audit as a normal user.
9. Confirm access-denied locations are reported rather than bypassed.
10. Confirm unavailable collectors are marked not applicable/unavailable rather than falsely successful.
11. Inspect the audit coverage explanation and verify it is not presented as a system-health or malware score.

## Elevated comparison

12. Optionally run the same Deep audit from a manually elevated Terminal.
13. Compare normal/elevated reports and explain differences in access-denied and collector coverage.
14. Confirm ReconSpace never prompts for elevation or changes ACLs.

## Filesystem correctness

15. Test a known hard-linked file pair; verify one physical instance is not counted twice and a single alias is not credited with guaranteed reclaim.
16. Test sparse/compressed files; compare logical and allocated evidence.
17. Test a very large flat directory and cancel during enumeration.
18. Test a long path and record any Windows/Python API limitations.
19. Test an explicit `--exclude` path and confirm the coverage warning.
20. Test `--keep` on a lab/evidence directory and confirm findings remain visible but reclaim becomes zero.

## Cloud and reparse safety

21. Use known OneDrive/Cloud Files placeholders and monitor network/disk activity.
22. Confirm placeholders are not unexpectedly hydrated by duplicate hashing.
23. Confirm directory junctions/reparse loops are not traversed.

## WSL, Docker, and virtualization

24. Confirm each WSL distro and backing VHDX is linked/classified as intentional tooling.
25. Verify no direct-delete recommendation is made for `ext4.vhdx` or AppData WSL files.
26. With Docker Desktop installed, compare ReconSpace Docker totals to `docker system df -v`.
27. Confirm volumes are treated conservatively and are not generic cleanup.
28. Validate Hyper-V, VirtualBox, and/or VMware inventory where installed.
29. Confirm VM disks/checkpoints/snapshots are not content-hashed unless explicitly opted in.

## Windows-managed storage

30. Compare component-store evidence with DISM’s analysis output; confirm raw WinSxS folder totals are not treated as physically reclaimable.
31. Validate VSS/shadow-storage and restore-point metadata.
32. Validate pagefile/hibernation/swap/Reserved Storage evidence and confirm no direct-delete recommendation.
33. Validate Recycle Bin, Windows Update, Delivery Optimization, WER, and dump evidence.
34. Validate physical disk, storage reliability, BitLocker, partition, and Storage Spaces collectors where supported.

## Applications, persistence, trust, permissions

35. Compare installed-app inventory with Windows Settings/Apps and Registry uninstall metadata.
36. Confirm multiple runtimes/SDKs are listed without autonomous “obsolete” verdicts.
37. Inspect Startup, services, and tasks; verify review signals are explainable and not malware labels.
38. Validate Authenticode status for known signed and unsigned binaries.
39. With `--signature-hashes`, verify local SHA-256 is produced without online lookup/upload.
40. Validate selected owner/ACL evidence and broad-write signals.
41. Confirm missing optional tools or inaccessible targets remain visible in collector evidence.

## Rule packs, query, trends, exports

42. Validate and use `examples/custom-rules.example.json` on a harmless test tree.
43. Confirm forbidden execution/action fields are rejected.
44. Test a custom large-file extension and verify it can match.
45. Test a sub-1-MiB rule and confirm the retention-floor coverage note.
46. Exercise query size, age, text, regex, OR, sort, and Windows-path handling.
47. Export CSV and confirm 16 tables for a schema-v4 report.
48. Export static HTML and confirm it opens offline with scripts disabled.
49. Add test secrets to a copied report, create redacted JSON/HTML, and manually inspect the results.
50. Compare two reports and run a three-report trend; verify same-volume/capacity consistency warnings.

## Dashboard and package

51. Launch the dashboard from its printed tokenized localhost URL.
52. Confirm a missing/incorrect token cannot access API data.
53. Confirm the token disappears from the visible URL after initialization.
54. Confirm the listener is loopback-only.
55. Confirm no cleanup/delete/uninstall/prune/remove/execute control or route exists.
56. Generate a plan and confirm every item remains `PENDING_REVIEW` with `Execution: NONE`.
57. Build the EXE with `build_windows_exe.bat` if needed, then repeat Quick/Deep/report smoke tests against the EXE.

Record Windows edition/build, filesystem type, privilege level, locale, Python/EXE build, installed WSL/Docker/virtualization stack, and collector errors with every acceptance result.
