# Commit 12 hostile review

Scope: final cleanup evidence for the development-only iOS receiver proof app
used by commit 10. This review covers the current documentation change and the
normalized device-side cleanup result; it does not reopen the cryptographic
implementation.

## Findings

| ID | Area / severity | Hostile scenario | Consequence | Required mitigation | Disposition |
| --- | --- | --- | --- | --- | --- |
| C12-01 | Cleanup scope / High | A broad uninstall or ambiguous device selection targets the product app or unrelated user data | Material data loss outside the authorized disposable proof | Resolve one connected iOS device, require exactly one match for the fixed development proof bundle, uninstall only that bundle, then verify zero matches | Resolved by exact precondition, scoped removal, and postcondition |
| C12-02 | Evidence privacy / High | Raw device-tool output republishes a serial, device identifier, assigned name, or signing metadata | Reintroduces the commit-11 evidence-boundary failure | Persist only fixed counts and normalized success/failure; omit raw output and every local identifier class | Resolved in durable evidence; current-tree category scan still required |
| C12-03 | Cleanup overclaim / Moderate | Exact app absence is described as a direct post-uninstall inventory of the container, or as erasing Keychain state, hosting caches, or all device state | Reviewer relies on a stronger lifecycle guarantee than was observed | Distinguish the exact bundle-query observation from container removal inferred from iOS uninstall semantics and the reviewed private-container-only layout; preserve the separate Keychain and published-history boundaries | Resolved by bounded observation/inference wording |
| C12-04 | Historical-result rewriting / Moderate | A later container reset is used to call the discarded `STORAGE` run exact at its failure boundary | Favorable-only evidence hides the original cleanup uncertainty | Keep commit 10's classification and explain that later reset removes residue without proving lock-time cleanup | Resolved |
| C12-05 | Disposable output retention / Moderate | The encrypted receiver archive remains indefinitely after inspection | Violates the private P2 disposable-run contract and expands retained proof state | Remove the exact development app/container after inspection and verify absence | Resolved |

## Result

No Critical or unresolved High finding remains in this documentation-only
cleanup change. The exact development proof app is verified absent; removal of
its private container follows from the documented storage layout and iOS
uninstall semantics rather than a separate post-uninstall filesystem
inventory. The hazardous physical fault matrix, published-history/cache
remediation, and independent human review remain open and keep the package and
pull requests non-production-ready.
