# Commit 15 hostile review

Status: Implementing-agent hostile review of the clean-slate migration
disposition. This is not independent security assurance.

- Scope: legacy-provider retention, tracked-tree isolation, provenance,
  canonical routing, visibility, pull-request state, and package-status limits
- Reviewed: 2026-08-21

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C15-01 | False erasure / High | A new repository is described as deleting old GitHub refs, caches, or external clones | Reviewers rely on a privacy guarantee the migration cannot provide | State that Support was declined and old provider/external remnants remain unresolved | **Accepted residual**: no Support request was submitted and no universal erasure is claimed |
| C15-02 | Git-graph contamination / Critical | The old `.git`, a bundle, alternate, graft, replace ref, or submodule crosses into the replacement | Historical objects become reachable in the clean repository | Import only the exact committed tree and verify the replacement object graph from a fresh clone | **Required cutover gate** |
| C15-03 | Dirty-tree contamination / High | Ignored, untracked, derived, credential, or temporary files are copied with source | Private evidence or machine state enters the new root commit | Use a tracked-tree archive; inspect the staged file list, identifier scan, non-documentation equality, and documentation delta before commit | **Required cutover gate** |
| C15-04 | Canonicality race / High | Links or status call the empty/private replacement canonical before validation and publication | D27's public-review boundary silently fails | Keep the old sanitized remote authoritative until the new full gate, audit, visibility, and routing checks pass | **Required cutover gate** |
| C15-05 | Provenance loss / High | The clean root has no exact source commit/tree record or silently changes implementation files | Reviewers cannot relate prior physical evidence to imported bytes | Record the old merged commit/tree, new root/final commits, and exact repository-specific delta | **Required cutover gate** |
| C15-06 | Security-report dead end / High | Public documentation retains the legacy vulnerability route after canonical cutover | Reports reach the wrong repository or disclose sensitive detail publicly | Verify `SECURITY.md` and repository security-advisory routing on the public replacement | **Required cutover gate** |
| C15-07 | Review drift / High | PR #3 or the replacement review points at a commit other than the validated head | Approval and evidence cover different bytes | Recheck exact head/base, draft state, mergeability, changed paths, and merge result at each boundary | **Required final inspection** |
| C15-08 | Status inflation / High | Migration is treated as independent review or product integration | Unreviewed cryptography reaches real user data | Limit completion to fixture-only Implemented and preserve D27/P8 gates | **Open separate gate** |
| C15-09 | Unauthorized legacy mutation / Medium | Migration authority is expanded into archive, deletion, or privacy changes to the old repository | Evidence availability or user intent is changed without approval | Leave the old repository visible and unchanged beyond the reviewed migration record | **Resolved by scope** |
| C15-10 | Checkout-dependent SBOM gate / High | Cargo emits a different local root package-ID suffix when the checkout directory matches the crate name | A fresh-clone pass can hide a failing normal-workspace reproducibility gate | Normalize only the two exact Cargo root forms, compare unchanged SBOM content, and test both directory-name cases | **Resolved**: the normal-workspace direct check and full gate pass; commit 14's differently named fresh clone exercised the other exact form |

## Hostile trace conclusion

The maintainer's choice removes GitHub Support from the execution plan, but it
does not resolve C14-06 by provider cleanup. It replaces that path with a
bounded risk acceptance plus a new graph-isolation control. That distinction
is security-relevant: the replacement can have a clean reachable history even
while the old repository and provider caches continue to retain old objects.

The only safe transfer unit is the final committed tree. A filesystem copy of
the repository root, a local clone, or a Git bundle is too broad because it can
carry Git metadata or ignored state. A tracked-tree archive plus a replacement
fresh-clone object audit gives a falsifiable boundary. Tree equality alone is
also insufficient: the new root must enumerate its repository-specific
documentation changes and repeat the complete build/test gate.

This review therefore permits the source-repository PR to proceed only as the
end of the old repository's reviewable package history. It does not
pre-approve the new root commit, public visibility, canonical cutover, private
handoff, or P2 status change. Those are separate observed gates. Independent
human review
continues to block real recordings, external testers, hosted audio,
end-to-end-encryption claims, and Milestone 3.
