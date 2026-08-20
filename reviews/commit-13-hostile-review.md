# Commit 13 hostile review

Status: Implementing-agent review of the local P2 closeout and history-
remediation candidate. Remote replacement, GitHub Support cleanup, final gate
evidence, and independent human review remain open. This is not independent
security assurance.

- Scope: evidence-claim strength, hazardous personal-device safety,
  deterministic host coverage, Android compatibility disposition, history-
  rewrite scope, pull-request/cache ownership, signature/check invalidation,
  and completion status
- Reviewed: 2026-08-20

## Findings

| ID | Classification / severity | Attack precondition and execution path | Impact and invariant | Evidence and smallest safe remediation | Regression / disposition |
| --- | --- | --- | --- | --- | --- |
| C13-01 | Evidence overclaim / High | Prior wording says exact production host fault adapters or a complete deterministic matrix passed | A reviewer treats raw-writer, conflict, reconstructed-state, or trigger tests as actual filesystem/commit failures | Replace the broad claim with named tests and explicit limits; do not manufacture a pass | Corrected in README/platform/commit-13 evidence; final diff and link audit pending |
| C13-02 | Personal-device safety / High | Closeout attempts real device-global `ENOSPC`, destructive secure-lock mutation, hostile rename timing, or kills at every internal transition on personal phones | Unrelated app, OS, or user data can be damaged for non-production evidence | Record the cells as not run; use only factory-reset disposable or isolated revertible infrastructure later | **Accepted safety disposition for fixture-only P2; not a pass** |
| C13-03 | Platform-assurance gap / Medium | Host recovery tests are generalized to APFS, Android filesystems, Keychain/Keystore, SQLite low-storage behavior, or Android 12–14 unlock modes | Platform-specific availability or durability defects can reach later integration | Retain exact unproved cells for P8 and independent review, with no fallback or automatic key replacement | Open later-package/review input; blocks real-use claim, not the fixture-only closeout candidate |
| C13-04 | Historical-result rewriting / Medium | The later C2-08 disposition edits the commit-2 row into a physical pass or hides that it originally blocked closeout | Review chronology becomes misleading | Preserve the original row and add an explicitly subsequent commit-13 note | Resolved in current candidate; C2-08 remains not run and carried to P8 |
| C13-05 | Incomplete remote remediation / High | A local rewrite is described as public erasure before remote branch replacement and fresh-clone validation | Old objects remain reachable and reviewers use unvalidated replacement heads | Keep closeout-candidate status; update exactly three named branches only after the final gate; record remote heads and fresh-clone checks | Open operational gate |
| C13-06 | Pull-request/cache ownership / High | A force-push is assumed to delete GitHub's read-only PR refs and cached object views | Sensitive historical metadata remains accessible through PR #1/#2 or cached views | After branch replacement, follow GitHub's official procedure and obtain Support dereference/cache-removal confirmation | Open external gate; Support-owned and not conflated with branch remediation |
| C13-07 | Rewrite blast radius / High | A mirror or broad force update changes an unrelated branch, tag, release, or concurrent work | Unrelated history or evidence is lost | Limit writes to public-core `main` and the two named package branches; verify every pre/post ref; change no tag/release | Locally scoped; remote execution and verification pending |
| C13-08 | Signature and status reuse / Medium | Old signatures, checks, approvals, comments, or hash links are presented as validating rewritten objects | Reviewers rely on evidence cryptographically or semantically bound to different commits | State that old signatures are invalidated and rerun/relink validation at replacement heads | Correctly documented; final gate and PR updates pending |
| C13-09 | Recontamination / High | An old clone merges or pushes the pre-rewrite history after branch cleanup | Removed objects become repository-reachable again | Coordinate the rewrite, replace or carefully clean old clones, and do not merge an old-history branch | Open operational risk; no fork was found, but independent clones cannot be disproved |
| C13-10 | Cross-repository scope / Medium | Private PR #7 is force-rewritten merely because it links old public hashes | An unnecessary second history rewrite expands disruption and invalidates private review state | Leave private history intact and update only its body/docs after public replacement hashes stabilize | Resolved scope decision; link update pending |
| C13-11 | Inventory overclaim / Low | Zero forks/releases/Actions artifacts/caches is read as proof that GitHub and all clones retain no object | Hidden clones or hosting caches are ignored | State exactly what the remote inventory observed and preserve the Support/fresh-clone steps | Resolved wording; external confirmation pending |
| C13-12 | Vendored-source omission / High | The unanchored `target/` ignore also matches upstream `vendor/cc/src/target/` | A clean clone lacks four checksum-listed compiler-detection sources and the offline build gate stops before compilation | Anchor the two real Rust output roots, restore only the four files whose bytes match the committed crate checksums, audit every vendored checksum entry, then rerun the exact clean-clone gate | Corrected locally; 7,693 checksum-listed files and complete local gate pass; rewritten-remote fresh clone pending |
| C13-13 | SBOM reproducibility check / Medium | The pinned generator includes the crate name in its checkout-root reference but the normalizer matches an obsolete shorter suffix | A correct generated inventory differs at four root refs and the gate cannot prove location-independent output | Normalize the exact emitted root prefix to the existing stable package URL; keep the committed SBOM and all dependency content unchanged | Corrected locally; uninterrupted full gate passed; rewritten-remote fresh clone pending |
| C13-14 | Validation-warning overclaim / Medium | A zero cargo-deny exit is summarized as a refreshed non-yanked dependency result despite registry-index failures | Reviewers infer an assurance cell that did not execute | Record the exact four passing policy categories, expected fuzz-only unmatched-licence warning, and unproved current yank status; keep the locked vendor checks separate | Corrected in commit-13 evidence; optional yank-aware refresh remains later review input |

## Hostile trace conclusion

No source-level cryptographic change is present in this candidate. The most
important correction is epistemic: current tests prove bounded writer,
conflict, transaction-rollback, state-recovery, cleanup, and selected physical
lifecycle behavior, not actual mobile `ENOSPC`, every production rename/sync
failure, or kill at every transition. The safety disposition is valid only as
a consciously accepted fixture-only P2 boundary and cannot authorize real
data.

The complete-gate attempt also exposed a pre-existing clean-clone defect:
`target/` ignored the upstream `cc` crate's nested source directory. The four
restored files are not newly selected dependency code; each byte sequence
matches the SHA-256 already committed in that crate's checksum manifest. The
anchored ignores and complete 7,693-entry vendor audit are the smallest repair.
The complete local gate now passes; a rewritten-remote fresh clone still has
to prove that the repair is durable.

The next stopped gate independently exposed an obsolete SBOM root-reference
normalizer. The correction is limited to the exact checkout-specific prefix
emitted by cargo-cyclonedx 0.5.9; it does not suppress component, dependency,
licence, or content differences. The uninterrupted full gate now passes; the
fresh-clone repetition remains required.

The final local gate exits zero, but its warnings remain evidence boundaries.
The four cargo-deny policy categories pass against the locked graph; the local
index does not establish current yank status, and the unmatched NCSA allowance
belongs to the separately checked fuzz graph rather than the production graph.
Neither warning is silently upgraded into a pass.

The history rewrite is likewise only locally prepared. GitHub's
[official sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
states that rewritten hashes invalidate signatures, pull-request refs cannot
be force-pushed, and cached views/eligible PR references require GitHub
Support. Repository-controlled replacement of the three named branches must
therefore remain separate from Support-owned dereference and garbage
collection.

C13-05, C13-06, C13-07, C13-08, and C13-09 remain completion gates. P2 must
stay a closeout candidate until the exact remote updates, Support result,
updated PR links, and fresh-clone validation are recorded.
Independent human review remains mandatory before real recordings or product
integration.
