# Commit 15 clean-slate migration disposition

Status: The repository-controlled P2 implementation and sanitized branch
history are ready for final pull-request review. The maintainer declined a
GitHub Support request and selected a history-clean committed-tree migration to
`robertbublik/mowy-crypto`. Provider-owned remnants in this source repository,
which becomes legacy only after cutover, remain explicitly unresolved; no
universal-erasure claim is made.

- Package: P2 sealed envelope foundation
- Requirements: `M2-KEY-01`, `M2-ENVELOPE-01`, `M2-ASSURANCE-01`
- Decision date: 2026-08-21
- Change class: SBOM-check robustness plus repository migration, evidence, and
  status documentation; no runtime, dependency, binding, or SBOM-content change

## Maintainer disposition

The maintainer explicitly chose not to contact GitHub Support. The prepared
request was never submitted, and no provider action or response exists to
record. Commit 14's Support step is therefore superseded as a package-closeout
condition, not completed.

Repository-controlled remediation remains valid: the three rewritten branches
were published, a fresh remote clone passed the complete gate, and the strict
reachable-history audit found no retained device/signing categories. Exact
commit 14 `0083f85b32a38dd187612ea6fd7680d58ff521b8` passed `scripts/check.sh`
and a strict audit of all 17 reachable commits and 6,933 reachable blobs, with
zero derived sensitive-category matches and only the public GitHub no-reply
identity in commit metadata. The final commit-15 PR head still requires its own
post-commit ref, gate, and reachable-history recheck. Public
PR #1 and closed PR #2 can still have provider-owned refs or cached views that
refer to changed history. Independent clones may also retain it. The migration
decision accepts those limits and must never be described as deletion,
dereference, garbage collection, or universal erasure.

No authority is inferred to delete, archive, privatize, or otherwise conceal
this repository. It remains a legacy public evidence source after cutover.

## Clean-slate import boundary

The replacement repository existed as an empty private Git repository when
this decision was recorded. Its cutover procedure is deliberately one-way:

1. merge public-core PR #3 and record the reviewed head, merge commit, and
   exact final source tree;
2. export only that committed tree with `git archive` or an equivalent
   tracked-tree operation;
3. extract it into the replacement worktree while preserving the replacement
   `.git` directory;
4. do not copy old refs, reflogs, Git objects, hooks, ignored files, untracked
   files, local configuration, credentials, build products, or temporary
   evidence;
5. adjust only repository-specific provenance, canonical links, and security
   reporting in the replacement tree;
6. before committing, stage and inspect the exact file list, run the strict
   current-tree identifier scan, compare every non-documentation path with the
   source tree, and enumerate the reviewed documentation delta;
7. create a new root commit with the public GitHub no-reply identity;
8. run the complete package gate and strict audit across every reachable
   replacement commit and blob, then push while the repository remains private
   and noncanonical;
9. make the replacement public while this source repository remains
   authoritative;
10. from an anonymous fresh clone, verify the exact public refs and tree,
    one-way object isolation, vendored completeness, complete gate, reachable-
    history audit, and working private security-advisory route;
11. record the old reviewed/merge/tree IDs, new root and final-main IDs, exact
    repository-specific delta, validation results, and review surface; and
12. only then designate the replacement canonical and update the private
    application handoff.

The replacement history must not contain an old commit as a parent, alternate,
bundle, graft, replace ref, or submodule. The imported implementation files
must match the final source tree byte-for-byte except for an enumerated,
reviewed repository-documentation delta. The old crate/package/SBOM name
`mowy-crypto-core` remains an implementation identifier and is not renamed by
the repository migration.

## Pull-request and handoff boundary

Before merge, PR #3 must point to this final documentation head, be non-draft,
remain mergeable, and have its body updated to the migration disposition and
residual provider-cache risk. A merge commit preserves the reviewed package
history in this source repository; squash or rebase is not used.

The private application repository is not history-rewritten. Its P2 handoff
must instead pin the new canonical repository's exact root and final main
commit, link the new review surface, retain the old-provider limitation as
historical provenance, and pass its complete documentation, architecture,
lint, test, and export gates before P2 status changes.

## Normal-workspace SBOM gate correction

The first correctly configured commit-15 worktree gate passed formatting,
clippy, all 83 Rust tests, the fuzz-target checks, and all four mobile release
builds before the SBOM comparison exposed a checkout-name dependency. Cargo
identifies the root package as `#0.1.0` when the checkout directory is named
`mowy-crypto-core`,
but as `#mowy-crypto-core@0.1.0` in a differently named checkout. Commit 13 had
normalized only the latter form observed in its fresh validation clone.

The checker now accepts only those two exact local root forms and normalizes
either to the same stable package URL before comparing the generated document.
It does not rewrite dependency references or SBOM content. The direct SBOM
check and final uninterrupted full gate passed in the normal workspace; commit
14's differently named fresh-clone gate had already exercised the named form.
The replacement must exercise that form again without weakening comparison
semantics.

## Final worktree validation

The validation chronology distinguishes environment setup from repository
findings:

1. the first run passed formatting, clippy, 83 Rust tests, and fuzz-target
   checks, then stopped before mobile builds because the shell lacked the
   pinned NDK variable;
2. the correctly pinned rerun reached the SBOM comparison and exposed the
   checkout-name defect described above;
3. after the fix, a rerun passed through the SBOM and four Swift tests but used
   an incomplete disposable Gradle cache, so the offline Android plugins were
   unavailable; and
4. the final uninterrupted run used the existing populated offline cache and
   completed with exit status zero.

The final pass covered formatting, warning-denying clippy, all 83 Rust tests,
fuzz-target compilation, all four frozen mobile release builds, signed-source
and build-script checks, generated-binding drift, the corrected SBOM
comparison, four Swift tests, five Android unit tests plus lint, cargo-deny's
four configured policy categories, and a clean OS-network-denied rebuild with
all 83 tests. No dependency, lockfile, SBOM, generated binding, or runtime file
changed.

Cargo-deny reported `advisories ok, bans ok, licenses ok, sources ok`. Its
registry-index warnings still mean current yank status was not proved. The
unmatched NCSA allowance remains expected for the separate fuzz graph and does
not place NCSA in the production graph. Neither warning is upgraded into a
stronger claim.

## Assurance boundary

This migration decision and SBOM-check correction do not alter a byte of Rust,
Swift, Kotlin, UniFFI, test-vector, dependency, SBOM, or protected-storage
behavior. They also do not turn the accepted-not-run personal-device fault
cells into passes. Android 12–14
secure-lock/biometric/profile coverage, mobile low-storage and hostile rename
timing, and the full per-transition kill matrix remain P8 and independent-
review inputs.

P2 may become Implemented only for the disposable-fixture boundary after the
clean repository and private handoff gates complete. It remains not product-
integrated, independently reviewed, Verified, or production-ready. Real
recordings, external testers, hosted audio, end-to-end-encryption claims, and
Milestone 3 remain blocked; P3 is not authorized by this work.

## Conclusion

The clean-slate migration is a containment and provenance decision, not a
provider-erasure result. It permits PR #3 to close the old repository's
reviewable implementation while making the replacement repository's strict
import, validation, visibility, and handoff checks the remaining
repository-controlled closeout work.
