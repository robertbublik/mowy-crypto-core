# Commit 13 P2 closeout-candidate evidence

Status: Closeout candidate prepared locally; pending final public branch
replacement, GitHub-owned pull-request/cache dereference, fresh-clone
validation, and exact remote evidence. This document does not mark P2 final,
Implemented, Verified, or production-ready.

- Package: P2 sealed envelope foundation
- Requirements: `M2-KEY-01`, `M2-ENVELOPE-01`, `M2-ASSURANCE-01`
- Rewritten baseline: commit-12 revision
  `0cbc293ac112d8cafdfc91125e2ac35c46961cc1`
- Change class: vendored-source completeness, documentation, evidence
  correction, reviewed safety disposition, and maintainer-authorized
  public-history remediation
- Recorded: 2026-08-20

## Reviewable outcome

This candidate makes no cryptographic, storage, ABI, binding, vector,
dependency-version, platform, or proof-app source change. It restores four
upstream `cc` crate source files whose nested `src/target/` directory had been
mistaken for a build-output directory by the repository-wide `target/` ignore,
and anchors the Rust build-output ignores to the two actual output roots. The
restored bytes match the hashes already pinned in
`vendor/cc/.cargo-checksum.json`; no dependency version or approved upstream
crate content changes.

The candidate also corrects the strength of the hazardous-fault claim,
reconciles the Android 12-through-14 compatibility cell, records the exact
locally rewritten public history, and separates repository-controlled branch
remediation from GitHub Support-owned cleanup.

The implementation remains the commit-12 source. Its existing deterministic,
fuzz, sanitizer, mobile-build, physical relay/restart, relock/recovery, and
disposable-output evidence remains bounded by the tests and observations that
actually ran. Commit 13 neither repeats physical work nor upgrades a simulated
or reconstructed state into physical evidence.

## Hazardous physical-fault disposition

The iPhone and Huawei available to this package are personal devices. Filling
either device to a real `ENOSPC` condition can affect device-global storage,
the operating system, and unrelated applications or user data. Changing secure
lock configuration, arranging a hostile rename race, or repeatedly killing a
process at internal storage boundaries also exceeds the approved personal-
device evidence scope.

The following cells are therefore **not run — accepted for personal-device
safety** for fixture-only P2 closeout:

- actual physical device storage exhaustion during source, ciphertext,
  plaintext, archive, SQLite, or cleanup writes;
- actual platform rename failure or hostile rename timing at every publication
  boundary; and
- process kill before and after every file sync, directory sync, rename,
  SQLite commit, and cleanup branch.

This is a safety disposition, not a passing test result. It does not say that
the connected personal devices are disposable, that the named platform faults
were observed, or that a normal force-stop proves every transition. Future
execution requires factory-reset disposable hardware or an isolated,
revertible emulator/simulator with no account or user data. Emulator evidence
must be labelled as emulator evidence rather than physical-device evidence.

### Exact current host coverage

| Boundary | Evidence that exists | Limit that remains |
| --- | --- | --- |
| Short and disk-full writes | `attachment_envelope::tests::reports_short_source_disk_full_and_cancellation_without_success` uses a deterministic writer that returns `StorageFull`; short successful I/O is separately covered | It is an envelope `Write` adapter, not actual filesystem exhaustion, file/directory-sync failure, archive/source path failure, or SQLite `FULL` |
| Ciphertext destination race | `private_files::tests::destination_race_preserves_conflict_and_removes_partial_ciphertext` creates the stable destination during encryption and proves fail-closed conflict handling | It does not force the production `rename(2)` call itself to fail |
| Rename/relaunch states | `private_files::tests::classifies_verified_temp_relaunch_states_and_removes_archive_orphans` and `receiver_lifecycle::tests::recovers_crashes_at_each_plaintext_and_archive_transition` reconstruct temp/final/archive states and exercise recovery | The tests construct durable states in one test process; they do not kill a process immediately before and after all three production renames or their directory syncs |
| SQLite rollback | Sender outbox, receiver/replay, available, and development-promotion tests use aborting SQLite triggers and prove transaction rollback | They do not inject commit-time filesystem I/O failure or physical `ENOSPC` |
| Available cleanup | `receiver_lifecycle::tests::available_relaunch_cleans_transport_before_returning_archive` and bridge tests prove cleanup-before-path behavior for named states | There is no injected failure at every remove/directory-sync branch, and development error cleanup is not a general crash journal |
| Physical process lifecycle | Recorded proof runs include ordinary terminate/relaunch, one receiver force-stop before resume, repeat durable resume, Android locked launch, and one controlled iOS relock before plaintext promotion | They are bounded checkpoints, not a physical kill-at-every-transition matrix |
| Platform protected storage | Host tests, source inspection, and bounded physical normal/lock paths cover the Android wrapped blob and iOS Keychain adapter | Rust host tests do not inject the Android file-sync/atomic-move/directory-sync path, iOS companion-file sync, Security.framework failures, or mobile low-storage timing |

Earlier statements that “exact production host fault adapters” or the complete
deterministic disk-full/rename/kill matrix passed were too broad. The table
above is the corrected claim. No new adapter was added by this documentation-
only closeout candidate.

Actual APFS and Android-filesystem low-storage/rename behavior, mobile
Keychain/Keystore and companion-file failure timing, direct production
file/sync/rename/SQLite fault injection, and the full per-transition kill
matrix remain P8 and independent-human-review inputs before real recordings,
product integration, or an end-to-end-encryption claim.

### Android 12-through-14 compatibility

Commit 2 correctly recorded C2-08 as open because only an Android 9 physical
device was available and changing the maintainer's secure-lock configuration
was destructive. That historical fact remains visible in
`evidence/commit-2.md` and `reviews/commit-2-hostile-review.md`.

For fixture-only P2, the maintainer now accepts the Android 12-through-14
secure-lock removal and credential/strong/weak biometric or shared-profile
matrix as **not run — unavailable**. The implementation continues to return a
stable unavailable result with no fallback or automatic replacement. The cell
is not physically passed and is retained for P8 and independent human review
before product use.

## Authorized public-history remediation

Commit 11 removed local device/signing identifiers and committed development-
team settings from the then-current tree but correctly said that already-
published objects remained. The maintainer subsequently authorized a bounded
rewrite. The replacement history is prepared locally and follows GitHub's
[official sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository),
including its warning that hashes change, old signatures no longer apply, PR
references are read-only to a force-push, and Support is required for eligible
PR dereference and cached-view removal.

### Strict rewrite scope

The rewrite is limited to public-core history reachable from exactly three
repository-controlled branches:

- `main`;
- `package/026-p2-sealed-envelope-foundation`; and
- `package/026-p2-sealed-envelope-foundation-implementation`.

Within that history it performs only these transformations:

1. normalize the project author's and committer's Git email metadata to the
   public GitHub no-reply identity while preserving names, timestamps, commit
   messages, and topology;
2. apply the already-reviewed commit-11 device/signing-identifier redactions to
   the historical versions of `evidence/commit-2.md` and
   `evidence/commit-7.md`;
3. remove the already-reviewed committed iOS development-team assignments from
   the historical proof-project settings where they first appeared; and
4. update only historical evidence baseline references that otherwise pointed
   to replaced commit objects.

No first-party Rust, Swift, Kotlin, UDL, generated binding, vector, corpus,
dependency version, lockfile, SBOM policy, cryptographic operation, fixture,
or proof result is changed. Commit 13 restores only the four checksum-pinned
upstream Rust source files described above. No tag or release is created,
deleted, or rewritten. The initial commit, package-foundation commit, and PR-1
merge necessarily receive new object IDs because their metadata or ancestry
changed. Old object IDs are intentionally not repeated in rewritten public
evidence because they can identify hosting-provider cached views that still
await Support cleanup:

| History object | Replacement |
| --- | --- |
| Initial commit | `2522dfa327cc363c9f3c247ab7d02a52b725a982` |
| Package-foundation commit | `079702bf71020c4c0464204ce3b0e06131a1b4a5` |
| PR-1 merge on `main` | `ed99484ed9db3927904e4554005580f037b7135d` |

### Exact implementation commit map

| Commit | Review slice | Replacement |
| --- | --- | --- |
| 1 | Pin public native crypto core | `b46c02d21af5496e9e618041d6694d815e51110a` |
| 2 | Add protected device key material | `2cc25a7b614d95c89f0b0606bc120bfb65a8d9a7` |
| 3 | Publish and pin signed key bundles | `4151a774ee26aeff3524882a2c49c199c83492ca` |
| 4 | Seal and open one manifest | `56c010f58cfe68f461ad88219147a44bb04b50d1` |
| 5 | Add attachment envelope v1 | `0bcdbc7b841d71bd9e350e516e51efc1cca31134` |
| 6 | Archive and erase transport material | `93385b2494ddcf11f04c04f014cced599ff849cc` |
| 7 | Connect physical development builds | `07a717c0cef9f2fb9903a318d8f1d6873030ab07` |
| 8 | Add bounded parser fuzzing | `b05d14c2d8cb13c22e537d1509efc78a267e8037` |
| 9 | Prove cross-device sealed transfer | `5108fa11e1c9bb39679d9743e24f597c5710c978` |
| 10 | Prove physical iOS relock recovery | `d7a9dd3238c80c109c9fb319d06eb7a961a9c9c1` |
| 11 | Redact device signing identifiers | `aec0833f330073c6d60846e8b71d73f2be18cba4` |
| 12 | Close disposable proof cleanup | `0cbc293ac112d8cafdfc91125e2ac35c46961cc1` |

Commit 13 will receive its final object ID only after this candidate is
validated and committed. Until then, `0cbc293` remains the exact rewritten
source baseline rather than a remote-completion claim.

### Pull requests, remote inventory, and ownership

The changed public history affects exactly public-core PR #1, which is merged,
and public-core PR #2, which is a closed draft. Private application PR #7 is
not history-rewritten; its body and package documentation must be updated to
the replacement public hashes after the public heads are stable.

The remote inventory found:

- no forks;
- no releases;
- no Actions artifacts; and
- no Actions caches.

That inventory does not prove that independent clones, GitHub object caches,
or GitHub's internal pull-request references are absent. The three branch refs
are repository-controlled and must be force-updated and verified explicitly.
The `refs/pull/*` references and cached PR/object views are GitHub-controlled,
read-only to repository pushes, and remain a separate Support-owned step.

Changing commit hashes invalidates every old commit or tag signature for the
replacement object. Any attestation, check result, approval, diff comment, or
link bound to an old hash likewise does not validate the replacement. No old
signature or status is carried forward as evidence.

## Validation completed for this candidate

The local history was inspected as a graph and the replacement map above was
matched to commit messages and parent order. A final source-tree comparison
between published commit 12 and rewritten commit 12 found only the authorized
historical evidence-reference corrections in the current checkout; the
commit-11 tip already owned the identifier and Xcode-setting redactions.
Commit 13 changes no first-party runtime implementation. Its non-documentation
changes are limited to the root-anchored ignore rules, the four
checksum-pinned upstream `cc` files described above, and correction of the
SBOM check's checkout-root normalization literal.

The first complete-gate attempt failed before compilation because Cargo
correctly rejected the four absent checksum-listed `cc` files. Inspection
found no other absent entry among 7,693 files listed by the vendored crate
checksum manifests. The restored files match their four already-committed
SHA-256 entries exactly. The ignore correction changes `target/` and
`artifacts/` to root-anchored `/target/` and `/artifacts/` entries and adds the
separate root-anchored `/fuzz/target/`, so nested upstream source directories
remain visible to Git. No current vendored manifest uses a nested `artifacts/`
path; anchoring it prevents the same omission class in a future dependency.

A subsequent gate attempt reached the SBOM comparison and found that the
pinned generator emitted its root reference as
`#mowy-crypto-core@0.1.0`, while the checker still matched the obsolete
`#0.1.0` suffix. Only the four checkout-root reference strings differed; the
component and dependency inventory did not. The checker now normalizes the
exact emitted root form to the same stable
`pkg:cargo/mowy-crypto-core@0.1.0` reference used by the committed SBOM. This
is a reproducibility-check correction, not an SBOM or dependency change.

`git diff --check` passes. The changed-file inventory is exactly `.gitignore`,
the root, platform, and supply-chain READMEs, the commit-2 and commit-11
evidence/review notes, the SBOM comparison script, the two new commit-13
evidence/review files, and the four checksum-pinned upstream `cc` source files.
No first-party source, binding, vector, dependency version, lockfile, SBOM, or
platform build file is modified.

After the two reproducibility corrections, the complete `scripts/check.sh`
gate passed in one uninterrupted run on 2026-08-20 with Rust/Cargo 1.97.1,
NDK 27.1.12297006, Gradle 8.14.3, rsign2 0.6.6,
cargo-cyclonedx 0.5.9, and cargo-deny 0.20.2. The result includes:

- format and warning-denying clippy checks;
- all 83 Rust tests and the exact maximum fixture;
- compile checks for every fuzz target;
- release builds for both frozen Apple and both frozen Android targets;
- exact signed-libsodium source verification, build-script inventory,
  generated-binding drift, unchanged normalized SBOM, and protected-storage
  checks;
- four passing Swift protected-store tests, five passing Android unit tests,
  and the passing Android lint task;
- cargo-deny's exact final result `advisories ok, bans ok, licenses ok, sources
  ok` with exit status zero; its separate `index-failure` warnings mean the
  local registry index could not answer current yank status for the locked
  crates, so this is not presented as a refreshed non-yanked result; the
  non-fatal unmatched-NCSA warning is expected because NCSA is absent from the
  production graph but retained for the separately checked fuzz graph's
  conjunctive `libfuzzer-sys` licence; and
- a clean recompilation and all 83 tests under the operating system's network
denial.

For completeness, six complete-script attempts were made. The first found the
missing vendored files, a repository defect. The second selected a same-version
Homebrew Rust installation without the four installed mobile target libraries;
the coherent preinstalled Rust 1.97.1 sysroot fixed that environment choice.
The third and fourth stopped when the disposable environment lacked rsign2 and
cargo-cyclonedx respectively; installing the exact documented versions fixed
those validation-tool setup omissions. The fifth exposed the repository's
obsolete SBOM root normalizer. The sixth, after both repository repairs and all
exact tools were in place, was the uninterrupted exit-zero result summarized
above. The three environment/tool stops are not described as code defects or
passing gates.

The final derived-token/category scan and clean rewritten-remote clone have not
yet passed for commit 13 and are not claimed here.

## Pending completion evidence

P2 must remain a closeout candidate until all of the following are recorded:

1. the final commit-13 object ID and updated replacement map/handoff links;
2. force-updated, exact remote heads for the three named public-core branches,
   with no other repository-controlled ref changed;
3. updated public-core PR #1 and #2 status/links and updated private PR #7
   body/documentation, without presenting old checks or approvals as current;
4. a GitHub Support request identifying the repository, the two affected PRs,
   and the first changed commit, followed by Support confirmation of eligible
   PR dereference, server garbage collection, and cached-view removal;
5. a fresh clone from the rewritten remote that passes the category-only
   identifier audit, history/hash inspection, generated-binding drift check,
   and complete package gate; and
6. final public/private exact-head, mergeability, changed-file, and evidence
   inspection.

Independent human design and implementation review remains a separate D27
gate before real recordings or later milestone authorization. The safety
disposition above does not replace that review and may be challenged by it.
