# Commit 2 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: root-key generation and zeroization, platform storage adapters,
  Android wrapped-key format and filesystem handling, lock transitions,
  build/test dependency boundary, and public ABI
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C2-01 | High | Generated seed bytes are first held in ordinary arrays or copied through an ordinary root buffer | A later fallible operation returns before those stack copies are cleared | Private identity, agreement, or archive material can survive longer than its operation | Generate both seeds directly into `Zeroizing` arrays, construct the root as a zeroizing owner before filling it, and avoid plain-array copies in the store test double | Clippy/test gate plus source inspection of every root construction and failure path | Resolved |
| C2-02 | High | Two Android adapter instances initialize or rewrap concurrently | Both use the same alias, blob, and temporary filename without shared serialization | Alias/blob mismatch, overwrite, or rollback can destroy valid state | Serialize every state, classify, store, load, and rewrap operation with one process-wide lock | Concurrency remains an integrated bridge regression; source inspection requires the shared lock on all public methods | Resolved in adapter; bridge regression required |
| C2-03 | High | A link or non-regular entry exists at the Android blob or package directory | Following `File.exists`, canonicalization, or an unbounded read treats the entry as absent or valid | State can be replaced silently, escape the no-backup namespace, or allocate from attacker-sized input | Use `NOFOLLOW_LINKS`, classify every non-regular blob as partial, reject linked/non-directory namespaces, require exact size before the bounded read, and check the canonical no-backup prefix | Parser tests plus expanded physical link/partial-state proof | Resolved |
| C2-04 | Medium | iOS locks after a Keychain read, or the stored item has a corrupt length | A loaded `Data` value is rejected without explicit clearing | Secret-adjacent bytes remain in a live native allocation after failure | Reset the loaded bytes before both unavailable and corrupt-length returns | Executed XCTest cases for corrupt length and a mid-operation lock transition | Resolved |
| C2-05 | High | Android Keystore initialization, key load, or cipher init fails because of lock state, provider behavior, or deleted material | Raw provider exceptions escape the adapter or are mistaken for a missing installation | The bridge leaks platform detail or silently regenerates identity | Initialize the provider lazily after the lock check and map provider, invalid-key, and unrecoverable-key failures to stable coarse states without replacement | Physical locked Huawei load and source inspection of every provider call | Resolved for covered provider paths |
| C2-06 | Medium | Android creates only the leaf key directory or reads a blob without an exact length precheck | A parent directory keeps weaker inherited mode, or a corrupt large file causes avoidable memory use | Local at-rest and availability controls are weaker than the frozen profile | Create each namespace component separately, reject links/non-directories, apply `0700` to both, require 126 bytes before read, and keep blob mode `0600` | Physical mode/no-backup proof and static exact-length inspection | Resolved |
| C2-07 | Medium | A reviewer assumes these adapters already protect Rust-generated keys in the app | Commit 2 contains native pieces but no secret-bearing ABI or physical Expo connection | Evidence could overclaim an unimplemented integration or tempt a raw-byte bridge | Keep the UDL unchanged, mark the Rust module internal, and state that commit 7 must connect it through reviewed native plumbing and remove the temporary dead-code allowance | Generated ABI diff must stay secret-free now and commit 7 must add an explicit boundary regression | Accepted slice boundary; blocks integration claim |
| C2-08 | Medium | P2 is evaluated on Android 12–14 lock-screen defects or unsupported unlock modes | Only an Android 9 physical device is available and changing the maintainer's secure-lock configuration would be destructive | The version-specific compatibility matrix cannot be empirically completed here | Record every unavailable cell, preserve stable unavailable behavior, and add no fallback or automatic replacement | Physical version/mode matrix where supported before P2 closeout | Open evidence limitation; does not weaken code policy |
| C2-09 | Low | The installed Android SDK metadata uses XML version 4 while one command-line component reports support through version 3; AGP's lint model also performs a null-attribute lookup deprecated for Gradle 10 | Gradle emits host-tool warnings during otherwise successful offline builds | Validation output is noisy and a future SDK/tool mismatch could be overlooked | Record both warnings, pin the SDK/tool versions in evidence, require lint to report no source issues, and keep compilation plus checksum verification mandatory | Platform gate must continue to compile/test with `No issues found`; any functional SDK error blocks | Accepted host-tool warnings |
| C2-10 | High | The standalone key-storage module declares min SDK 28 | Gradle manifest merging raises the entire Expo application's minimum from its approved API-24 floor | Existing API 24–27 users cannot install even though only P2 should be unavailable | Keep the library at min SDK 24, perform the availability check before input/state handling, and run Android lint against the guarded API-28 calls | Android lint plus later API 24–27 physical/emulator unavailable test | Resolved in build boundary; runtime proof remains commit 7 |

## Negative inspection

- The UDL and both generated language bindings remain free of private keys,
  archive keys, plaintext arrays, opened manifests, key import/export, and
  caller-provided randomness.
- No authored Rust `unwrap`, `expect` invocation, panic macro, `todo`,
  `unimplemented`, `dbg`, stdout, or stderr formatting exists in the slice.
- Android logs and errors contain only stable result labels and coarse codes;
  the production adapter logs nothing.
- Swift errors contain no OSStatus, query, account, service, or data value.
- The Android manifest disables backup and the blob path originates only from
  `Context.noBackupFilesDir`; no external-storage API occurs in the adapter.

C2-08 and C2-09 are carried honestly. C2-07 is the deliberate commit boundary,
not evidence that native integration is complete. Independent implementation
review remains mandatory before any real recording.
