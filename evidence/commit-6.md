# Commit 6 archive-and-erasure evidence

Status: Implemented and locally validated for the P2 archive, receiver
recovery, transport-erasure, and local-expiry slice; physical bridge and
device-container inspection remain later commits.

- Package: P2 sealed envelope foundation
- Requirements: `M2-ENVELOPE-01`, `M2-KEY-01`, `M2-ASSURANCE-01`
- Baseline: commit-5 revision `e8fd450140bd1ae5858b2a0bfee3ff9f0a28c34a`
- Recorded: 2026-08-19

## Reviewable outcome

The native core now reuses the frozen envelope-v1 framing for a device-local
archive without exposing a caller-key entry point. `ArchiveKey` copies the
archive-secret segment of the already-zeroizing root material into a separate
zeroizing owner. Each archive uses the long-lived protected archive key with a
fresh libsodium secretstream header, and binds the exact conversation UUID,
asset UUID, plaintext length, ciphertext length, and ciphertext digest as
associated data.

Archive creation reads only the promoted package-private verified file and
writes one mode-0600 archive partial. Before publication it seeks the same
archive descriptor back to the beginning, authenticates every record, and
compares the decrypted stream with the original file using libsodium
constant-time comparison and an exact final EOF check. It then syncs, renames,
syncs the parent, and validates the stable archive. The proof object returned
by that process has private fields and can be constructed only inside the
archive verifier; SQLite's `available` transition accepts that proof object,
not a freely constructed descriptor.

Receiver SQLite has explicit `waiting_for_ciphertext`, `verified_temp`,
`available`, and `unavailable/resend` states with conditional schema checks.
One immediate transaction changes `verified_temp` to `available`, stores only
the public archive name/length/digest, and sets the sealed blob to `NULL`.
Forced transaction failure leaves `verified_temp`, its sealed blob, and no
archive descriptor. A successful transition is exactly idempotent. The opened
manifest is consumed by value by the lifecycle coordinator, so its zeroizing
attachment key owner is dropped before success returns.

The SHA-256 of the exact 128-byte manifest remains as a one-way replay
fingerprint after sealed-blob erasure. It is not sufficient to reconstruct the
independently random attachment key. It lets an exact authenticated manifest
replay resume the original operation while conflicting manifest bytes fail.
The replay ledger and archive descriptor therefore remain usable without
retaining the opened manifest, attachment key, or sealed blob.

After `available` commits, the coordinator deletes the exact generated
receiver plaintext temp/final and ciphertext temp/final entries, syncs each
directory, and returns only the archive path plus its public descriptor. A
crash between the database commit and file cleanup can leave transport files
beside an internal `available` state; no path was returned. Relaunch recovery
needs only the opaque operation handle, removes those exact transport entries,
opens the expected regular archive, and returns no path before cleanup. It
never needs or reconstructs the transport key.

The frozen D24 relaunch matrix is implemented explicitly: an unrecorded temp
is removed and decrypted fresh, `verified_temp` plus temp resumes promotion,
`verified_temp` plus final or conflicting files deletes uncertain plaintext
and archive output before decrypting fresh, and missing state fails unavailable
without a path. Archive partial/final files from an uncommitted attempt are
removed by exact asset-derived names. A 24-hour
`waiting_for_ciphertext` expiry atomically sets unavailable/resend and erases
the sealed blob at the exact boundary, followed by exact local cleanup. A
failed cleanup is retryable only with that unavailable operation handle; there
is no broad directory scan or caller path.

## Deterministic validation

The exact final source passed:

- `cargo fmt --all -- --check`;
- zero-warning `cargo clippy --locked --offline --all-targets --all-features
  -- -D warnings`;
- `cargo test --locked --offline --all-targets`: 70 tests passed, including
  fresh archive headers/output, correct archive open, wrong archive key,
  conversation/asset binding, ciphertext tamper, plaintext mutation between
  archive passes, exact EOF comparison, mode/path checks, archive publication,
  full transport cleanup, every receiver file transition, missing verified
  temp, crash after `available`, available-transaction rollback, exact replay
  after sealed erasure, exact 24-hour expiry, explicit cleanup retry, and the
  unchanged envelope/sealing adversarial suites;
- all four frozen mobile release targets rebuilt: `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, `aarch64-linux-android`, and
  `x86_64-linux-android`;
- vendored source archives, crates.io checksum, and both minisign signature
  layers verified;
- generated Swift/Kotlin bindings, build-script inventory, dependency lock,
  and 131-component CycloneDX SBOM remained unchanged;
- the unchanged platform suite passed 4 XCTest cases, 5 Android unit tests,
  and Android lint;
- a fresh host build completed in 46.16 seconds while macOS denied all network
  access, then all 70 tests passed there; and
- a final cached-index `cargo-deny 0.20.2` run reported exactly
  `advisories ok, bans ok, licenses ok, sources ok` without warnings.

The full gate's deliberately offline first cargo-deny invocation emitted the
same cache-index warnings as earlier commits while reporting all four
categories `ok`. Android tooling retained its existing SDK-XML-version
warning. Neither warning changed resolution, compilation, source identity, or
the separately warning-free cached result.

## Remaining boundary

- Commit 7 must own namespace creation, apply iOS backup/file-protection
  attributes and Android `noBackupFilesDir`, recheck protected-data/device-lock
  state before plaintext promotion and `available`, and map missing, corrupt,
  or locked archive-key state to one coarse unavailable bridge result.
- Commit 7 must expose only semantic operation handles, public descriptors,
  cancellation, and coarse errors through UniFFI. The UDL and generated
  Swift/Kotlin bindings remain unchanged in this commit.
- SQLite and file rename/removal are separate resources. `available` erases
  the sealed blob atomically, while exact transport-file cleanup completes
  before a path is returned and is repeated on every available relaunch.
- App-private file removal is a logical lifetime guarantee, not a claim that a
  flash filesystem physically overwrote every historical storage block.
- Physical device inspection, ten maximum-size cycles, memory profiling,
  protected-container/backup inspection, and real signing remain commit-7/8
  evidence. No real recording, upload, external tester, product playback, or
  public encryption claim is authorized.
