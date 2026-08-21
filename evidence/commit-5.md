# Commit 5 attachment-envelope evidence

Status: Implemented and locally validated for the P2 streaming-envelope,
private-file, sender-outbox, and receiver-replay slice; archive-before-erasure
and physical bridge integration remain later commits.

- Package: P2 sealed envelope foundation
- Requirements: `M2-ENVELOPE-01`, `M2-KEY-01`, `M2-ASSURANCE-01`
- Baseline: commit-4 revision `56c010f58cfe68f461ad88219147a44bb04b50d1`
- Recorded: 2026-08-19

## Reviewable outcome

The core now emits and parses D28's exact 56-byte identifier-free envelope
header, reconstructs the exact 115-byte per-record associated data from the
authenticated manifest, and uses libsodium secretstream with 65,536-byte
plaintext records. Every non-final record requires `TAG_MESSAGE`; the final
positive-length record requires `TAG_FINAL`. Encryption generates a fresh
32-byte attachment key and 24-byte stream header internally, streams SHA-256,
rejects a short or long source, and returns the exact 128-byte zeroizing
manifest only after the final output flush.

The format parser accepts the frozen format range through
`u32::MAX * 65,536` bytes without allocating from declared geometry. The P2
operation path separately rejects zero or more than 25 MiB before encryption
or decryption. For exactly 25 MiB it processes 400 records and produces
26,221,256 bytes.

Decryption first streams the complete expected ciphertext through SHA-256 and
requires exact size and EOF before creating plaintext. It then seeks to the
start, parses the same header, reconstructs each record AAD from the manifest,
authenticates every exact record and tag in order, and requires EOF again. Its
plaintext and Mowy-owned attachment-key buffers are zeroizing and bounded;
the ciphertext record buffer is fixed at one maximum record. The only
integrated output is a package-private temporary file that is synced and
returned as an unpromoted verified temp. Every authentication, I/O, or
cancellation failure deletes that partial temp and returns no path.

The private file store accepts only three already-created mode-0700 direct
children of one canonical package root. It derives source, ciphertext,
ciphertext-temp, and plaintext-temp names only from canonical asset UUIDs,
creates mode-0600 files without replacement, rejects links/non-regular files,
compares the opened source's device/inode to its pre-open metadata, serializes
process file operations, checks the stable destination both before and after
encryption, syncs files and parent directories, and never deletes an
unexpected link or non-regular entry. Relaunch cleanup for an `encrypting`
operation removes both a partial temp and a stable ciphertext renamed before
the SQLite commit; receiver cleanup removes only the exact generated temp.

Plain SQLite now holds public operation metadata and opaque sealed bytes only.
The sender first commits `encrypting`; after the stable ciphertext and sealed
manifest exist, one immediate transaction commits its descriptor, exact
408-byte sealed-manifest outbox row, and `outbox` state. Receiver state can be
created only from an `OpenedManifest` that retains the exact sealed blob it
came from. One transaction commits that blob, public descriptor, 24-hour
expiry, `waiting_for_ciphertext`, and replay tuple keyed by conversation,
asset, and sender device. An exact duplicate returns the first operation;
conflicting tuple or operation reuse fails without mutation. SQLite trigger
faults prove both sender and receiver transactions roll back completely, and
committed rows survive repository reopen.

## Public deterministic vector

`vectors/attachment-envelope-v1.txt` contains a fabricated disposable key,
conversation and asset UUID, 33-byte plaintext pattern, exact header, exact
record AAD, final ciphertext record, complete 106-byte envelope, and SHA-256.
Its SHA-256 is
`d9e26293631c56aeb3be85214f32eaf141670bd704a76a6165c8f0623e4621c4`.
The test reads the committed text, compares each byte field, reconstructs the
manifest, and opens the exact envelope. Production code exposes no fixture-key
or caller-header constructor.

## Deterministic validation

The exact final source passed:

- `cargo fmt --all -- --check`;
- zero-warning `cargo clippy --locked --offline --all-targets --all-features
  -- -D warnings`;
- `cargo test --locked --offline --all-targets`: 57 tests passed, including the
  committed vector, exact 25 MiB cycle, format/policy boundaries, fresh
  key/header/output checks, every header field and record position, all
  disallowed authenticated final tags, wrong key/conversation/asset, tamper,
  truncation, reorder, duplication, trailing data, short successful I/O,
  short source, disk full, cancellation before and after partial output,
  symlink and destination races, orphan cleanup, schema inspection, exact
  replay, conflicting reuse, transaction fault injection, reload, and
  64-case header and length property input;
- all four frozen mobile release targets rebuilt: `aarch64-apple-ios`,
  `aarch64-apple-ios-sim`, `aarch64-linux-android`, and
  `x86_64-linux-android`;
- vendored source archives, crates.io checksum, and both minisign signature
  layers verified;
- generated Swift/Kotlin bindings, the build-script inventory, dependency
  lock, and 131-component CycloneDX SBOM remained unchanged;
- the unchanged platform suite passed 4 XCTest cases, 5 Android unit tests,
  and Android lint;
- a fresh host build completed in 48.60 seconds while macOS denied all network
  access, then all 57 tests passed there; and
- a final cached-index `cargo-deny 0.20.2` run reported exactly
  `advisories ok, bans ok, licenses ok, sources ok` without warnings.

The full gate's deliberately offline first cargo-deny invocation emitted the
same cache-index warnings as earlier commits while reporting all four
categories `ok`. Android tooling retained its existing SDK-XML-version
warning. Neither warning changed resolution, compilation, source identity, or
the separately warning-free cached result. The initially supplied Gradle cache
directory had been replaced locally; the gate was rerun from the start with
the discovered Gradle 8.14.3 executable and passed.

## Remaining boundary

- Commit 6 must add `verified_temp` recovery, archive re-encryption and
  verification, `available` plus sealed-blob erasure in one transaction,
  24-hour expiry cleanup, and archive-only playback output.
- Commit 7 must make platform code create and protect these namespaces, apply
  iOS backup/file-protection flags, use Android `noBackupFilesDir`, recheck
  device lock state before promotion/commit, and expose only semantic handles
  and public descriptors through UniFFI.
- The sender file and SQLite steps are deliberately separate resources. The
  later coordinator must call cleanup for every still-`encrypting` operation
  and on transaction failure; it may return a descriptor only after the
  outbox commit.
- Property tests are committed here. The pinned sustained fuzz corpus and
  sanitizer-capable run remain commit-8 evidence rather than an assurance
  claim for this slice.
- No physical-device transfer, archive, playback, real recording, service
  upload, account binding, external tester, or encryption claim is asserted.
