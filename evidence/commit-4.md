# Commit 4 sealed-manifest evidence

Status: Implemented and locally validated for the P2 sign-then-seal slice;
durable replay/state integration and physical bridge proof remain later commits.

- Package: P2 sealed envelope foundation
- Requirements: `M2-DELIVER-01`, `M2-ASSURANCE-01`
- Baseline: commit-3 revision `4151a774ee26aeff3524882a2c49c199c83492ca`
- Recorded: 2026-08-19

## Reviewable outcome

The native core now owns one exact 128-byte attachment manifest. It validates
the fixed magic, version, envelope version and algorithm, zero reserved field,
non-nil canonical conversation and asset UUIDs, P2's `1..=25 MiB` policy, and
the exact ciphertext expansion implied by 65,536-byte chunks plus 17 bytes per
secretstream record. The complete serialized manifest is one non-cloneable
zeroizing owner; its final 32 bytes are the attachment key.

Manifest delivery follows the frozen sign-before-encrypt order. The exact
296-byte signed region contains the 24-byte domain, sender device and Ed25519
identity, recipient device/key ID/X25519 public key, conversation and asset
IDs, and the complete 128-byte manifest. Appending the 64-byte detached
signature produces exactly 360 secret-bearing bytes. Libsodium
`crypto_box_seal` adds exactly 48 bytes, and only the resulting 408-byte opaque
blob plus its canonical public recipient-key-ID selector may leave the
operation.

Opening rejects a nonmatching selector or inactive key before sealed-box work,
selects one already-named local key without scanning, and keeps both the
libsodium output vector and fixed inner buffer in zeroizing owners. It compares
the embedded identity to the trusted sender pin, verifies the signature over
all 296 bytes, then checks sender, exact intended recipient device/key/public
key, outer-to-manifest identifiers, and caller-expected conversation/asset.
Only then does it return the still-native zeroizing manifest. Wrong recipient,
forwarding by re-sealing, signature stripping, validly signed unknown versions,
and validly signed identifier disagreement all fail closed.

## Public deterministic vector

`vectors/sealed-manifest-v1.txt` contains fabricated disposable seeds,
identifiers, digest, attachment key, lengths, the signed-region SHA-256, exact
detached Ed25519 signature, and complete 360-byte inner-plaintext SHA-256. Its
SHA-256 is
`a27b11caf230f1fd6f1ad32a3f3ccfecddac68d64587668e3986ebc7f21c9d4c`.
The sealed-box bytes are intentionally absent because libsodium owns a fresh
ephemeral key for every seal; the test instead requires two seals of the same
inner plaintext to differ and both to open successfully.

## Deterministic validation

The exact final source passed:

- `cargo fmt --all -- --check`;
- zero-warning `cargo clippy --locked --offline --all-targets --all-features
  -- -D warnings`;
- `cargo test --locked --offline --all-targets`: 31 tests passed, including 13
  manifest/sealed-delivery tests for exact layout and geometry, all structural
  fields, wrong recipient secret and selector, expired key, ciphertext tamper,
  changed sender identity, expected and embedded identifier mismatch,
  stripped signature, forwarded/re-sealed inner plaintext, signed unknown
  version, randomized sealing, vector stability, 64-case manifest property
  input, 64-case length fuzzing, and 64 exact-size random sealed blobs;
- all four frozen mobile release targets rebuilt;
- source archive hashes and both signature layers verified;
- generated Swift/Kotlin bindings, the build-script inventory, dependency
  lock, and the 131-component CycloneDX SBOM remained unchanged;
- the unchanged platform-storage suite passed 4 XCTest cases, 5 Android unit
  tests, and Android lint;
- a fresh host build completed in 48.29 seconds while macOS denied all network
  access; and
- a final warning-free `cargo-deny 0.20.2` cached-index run reported exactly
  `advisories ok, bans ok, licenses ok, sources ok`.

The full gate's first offline cargo-deny pass and Android tooling retain the
same recorded cache-index and SDK-XML warnings as commits 2 and 3. No new
dependency, build script, generated binding, or platform adapter was added.

## Remaining boundary

- Commit 5 must stream the ciphertext, compare the manifest size and digest,
  authenticate every record and exact EOF, and place replay plus receiver
  operation state in SQLite before this opened manifest can cause durable
  progress.
- Commit 6 must archive verified plaintext before atomically erasing this
  manifest and its attachment key with `available`.
- Commit 7 must implement selector lookup through protected storage, trusted
  sender lookup through the pinned repository, canonical bridge input parsing,
  lock rechecks, and physical cross-device publication/opening. The core never
  scans retained private keys; a bridge implementation that does is invalid.
- The public vector uses only disposable fixture material. No physical device,
  real recording, service publication, account binding, or encryption claim is
  asserted by this commit.
