# Platform protected-key adapters

Status: Implemented for P2 commit 2; native integration and physical lifecycle
evidence continue in later package slices.

Rust generates three independent secrets through the pinned libsodium layer:
an Ed25519 identity seed, an X25519 private key, and a 32-byte archive key. The
only private root layout is their 96-byte concatenation in that order. It is an
internal storage representation, not a service or JavaScript format.

The Swift adapter stores those bytes as one non-synchronizing generic-password
Keychain item under service `app.mowy.prototype.p2.keys.v1`, account
`root-key-material-v1`, and
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. It checks protected-data state
at entry and before success, never overwrites an existing item, and attempts to
remove a new item if the device locks during creation.

The Kotlin library retains the application's API-24 installation floor but
requires API 28 and an unlocked device before inspecting or creating P2 state.
It wraps the 96 bytes with a non-exportable 256-bit AES Android Keystore key
under alias `app.mowy.prototype.p2.key-wrap.v1`, AES-GCM without padding, no
caller IV, randomized encryption required, user authentication disabled, and
unlocked-device use required. StrongBox is requested when available and
absence falls back to the same non-exportable Keystore class.

The provider-generated IV must be 12 bytes. The associated data is ASCII
`MOWY-P2-KEY-WRAP-V1` followed by one zero byte. The no-backup file contains
exactly version `1`, IV length `12`, the IV, and 96 ciphertext bytes plus the
16-byte GCM tag. Writes use `0600`, directories use `0700`, files are synced
and moved atomically on the same volume, and the directory is synced. Rewrap
uses the same key but a fresh provider IV and atomically replaces the blob.

Both adapters return coarse states and errors only. Their raw byte methods are
internal native plumbing for the later Rust connection; no UniFFI or Expo API
currently exposes them. Callers must zeroize the one returned native buffer
after Rust has copied it into its zeroizing container.

Run `scripts/check-platform-key-storage.sh` with Xcode, Android SDK 36, and
Gradle 8.14.3. It type-checks production Swift for an iOS device, executes the
Keychain failure tests on the macOS host, and runs the Android wrapped-blob and
AES-GCM tests plus Android lint fully offline. Gradle dependency verification
is strict: the committed metadata freezes SHA-256 for all 312 resolved
build/test components and 552 artifacts. The Android adapter adds no
third-party runtime library. The physical-device lifecycle matrix is recorded
separately from these deterministic host checks.
