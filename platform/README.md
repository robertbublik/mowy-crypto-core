# Platform protected-key adapters

Status: Protected storage is implemented; the semantic development bridge and
signed proof apps are implemented on the package branch. Physical single-device
lifecycle evidence passes on both named devices. The cross-device relay ABI and
iOS mid-operation relock proof remain open.

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

Both adapters return coarse states and errors only. Generated UniFFI callbacks
connect the 96-byte root item as twelve fixed-width words to avoid a general
byte-buffer or key API. Swift/Kotlin holds one temporary protected-store buffer,
uses a tokenized begin/word/finish load protocol, zeroizes that buffer at
finish, and rejects concurrent loads. This callback is trusted native plumbing,
not a JavaScript or Expo interface. The semantic caller can invoke only the
named fixture proof and receives a coarse code or a public receipt.

The platform adapters also create one fixed `proof-v1` namespace with
`source`, `ciphertext`, `receive-temp`, `verified`, and `archive` children,
an installation marker, and the operation database. iOS applies mode `0700` or
`0600`, `NSFileProtectionComplete`, and backup exclusion. Android uses
`noBackupFilesDir`, the same modes, and an application manifest with
`allowBackup=false` and `fullBackupContent=false`. Rust validates canonical,
non-linked directories and regular files again before use.

`platform/android/proof-app` and `platform/ios/proof-app` are development-only
native applications. Each runs one warmup maximum fixture, establishes a
settled resident-memory baseline, then runs one to ten exact 25 MiB cycles. The
apps write only public receipt data to an app-private temporary/cache file and
do not log proof results. They enforce peak growth at most 100 MiB and final
growth at most 20 MiB.

Run `scripts/check-platform-key-storage.sh` with Xcode, Android SDK 36, and
Gradle 8.14.3. It type-checks production Swift for an iOS device, executes the
Keychain failure tests on the macOS host, and runs the Android wrapped-blob and
AES-GCM tests plus Android lint fully offline. Gradle dependency verification
is strict. The generated UniFFI Kotlin binding requires the separately pinned
JNA 5.19.1 AAR; it is bridge plumbing and not another cryptographic provider.
The complete physical commands, signing/linkage checks, memory results,
container inventories, relaunches, and locked-device outcomes are recorded in
`evidence/commit-7.md` and `evidence/commit-8.md`.
