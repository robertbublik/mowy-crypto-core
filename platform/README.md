# Platform protected-key adapters

Status: Protected storage and the bounded semantic development bridge are a P2
closeout candidate. Physical single-device lifecycle evidence passes on both
named devices, and the iPhone-to-Huawei relay/stage/restart/resume/cleanup
journey passes. A controlled physical iOS relock before plaintext promotion
also fails closed and recovers through the same opaque operation after unlock.
The hazardous personal-device cases have the not-run safety disposition below.
The scoped history rewrite and fresh-clone validation pass; GitHub-owned
cleanup, the private handoff, and independent human review remain incomplete.
This is not production-readiness evidence.

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
not a JavaScript or Expo interface. The semantic caller can invoke the named
self-contained fixture proof or the fixed cross-device fixture lifecycle and
receives only a coarse code plus public/opaque records.

The development proof apps accept these modes:

| Mode | Public input | Result after durable transition |
| --- | --- | --- |
| `publish` | none | signed public bundle |
| `prepare` | recipient public bundle and bounded fixture length | opaque/public transfer plus exact sender ciphertext path |
| `stage` | sender public bundle and opaque/public transfer | opaque receiver operation ID plus exact destination path; sealed bytes remain unopened |
| `resume` | opaque receiver operation ID | public length/digest receipt after authenticate, decrypt, archive, verify, and transport erasure |
| `cleanup-sender` | exact opaque/public transfer | coarse success after exact generated sender files and durable row are removed |

The iOS proof app additionally accepts development-only
`resume-relock-probe`. It wraps ordinary `resume` and pauses at the protected
availability check after authenticated decryption/sync but before plaintext
promotion so a maintainer can physically lock the device. This callback
position is valid only for a freshly staged, never-resumed operation; a valid
run must also prove the ciphertext-only prelaunch/locked inventories, unlock
recovery, and idempotent repeat. The coarse verdict alone is insufficient.

Its separate private temporary verdict is mode `0600`, readable while locked,
and contains only the fixed mode, coarse code, receipt presence, and
checkpoint/lock/result booleans. Each process launch removes and recreates the
exact file before core work, handles every write/sync failure as a failed run,
and forces unavailable on timeout or background-task expiry. The operator must
terminate the prior process and observe the same run's
`LOCK_DEVICE_NOW`-to-final transition. Every core artifact retains
`NSFileProtectionComplete`; the production adapter and generated ABI are
unchanged.

iOS supplies `--mode`, `--bundle`, `--transfer`, `--operation`, and `--length`
arguments. Android uses intent extras with the same names. The apps serialize
public fields with `|` only as proof-runner plumbing; UniFFI records are the ABI,
and this text is not a product or service wire format. The returned paths are
generated within the fixed app-private namespace and are never accepted back
as receiver input.

The platform adapters also create one fixed `proof-v1` namespace with
`source`, `ciphertext`, `receive-temp`, `verified`, and `archive` children,
an installation marker, and the operation database. iOS applies mode `0700` or
`0600`, `NSFileProtectionComplete`, and backup exclusion. Android uses
`noBackupFilesDir`, the same modes, and an application manifest with
`allowBackup=false` and `fullBackupContent=false`. Rust validates canonical,
non-linked directories and regular files again before use.

## Physical-fault and compatibility disposition

The iPhone and Huawei used for the bounded proofs are personal devices. No test
filled their storage, forced a real platform rename failure, changed the
Huawei's secure-lock configuration, or killed the process at every sync,
rename, SQLite-commit, and cleanup transition. Those cells are **not run —
accepted for personal-device safety** for the fixture-only P2 closeout. They
are not physical passes and must not be inferred from normal atomic-write,
force-stop, relaunch, or relock evidence.

Host tests cover an envelope-writer `StorageFull` error, short I/O, destination
conflict, reconstructed rename/relaunch states, transaction trigger rollback,
and exact successful cleanup. They do not inject actual file or directory sync
failures, each production rename failure, SQLite commit-time storage failure,
or every process-death cut. The Rust tests also do not inject faults into the
Android Keystore blob's file sync/atomic move/directory sync, the proof
namespace setup, or the iOS Keychain and companion-file boundaries.

Android 12 through 14 secure-lock removal and credential/strong/weak biometric
or shared-profile behavior was unavailable in the approved device set. The
implementation retains the fail-closed `unavailable` result with no fallback
or automatic key replacement. Actual mobile low-storage/rename timing, that
Android compatibility matrix, and the full per-transition kill matrix are
carried to P8 and independent human review before real recordings or product
use. Any later execution must use factory-reset disposable hardware or an
isolated, revertible emulator/simulator and must label emulator evidence as
such.

`platform/android/proof-app` and `platform/ios/proof-app` are development-only
native applications. Each runs one warmup maximum fixture, establishes a
settled resident-memory baseline, then runs one to ten exact 25 MiB cycles. The
apps write only public receipt data to an app-private temporary/cache file and
do not log proof results. They enforce peak growth at most 100 MiB and final
growth at most 20 MiB.

The iOS proof Xcode project intentionally commits no development-team value.
Supply the team only through local Xcode settings or a physical-build command,
for example `DEVELOPMENT_TEAM="$MOWY_P2_APPLE_TEAM"`, and never persist or copy
that value into public source, logs, receipts, or evidence. Generic unsigned
device builds omit the override.

Run `scripts/check-platform-key-storage.sh` with Xcode, Android SDK 36, and
Gradle 8.14.3. It type-checks production Swift for an iOS device, executes the
Keychain failure tests on the macOS host, and runs the Android wrapped-blob and
AES-GCM tests plus Android lint fully offline. Gradle dependency verification
is strict. The generated UniFFI Kotlin binding requires the separately pinned
JNA 5.19.1 AAR; it is bridge plumbing and not another cryptographic provider.
The complete physical commands, signing/linkage checks, memory results,
container inventories, relaunches, locked-device outcomes, and cross-device
relay are recorded in `evidence/commit-7.md`, `evidence/commit-8.md`, and
`evidence/commit-9.md`. The controlled iOS relock, retry, cleanup, failed
self-proof correction, and exact evidence boundary are in
`evidence/commit-10.md`. Current-tree device/signing identifier redaction and
the local-only signing-team rule are in `evidence/commit-11.md`; it explicitly
does not claim published-history erasure. Commit-13 evidence records the
rewrite scope, exact coverage correction, and safety disposition. The
published remote heads, fresh-clone gate, and still-pending GitHub-owned
cleanup are recorded in `evidence/commit-14.md`.
