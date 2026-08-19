# Commit 7 physical development-build evidence

Status: Implemented and locally validated for the single-device semantic bridge
slice. The approved two-device relay flow is not implemented, so this evidence
does not close P2 or authorize a completed-package merge.

- Package: P2 sealed envelope foundation
- Requirements exercised: `M2-DELIVER-01`, `M2-KEY-01`,
  `M2-ENVELOPE-01`, `M2-ASSURANCE-01`
- Baseline: commit-6 revision `93385b2`
- Recorded: 2026-08-19
- Durable checkout: the normal workspace checkout `mowy-crypto-core/`, outside
  `/private/tmp`

## Reviewable outcome

One generated UniFFI operation, `run_development_proof`, now coordinates the
implemented key, bundle, sealed-manifest, envelope, receiver, archive, and
cleanup modules. It accepts a trusted native protected-store callback, a
cancellation callback, a public timestamp, and a bounded public fixture length.
It returns exactly one coarse `MowyCoreCode` and, only on success, a public
receipt containing an opaque random proof ID, plaintext/ciphertext lengths, and
SHA-256 digests of ciphertext and archive ciphertext.

The current operation is intentionally self-contained on one device:

1. create or load the platform-protected 96-byte root item;
2. publish and pin a fresh signed bundle for that device;
3. write the deterministic public fixture through the streaming envelope;
4. sign and seal the manifest to that same device's current agreement key;
5. commit the sender outbox, reopen and authenticate the sealed manifest;
6. commit the receiver replay/waiting state;
7. verify ciphertext, promote verified plaintext, re-encrypt and verify the
   archive, commit `available`, erase the sealed blob, and remove transport
   files;
8. reopen `available` through the relaunch path and compare the archive against
   the fixture pattern without returning a plaintext buffer; and
9. delete only the proof's temporary operation rows, published bundle, and
   exact generated file names.

That proves mobile linkage and the complete local state machine. It does not
prove the work packet's required device-B bundle publication, device-A sealed
send, untrusted file relay, device-B durable restart, and device-B receive. The
semantic transfer/import/export ABI needed for that flow was proposed twice and
rejected by the active safety gate because it expands the cryptographic API.
No alternate raw-key, raw-manifest, general encrypt/decrypt, arbitrary-path, or
JavaScript surface was introduced to route around that decision.

## Exact generated ABI

The UDL exposes:

- `core_profile_version()`;
- `run_development_proof(protected_store, cancellation, now,
  plaintext_length)`;
- fixed enums for success, invalid input, unavailable, conflict, storage,
  authentication, cryptography, and cancellation;
- one public receipt dictionary and one fixed platform-response dictionary;
- protected-store callbacks for availability, state, companion files, fixed
  namespace preparation, one create, and a tokenized begin/word/finish load;
  and
- one cancellation callback.

There is no attachment-key, archive-key, private-key, plaintext-buffer,
manifest-buffer, sealed-blob, caller-randomness, SQL, or arbitrary-path
operation. The generated Swift/Kotlin code includes twelve `u64` parameters for
the 96-byte root item only in the trusted protected-store callback. The
platform adapter zeroizes its temporary buffer. No Expo module or JavaScript
bridge was added.

## Durable state and schema migration

The operation database schema is explicitly version 2. Version 1—the exact
unreleased schema from commits 4 through 6—is migrated in place by adding only
the public singleton `development_profile` table and advancing
`PRAGMA user_version`. Existing sender/outbox/receiver/replay rows are not
rewritten. An operation-shaped database with any other or absent version fails
closed instead of being guessed, dropped, or silently reset.

The public development profile holds only account UUID, device UUID, agreement
key UUID, and validity bounds. A regression inspects its SQL for `secret`,
`private`, `attachment_key`, and `archive_key`. The table is present for the
future two-device development flow but is not used by the current self-contained
operation.

## Platform integration

### Android

- App: `app.mowy.crypto.proof`, compile/target API 36, minimum API 24;
  protected-key operations require API 28.
- Physical device: Huawei COR-L29, Android 9/API 28. The hardware serial is
  intentionally omitted from this public repository.
- Rust libraries: `aarch64-linux-android` and `x86_64-linux-android`, both with
  ELF `LOAD` alignment `0x4000`.
- Generated Kotlin runtime: JNA 5.19.1 AAR, exact dependency verification;
  `libmowy_crypto_core.so` remains the only cryptographic core.
- Storage root: `noBackupFilesDir/app.mowy.prototype.p2/proof-v1` with fixed
  five child directories. Directories are mode `0700`; marker/database are
  mode `0600`.
- Backup: installed manifest source sets `allowBackup=false` and
  `fullBackupContent=false`; package inspection did not show `ALLOW_BACKUP`.
- Proof APK: debug-signed v2 APK, SHA-256
  `47c80a41e171e5bd156352621938e14afe5f6b1396f3b677cbdb39c02eff5529`,
  10,965,758 bytes. The debug certificate is proof infrastructure, not a
  release identity.

### iOS

- App: `app.mowy.prototype.p2proof`, deployment target iOS 15.1.
- Physical device: iPhone 14, iOS 26.6. The user-assigned device name,
  CoreDevice identifier, and UDID are intentionally omitted from this public
  repository.
- Rust libraries: `aarch64-apple-ios` and `aarch64-apple-ios-sim`.
- The physical executable statically includes the Rust core: `otool -L` lists
  Apple frameworks/system libraries and SQLite but no Mowy dylib.
- Signing: automatic local development signing; concrete signing, team,
  profile, application-prefix, and device identifiers are omitted from
  rewritten history.
- Storage root: Application Support
  `app.mowy.prototype.p2/proof-v1`; fixed children and files receive modes
  `0700`/`0600`, `NSFileProtectionComplete`, and backup exclusion.
- Latest measured executable SHA-256 before final documentation rebuild:
  `9758be8fbd0dfafb59dfd0a05cc07fac5c439fcfc385e168d8382b2269b067aa`,
  2,983,904 bytes.

## Physical execution results

Both apps run one warmup maximum fixture before taking the settled baseline.
The warmup prevents JNA/native runtime initialization and one-time allocator
state from being mistaken for retained per-cycle memory.

| Device | Measured cycles | Plaintext per cycle | Ciphertext per cycle | Peak growth | Final growth | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Huawei COR-L29 | 10 | 26,214,400 | 26,221,256 | 54,069,248 | 0 | pass |
| iPhone 14 | 10 | 26,214,400 | 26,221,256 | 0 | 0 | pass |

Huawei settled values: baseline 48,850,944 bytes, peak 102,920,192 bytes,
final 32,719,872 bytes. All ten cycles returned distinct proof IDs,
ciphertext digests, and archive digests. Cycle 1 used proof ID
`9ff3f931e28d60abd2749e1ecce0c69e`, ciphertext digest
`fd00d6…9800`, and archive digest `771b07…2c88`; cycle 10 used proof ID
`36b8c6daf0c90c86762720307c7784bd`, ciphertext digest `b518fe…90d1`,
and archive digest `325fb7…a1c6`. The later locked-device test intentionally
overwrote the app-private receipt, so the complete intermediate Huawei digest
list is not claimed as durable evidence.

The complete iPhone public receipt survived in disposable evidence storage:

| Cycle | Proof ID | Ciphertext SHA-256 | Archive SHA-256 | Resident bytes |
| ---: | --- | --- | --- | ---: |
| 1 | `f5d476145c97f31498ac92d2eba0f149` | `281a9bbb825ad8cfe51fc100571179a37df1123c0c0ae02e6ffd81cdedaf3b32` | `4eac5bed70d1cf69dca3d8bdf9d907686f6e3ec74de66331e2e9975de7400a2f` | 33,996,800 |
| 2 | `d5d3875bcf0ae53f4a264d4a24fbbd8b` | `abcc41e533dc98c04394083c0438f0b925b9c8aa3970b8e564f579b70bb9aee7` | `37ca893180bdf0642d8d973df8ac5012c736d74209683d9e27104af8ab219dd4` | 33,996,800 |
| 3 | `f12fcebc9c29e6145974740eb15b60b3` | `11b8b0e098a467b940c490e5c7e13286df2040cb3b6b88332dc289ea2c5d9f43` | `7e843232f6498609a68c516bc9d2ea0072300ec440bbdf04e6dcb8bf8d5b25f4` | 33,996,800 |
| 4 | `90e8fe0ba973581741d3724e64ce806d` | `be4253fa850b04a0e82f80b1c198ef64da85c9f7bc256d8694357dba9d878de2` | `bdbe4dbe0ca77a4043758186e0f8f2d02f8285bf917e989be16d47bccaa0e75f` | 33,734,656 |
| 5 | `fa7e7b6b4aa9eead893c688ea0a6f8e9` | `a808efefe11ed90fdb78ed798fade9f583f380d4a96aad5e4f864119e6b17127` | `34f269082fd9a87dc8237d0f920fd7fa247cae8dfea49b64d647599faf570e61` | 33,636,352 |
| 6 | `dc1aec5c77b5b9609a8bfddb4a5f86f2` | `20d1fdbe5429c3f206e76d2be414c6100599661a9e1ccc4b8b68998ffd9240b6` | `e803c61046bd1ec40a78aedc141806b65251d23575616279ea105f8298b70412` | 33,587,200 |
| 7 | `11f8a25d3d923b518fccc09684246189` | `836d4afeec49f47f3d7452e74a0be93d33b0675ece330b3f67640c29f3ca5f59` | `b47471c49cfc162ead9366d7e1e49ae61edcb9669c892ae3773a4640320c7dfe` | 33,587,200 |
| 8 | `732b0754280e08690a28408809f11aca` | `89b52ea901b4f6c462325a248ea8bc52e2365795baf75ab9030141c60d7192be` | `48c618d933429c6c7f12812e5c8ac607f7236328866b5c9aceafb09308f2a595` | 33,587,200 |
| 9 | `c5a5a98afdb58f373fcfa3b1ab906fd3` | `33e6a9f775fe5ffdbfaa2e6f69c0db225c32cb3610db2dab60257a74269e8361` | `855d11b9f18da67b026be401e91fd2fb1b34bbf37646a8503db14b6d70d3eb6e` | 33,587,200 |
| 10 | `30ae8056e62016ffc742deeee9761eed` | `c99560315d571163159fb0741514a800917cd7e7dfa26374a418d1599120f2cb` | `9e677bb8cdf2988a378de75a83cc7543ad7fc21b4a89e39b0743fa630196b05a` | 33,587,200 |

## Relaunch, lock, and container evidence

- Huawei force-stop/relaunch passed one maximum measured cycle with baseline
  49,770,496 bytes, peak growth 50,081,792 bytes, and final growth 0.
- iPhone terminate/relaunch passed one maximum measured cycle with baseline
  28,721,152 bytes and both peak/final growth 49,152 bytes.
- With the Huawei relocked, a fresh launch returned exactly `UNAVAILABLE` and
  `warmup_completed=false`; no proof receipt or partial success was published.
- iOS mid-operation relock has not been performed and remains open.
- Post-success Android inventory contained exactly the five empty fixed
  directories, a zero-byte marker, and a 49,152-byte database. No source,
  transport ciphertext, receive temp, verified plaintext, archive partial, or
  sealed blob remained. Modes were `0700`/`0600`.
- Post-success iPhone inventory likewise contained exactly five empty fixed
  directories, the marker, and a 48 KiB database. The device inspection tool
  did not expose protection/backup metadata; those attributes are enforced and
  host-tested in code but not claimed as physically enumerated.

## Corrections and failed approaches preserved

- The first Android ten-cycle measurement sampled its baseline before JNA and
  native runtime initialization. Crypto completed all cycles, but final growth
  was 21,535,744 bytes—564,224 bytes above the 20 MiB bound. The runner was
  corrected to perform one maximum warmup before the baseline; the repeated
  settled run passed. The failed number is retained to prevent favorable-only
  reporting.
- The first iOS project link attempted dynamic symbol lookup. It was replaced
  with an explicit static `-force_load` of the Rust archive; `otool -L` now
  proves there is no Mowy dylib dependency.
- The initial iOS Application Support creation assumed parents already existed.
  The adapter now creates only the system-owned parent chain with intermediate
  directories, then creates every protected Mowy directory individually.
- An early Android shell command quoted a path incorrectly and enumerated
  package-private names instead of the requested file. Later inspection used
  exact fixed paths only. No broad container copy was taken.
- Xcode emits an empty-supported-platform scheme diagnostic and an AppIntents
  metadata warning even though the physical release build links, signs, and
  runs. Android emits its known SDK XML/deprecation warnings. None is hidden or
  treated as a security pass.

## Validation at this checkpoint

- Rust 1.97.1 format, zero-warning clippy, and 78 tests pass.
- The explicit `cfg(fuzzing)` parser entry points compile on stable Rust.
- Four mobile release targets build at the frozen triples.
- Generated Swift/Kotlin bindings regenerate without drift.
- Four Swift protected-store tests, five Android unit tests, and Android lint
  pass; the focused platform suite passed again after the final Swift package
  exclusions.
- The complete source/signature, build-script, SBOM, Gradle verification,
  cargo-deny, and operating-system-denied-network gate passed before the fuzz
  harness was added. Commit 8 reruns and owns the final combined gate.
- Static negative inspection found no authored `Log`, `NSLog`, `os_log`,
  print, panic, TODO, or unimplemented path. The proof apps mention plaintext
  only as the public fixture length/receipt field.

## Open integration boundary

The smallest remaining implementation change is a reviewed semantic ABI that
lets one development device publish its public signed bundle, lets the other
produce only a sealed manifest plus ciphertext for an untrusted relay, and lets
the recipient import that public transport into durable state before a restart.
It must preserve every existing invariant: no raw key, opened manifest,
plaintext buffer, arbitrary path, SQL, caller randomness, or detailed crypto
oracle. Until that surface is explicitly authorized and implemented, commit 7
is a useful review point rather than completion of its original cross-device
Definition of Done.
