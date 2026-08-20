# Commit 10 physical iOS relock and semantic recovery evidence

Status: Implemented for one controlled physical iOS relock during semantic
receiver resume. The operation failed closed before plaintext promotion,
returned no receipt while locked, recovered from the same durable opaque
operation after unlock, and cleaned the exact transport/plaintext namespaces.
The hazardous real-device disk-full/rename/kill matrix and independent human
review remain open.

- Package: P2 sealed envelope foundation
- Requirements: `M2-KEY-01`, `M2-ENVELOPE-01`, `M2-ASSURANCE-01`
- Findings exercised: `reviews/commit-7-hostile-review.md` C7-04 and
  `reviews/commit-9-hostile-review.md` C9-10
- Recorded: 2026-08-20

## Reviewable outcome

The signed development app now has one physical-fault mode around the existing
`resume_development_transfer` semantic operation. It pauses on the eighth
protected-data callback: after the complete ciphertext authenticated and
decrypted to a synced, unpromoted temporary file, but before the first
plaintext promotion. The user can then physically lock the device.

The wrapper changes only the development proof app. It delegates all protected
key operations to `MowyNativeProtectedKeyStore`, changes no Keychain item,
storage class, Rust production transition, UDL, generated binding, or product
surface, and accepts only the already-approved opaque receiver operation ID.
The normal product-independent lifecycle remains:

1. stage the exact sealed transfer unopened and receive one opaque operation
   ID plus a generated ciphertext destination;
2. resume by that operation ID;
3. authenticate and decrypt into the fixed `receive-temp` namespace;
4. recheck protected-data availability before promotion;
5. on relock, remove the exact unpromoted plaintext and return coarse
   `UNAVAILABLE` with no receipt; and
6. after unlock, retry the same operation from durable state, archive and
   verify the fixture, erase transport material, and return the stable public
   receipt.

The checkpoint is deliberately attached to semantic resume rather than the
self-contained fixture runner. Resume has a caller-retained opaque operation
ID and a durable recovery contract; a relock is therefore a normal retryable
state rather than an unaddressable half-run.

Callback eight has this meaning only for a newly staged, never-resumed
operation. An already-available operation has a different callback sequence.
The probe verdict alone is therefore not evidence: a valid run also requires
the fresh stage, the ciphertext-only prelaunch and locked inventories, the
same-operation unlock success, and the byte-identical repeated resume recorded
below.

## Locked-readable probe verdict

The app writes one development-only verdict file named
`mowy-p2-relock-result.txt` in its private temporary directory. Its mode is
`0600` and its iOS protection class is deliberately `None` so a device tool can
observe the result while all core files remain protected. The file contains
only a fixed heading, the fixed mode name, two booleans, one stable coarse core
code, receipt presence, and the final boolean verdict. It contains no device,
account, operation, conversation, asset, key, path, digest, length, plaintext,
sealed bytes, signing metadata, or arbitrary error text.

Every probe launch removes and recreates that exact verdict before starting
core work. Preparation, attribute, open, truncate, write, and sync failures are
handled as coarse evidence failures; a failed write removes the file. The
checkpoint wrapper also forces unavailable on background-task denial,
expiration, low remaining time, or the 45-second deadline. A valid consumer
must terminate the previous process and observe one fresh
`LOCK_DEVICE_NOW`-to-final transition; polling an old final string is not a
valid procedure.

This exception applies only to the coarse development verdict. The root,
database, source, ciphertext, receive temporary, verified plaintext, archive,
installation marker, and Keychain item keep their existing protection and
backup rules. The proof app still emits no system log.

## Deterministic regression

`semantic_receiver_relock_retries_by_opaque_operation_and_cleans_exactly`
uses two independent temporary roots and protected stores. It publishes two
distinct bundles, prepares and stages one transfer, copies the opaque
ciphertext to the generated receiver destination, and makes the receiver's
eighth protected-data query transition to unavailable.

The regression asserts the public façade returns exactly `Unavailable` with a
missing receipt. At that boundary it also proves:

- the transfer inbox is durably `promoted` and its staged sealed copy is gone;
- the normal receiver remains `waiting_for_ciphertext`, so no success is
  committed;
- the exact plaintext state is missing from both `receive-temp` and
  `verified`;
- no archive exists;
- the one opaque ciphertext remains available for retry; and
- the fresh receiver file inventory is exactly source 0, ciphertext 1,
  receive-temp 0, verified 0, archive 0.

After the store is unlocked, the same operation ID succeeds. A third resume is
byte-identical, then test-only exact sender and receiver cleanup leaves all
five artifact directories empty in both roots. No broad scan or caller path is
introduced.

Focused command:

```sh
cargo test semantic_receiver_relock_retries_by_opaque_operation_and_cleans_exactly --lib
```

Result: 1 passed, 0 failed, 82 filtered out.

## Physical setup and evidence boundary

The controlled run on 2026-08-20 used the signed development proof app on the
same iPhone 14 and iOS 26.6 already recorded in commit 9. It used only the
fabricated deterministic maximum fixture; no recording, product account,
service credential, or hosted payload entered the run.

The Android device was not visible to ADB during this gate. A temporary second
signed proof-app identity on the iPhone therefore supplied a separate sender
container, protected root, Keychain access group, and valid public bundle. The
existing main proof app was the receiver. This is a physical iOS relock and
two-store recovery test, not a second cross-device interoperability result.
Commit 9's iPhone-to-Huawei run remains the sole physical cross-device claim.

No bundle identifier, Keychain access group, team, signing identity,
provisioning record, user-assigned device name, device identifier, opaque
operation value, or private container path is recorded here.

## Physical execution

The sender prepared the exact 26,214,400-byte deterministic fixture. The
resulting ciphertext was 26,221,256 bytes, its host-relay digest matched the
public transfer descriptor, and the exact relay file was mode `0600`. The
receiver staged the transfer unopened and returned one opaque operation ID and
one generated destination beneath its fixed private root. The relayed
ciphertext was a regular, non-linked `0600` file and the receiver had exactly
one ciphertext file before resume.

The receiver then launched `resume-relock-probe` with only that operation ID.
When the development wrapper reached protected callback eight it published
`LOCK_DEVICE_NOW`. The maintainer physically locked the iPhone; the device
state reported passcode required. The bounded wrapper observed protected data
become unavailable and the locked-readable verdict reported:

```text
Mowy P2 relock probe: SUCCESS
mode=resume-relock-probe
checkpoint_reached=true
lock_observed=true
core_code=UNAVAILABLE
receipt_present=false
expected_fail_closed=true
```

A metadata-only inventory while the device remained locked reported:

| Fixed receiver directory | Regular files |
| --- | ---: |
| `source` | 0 |
| `ciphertext` | 1 |
| `receive-temp` | 0 |
| `verified` | 0 |
| `archive` | 0 |

There were no symlinks. The inventory did not read protected contents, export
the database, or copy the container.

After the maintainer unlocked the iPhone, ordinary `resume` with the same
opaque operation ID succeeded. The public receipt reported the expected
26,214,400 plaintext bytes and 26,221,256 ciphertext bytes. A repeated resume
returned a byte-identical receipt from durable `available` state.

The terminal receiver inventory contained exactly one regular archive file,
mode `0600`; `source`, `ciphertext`, `receive-temp`, and `verified` were empty,
and there were no symlinks. Exact sender cleanup succeeded and all five sender
artifact directories were empty. The temporary sender's exact Keychain item
was deleted through a narrowly scoped disposable build, then that temporary
app was uninstalled. The temporary cleanup mode and Security import were
removed before the reviewed source state; neither is part of this commit.

The receiver archive was retained temporarily in the main disposable proof
app as the successful terminal state while the evidence and handoff were
inspected. It was an encrypted archive of the public fixture, not plaintext or
transport material. Commit 12 records the subsequent exact removal of that
development app/container and the verified absence of the disposable output.

## Exploratory self-proof result and correction

Before using semantic resume, an exploratory wrapper paused the older
self-contained `run_development_proof` after it had created the public fixture
source and begun an `encrypting` sender row. Physical lock was observed, but
the result was coarse `STORAGE`, not `UNAVAILABLE`.

Source tracing showed that the protected-data check itself returned
unavailable. The self-proof then correctly attempted all three exact cleanup
classes. Because its database and namespaces use
`NSFileProtectionComplete`, SQLite cleanup can fail while locked; the bridge's
intentional cleanup-error precedence returned `STORAGE` rather than falsely
claiming a clean unavailable result. No production error mapping was changed
or masked.

The fixed file inventory for that exploratory run was empty after unlock. At
the lock boundary no attachment key, sealed blob, ciphertext, receive temp,
verified plaintext, archive, or receipt had been created. A disposable
`encrypting` sender metadata row and/or public signed-bundle row may remain in
the proof database because the database was not exported or broadly inspected.
Exact database cleanup is therefore not claimed for that discarded attempt.
The possible residue is public identifiers/state metadata, not playable audio
or recoverable transport key material. If self-contained mid-operation relock
ever becomes a required supported operation, it needs a durable exact-ID
cleanup journal or explicit reset design; it is not used as this gate's proof
vehicle.

This failed attempt is retained because it distinguishes honest cleanup
failure from the passing semantic retry path and prevents favorable-only
reporting.

## Post-run evidence hardening

The implementing-agent hostile review found that the coarse verdict writer
discarded file errors and that callback eight is path-dependent. The completed
physical run already met the corrected evidence preconditions: it began from a
fresh unopened stage, the live checkpoint transition was observed, and both
locked and terminal inventories were recorded. The final source additionally
clears the verdict before starting, makes every receipt failure coarse and
fail-closed, handles background-task expiry/timeout, documents the fresh-path
precondition, and asserts exact durable-row deletion in the Rust regression.

The first generic-device compile of that hardening caught a Swift optional
closure-result mismatch and failed before linking. Adding the explicit
`?? false` fail-closed default corrected it; the repeated unsigned Release
device build compiled and linked the final proof-app source successfully. The
physical lock was not repeated after this evidence-only hardening. It changes
neither the core, callback position, storage protection, semantic result, nor
the live sequence already observed. A reviewer with an exact-proof-binary rule
can require another manual run without reopening the production design.

## Complete deterministic gate

After the regression and physical run, the final `scripts/check.sh` invocation
uses the pinned Rust 1.97.1 toolchain, Android NDK 27.1.12297006, Gradle
8.14.3, cargo-cyclonedx 0.5.9, cargo-deny 0.20.2, the signed-source verifier,
and committed/vendor-only inputs. The canonical form is:

```sh
MOWY_ANDROID_NDK_HOME=/path/to/android-ndk-27.1.12297006 \
MOWY_CARGO_BIN=/path/to/rust-1.97.1/bin/cargo \
MOWY_MOBILE_CARGO_BIN=/path/to/rust-1.97.1/bin/cargo \
MOWY_RUSTC_BIN=/path/to/rust-1.97.1/bin/rustc \
MOWY_RUSTDOC_BIN=/path/to/rust-1.97.1/bin/rustdoc \
MOWY_CARGO_DENY_BIN=/path/to/cargo-deny-0.20.2 \
MOWY_CARGO_CYCLONEDX_BIN=/path/to/cargo-cyclonedx-0.5.9 \
MOWY_GRADLE_BIN=/path/to/gradle-8.14.3/bin/gradle \
scripts/check.sh
```

It passes formatting, zero-warning clippy, all 83 Rust tests, stable fuzz
target compilation, all four frozen mobile release targets, signed libsodium
source verification, build-script and generated-binding drift, exact SBOM,
four Swift tests, five Android tests and lint, cargo-deny, and the clean repeat
of all 83 tests while the operating system denies network access. The already
disclosed offline advisory-index and unused NCSA allowance warnings remain;
all cargo-deny categories report `ok`.

Three setup-only attempts are recorded before the passing invocation. The
first omitted the NDK path and stopped after 83 passing tests. The second added
the NDK but omitted the signed-source verifier path and stopped after all four
mobile builds and source hashes. The third selected the host's current Gradle
rather than the pinned 8.14.3 binary and stopped at the version assertion after
the SBOM check. Focused SBOM and platform sub-gates passed after correcting
those paths. A later test-hardening invocation correctly caught an
`assert_eq!` that required an intentionally absent comparison trait on a
durable row; replacing it with an explicit `is_none()` assertion made the
focused regression and the final end-to-end gate pass. The definitive
invocation names every pinned tool and exits zero.

## Evidence handling and remaining boundary

Only normalized counts, coarse verdict fields, public lengths, and pass/fail
results belong in durable evidence. Raw CoreDevice output, public bundles,
opaque handles, transfer serialization, copied receipts, build directories,
and the host relay are task-local artifacts and are removed after this record
and the PR checks no longer need them. The durable source checkout was always
the workspace repository, never `/private/tmp`.

This result closes C9-10 and supplies physical iOS evidence for C7-04 at this
exact implementation revision. It does not prove backup/restore, reinstall,
device transfer, every iOS version, every timing point, or a hazardous physical
disk-full/rename/kill-at-every-transition matrix. It is implementing-agent
evidence, not independent human review. It authorizes no real recording,
product integration, hosted audio, P3 work, Milestone 3 entry, or end-user
encryption claim.
