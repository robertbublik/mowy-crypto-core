# Commit 9 cross-device semantic transfer evidence

Status: Implemented for the bounded cross-device fixture ABI, durable unopened
staging, Linux AddressSanitizer fuzzing, and one physical
iPhone-to-Huawei relay/restart journey. Physical iOS mid-operation relock, the
hazardous real-device disk-full/rename matrix, and independent human review
remain open.

- Package: P2 sealed envelope foundation
- Requirements: `M2-DELIVER-01`, `M2-KEY-01`, `M2-ENVELOPE-01`,
  `M2-ASSURANCE-01`
- Finding resolved: `reviews/commit-7-hostile-review.md` C7-01
- Boundary contract: `reviews/c7-01-semantic-contract.md`
- Recorded: 2026-08-19

## Reviewable outcome

The generated UniFFI surface now proves the package's required development
journey without becoming a general cryptographic API:

1. receiver B initializes its protected root and publishes a signed public
   bundle;
2. sender A validates and pins B, creates only the bounded deterministic public
   fixture, encrypts it, seals the manifest to B, and commits a sender outbox;
3. an untrusted relay carries the public/opaque transfer record and ciphertext;
4. B validates and pins A, verifies public encodings and its exact recipient
   selector, and durably stages the exact sealed bytes without opening them;
5. B terminates and restarts;
6. B resumes using only its opaque receiver operation ID, reloads all other
   input from durable native state, authenticates and opens the manifest,
   verifies and decrypts the ciphertext, archives and verifies the fixture,
   and erases transport state; and
7. A removes only the exact disposable sender row and generated fixture files.

The host integration test executes the same journey with two distinct
protected roots and two independent SQLite/file namespaces. The physical run
uses the signed iOS proof app as A and the Android proof app as B. The
reciprocal direction is covered by the same two-store semantic contract and is
not another product operation.

## Semantic ABI

The public/opaque records are:

- `MowyPublicBundle`: lowercase-hex public account/device/key identifiers,
  Ed25519/X25519 public keys, validity bounds, and signature;
- `MowyDevelopmentTransfer`: public operation/context identifiers, recipient
  key selector, exact 408-byte sealed blob encoded as 816 lowercase hex
  characters, public lengths, and ciphertext SHA-256;
- prepared/staged result records containing the transfer or opaque operation
  ID and one exact generated app-private path; and
- the existing public receipt and stable coarse result code.

The five operations are `publish_development_bundle`,
`prepare_development_transfer`, `stage_development_transfer`,
`resume_development_transfer`, and `cleanup_development_sender`. There is no
public receiver cleanup. Receiver archive availability is the successful
terminal proof state.

The UDL exposes no key, nonce, caller randomness, opened manifest, plaintext
array, arbitrary input/output path, SQL, namespace reset, generic parser,
generic encrypt/decrypt/seal/open operation, or JavaScript registration.
Twelve fixed-width words remain the trusted protected-store callback's private
root transport and never enter a semantic result.

The Swift/Kotlin proof apps use a `|`-delimited representation only to carry
public fields through development arguments and app-private result files.
UniFFI records remain the actual ABI; the proof text is explicitly not a
product or service wire format.

## Durable state and retry behavior

Schema version 3 adds strict table `development_transfer_inbox`:

- state 1 (`staged`) owns the exact unopened sealed blob and public
  sender/context/descriptor fields;
- exact duplicate stage is idempotent, including a later caller time; a
  conflicting operation or tuple fails closed;
- promotion creates/reuses the normal receiver row and replay ledger in one
  SQLite transaction, moves the inbox to state 2, and clears its sealed bytes;
- the normal receiver row clears its own sealed bytes only when `available`
  commits after archive verification; and
- the promoted inbox retains only public fields needed to recover the pinned
  sender and stable receipt after relaunch.

`resume_development_transfer` accepts only the receiver operation ID. A staged
tampered sealed blob is deliberately accepted as opaque durable input, remains
staged across repository reopen, and fails authentication only on resume. It
cannot create a normal receiver row before a successful open.

Sender cleanup first verifies the exact durable outbox/operation/asset tuple,
then removes the fixed generated source and ciphertext files, then deletes the
sender row. A database-delete failure therefore leaves authorization for an
idempotent retry rather than leaving unowned generated files. Receiver cleanup
exists only under Rust test configuration so the physical success state keeps
its archive.

## Focused deterministic tests

`cargo test --lib` passes all 82 tests. New load-bearing cases include:

- `cross_device_transfer_stages_before_open_survives_relaunch_and_cleans_exactly`:
  two distinct protected stores and roots, bundle exchange, 25 MiB prepare,
  exact duplicate stage at a later time, proof that no receiver table exists
  before relay/open, repository reopen, resume, repeat resume from durable
  `available`, and exact sender/receiver test cleanup;
- `staged_transfer_is_not_opened_until_resume_and_tamper_remains_durable`:
  hostile sealed bytes stage successfully as opaque input, survive reopen,
  fail on resume, and never produce a normal receiver row;
- schema v1/v2 migration to strict v3, stage/promotion rollback, conflicting
  duplicate rejection, post-promotion sealed-null assertions, and resumable
  public-field reconstruction; and
- existing wrong-recipient, sender substitution, context/asset mismatch,
  replay, malformed/truncated/oversized input, cancellation, fault injection,
  archive recovery, and erasure cases.

The test names prove only their named in-process states. Physical behavior is
reported separately below.

## Complete deterministic gate

The final `scripts/check.sh` run after the semantic implementation exited 0 on
2026-08-19. It used stable Rust 1.97.1 for production/host/mobile artifacts,
Android NDK 27.1.12297006, Gradle 8.14.3, Xcode 26.3, cargo-deny 0.20.2,
cargo-cyclonedx 0.5.9, and the repository's locked/vendor-only inputs. It
passed:

- format and zero-warning clippy for every target and feature;
- all 82 Rust tests;
- stable compilation of both production-source fuzz targets under
  `cfg(fuzzing)`;
- release builds for `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
  `aarch64-linux-android`, and `x86_64-linux-android`, plus the two additional
  Android ABIs required by the repository gate;
- generated Swift/Kotlin/header regeneration and byte-for-byte drift checks;
- four Swift protected-store tests, five Android protected-store tests,
  Android lint, Android proof-app assembly, and a signed/linkable iOS device
  proof build;
- vendored-source, signed libsodium archive, native build-script,
  configuration/lock, SBOM, licence, advisory, ban, and source checks; and
- a clean rebuild and repeat of all 82 tests while the operating system denied
  network access.

The offline advisory index still emits the previously disclosed missing-index
and separately used NCSA warnings; every cargo-deny category reports `ok`.

Two non-final build attempts are retained as troubleshooting evidence. The
Homebrew host Cargo did not have the four pinned cross targets, so the final
gate used the explicitly pinned rustup Cargo/rustc. The first signed Xcode
destination used a CoreDevice identifier where Xcode required its own device
identifier namespace; selecting the same authorized device through Xcode's
identifier made the signed build pass. No signing identity, team, profile,
device identifier, or user name is recorded here.

## Linux AddressSanitizer fuzz evidence

The Apple linker limitation recorded in `evidence/commit-8.md` remains a true
Apple-host result, but no longer leaves sanitizer execution open. Both exact
fuzz targets passed under Linux AddressSanitizer with:

- official image
  `rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`
  (`rust:1.97.1-bookworm`);
- aarch64 Linux container on the Apple Silicon host;
- `nightly-2026-08-19-aarch64-unknown-linux-gnu`;
- rustc `1.100.0-nightly (e71c0f1e3 2026-08-18)`, LLVM 23.1.0;
- cargo-fuzz 0.13.2 and libfuzzer-sys 0.4.13; and
- the repository mounted read-only, with build targets and evolving corpus
  copies confined to disposable container/temp paths.

The standardized repository script ran with `MOWY_FUZZ_RUNS=10000` and
`MOWY_FUZZ_SANITIZER=address`:

| Target | Runs | Maximum input | End coverage/features | Peak RSS | Crash/artifact |
| --- | ---: | ---: | ---: | ---: | --- |
| `sealed_manifest` | 10,000 | 1,024 | 222 / 255 | 39 MiB | none |
| `attachment_envelope` | 10,000 | 4,096 | 60 / 132 | 40 MiB | none |

The coverage counts are run-specific. This is a bounded sanitizer run, not a
proof of memory safety, parser correctness, or absence of vulnerabilities.
The production dependency graph and compiler pin did not change.

## Signed native application builds

After the final source and generated binding changes:

- the Android proof app assembled and was installed on the connected Huawei;
- the iOS proof app compiled, linked the current static core, signed with the
  already-present Apple Development identity, and was installed on the
  connected iPhone; and
- neither app exposes a JavaScript bridge or writes result data to system logs.

Personal signing metadata and device identifiers are intentionally excluded.

## Physical iPhone-to-Huawei relay and restart

The bounded physical run on 2026-08-19 used a fabricated deterministic 25 MiB
fixture and no real recording:

1. both signed proof apps loaded their existing protected roots and returned
   valid signed public bundles;
2. the iPhone prepared a transfer to the Huawei, durably committed its sender
   state, and produced a 26,221,256-byte opaque ciphertext for 26,214,400
   plaintext fixture bytes;
3. the disposable host relay's SHA-256 matched the public transfer descriptor:
   `ff7acda1371f1ce9b6c3c3c46fbb77a37545bbfaf49f3080b7bcc81a7567b432`;
4. the Huawei staged the public record and exact sealed blob, returned an
   opaque receiver operation ID and generated private destination, and had no
   normal receiver open in the audited host-equivalent contract at this point;
5. the relay placed only the opaque ciphertext at that exact destination with
   mode `0600`;
6. the Huawei proof process was force-stopped after staging and restarted;
7. resume received only the opaque operation ID, authenticated/decrypted the
   full fixture, committed its archive, erased transport files/state, and
   returned the expected public lengths/digest plus archive SHA-256
   `0eca1eb0595f8b13aad7f60c7c23a02e7a843de907ee565f11c8273dc5482ee0`;
8. a second force-stop/restart and resume returned a byte-identical public
   receipt from durable `available` state; and
9. exact sender cleanup succeeded on the iPhone.

Scoped post-success inspection found only the archive, installation marker,
and operation database in the Huawei proof namespace. There was no source,
ciphertext, receive-temp, or verified plaintext file. Metadata-only inspection
reported zero files in both the iPhone proof source and ciphertext directories.

The physical Android image has no SQLite shell. Exporting the full private
database solely to inspect it was consciously rejected because its earlier
staged state contained sealed material. Post-success sealed-null assertions
therefore come from the exact production repository's SQL tests, not a broad
device database copy. No container archive, device log, private bundle, key,
plaintext, signing identity, device identifier, or unrelated file inventory
was retained.

After recording the bounded results, the exact host relay, three copied iOS
public receipt files, Android `/data/local/tmp` relay, disposable sanitizer
container, and task-only Rust container image were permanently removed. They
are reproducible from the committed source and proof apps but are not retained
or recoverable locally.

## Operational corrections during the physical proof

The first Android stage launch let the host shell strip quoting around the
proof-only `|` serialization, so the remote shell treated public fields as
commands. It did not reach the app or mutate stage state. Wrapping the complete
remote command preserved the fixed public argument. The next corrected intent
was delivered to an already-running top activity, whose development runner
only reads launch extras on process creation; the public receipt correctly
remained `publish`. Force-stopping the proof app and relaunching produced the
successful stage and also kept the proof sequence explicit.

Two proposed negative inspections were rejected before data left either
device: exporting the full Huawei database and attempting to copy supposedly
deleted iPhone ciphertext. Both were replaced with narrower on-device or
metadata-only checks. These are evidence-handling protections, not core
failures.

## ABI and privacy inspection

- The UDL and generated bindings contain the five fixed lifecycle operations
  and their public/opaque records only.
- No source path is accepted by the receiver; both returned paths are derived
  under a canonical non-linked fixed root after the owning durable transition.
- Authored Rust/Swift/Kotlin source contains no application log statement,
  print, panic, TODO, unimplemented path, key serialization, or plaintext
  receipt field.
- Stable coarse errors are preserved; optional records are absent on failure.
- The proof profile and fixture are development-only and cannot accept a real
  recording path or plaintext buffer.
- The source, ABI, schema, tests, device steps, hashes, and review belong in
  this public repository. Product requirement status, gate decisions,
  residual-risk acceptance, and implementation handoff belong in the private
  Mowy repository.

## Remaining assurance and product boundaries

1. Physical iOS mid-operation relock has not been timed and observed in this
   signed cross-device app. Host/platform callbacks and Android locked-device
   behavior fail closed, but those are not the missing physical iOS result.
2. Deterministic host fault injection covers short read/write, disk full,
   cancellation, rename/promotion boundaries, rollback, relaunch, and orphan
   cleanup. A hazardous real-device disk-full/rename/kill-at-every-transition
   matrix was not performed on the user's phones.
3. The implementing-agent hostile review is not independent human review.
4. P3 must bind disposable device keys to authenticated accounts, show human
   verification, and handle replacement/change; service substitution remains
   the dominant residual design risk until then.

These items do not reopen C7-01: the accepted bounded semantic ABI and required
physical relay/restart journey now exist. They remain explicit completion or
review inputs. No real recording, external tester, hosted audio, P3 work,
Milestone 3 entry, or public end-to-end-encryption claim is authorized by this
evidence.
