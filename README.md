# Mowy crypto core

Status: P2 closeout candidate after implementation through rewritten commit
12. The package branch includes the bounded cross-device semantic façade,
durable unopened receiver staging, a successful iPhone-to-Huawei
relay/restart proof, Linux AddressSanitizer fuzz evidence, and a controlled
physical iOS relock with durable semantic recovery. The hazardous personal-
device fault cases now have a reviewed not-run safety disposition, with the
unproved platform behavior retained below. A maintainer-authorized history
rewrite has been prepared locally, but the public branch updates, GitHub-owned
pull-request/cache dereference, fresh-clone validation, and final remote
evidence are not complete. Independent human review remains open. P2 is not
yet final or production-ready.

After the commit-10 physical evidence was inspected, the exact development
proof app and its private container were removed from the iPhone and absence
was verified by an exact bundle query. Under iOS uninstall semantics and the
app's reviewed private-container-only storage layout, that final
disposable-run cleanup removed the retained encrypted receiver archive and
proof database without targeting the product app or unrelated user data. See
`evidence/commit-12.md`.

The commit-13 closeout candidate also restores four checksum-pinned upstream
`cc` source files that an unanchored build-output ignore had omitted from clean
clones. It records that reproducibility repair, the exact rewritten commit map,
history-remediation boundary, fault-evidence limits, and retained review work
in `evidence/commit-13.md` and `reviews/commit-13-hostile-review.md`. It must not
be read as final history erasure or final P2 status while its named remote
steps remain pending.

This public, permissively licensed repository owns the native implementation
mechanics for Mowy Package P2: byte-exact signed key bundles and sealed
manifests, the streaming attachment envelope, protected device-key adapters,
durable operation state, private file and archive lifecycles, public disposable
vectors, generated UniFFI bindings, proof apps, fuzz targets, hostile reviews,
and reproducible build/device evidence.
The private application repository owns product UI, account and service
configuration, hosted delivery, and real user data.

The private application repository owns the approved product requirements,
milestone/package status, architecture and decision authority, requirement
traceability, governance gates, residual-risk acceptance, and the handoff to
later product integration. Low-level implementation truth is deliberately kept
here so a reviewer can reproduce it without access to service credentials or
product data.

## Closeout fault disposition

The connected iPhone and Huawei are personal devices. P2 therefore did not
fill either device to a real `ENOSPC` condition, race a real platform rename,
or kill the process at every file-sync, rename, SQLite-commit, and cleanup
boundary. Those cases are recorded as **not run — accepted for personal-device
safety**, not as passing physical evidence. Repeating them requires a
factory-reset disposable device or isolated, revertible emulator/simulator
environment with no account or user data.

Current host coverage is narrower than an exact storage-fault matrix. It
includes a deterministic short/disk-full writer at the envelope layer,
destination-conflict and reconstructed rename/relaunch states, SQLite
trigger-abort rollback tests, exact cleanup tests, and bounded child-state or
physical relaunch cases. It does not inject actual filesystem exhaustion,
file/directory-sync failure, direct failure of each production rename, SQLite
commit-time I/O failure, or process death around every transition. The earlier
wording that called these exact production host adapters is corrected by the
commit-13 evidence; it is not converted into a pass.

Actual APFS/Android-filesystem low-storage and rename timing, mobile
Keychain/Keystore and companion-file fault behavior, Android 12 through 14
secure-lock and biometric/profile behavior, and the full per-transition kill
matrix remain P8 and independent-review inputs before real recordings or a
product encryption claim.

## Security boundary

The core keeps private keys, attachment keys, archive keys, opened manifests,
and plaintext byte buffers behind a narrow native API. The development façade
can run the original self-contained fixture proof or five fixed lifecycle
operations: publish a public bundle, prepare the one bounded public fixture,
stage its opaque transfer, resume by an opaque operation ID, and clean the
exact sender artifacts. It returns only coarse codes, public descriptors,
opaque sealed bytes, exact generated app-private paths after durable commits,
and public lengths/digests. It accepts no arbitrary path, key, nonce,
randomness, SQL, or general cryptographic operation.

Twelve fixed-width words carry the 96-byte root item only across the trusted
Rust-to-Swift/Kotlin protected-store callback; no JavaScript, product API, log,
receipt, or persisted SQLite row receives them. The receiver stages the exact
sealed blob unopened, survives process termination, and reconstructs every
input except the opaque receiver operation ID from durable native state. See
`reviews/c7-01-semantic-contract.md` and `evidence/commit-9.md`.

Even after P2 implementation, this core alone will not provide:

- account or device identity verification;
- product conversation authorization or ciphertext delivery;
- groups, multiple active devices, key escrow, or replacement-device recovery;
- forward secrecy beyond the approved rotating sealed-key model;
- post-compromise security, metadata hiding, or traffic-analysis resistance;
- permission to protect real recordings or make an end-to-end-encryption
  claim before independent review of the finished integration.

Only fabricated identities and disposable public fixtures belong here. Never
commit production identifiers, service configuration, credentials, private
keys, tokens, or meaningful recordings.

## Reporting vulnerabilities

Please follow [SECURITY.md](SECURITY.md). Do not disclose a suspected
vulnerability in a public issue.

## Build and validation

Rust 1.97.1 and Android NDK 27.1.12297006 are required. Cargo is configured to
use only the committed `vendor/` tree and to remain offline.

```sh
scripts/check.sh
```

The gate formats, lints, tests, cross-builds all four mobile targets, compiles
the Keychain and Keystore adapters, regenerates both bindings, verifies the
signed libsodium source and SBOM/build-script inventories, checks
advisories/licences/sources with cargo-deny 0.20.2, and performs a clean build
while the operating system denies network access. See
`supply-chain/README.md` and `platform/README.md` for tool and environment
details.

The development-only parser fuzz targets have their own exact lockfile and
corpus:

```sh
MOWY_CARGO_FUZZ_BIN=/path/to/cargo-fuzz scripts/check-fuzz.sh
```

See `fuzz/README.md` for the date-pinned nightly driver, bounds, current Apple
AddressSanitizer linker limitation, and the distinction between a passing
coverage-guided run and sanitizer evidence.

## History-remediation boundary

The sanitized history is currently a local candidate. Repository-controlled
remediation is limited to force-updating the public core's `main`,
`package/026-p2-sealed-envelope-foundation`, and
`package/026-p2-sealed-envelope-foundation-implementation` branches after the
candidate gate passes. Public-core PR #1 and the closed draft PR #2 reference
changed history; their GitHub-owned references and cached views cannot be
removed by a branch push and still require GitHub Support. Private application
PR #7 is not being history-rewritten; only its body and documentation must be
updated to the replacement hashes.

The remote inventory found no forks, releases, Actions artifacts, or Actions
caches. That does not prove absence from independent clones or GitHub's
pull-request/object caches. Old object IDs and any signatures, attestations,
checks, or links bound to them do not transfer to the rewritten commits. See
`evidence/commit-13.md` for the exact map and pending completion checks.

## Repository and temporary paths

The commit-1-through-12 implementation used the durable normal workspace
checkout named `mowy-crypto-core/`, outside `/private/tmp`. Its temporary paths
held only disposable toolchains, tools, derived products, mutable fuzz corpora,
and copies of public proof receipts. The authorized commit-13 history rewrite
is deliberately different: it uses an isolated disposable checkout under
`/private/tmp` so destructive graph reconstruction cannot mutate the durable
workspace checkout. That isolated checkout is a local remediation candidate,
not the durable or remote source of truth, and must be removed after the
rewritten remote and fresh clone are validated.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
