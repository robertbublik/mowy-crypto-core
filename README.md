# Mowy crypto core

Status: P2 implementation active. Commits 1 through 6 are implemented on the
package branch. The signed Android/iOS development proof, semantic UniFFI
façade, parser fuzz harness, and physical evidence are prepared for commits 7
and 8, but the required two-device relay surface remains open. This repository
is not independently reviewed or production-ready.

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

## Security boundary

The core keeps private keys, attachment keys, archive keys, opened manifests,
and plaintext byte buffers behind a narrow native API. The current development
façade runs one deterministic, self-contained native proof and returns only a
coarse code plus public lengths and digests. Twelve fixed-width words carry the
96-byte root item only across the trusted Rust-to-Swift/Kotlin protected-store
callback; no JavaScript, product API, log, receipt, or persisted SQLite row
receives them.

That proof is not the package's required interoperability result. It currently
publishes, pins, seals, opens, decrypts, archives, and cleans up on one device.
The approved device-B-publication/device-A-send/device-B-receive relay needs an
additional narrowly reviewed semantic ABI. Until that gap is resolved, the P2
package must not be marked completed or merged as a finished foundation.

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

## Repository and temporary paths

All durable source, generated bindings, vectors, reviews, and evidence live in
this checkout. `/private/tmp` was used only for disposable Rust toolchains,
Cargo tools, derived build products, mutable fuzz corpora, and copies of public
proof receipts. It kept host-global tooling and generated artifacts out of the
repository and never served as the source checkout. The durable repository path
used for this work is the normal workspace checkout named
`mowy-crypto-core/`, outside `/private/tmp`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
