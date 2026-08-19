# Mowy crypto core

Status: P2 implementation active; the pinned build boundary is implemented and
the protected device-key slice is under review. No secret-bearing bridge
operation exists yet.

This repository is the planned public, permissively licensed native
cryptographic core for Mowy Package P2. It will contain the byte-exact sealed
manifest, streaming attachment envelope, device-key operations, durable native
state, public disposable vectors, generated UniFFI bindings, and their tests.
The private application repository owns product UI, account and service
configuration, hosted delivery, and real user data.

The governing design is maintained in the private application repository. The
repository is public, private vulnerability reporting is enabled, and the
throwaway physical-device feasibility spike passed on 2026-08-19. Complete
public format documentation, vectors, dependency evidence, licences, notices,
and exact application revision linkage remain P2 closeout requirements.

## Security boundary

The core keeps private keys, attachment keys, archive keys, opened manifests,
and plaintext byte buffers behind a narrow native API. Rust key generation and
the platform protected-storage adapters now exist, but they are not connected
to an application bridge and have not been independently reviewed. This
repository currently makes no confidentiality, interoperability, audit, or
production-readiness claim.

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

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
