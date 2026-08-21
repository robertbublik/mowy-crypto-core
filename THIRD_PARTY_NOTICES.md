# Third-party notices

Status: Implemented inventory through the P2 protected-key slice.

The shipped/build package, version, source checksum, dependency, and SPDX
licence inventory is `supply-chain/bom.cdx.json`. The complete corresponding
source and licence files are committed under `vendor/`; `Cargo.lock` is the
authoritative inventory including development-only packages. `cargo-deny
0.20.2` must accept every licence before merge.

The direct approved dependencies are:

| Dependency | Version | Licence or notice |
| --- | --- | --- |
| `libsodium-rs` | 0.2.4 | MIT |
| `libsodium-sys-stable` | 1.24.0 | MIT OR Apache-2.0; bundles signed libsodium 1.0.22-stable source under ISC |
| `uniffi` | 0.31.2 | MPL-2.0 |
| `rusqlite` | 0.40.1 | MIT |
| `libsqlite3-sys` | 0.38.1 | MIT; bundled SQLite is dedicated to the public domain |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT |
| `proptest` | 1.11.0 | Apache-2.0 OR MIT; development only |
| `libfuzzer-sys` | 0.4.13 | `(MIT OR Apache-2.0) AND NCSA`; fuzzing only |
| `arbitrary` | 1.4.2 | Apache-2.0 OR MIT; transitive fuzzing only |
| `jobserver` | 0.1.35 | Apache-2.0 OR MIT; transitive fuzz build only |

The fuzz-only graph is frozen separately in `fuzz/Cargo.lock` because it is
not part of the shipped/build package represented by the production
CycloneDX SBOM. Its committed source shares `vendor/` and is checked offline.
The `cargo-fuzz 0.13.2` executable and nightly compiler are development tools,
not redistributed dependencies.

The transitive graph uses SPDX expressions drawn from 0BSD, Apache-2.0,
Apache-2.0 WITH LLVM-exception, LGPL-2.1-or-later, MIT, MPL-2.0, Unicode-3.0,
Unlicense, and Zlib. An expression containing alternatives does not require all
alternatives; the exact expression for each component is retained in the SBOM.

The commit-2 platform-adapter gate adds no runtime library to the mobile core.
Its build/test tools are pinned separately and are not described as shipped
Rust components:

| Build or test tool | Version | Licence or notice |
| --- | --- | --- |
| Gradle | 8.14.3 | Apache-2.0; the installed distribution carries `LICENSE` and `NOTICE` |
| Android Gradle Plugin | 8.11.0 | Apache-2.0 |
| Kotlin Gradle plugin | 2.1.20 | Apache-2.0 |
| JUnit | 4.13.2 | EPL-1.0; test only |
| Hamcrest Core | 1.3 | BSD-3-Clause; transitive test only |

`platform/android/gradle/verification-metadata.xml` freezes SHA-256 for the
complete 312-component, 552-artifact Gradle build/test resolution. Xcode,
Swift, the Apple SDK, Java, and Android SDK/NDK are platform toolchains rather
than redistributed repository dependencies.

No trademark licence, warranty, security assurance, or endorsement is implied.
See each vendored package for its complete terms and notices.
