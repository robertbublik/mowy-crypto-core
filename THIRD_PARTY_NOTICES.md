# Third-party notices

Status: Implemented inventory for the P2 commit-1 dependency graph.

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

The transitive graph uses SPDX expressions drawn from 0BSD, Apache-2.0,
Apache-2.0 WITH LLVM-exception, LGPL-2.1-or-later, MIT, MPL-2.0, Unicode-3.0,
Unlicense, and Zlib. An expression containing alternatives does not require all
alternatives; the exact expression for each component is retained in the SBOM.

No trademark licence, warranty, security assurance, or endorsement is implied.
See each vendored package for its complete terms and notices.
