# Supply-chain evidence

Status: Implemented for the P2 Rust boundary and protected-key platform build;
refreshed at every dependency change and reviewed again at package closeout.

`Cargo.lock` is the exact version/checksum inventory and `vendor/` is the only
Cargo source. The repository configuration replaces crates.io with that tree
and sets Cargo offline. Cargo verifies each vendored crate against its generated
`.cargo-checksum.json` during every build.

The repository ignores only the root Rust output trees (`/target/` and
`/fuzz/target/`) and root proof artifacts (`/artifacts/`). The anchors are
security-relevant: an unanchored `target/` pattern once hid the upstream
`vendor/cc/src/target/` source directory from Git even though the crate
checksum manifest required it. Commit-13 closeout restored the four affected
files byte-for-byte against their existing pinned SHA-256 values and audited
all 7,693 checksum-listed vendored files. Cargo verifies bytes present in a
checkout; the final fresh-clone gate additionally proves that Git carries the
files rather than merely finding ignored local copies.

`bom.cdx.json` is the CycloneDX 1.5 machine-readable shipped/build package and
licence inventory generated with `cargo-cyclonedx 0.5.9`, all features, all
targets, and `SOURCE_DATE_EPOCH=1787097600`; dev-only packages remain in
`Cargo.lock` and the notices below. `build-scripts.txt` is the reviewed list of
vendored crates that can execute a build script. `libsodium-source.sha256`
freezes the signed archive and signature bytes bundled by the immutable
`libsodium-sys-stable 1.24.0` crate.

The generator's root `bom-ref` contains the absolute checkout directory. The
generation check normalizes that root and its target suffixes to the stable
`pkg:cargo/mowy-crypto-core@0.1.0` reference before comparison. This prevents a
developer path from becoming public evidence and makes the committed SBOM
independent of checkout location; dependency references and content are not
rewritten.

The source check also requires independent `rsign 0.6.6` verification with the
libsodium minisign public key. The historical filename `LATEST.tar.gz` is part
of the immutable crate; scripts never fetch the mutable upstream `LATEST`
endpoint.

`scripts/build-mobile.sh` binds Android to NDK 27.1.12297006 and API 24 and
builds the two Apple and two Android target triples frozen by P2. A non-rustup
host must additionally point `MOWY_CARGO_BIN`, `MOWY_RUSTC_BIN`, and
`MOWY_RUSTDOC_BIN` at the same 1.97.1 sysroot so Cargo cannot select another
installation with the same displayed version.

Development tools used for this boundary:

- Rust and Cargo 1.97.1;
- UniFFI 0.31.2 from the locked dependency graph;
- cargo-fuzz 0.13.2 with a disposable date-pinned
  `nightly-2026-08-19` driver toolchain;
- libfuzzer-sys 0.4.13, arbitrary 1.4.2, and jobserver 0.1.35 in the separate
  development-only `fuzz/Cargo.lock` and shared vendor tree;
- cargo-deny 0.20.2;
- cargo-cyclonedx 0.5.9;
- rsign 0.6.6.

The platform-adapter gate additionally pins Gradle 8.14.3, Android Gradle
Plugin 8.11.0, Kotlin 2.1.20, Android compile SDK 36, Java 17, and JUnit
4.13.2. Strict Gradle dependency verification records SHA-256 for all 312
resolved build/test components and 552 artifacts. The gate runs with
`--offline`; adding or substituting any artifact fails until the metadata is
reviewed and deliberately regenerated. These tools do not change the Rust
runtime dependency graph or its CycloneDX SBOM.

The committed SBOM has no component without a licence expression. The
human-readable shipped-source notices are in `THIRD_PARTY_NOTICES.md`.

The cargo-deny gate evaluates advisories, bans, licences, and sources against
the exact locked graph. Because Cargo replaces the registry with the vendored
tree, a local run can lack registry-index entries needed for a current yank
query. An `index-failure` warning therefore does not invalidate the four
reported policy-category results, but it also does not prove that every locked
release is currently non-yanked. A reviewer who requires that separate result
must first populate a trusted current index and record the resulting check.

The duplicate-version check denies additions except five reviewed legacy
branches forced by the exact approved graph: `hashbrown 0.16.1` from
libsodium's compression tooling, `syn 2.0.119` and `winnow 0.7.15` from UniFFI,
and `thiserror 1.0.69` plus its matching macro from `libsodium-rs`. Their newer
counterparts are required by other pinned packages; changing either side would
change an approved pin.
