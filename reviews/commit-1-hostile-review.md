# Commit 1 hostile review

Status: Implemented agent review; not independent cryptographic assurance.

- Scope: P2 commit-1 build boundary, dependency graph, generated façade,
  source-integrity controls, and validation scripts
- Reviewed: 2026-08-19
- Reviewer: implementing agent in a separate hostile pass
- Independent-review status: open; this review cannot authorize real data

## Findings

| ID | Severity | Precondition | Execution path | Impact | Remediation | Required regression | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1-01 | High | UniFFI UDL scaffolding is compiled under the crate-wide unsafe lint | Generated `no_mangle` exports fail the deny lint, encouraging removal of the lint for the whole crate | Later authored unsafe code could enter the cryptographic core without an explicit exception | Isolate generated scaffolding in one `#[allow(unsafe_code)]` module and re-export only UniFFI's tag; retain deny for the crate | All-target Clippy plus inspection showing no authored unsafe block | Resolved |
| C1-02 | Medium | Two Rust 1.97.1 installations exist and only the rustup sysroot contains mobile standard libraries | Cargo invokes the Homebrew `rustc` by name while the command appears version-correct | Mobile evidence can fail or accidentally use a different sysroot than the frozen targets | Support explicit Cargo/rustc/rustdoc paths in the four-target script and record the selected sysroot | All four release targets build from the one rustup sysroot | Resolved |
| C1-03 | Medium | A dependency changes transitively while the direct pins remain unchanged | A shallow SBOM check sees the direct versions and misses stale transitive components | Published dependency/licence evidence can disagree with the binary graph | Recreate the complete SBOM with fixed time and require a byte-for-byte diff | `scripts/check-sbom.sh` regenerates 131 components identically | Resolved |
| C1-04 | Medium | A broad duplicate-version warning or allow rule is accepted | Future dependency changes add another version without failing the gate | Review and attack surface grow silently | Deny duplicate versions and skip only five exact, documented legacy branches forced by approved pins | `cargo-deny check bans` completes without warning | Resolved |
| C1-05 | High | The upstream `libsodium-sys-stable` build script contains a network retrieval path and the bundled archive is absent or changed | Build script attempts to retrieve a mutable upstream filename | A nominally pinned build could consume unreviewed cryptographic source | Commit Cargo-verified vendor bytes, independently verify both signature layers, force Cargo offline, and run a clean build with OS networking denied | Hash/signature check plus `scripts/check-network-denied.sh` | Resolved for this graph |
| C1-06 | Low | The binding-generator feature is enabled in a product build | UniFFI CLI dependencies are compiled unnecessarily | Larger build and review surface, though no secret API exists | Keep the generator behind a non-default feature and build mobile libraries with defaults | Default iOS normal graph excludes `uniffi_bindgen`, `ureq`, `zip`, and `proptest` | Resolved |
| C1-07 | Low | Linux CI lacks permission for `unshare --net` | The portable denied-network script cannot create a network namespace | Linux cannot reproduce this one gate without runner configuration | Fail rather than downgrade; macOS denial evidence is recorded, and Linux runners must grant namespace capability or supply an equivalent container boundary | Unsupported or denied namespace exits non-zero | Accepted portability limit |
| C1-08 | Medium | `cargo-cyclonedx` records the absolute checkout path as the root component reference | The committed SBOM publishes a developer path and differs across workspaces | Local identity leaks and independent byte-for-byte reproduction fails | Normalize only the root package reference and its target suffixes to the stable Cargo PURL during generation | SBOM regeneration is byte-identical and contains no local absolute path | Resolved |

## Negative inspection

- The UDL contains one parameterless public-profile function only.
- No prohibited MLS, AWS-LC, OpenSSL, or SQLCipher package appears in
  `Cargo.lock`.
- No authored `unwrap`, `expect`, panic, `todo`, `unimplemented`, or `dbg`
  invocation appears under `src/`, `build.rs`, `tools/`, or `scripts/`.
- No production identifier, credential, private key, meaningful recording, or
  application/service configuration is present outside third-party vendor
  source.

No open finding weakens the commit-1 acceptance boundary. C1-07 is an honest
reproduction limitation, not a bypass: the check fails when denial cannot be
established.
