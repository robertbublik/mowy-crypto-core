# Commit 8 cross-platform assurance evidence

Status: Implemented for bounded parser fuzzing, repeated physical memory,
negative inspection, and separate fuzz supply-chain review. AddressSanitizer,
the full physical crash/fault matrix, iOS mid-operation lock, and the true
cross-device relay remain open; this is not independent assurance.

- Package: P2 sealed envelope foundation
- Requirements: `M2-DELIVER-01`, `M2-KEY-01`, `M2-ENVELOPE-01`,
  `M2-ASSURANCE-01`
- Integration evidence: `evidence/commit-7.md`
- Recorded: 2026-08-19

## Fuzz boundary

The repository now contains two cargo-fuzz 0.13.2 targets and four auditable
text seeds:

- sealed-manifest valid-inner mutation seed and hostile outer-length seed;
- attachment-envelope exact public-vector hex seed and truncated header seed.

The rlib-only fuzz support crate compiles the production
`attachment_manifest.rs`, `attachment_envelope.rs`, `key_material.rs`,
`key_bundle.rs`, and `sealed_manifest.rs` files in place. It contains no copied
parser. Keeping it separate avoids applying coverage/sanitizer flags to the
production crate's mobile `staticlib` and `cdylib` outputs.

The sealed target always exercises the exact 408-byte outer parser. A
`mutate:` input builds the exact public-vector signed inner using fixed
disposable seeds and then applies three-byte offset/XOR mutations before the
production authenticated-inner validator. This gives the fuzzer a valid path
through domain, embedded identity, signature, recipient, manifest, and
identifier checks without adding caller signatures or a production parser API.

The envelope target parses arbitrary headers. When a header and length are
canonical, it computes the input digest, builds a disposable manifest for the
fixed public IDs/key, and executes the production two-pass digest and
secretstream authentication path into `std::io::sink()`. A `hex:` prefix makes
the exact binary public vector mutation-friendly while remaining readable in
Git.

Neither target returns keys, opened manifests, plaintext, paths, or detailed
error information. Cargo supplies `cfg(fuzzing)` only for these targets; normal
host/mobile artifacts contain no fuzz entry point.

## Exact fuzz runs

Tooling:

- cargo-fuzz 0.13.2;
- libfuzzer-sys 0.4.13;
- temporary `nightly-2026-08-19-aarch64-apple-darwin`;
- rustc `1.100.0-nightly (e71c0f1e3 2026-08-18)`;
- Apple Silicon host;
- each run used a uniquely named copy of the committed corpus and deleted that
  copy on exit.

The standardized command was:

```sh
MOWY_CARGO_FUZZ_BIN=/private/tmp/mowy-p2-cargo-fuzz/bin/cargo-fuzz \
MOWY_FUZZ_RUNS=10000 \
MOWY_FUZZ_SANITIZER=none \
scripts/check-fuzz.sh
```

Results:

| Target | Runs | Maximum input | End coverage/features | Peak RSS | Crash/artifact |
| --- | ---: | ---: | ---: | ---: | --- |
| `sealed_manifest` | 10,000 | 1,024 | 51 / 62 | 25 MiB | none |
| `attachment_envelope` | 10,000 | 4,096 | 35 / 83 | 26 MiB | none |

LibFuzzer completed both bounded runs with exit 0. `fuzz/artifacts` contained no
failure input. The exact coverage counts are run-specific evidence, not a
coverage guarantee.

## AddressSanitizer limitation

The initial cargo-fuzz attempt correctly failed on stable Rust 1.97.1 because
`-Zsanitizer=address` is nightly-only. A temporary date-pinned nightly was then
installed under `/private/tmp`, leaving the stable production pin and normal
rustup installation unchanged.

With the pinned nightly, the default ASan build compiled every Rust/C/C++
object but Apple's final linker rejected initializer metadata from the pinned
`ctor 0.9.1` and `libsodium-rs 0.2.4` archives: `initializer pointer has no
target`. Moving the exact production parser files into an rlib-only support
crate correctly removed the unrelated mobile `cdylib` link, but the final fuzz
binary still hit the constructor error. Retrying with dead-code stripping
disabled also failed.

The passing runs therefore use coverage-guided libFuzzer with sanitizer
`none`. Missing sanitizer coverage is an open assurance item. It must not be
described as ASan, and production dependency pins must not change merely to
make the development tool link. The preferred closeout is the same locked
source/corpus under compatible Linux ASan in the independent-review environment.

## Separate fuzz dependency graph

`fuzz/Cargo.toml` pins `libfuzzer-sys =0.4.13`; `fuzz/Cargo.lock` freezes the
77-package graph. The only vendor directories newly required beyond the main
lock are:

- `arbitrary 1.4.2`, checksum
  `c3d036a3c4ab069c7b410a2ce876bd74808d2d0888a82667669f8e783a898bf1`;
- `jobserver 0.1.35`, checksum
  `1c00acbd29eabad4a2392fa0e921c874934dbbf4194312ad20f04a0ed67a3cb3`;
- `libfuzzer-sys 0.4.13`, checksum
  `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`.

An early minimal-manifest `cargo vendor` invocation exposed that Cargo treats
its destination as an exact mirror: it removed 7,099 tracked files belonging
to unrelated already-vendored packages. No commit was made. The tracked vendor
tree was restored exactly from `HEAD`, leaving only the three intended new
directories. This failure and correction are recorded so later maintainers do
not repeat the destructive invocation; a future refresh must sync both locks or
vendor to a disposable directory first.

`cargo-deny 0.20.2 --manifest-path fuzz/Cargo.toml --frozen` reports
`advisories ok, bans ok, licenses ok, sources ok`. The offline advisory check
warns that cached index entries for the two newly resolved crates are absent,
so it cannot prove yanked status; exact crate checksums/source are present and
the warning is not hidden. The NCSA component of libFuzzer's
`(MIT OR Apache-2.0) AND NCSA` expression is explicitly allowed and recorded in
`THIRD_PARTY_NOTICES.md`.

## Physical repetition and memory

The proof apps run exactly one unmeasured 25 MiB warmup followed by ten measured
25 MiB cycles. Both devices complete every encrypt, sealed-manifest open,
decrypt, archive verification, relaunch-path open, and proof cleanup. Each
ciphertext length is the canonical 26,221,256 bytes. Full values and the
unsettled Android correction are in `evidence/commit-7.md`.

- Huawei: 54,069,248-byte peak growth and zero final growth from settled
  baseline.
- iPhone: zero peak/final growth from settled baseline.
- Huawei and iPhone one-cycle force-stop/terminate relaunches pass.
- Huawei locked launch fails before warmup with coarse unavailable.
- iOS mid-operation relock is not proven.

## Negative inspection

- Authored Rust/Swift/Kotlin source has no application log statement, print,
  panic, TODO, or unimplemented path. The proof receipt is written only to an
  app-private public-evidence file.
- The UDL contains the public fixture length and public receipt length, but no
  key/secret/manifest/plaintext byte sequence.
- iOS linkage is static; Android Mowy ELF segments are 16 KiB aligned.
- Android disables backup in its manifest and stores proof state under
  `noBackupFilesDir`; iOS applies complete file protection and backup exclusion
  in the adapter. Device tools proved exact post-success contents but not the
  iOS metadata attributes.
- Post-success namespaces contain no transport or plaintext file. SQLite tests
  and schema scans reject secret-bearing fields. No broad container archive or
  device log dump is retained.

## Combined deterministic gate

The final `scripts/check.sh` run exited 0 on 2026-08-19. It used the pinned
Rust 1.97.1 host compiler, the separately pinned temporary mobile Cargo,
Gradle 8.14.3, Android NDK 27.1.12297006, cargo-cyclonedx 0.5.9, cargo-deny
0.20.2, and the checked-in/vendor-only dependency inputs. It passed:

- stable format, clippy with warnings denied, and all 78 Rust tests;
- stable compilation of both fuzz targets under `cfg(fuzzing)`;
- release builds for Android arm64-v8a, x86_64, armeabi-v7a, and i686;
- vendored-source, libsodium archive/signature, native build-script,
  generated-binding, lock/configuration, and SBOM consistency checks;
- all four Swift protected-storage tests;
- all five Android protected-storage tests and Android lint;
- cargo-deny (`advisories ok, bans ok, licenses ok, sources ok`), with the
  already-disclosed offline-index warnings and an expected warning that NCSA
  is used only by the separately checked fuzz graph; and
- a clean rebuild and repeat of all 78 tests while network access was denied by
  the operating system.

Two failed preparation runs are preserved as part of the result. The first
used the Homebrew host Cargo for mobile targets, whose matching compiler did
not have the cross-compilation targets; the gate now keeps host and mobile
Cargo pins explicit. The next reached the native-build inventory check and
correctly rejected the newly introduced `libfuzzer-sys` build script until it
was added to `supply-chain/build-scripts.txt`. The final run included both
corrections and was the run counted above.

## Remaining assurance gaps

1. Critical cross-device interoperability finding C7-01.
2. ASan or another approved sanitizer-capable execution of both fuzz targets.
3. iOS mid-operation relock on the physical signed app.
4. Complete physical kill/disk-full/rename fault matrix rather than the
   deterministic host matrix plus force-stop relaunch.
5. Independent human review of the exact final revisions.

These are explicit blockers or review inputs. The passing local/device results
do not authorize real recordings, a product encryption claim, P3, or Milestone
3 entry.
