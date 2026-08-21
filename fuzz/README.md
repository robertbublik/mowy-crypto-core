# Parser fuzzing

This directory owns the development-only fuzzing mechanics for the public
native core. It is intentionally separate from the production crate so LLVM
coverage and sanitizer flags never change the `staticlib` or `cdylib` mobile
artifacts.

## What is exercised

- `sealed_manifest` calls the production outer sealed-blob length parser for
  arbitrary bytes. Inputs beginning with `mutate:` also apply three-byte
  `(offset-high, offset-low, xor-value)` mutations to the exact valid signed
  inner fixture before the production authenticated-inner validator runs.
  This reaches the valid parser path while production code still creates and
  verifies every signature itself.
- `attachment_envelope` calls the production header parser and, whenever the
  framing is canonical, reconstructs the public binding and executes the
  production digest and record-authentication path into `std::io::sink()`.
  The `hex:` corpus encoding keeps the exact 106-byte public vector auditable
  as text; fuzzed valid hex is decoded before parsing.

Neither target returns plaintext, keys, decoded manifests, or internal error
detail. Both compile the production source files in place through the rlib-only
`support` crate. There is no copied parser implementation and no UniFFI entry.

## Reproducibility

`Cargo.toml` pins `libfuzzer-sys =0.4.13`; `Cargo.lock` freezes its complete
77-package development graph. `vendor/arbitrary`, `vendor/jobserver`, and
`vendor/libfuzzer-sys` are the only additions not already present for the main
crate. Cargo's repository configuration keeps target builds offline and checks
each directory against `.cargo-checksum.json`.

The approved driver is `cargo-fuzz 0.13.2`. It requires nightly-only compiler
coverage flags, so the evidence run used the disposable date-pinned toolchain
`nightly-2026-08-19` (`rustc 1.100.0-nightly e71c0f1e3 2026-08-18`). The stable
Rust 1.97.1 production pin remains unchanged. Run both bounded targets with:

```sh
MOWY_CARGO_FUZZ_BIN=/path/to/cargo-fuzz \
MOWY_FUZZ_RUNS=10000 \
MOWY_FUZZ_SANITIZER=none \
scripts/check-fuzz.sh
```

The script copies the committed seeds to a uniquely named temporary directory
because libFuzzer evolves the supplied corpus in place. It removes that work
directory on exit; only the two intentional text seeds per target are durable.

## Sanitizer evidence and Apple limitation

Coverage-guided runs pass on Apple Silicon with `--sanitizer none`. The default
AddressSanitizer build on the pinned 2026-08-19 nightly reaches the final link
but Apple's linker rejects initializer metadata in the pinned `ctor 0.9.1` and
`libsodium-rs 0.2.4` objects (`initializer pointer has no target`). Disabling
dead-code stripping does not resolve that host-specific failure.

The exact same repository source, lockfiles, vendored graph, corpora,
cargo-fuzz 0.13.2 driver, and `nightly-2026-08-19` compiler subsequently passed
10,000 iterations per target with `--sanitizer address` in an aarch64 Linux
container. The repository was mounted read-only and target/corpus mutations
were disposable. Exact image/compiler metadata, coverage counts, RSS, and the
absence of crash artifacts are recorded in `evidence/commit-9.md`. This closes
the missing ASan execution; it does not make fuzzing proof of memory safety or
independent assurance. Production dependency pins did not change.
