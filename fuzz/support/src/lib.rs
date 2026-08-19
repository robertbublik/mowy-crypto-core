//! Fuzz-only rlib that compiles the production parser modules in place.
//!
//! The mobile core also emits static and dynamic libraries. Keeping this
//! support crate rlib-only prevents sanitizer flags from touching those mobile
//! link products while every exercised parser function still comes directly
//! from the production source files.

#![allow(
    dead_code,
    reason = "the support crate includes complete production modules so fuzzed functions stay exact"
)]

#[path = "../../../src/attachment_envelope.rs"]
mod attachment_envelope;
#[path = "../../../src/attachment_manifest.rs"]
mod attachment_manifest;
#[path = "../../../src/key_bundle.rs"]
mod key_bundle;
#[path = "../../../src/key_material.rs"]
mod key_material;
#[path = "../../../src/sealed_manifest.rs"]
mod sealed_manifest;

/// Exercises the exact sealed-blob length parser and authenticated inner
/// manifest validator without returning decoded or secret-bearing data.
pub fn sealed_manifest(input: &[u8]) {
    sealed_manifest::fuzz_parser(input);
}

/// Exercises envelope framing, geometry, digest, and authentication while
/// discarding any plaintext produced by a valid public fixture.
pub fn attachment_envelope(input: &[u8]) {
    attachment_envelope::fuzz_parser(input);
}
