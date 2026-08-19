//! Narrow public boundary for Mowy's fixture-only sealed-envelope foundation.
//!
//! Secret-bearing implementation modules stay behind the generated semantic
//! façade. The current façade still exposes no key, plaintext, path, or
//! cryptographic operation.

// Commit 7 connects this reviewed native-only layer to the semantic façade.
#[expect(dead_code, reason = "platform integration is a later reviewed slice")]
mod key_material;

#[expect(dead_code, reason = "platform integration is a later reviewed slice")]
mod key_bundle;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod attachment_manifest;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod sealed_manifest;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod attachment_envelope;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod private_files;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod operation_repository;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod archive;

#[allow(dead_code, reason = "platform integration is a later reviewed slice")]
mod receiver_lifecycle;

/// Identifies the pinned public-core profile without accepting hostile input.
pub fn core_profile_version() -> u16 {
    1
}

// UniFFI's generated C ABI is isolated from authored code because it requires
// `no_mangle`; crate-owned code remains under the deny-level unsafe lint.
#[allow(unsafe_code)]
mod ffi {
    use crate::core_profile_version;

    uniffi::include_scaffolding!("mowy_crypto_core");
}

#[doc(hidden)]
pub use ffi::UniFfiTag;

#[cfg(test)]
mod tests {
    #[test]
    fn reports_the_initial_profile() {
        assert_eq!(super::core_profile_version(), 1);
    }
}
