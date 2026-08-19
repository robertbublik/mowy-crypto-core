//! Narrow public boundary for Mowy's fixture-only sealed-envelope foundation.
//!
//! Secret-bearing implementation modules stay behind the generated semantic
//! façade. The façade exposes only a named fixture proof, opaque/public
//! receipts, protected-store plumbing, cancellation, and coarse errors.

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod key_material;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod key_bundle;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod attachment_manifest;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod sealed_manifest;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod attachment_envelope;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod private_files;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod operation_repository;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod archive;

#[allow(
    dead_code,
    reason = "semantic facade exposes one reviewed proof subset"
)]
mod receiver_lifecycle;

mod bridge;

pub use bridge::{
    MowyCancellation, MowyCoreCode, MowyProofReceipt, MowyProofResult, NativeBridgeResponse,
    NativeProtectedKeyState, NativeProtectedKeyStore, run_development_proof,
};

/// Identifies the pinned public-core profile without accepting hostile input.
pub fn core_profile_version() -> u16 {
    1
}

// UniFFI's generated C ABI is isolated from authored code because it requires
// `no_mangle`; crate-owned code remains under the deny-level unsafe lint.
#[allow(unsafe_code)]
mod ffi {
    use crate::{
        MowyCancellation, MowyCoreCode, MowyProofReceipt, MowyProofResult, NativeBridgeResponse,
        NativeProtectedKeyState, NativeProtectedKeyStore, core_profile_version,
        run_development_proof,
    };

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
