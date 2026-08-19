//! Narrow bootstrap surface for the public Mowy cryptographic core.
//!
//! Commit 1 intentionally exposes no key, plaintext, path, or cryptographic
//! operation. Later reviewed slices add semantic operations behind this same
//! generated boundary.

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
