#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mowy_crypto_core_fuzz_support::attachment_envelope(data);
});
