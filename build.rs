// Generates the Rust half of the intentionally non-secret UniFFI bootstrap API.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    uniffi::generate_scaffolding("src/mowy_crypto_core.udl")?;
    Ok(())
}
