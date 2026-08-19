//! Exact secret-bearing attachment manifest used only inside the native core.

use libsodium_rs::{ensure_init, random};
use zeroize::Zeroizing;

use crate::key_bundle::CanonicalUuid;

pub(crate) const MANIFEST_BYTES: usize = 128;
pub(crate) const ATTACHMENT_KEY_BYTES: usize = 32;
pub(crate) const DIGEST_BYTES: usize = 32;
pub(crate) const ENVELOPE_HEADER_BYTES: u64 = 56;
pub(crate) const CHUNK_BYTES: u64 = 65_536;
pub(crate) const RECORD_OVERHEAD_BYTES: u64 = 17;
pub(crate) const MAX_P2_PLAINTEXT_BYTES: u64 = 25 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"MOWYAMF\0";
const VERSION: u16 = 1;
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_ALGORITHM: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentManifestError {
    InvalidInput,
    Cryptography,
}

pub(crate) struct AttachmentKey(Zeroizing<[u8; ATTACHMENT_KEY_BYTES]>);

impl AttachmentKey {
    pub(crate) fn generate() -> Result<Self, AttachmentManifestError> {
        ensure_init().map_err(|_| AttachmentManifestError::Cryptography)?;
        let mut key = Zeroizing::new([0_u8; ATTACHMENT_KEY_BYTES]);
        random::fill_bytes(key.as_mut());
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(crate) fn from_fixture(bytes: [u8; ATTACHMENT_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; ATTACHMENT_KEY_BYTES] {
        &self.0
    }
}

/// The complete serialized manifest zeroizes as one owner and is not cloneable.
pub(crate) struct AttachmentManifest(Zeroizing<[u8; MANIFEST_BYTES]>);

impl AttachmentManifest {
    pub(crate) fn new(
        conversation_id: CanonicalUuid,
        asset_id: CanonicalUuid,
        plaintext_length: u64,
        ciphertext_length: u64,
        ciphertext_digest: [u8; DIGEST_BYTES],
        attachment_key: AttachmentKey,
    ) -> Result<Self, AttachmentManifestError> {
        if canonical_ciphertext_length(plaintext_length)? != ciphertext_length {
            return Err(AttachmentManifestError::InvalidInput);
        }

        let mut bytes = Zeroizing::new([0_u8; MANIFEST_BYTES]);
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        bytes[12..14].copy_from_slice(&ENVELOPE_ALGORITHM.to_be_bytes());
        bytes[16..32].copy_from_slice(conversation_id.as_network_bytes());
        bytes[32..48].copy_from_slice(asset_id.as_network_bytes());
        bytes[48..56].copy_from_slice(&plaintext_length.to_be_bytes());
        bytes[56..64].copy_from_slice(&ciphertext_length.to_be_bytes());
        bytes[64..96].copy_from_slice(&ciphertext_digest);
        bytes[96..128].copy_from_slice(attachment_key.as_bytes());
        Ok(Self(bytes))
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, AttachmentManifestError> {
        if bytes.len() != MANIFEST_BYTES {
            return Err(AttachmentManifestError::InvalidInput);
        }
        let mut exact = Zeroizing::new([0_u8; MANIFEST_BYTES]);
        exact.copy_from_slice(bytes);
        let manifest = Self(exact);
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; MANIFEST_BYTES] {
        &self.0
    }

    pub(crate) fn conversation_id(&self) -> Result<CanonicalUuid, AttachmentManifestError> {
        CanonicalUuid::from_network_bytes(exact_field(&self.0[16..32])?)
            .map_err(|_| AttachmentManifestError::InvalidInput)
    }

    pub(crate) fn asset_id(&self) -> Result<CanonicalUuid, AttachmentManifestError> {
        CanonicalUuid::from_network_bytes(exact_field(&self.0[32..48])?)
            .map_err(|_| AttachmentManifestError::InvalidInput)
    }

    pub(crate) fn plaintext_length(&self) -> Result<u64, AttachmentManifestError> {
        Ok(u64::from_be_bytes(exact_field(&self.0[48..56])?))
    }

    pub(crate) fn ciphertext_length(&self) -> Result<u64, AttachmentManifestError> {
        Ok(u64::from_be_bytes(exact_field(&self.0[56..64])?))
    }

    pub(crate) fn ciphertext_digest(&self) -> Result<[u8; DIGEST_BYTES], AttachmentManifestError> {
        exact_field(&self.0[64..96])
    }

    pub(crate) fn attachment_key(
        &self,
    ) -> Result<&[u8; ATTACHMENT_KEY_BYTES], AttachmentManifestError> {
        self.0[96..128]
            .try_into()
            .map_err(|_| AttachmentManifestError::InvalidInput)
    }

    fn validate(&self) -> Result<(), AttachmentManifestError> {
        if &self.0[0..8] != MAGIC
            || u16::from_be_bytes(exact_field(&self.0[8..10])?) != VERSION
            || u16::from_be_bytes(exact_field(&self.0[10..12])?) != ENVELOPE_VERSION
            || u16::from_be_bytes(exact_field(&self.0[12..14])?) != ENVELOPE_ALGORITHM
            || self.0[14..16] != [0, 0]
        {
            return Err(AttachmentManifestError::InvalidInput);
        }
        self.conversation_id()?;
        self.asset_id()?;
        let plaintext_length = self.plaintext_length()?;
        if canonical_ciphertext_length(plaintext_length)? != self.ciphertext_length()? {
            return Err(AttachmentManifestError::InvalidInput);
        }
        Ok(())
    }
}

pub(crate) fn chunk_count(plaintext_length: u64) -> Result<u32, AttachmentManifestError> {
    if plaintext_length == 0 || plaintext_length > MAX_P2_PLAINTEXT_BYTES {
        return Err(AttachmentManifestError::InvalidInput);
    }
    let count = plaintext_length
        .checked_add(CHUNK_BYTES - 1)
        .ok_or(AttachmentManifestError::InvalidInput)?
        / CHUNK_BYTES;
    u32::try_from(count).map_err(|_| AttachmentManifestError::InvalidInput)
}

pub(crate) fn canonical_ciphertext_length(
    plaintext_length: u64,
) -> Result<u64, AttachmentManifestError> {
    let count = u64::from(chunk_count(plaintext_length)?);
    ENVELOPE_HEADER_BYTES
        .checked_add(plaintext_length)
        .and_then(|length| length.checked_add(count * RECORD_OVERHEAD_BYTES))
        .ok_or(AttachmentManifestError::InvalidInput)
}

fn exact_field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AttachmentManifestError> {
    bytes
        .try_into()
        .map_err(|_| AttachmentManifestError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(value: u8) -> Result<CanonicalUuid, AttachmentManifestError> {
        CanonicalUuid::from_network_bytes([value; 16])
            .map_err(|_| AttachmentManifestError::InvalidInput)
    }

    fn fixture_manifest() -> Result<AttachmentManifest, AttachmentManifestError> {
        let plaintext_length = CHUNK_BYTES + 1;
        AttachmentManifest::new(
            uuid(1)?,
            uuid(2)?,
            plaintext_length,
            canonical_ciphertext_length(plaintext_length)?,
            [0x80; DIGEST_BYTES],
            AttachmentKey::from_fixture([0xa0; ATTACHMENT_KEY_BYTES]),
        )
    }

    #[test]
    fn exact_manifest_round_trip() -> Result<(), AttachmentManifestError> {
        let manifest = fixture_manifest()?;
        let parsed = AttachmentManifest::parse(manifest.as_bytes())?;
        assert_eq!(parsed.conversation_id()?, uuid(1)?);
        assert_eq!(parsed.asset_id()?, uuid(2)?);
        assert_eq!(parsed.plaintext_length()?, CHUNK_BYTES + 1);
        assert_eq!(parsed.ciphertext_length()?, CHUNK_BYTES + 1 + 56 + 34);
        assert_eq!(parsed.ciphertext_digest()?, [0x80; DIGEST_BYTES]);
        assert_eq!(parsed.attachment_key()?, &[0xa0; ATTACHMENT_KEY_BYTES]);
        Ok(())
    }

    #[test]
    fn rejects_every_structural_class() -> Result<(), AttachmentManifestError> {
        let manifest = fixture_manifest()?;
        for offset in [0, 8, 10, 12, 14, 15] {
            let mut bytes = *manifest.as_bytes();
            bytes[offset] ^= 1;
            assert_eq!(
                AttachmentManifest::parse(&bytes).err(),
                Some(AttachmentManifestError::InvalidInput)
            );
        }
        assert_eq!(
            AttachmentManifest::parse(&manifest.as_bytes()[..127]).err(),
            Some(AttachmentManifestError::InvalidInput)
        );
        Ok(())
    }

    #[test]
    fn enforces_policy_and_canonical_geometry() {
        assert_eq!(chunk_count(0), Err(AttachmentManifestError::InvalidInput));
        assert_eq!(chunk_count(1), Ok(1));
        assert_eq!(chunk_count(CHUNK_BYTES), Ok(1));
        assert_eq!(chunk_count(CHUNK_BYTES + 1), Ok(2));
        assert_eq!(chunk_count(MAX_P2_PLAINTEXT_BYTES), Ok(400));
        assert_eq!(
            canonical_ciphertext_length(MAX_P2_PLAINTEXT_BYTES),
            Ok(26_221_256)
        );
        assert_eq!(
            chunk_count(MAX_P2_PLAINTEXT_BYTES + 1),
            Err(AttachmentManifestError::InvalidInput)
        );
    }
}
