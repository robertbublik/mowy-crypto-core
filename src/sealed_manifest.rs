//! Sign-then-seal delivery of one exact attachment manifest.

use libsodium_rs::{crypto_box, crypto_sign, crypto_verify, ensure_init};
use zeroize::Zeroizing;

use crate::attachment_manifest::{AttachmentManifest, AttachmentManifestError, MANIFEST_BYTES};
use crate::key_bundle::{
    CanonicalUuid, DeviceKeyBundle, KeyBundleError, KeyValidityWindow, verify_bundle_at,
};
use crate::key_material::RootKeyMaterial;

const DOMAIN: &[u8; 24] = b"MOWY-SEALED-MANIFEST-V1\0";
const SIGNED_REGION_BYTES: usize = 296;
const INNER_BYTES: usize = 360;
pub(crate) const SEALED_BYTES: usize = 408;
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

const SENDER_DEVICE_OFFSET: usize = 24;
const SENDER_IDENTITY_OFFSET: usize = 40;
const RECIPIENT_DEVICE_OFFSET: usize = 72;
const RECIPIENT_KEY_ID_OFFSET: usize = 88;
const RECIPIENT_PUBLIC_KEY_OFFSET: usize = 104;
const CONVERSATION_OFFSET: usize = 136;
const ASSET_OFFSET: usize = 152;
const MANIFEST_OFFSET: usize = 168;
const SIGNATURE_OFFSET: usize = 296;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SealedManifestError {
    InvalidInput,
    Unavailable,
    ExpiredKey,
    Cryptography,
    Signature,
    IdentityChanged,
    RecipientMismatch,
    IdentifierMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrustedSender {
    pub(crate) device_id: CanonicalUuid,
    pub(crate) identity_public_key: [u8; KEY_BYTES],
}

/// One local X25519 key loaded from protected storage for this operation only.
pub(crate) struct LocalAgreementKey {
    secret: Zeroizing<[u8; KEY_BYTES]>,
    public: [u8; KEY_BYTES],
    pub(crate) device_id: CanonicalUuid,
    pub(crate) key_id: CanonicalUuid,
    pub(crate) validity: KeyValidityWindow,
}

impl LocalAgreementKey {
    pub(crate) fn from_current_root(
        root: &RootKeyMaterial,
        device_id: CanonicalUuid,
        key_id: CanonicalUuid,
        validity: KeyValidityWindow,
    ) -> Result<Self, SealedManifestError> {
        let mut secret = Zeroizing::new([0_u8; KEY_BYTES]);
        secret.copy_from_slice(root.agreement_secret());
        Self::from_protected_secret(secret, device_id, key_id, validity)
    }

    pub(crate) fn from_protected_secret(
        secret: Zeroizing<[u8; KEY_BYTES]>,
        device_id: CanonicalUuid,
        key_id: CanonicalUuid,
        validity: KeyValidityWindow,
    ) -> Result<Self, SealedManifestError> {
        ensure_init().map_err(|_| SealedManifestError::Cryptography)?;
        KeyValidityWindow::from_bounds(validity.not_before, validity.not_after)
            .map_err(|_| SealedManifestError::InvalidInput)?;
        let public = libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(secret.as_ref())
            .map_err(|_| SealedManifestError::Cryptography)?;
        Ok(Self {
            secret,
            public,
            device_id,
            key_id,
            validity,
        })
    }

    pub(crate) fn public_key(&self) -> &[u8; KEY_BYTES] {
        &self.public
    }
}

/// Public routing selector plus the exact opaque sealed-box bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SealedManifest {
    pub(crate) recipient_key_id: CanonicalUuid,
    blob: [u8; SEALED_BYTES],
}

impl SealedManifest {
    pub(crate) fn parse(
        recipient_key_id: CanonicalUuid,
        blob: &[u8],
    ) -> Result<Self, SealedManifestError> {
        let exact = blob
            .try_into()
            .map_err(|_| SealedManifestError::InvalidInput)?;
        Ok(Self {
            recipient_key_id,
            blob: exact,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SEALED_BYTES] {
        &self.blob
    }
}

pub(crate) struct OpenedManifest {
    pub(crate) sender_device_id: CanonicalUuid,
    manifest: AttachmentManifest,
    source_sealed: SealedManifest,
}

impl OpenedManifest {
    pub(crate) fn manifest(&self) -> &AttachmentManifest {
        &self.manifest
    }

    pub(crate) fn source_sealed(&self) -> &SealedManifest {
        &self.source_sealed
    }

    #[cfg(test)]
    pub(crate) fn from_fixture(
        sender_device_id: CanonicalUuid,
        manifest: AttachmentManifest,
        source_sealed: SealedManifest,
    ) -> Self {
        Self {
            sender_device_id,
            manifest,
            source_sealed,
        }
    }
}

/// Re-verifies the recipient's current published bundle before sealing.
pub(crate) fn seal_manifest(
    sender_root: &RootKeyMaterial,
    sender_device_id: CanonicalUuid,
    recipient: &DeviceKeyBundle,
    manifest: &AttachmentManifest,
    now: u64,
) -> Result<SealedManifest, SealedManifestError> {
    verify_bundle_at(recipient, now).map_err(map_key_bundle_error)?;
    ensure_init().map_err(|_| SealedManifestError::Cryptography)?;
    let identity = crypto_sign::KeyPair::from_seed(sender_root.identity_seed())
        .map_err(|_| SealedManifestError::Cryptography)?;
    let inner = build_signed_inner(
        &identity,
        sender_device_id,
        recipient.device_id,
        recipient.agreement_key_id,
        &recipient.agreement_public_key,
        manifest,
    )?;
    let recipient_public = crypto_box::PublicKey::from_bytes_exact(recipient.agreement_public_key);
    let sealed = crypto_box::seal_box(inner.as_ref(), &recipient_public)
        .map_err(|_| SealedManifestError::Cryptography)?;
    let blob = sealed
        .try_into()
        .map_err(|_| SealedManifestError::Cryptography)?;
    Ok(SealedManifest {
        recipient_key_id: recipient.agreement_key_id,
        blob,
    })
}

pub(crate) fn open_manifest(
    sealed: &SealedManifest,
    local_key: &LocalAgreementKey,
    trusted_sender: TrustedSender,
    expected_conversation_id: CanonicalUuid,
    expected_asset_id: CanonicalUuid,
    now: u64,
) -> Result<OpenedManifest, SealedManifestError> {
    if !uuid_equal(sealed.recipient_key_id, local_key.key_id) {
        return Err(SealedManifestError::Unavailable);
    }
    local_key
        .validity
        .require_active_at(now)
        .map_err(map_key_bundle_error)?;
    ensure_init().map_err(|_| SealedManifestError::Cryptography)?;
    let recipient_public = crypto_box::PublicKey::from_bytes_exact(local_key.public);
    let recipient_secret = crypto_box::SecretKey::from_bytes(local_key.secret.as_ref())
        .map_err(|_| SealedManifestError::Unavailable)?;
    let opened = Zeroizing::new(
        crypto_box::open_sealed_box(sealed.as_bytes(), &recipient_public, &recipient_secret)
            .map_err(|_| SealedManifestError::Cryptography)?,
    );
    let mut inner = Zeroizing::new(
        <[u8; INNER_BYTES]>::try_from(opened.as_slice())
            .map_err(|_| SealedManifestError::InvalidInput)?,
    );

    let result = validate_opened_inner(
        &inner,
        local_key,
        trusted_sender,
        expected_conversation_id,
        expected_asset_id,
        *sealed,
    );
    inner.fill(0);
    result
}

fn validate_opened_inner(
    inner: &[u8; INNER_BYTES],
    local_key: &LocalAgreementKey,
    trusted_sender: TrustedSender,
    expected_conversation_id: CanonicalUuid,
    expected_asset_id: CanonicalUuid,
    source_sealed: SealedManifest,
) -> Result<OpenedManifest, SealedManifestError> {
    if &inner[..DOMAIN.len()] != DOMAIN {
        return Err(SealedManifestError::InvalidInput);
    }

    let embedded_identity: [u8; KEY_BYTES] =
        exact_field(&inner[SENDER_IDENTITY_OFFSET..SENDER_IDENTITY_OFFSET + KEY_BYTES])?;
    if !crypto_verify::verify_32(&embedded_identity, &trusted_sender.identity_public_key) {
        return Err(SealedManifestError::IdentityChanged);
    }
    let signature: [u8; SIGNATURE_BYTES] = exact_field(&inner[SIGNATURE_OFFSET..INNER_BYTES])?;
    let identity = crypto_sign::PublicKey::from_bytes_exact(trusted_sender.identity_public_key);
    if !crypto_sign::verify_detached(&signature, &inner[..SIGNED_REGION_BYTES], &identity) {
        return Err(SealedManifestError::Signature);
    }

    let sender_device_id = canonical_uuid(&inner[SENDER_DEVICE_OFFSET..SENDER_IDENTITY_OFFSET])?;
    let recipient_device_id =
        canonical_uuid(&inner[RECIPIENT_DEVICE_OFFSET..RECIPIENT_KEY_ID_OFFSET])?;
    let recipient_key_id =
        canonical_uuid(&inner[RECIPIENT_KEY_ID_OFFSET..RECIPIENT_PUBLIC_KEY_OFFSET])?;
    let recipient_public: [u8; KEY_BYTES] =
        exact_field(&inner[RECIPIENT_PUBLIC_KEY_OFFSET..RECIPIENT_PUBLIC_KEY_OFFSET + KEY_BYTES])?;
    let conversation_id = canonical_uuid(&inner[CONVERSATION_OFFSET..ASSET_OFFSET])?;
    let asset_id = canonical_uuid(&inner[ASSET_OFFSET..MANIFEST_OFFSET])?;

    if !uuid_equal(sender_device_id, trusted_sender.device_id) {
        return Err(SealedManifestError::IdentityChanged);
    }
    if !uuid_equal(recipient_device_id, local_key.device_id)
        || !uuid_equal(recipient_key_id, local_key.key_id)
        || !crypto_verify::verify_32(&recipient_public, local_key.public_key())
    {
        return Err(SealedManifestError::RecipientMismatch);
    }

    let manifest =
        AttachmentManifest::parse(&inner[MANIFEST_OFFSET..MANIFEST_OFFSET + MANIFEST_BYTES])
            .map_err(map_manifest_error)?;
    if !uuid_equal(
        conversation_id,
        manifest.conversation_id().map_err(map_manifest_error)?,
    ) || !uuid_equal(asset_id, manifest.asset_id().map_err(map_manifest_error)?)
        || !uuid_equal(conversation_id, expected_conversation_id)
        || !uuid_equal(asset_id, expected_asset_id)
    {
        return Err(SealedManifestError::IdentifierMismatch);
    }

    Ok(OpenedManifest {
        sender_device_id,
        manifest,
        source_sealed,
    })
}

fn build_signed_inner(
    identity: &crypto_sign::KeyPair,
    sender_device_id: CanonicalUuid,
    recipient_device_id: CanonicalUuid,
    recipient_key_id: CanonicalUuid,
    recipient_public_key: &[u8; KEY_BYTES],
    manifest: &AttachmentManifest,
) -> Result<Zeroizing<[u8; INNER_BYTES]>, SealedManifestError> {
    let conversation_id = manifest.conversation_id().map_err(map_manifest_error)?;
    let asset_id = manifest.asset_id().map_err(map_manifest_error)?;
    let mut inner = Zeroizing::new([0_u8; INNER_BYTES]);
    inner[0..DOMAIN.len()].copy_from_slice(DOMAIN);
    inner[SENDER_DEVICE_OFFSET..SENDER_IDENTITY_OFFSET]
        .copy_from_slice(sender_device_id.as_network_bytes());
    inner[SENDER_IDENTITY_OFFSET..RECIPIENT_DEVICE_OFFSET]
        .copy_from_slice(identity.public_key.as_bytes());
    inner[RECIPIENT_DEVICE_OFFSET..RECIPIENT_KEY_ID_OFFSET]
        .copy_from_slice(recipient_device_id.as_network_bytes());
    inner[RECIPIENT_KEY_ID_OFFSET..RECIPIENT_PUBLIC_KEY_OFFSET]
        .copy_from_slice(recipient_key_id.as_network_bytes());
    inner[RECIPIENT_PUBLIC_KEY_OFFSET..CONVERSATION_OFFSET].copy_from_slice(recipient_public_key);
    inner[CONVERSATION_OFFSET..ASSET_OFFSET].copy_from_slice(conversation_id.as_network_bytes());
    inner[ASSET_OFFSET..MANIFEST_OFFSET].copy_from_slice(asset_id.as_network_bytes());
    inner[MANIFEST_OFFSET..SIGNATURE_OFFSET].copy_from_slice(manifest.as_bytes());
    let signature = crypto_sign::sign_detached(&inner[..SIGNED_REGION_BYTES], &identity.secret_key)
        .map_err(|_| SealedManifestError::Cryptography)?;
    inner[SIGNATURE_OFFSET..].copy_from_slice(&signature);
    Ok(inner)
}

fn canonical_uuid(bytes: &[u8]) -> Result<CanonicalUuid, SealedManifestError> {
    CanonicalUuid::from_network_bytes(exact_field(bytes)?)
        .map_err(|_| SealedManifestError::InvalidInput)
}

fn exact_field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], SealedManifestError> {
    bytes
        .try_into()
        .map_err(|_| SealedManifestError::InvalidInput)
}

fn uuid_equal(left: CanonicalUuid, right: CanonicalUuid) -> bool {
    crypto_verify::verify_16(left.as_network_bytes(), right.as_network_bytes())
}

fn map_manifest_error(error: AttachmentManifestError) -> SealedManifestError {
    match error {
        AttachmentManifestError::InvalidInput => SealedManifestError::InvalidInput,
        AttachmentManifestError::Cryptography => SealedManifestError::Cryptography,
    }
}

fn map_key_bundle_error(error: KeyBundleError) -> SealedManifestError {
    match error {
        KeyBundleError::NotYetValid => SealedManifestError::Unavailable,
        KeyBundleError::Expired => SealedManifestError::ExpiredKey,
        KeyBundleError::Signature => SealedManifestError::Signature,
        KeyBundleError::IdentityChanged => SealedManifestError::IdentityChanged,
        KeyBundleError::InvalidInput
        | KeyBundleError::Rollback
        | KeyBundleError::Storage
        | KeyBundleError::Cryptography => SealedManifestError::Cryptography,
    }
}

#[cfg(test)]
mod tests {
    use libsodium_rs::crypto_hash;
    use proptest::prelude::*;

    use super::*;
    use crate::attachment_manifest::{AttachmentKey, DIGEST_BYTES, canonical_ciphertext_length};
    use crate::key_bundle::{KeyValidityWindow, sign_current_bundle};
    use crate::key_material::{derive_public_keys, generate};

    const NOW: u64 = 1_770_000_000;

    fn uuid(value: u8) -> Result<CanonicalUuid, SealedManifestError> {
        CanonicalUuid::from_network_bytes([value; 16])
            .map_err(|_| SealedManifestError::InvalidInput)
    }

    fn fixture_manifest() -> Result<AttachmentManifest, SealedManifestError> {
        let plaintext_length = 65_537;
        AttachmentManifest::new(
            uuid(4)?,
            uuid(5)?,
            plaintext_length,
            canonical_ciphertext_length(plaintext_length).map_err(map_manifest_error)?,
            [0x80; DIGEST_BYTES],
            AttachmentKey::from_fixture([0xa0; KEY_BYTES]),
        )
        .map_err(map_manifest_error)
    }

    struct FixtureContext {
        sender_root: RootKeyMaterial,
        recipient_bundle: DeviceKeyBundle,
        recipient_local: LocalAgreementKey,
        trusted_sender: TrustedSender,
    }

    fn fixture_context() -> Result<FixtureContext, SealedManifestError> {
        let (sender_root, _) = generate().map_err(|_| SealedManifestError::Cryptography)?;
        let (recipient_root, _) = generate().map_err(|_| SealedManifestError::Cryptography)?;
        let validity = KeyValidityWindow::starting_at(NOW).map_err(map_key_bundle_error)?;
        let recipient_bundle =
            sign_current_bundle(&recipient_root, uuid(1)?, uuid(3)?, uuid(6)?, validity)
                .map_err(map_key_bundle_error)?;
        let recipient_local =
            LocalAgreementKey::from_current_root(&recipient_root, uuid(3)?, uuid(6)?, validity)?;
        let sender_public =
            derive_public_keys(&sender_root).map_err(|_| SealedManifestError::Cryptography)?;
        Ok(FixtureContext {
            sender_root,
            recipient_bundle,
            recipient_local,
            trusted_sender: TrustedSender {
                device_id: uuid(2)?,
                identity_public_key: sender_public.identity,
            },
        })
    }

    fn open_fixture(
        sealed: &SealedManifest,
        context: &FixtureContext,
    ) -> Result<OpenedManifest, SealedManifestError> {
        open_manifest(
            sealed,
            &context.recipient_local,
            context.trusted_sender,
            uuid(4)?,
            uuid(5)?,
            NOW,
        )
    }

    fn opened_inner(
        sealed: &SealedManifest,
        local: &LocalAgreementKey,
    ) -> Result<Zeroizing<Vec<u8>>, SealedManifestError> {
        let public = crypto_box::PublicKey::from_bytes_exact(local.public);
        let secret = crypto_box::SecretKey::from_bytes(local.secret.as_ref())
            .map_err(|_| SealedManifestError::Cryptography)?;
        crypto_box::open_sealed_box(sealed.as_bytes(), &public, &secret)
            .map(Zeroizing::new)
            .map_err(|_| SealedManifestError::Cryptography)
    }

    fn reseal(
        selector: CanonicalUuid,
        inner: &[u8],
        recipient_public: [u8; KEY_BYTES],
    ) -> Result<SealedManifest, SealedManifestError> {
        let public = crypto_box::PublicKey::from_bytes_exact(recipient_public);
        let blob =
            crypto_box::seal_box(inner, &public).map_err(|_| SealedManifestError::Cryptography)?;
        SealedManifest::parse(selector, &blob)
    }

    #[test]
    fn seals_opens_and_binds_all_fields() -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let first = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        let second = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        assert_eq!(first.as_bytes().len(), SEALED_BYTES);
        assert_ne!(first.as_bytes(), second.as_bytes());

        let opened = open_fixture(&first, &context)?;
        assert_eq!(opened.sender_device_id, context.trusted_sender.device_id);
        assert_eq!(
            opened
                .manifest()
                .conversation_id()
                .map_err(map_manifest_error)?,
            uuid(4)?
        );
        assert_eq!(
            opened.manifest().asset_id().map_err(map_manifest_error)?,
            uuid(5)?
        );
        assert_eq!(
            opened
                .manifest()
                .attachment_key()
                .map_err(map_manifest_error)?,
            &[0xa0; KEY_BYTES]
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_recipient_selector_expiry_and_tamper() -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let sealed = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;

        let mut wrong_selector = sealed;
        wrong_selector.recipient_key_id = uuid(7)?;
        assert_eq!(
            open_fixture(&wrong_selector, &context).err(),
            Some(SealedManifestError::Unavailable)
        );

        let mut tampered = sealed;
        tampered.blob[SEALED_BYTES - 1] ^= 1;
        assert_eq!(
            open_fixture(&tampered, &context).err(),
            Some(SealedManifestError::Cryptography)
        );

        let (wrong_root, _) = generate().map_err(|_| SealedManifestError::Cryptography)?;
        let wrong_local = LocalAgreementKey::from_current_root(
            &wrong_root,
            context.recipient_local.device_id,
            context.recipient_local.key_id,
            context.recipient_local.validity,
        )?;
        assert_eq!(
            open_manifest(
                &sealed,
                &wrong_local,
                context.trusted_sender,
                uuid(4)?,
                uuid(5)?,
                NOW,
            )
            .err(),
            Some(SealedManifestError::Cryptography)
        );

        assert_eq!(
            open_manifest(
                &sealed,
                &context.recipient_local,
                context.trusted_sender,
                uuid(4)?,
                uuid(5)?,
                context.recipient_local.validity.not_after,
            )
            .err(),
            Some(SealedManifestError::ExpiredKey)
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_sender_and_identifier_context() -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let sealed = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        let (other_sender, _) = generate().map_err(|_| SealedManifestError::Cryptography)?;
        let other_public =
            derive_public_keys(&other_sender).map_err(|_| SealedManifestError::Cryptography)?;
        let changed = TrustedSender {
            device_id: context.trusted_sender.device_id,
            identity_public_key: other_public.identity,
        };
        assert_eq!(
            open_manifest(
                &sealed,
                &context.recipient_local,
                changed,
                uuid(4)?,
                uuid(5)?,
                NOW,
            )
            .err(),
            Some(SealedManifestError::IdentityChanged)
        );
        assert_eq!(
            open_manifest(
                &sealed,
                &context.recipient_local,
                context.trusted_sender,
                uuid(4)?,
                uuid(8)?,
                NOW,
            )
            .err(),
            Some(SealedManifestError::IdentifierMismatch)
        );
        Ok(())
    }

    #[test]
    fn rejects_stripped_signature_and_forwarded_blob() -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let sealed = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        let mut inner = opened_inner(&sealed, &context.recipient_local)?;
        inner[SIGNATURE_OFFSET..].fill(0);
        let stripped = reseal(
            sealed.recipient_key_id,
            inner.as_ref(),
            context.recipient_bundle.agreement_public_key,
        )?;
        assert_eq!(
            open_fixture(&stripped, &context).err(),
            Some(SealedManifestError::Signature)
        );

        let (third_root, _) = generate().map_err(|_| SealedManifestError::Cryptography)?;
        let validity = KeyValidityWindow::starting_at(NOW).map_err(map_key_bundle_error)?;
        let third_local =
            LocalAgreementKey::from_current_root(&third_root, uuid(9)?, uuid(10)?, validity)?;
        let original_inner = opened_inner(&sealed, &context.recipient_local)?;
        let forwarded = reseal(uuid(10)?, original_inner.as_ref(), third_local.public)?;
        assert_eq!(
            open_manifest(
                &forwarded,
                &third_local,
                context.trusted_sender,
                uuid(4)?,
                uuid(5)?,
                NOW,
            )
            .err(),
            Some(SealedManifestError::RecipientMismatch)
        );
        Ok(())
    }

    #[test]
    fn rejects_validly_signed_unknown_manifest_version() -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let sealed = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        let mut inner = opened_inner(&sealed, &context.recipient_local)?;
        inner[MANIFEST_OFFSET + 8] ^= 1;
        let identity = crypto_sign::KeyPair::from_seed(context.sender_root.identity_seed())
            .map_err(|_| SealedManifestError::Cryptography)?;
        let signature =
            crypto_sign::sign_detached(&inner[..SIGNED_REGION_BYTES], &identity.secret_key)
                .map_err(|_| SealedManifestError::Cryptography)?;
        inner[SIGNATURE_OFFSET..].copy_from_slice(&signature);
        let malformed = reseal(
            sealed.recipient_key_id,
            inner.as_ref(),
            context.recipient_bundle.agreement_public_key,
        )?;
        assert_eq!(
            open_fixture(&malformed, &context).err(),
            Some(SealedManifestError::InvalidInput)
        );
        Ok(())
    }

    #[test]
    fn rejects_validly_signed_outer_manifest_identifier_disagreement()
    -> Result<(), SealedManifestError> {
        let context = fixture_context()?;
        let manifest = fixture_manifest()?;
        let sealed = seal_manifest(
            &context.sender_root,
            context.trusted_sender.device_id,
            &context.recipient_bundle,
            &manifest,
            NOW,
        )?;
        let mut inner = opened_inner(&sealed, &context.recipient_local)?;
        inner[CONVERSATION_OFFSET..ASSET_OFFSET].copy_from_slice(uuid(11)?.as_network_bytes());
        let identity = crypto_sign::KeyPair::from_seed(context.sender_root.identity_seed())
            .map_err(|_| SealedManifestError::Cryptography)?;
        let signature =
            crypto_sign::sign_detached(&inner[..SIGNED_REGION_BYTES], &identity.secret_key)
                .map_err(|_| SealedManifestError::Cryptography)?;
        inner[SIGNATURE_OFFSET..].copy_from_slice(&signature);
        let mismatched = reseal(
            sealed.recipient_key_id,
            inner.as_ref(),
            context.recipient_bundle.agreement_public_key,
        )?;
        assert_eq!(
            open_fixture(&mismatched, &context).err(),
            Some(SealedManifestError::IdentifierMismatch)
        );
        Ok(())
    }

    #[test]
    fn canonical_signed_inner_vector() -> Result<(), SealedManifestError> {
        let identity_seed: [u8; KEY_BYTES] = std::array::from_fn(|index| index as u8);
        let identity = crypto_sign::KeyPair::from_seed(&identity_seed)
            .map_err(|_| SealedManifestError::Cryptography)?;
        let agreement_seed: [u8; KEY_BYTES] = std::array::from_fn(|index| 0x20 + index as u8);
        let recipient = crypto_box::KeyPair::from_seed(&agreement_seed)
            .map_err(|_| SealedManifestError::Cryptography)?;
        let manifest = fixture_manifest()?;
        let inner = build_signed_inner(
            &identity,
            uuid(2)?,
            uuid(3)?,
            uuid(6)?,
            recipient.public_key.as_bytes(),
            &manifest,
        )?;
        const EXPECTED_SIGNED_HASH: [u8; 32] = [
            0x5e, 0x2b, 0x98, 0xed, 0x9a, 0x65, 0x7e, 0x16, 0x4a, 0xb3, 0x32, 0x1f, 0x99, 0x19,
            0xd8, 0x8e, 0x6a, 0x85, 0xc3, 0x8a, 0x84, 0x8c, 0x7d, 0xd9, 0x2f, 0x20, 0xe7, 0x2d,
            0x57, 0x83, 0x9a, 0xa2,
        ];
        const EXPECTED_SIGNATURE: [u8; SIGNATURE_BYTES] = [
            0x9a, 0x36, 0x5e, 0x82, 0xd6, 0x53, 0xb3, 0x92, 0x3f, 0x3d, 0xea, 0xf2, 0x9f, 0x3d,
            0xaf, 0x84, 0xdf, 0xf0, 0x69, 0x42, 0x13, 0xc9, 0x38, 0xf5, 0x6f, 0x00, 0x5b, 0x1a,
            0x5d, 0x5d, 0x31, 0x39, 0xd9, 0x7f, 0xd4, 0x9e, 0xfc, 0xb9, 0x9b, 0xbe, 0xad, 0xcd,
            0xd5, 0xb9, 0x8e, 0xf2, 0x57, 0x5b, 0x39, 0x85, 0xb4, 0xb6, 0x1e, 0x6b, 0xa0, 0x31,
            0xc2, 0xc9, 0xd9, 0x01, 0xac, 0x19, 0xe6, 0x02,
        ];
        const EXPECTED_INNER_HASH: [u8; 32] = [
            0x38, 0x83, 0x41, 0x76, 0xbf, 0x73, 0xc5, 0xc3, 0xa2, 0x61, 0x6a, 0xdc, 0x78, 0xac,
            0x01, 0xf3, 0x82, 0x42, 0x01, 0xdc, 0x32, 0x91, 0xca, 0xaf, 0xa3, 0x9b, 0x76, 0x63,
            0xcb, 0x6c, 0xa9, 0xa9,
        ];
        assert_eq!(
            crypto_hash::hash_sha256(&inner[..SIGNED_REGION_BYTES]),
            EXPECTED_SIGNED_HASH
        );
        assert_eq!(&inner[SIGNATURE_OFFSET..], &EXPECTED_SIGNATURE);
        assert_eq!(
            crypto_hash::hash_sha256(inner.as_ref()),
            EXPECTED_INNER_HASH
        );
        assert_eq!(
            include_str!("../vectors/sealed-manifest-v1.txt"),
            "# Mowy sealed manifest v1 public test vector\n\
sender_identity_seed=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
sender_identity_public_key=03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8\n\
recipient_agreement_seed=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n\
recipient_agreement_public_key=5730800ab340fcb18ce5111eda9d705f91388b41e4544cbd103ba5942db2233e\n\
sender_device_uuid=02020202020202020202020202020202\n\
recipient_device_uuid=03030303030303030303030303030303\n\
recipient_key_uuid=06060606060606060606060606060606\n\
conversation_uuid=04040404040404040404040404040404\n\
asset_uuid=05050505050505050505050505050505\n\
plaintext_length_u64be=0000000000010001\n\
ciphertext_length_u64be=000000000001005b\n\
ciphertext_digest=8080808080808080808080808080808080808080808080808080808080808080\n\
fixture_attachment_key=a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0\n\
signed_region_sha256=5e2b98ed9a657e164ab3321f9919d88e6a85c38a848c7dd92f20e72d57839aa2\n\
signature=9a365e82d653b3923f3deaf29f3daf84dff0694213c938f56f005b1a5d5d3139d97fd49efcb99bbeadcdd5b98ef2575b3985b4b61e6ba031c2c9d901ac19e602\n\
inner_plaintext_sha256=38834176bf73c5c3a2616adc78ac01f3824201dc3291caafa39b7663cb6ca9a9\n"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_manifest_bytes_do_not_panic(bytes in any::<[u8; MANIFEST_BYTES]>()) {
            let result = AttachmentManifest::parse(&bytes);
            if let Ok(parsed) = result {
                prop_assert_eq!(parsed.as_bytes(), &bytes);
            }
        }

        #[test]
        fn noncanonical_sealed_lengths_are_rejected(
            blob in proptest::collection::vec(any::<u8>(), 0..SEALED_BYTES)
        ) {
            let selector = CanonicalUuid::from_network_bytes([1; 16]);
            prop_assert!(selector.is_ok());
            if let Ok(selector) = selector {
                prop_assert_eq!(
                    SealedManifest::parse(selector, &blob).err(),
                    Some(SealedManifestError::InvalidInput)
                );
            }
        }

        #[test]
        fn arbitrary_exact_sealed_blob_fails_without_panic(blob in any::<[u8; SEALED_BYTES]>()) {
            let selector = CanonicalUuid::from_network_bytes([1; 16]);
            let device = CanonicalUuid::from_network_bytes([2; 16]);
            let conversation = CanonicalUuid::from_network_bytes([3; 16]);
            let asset = CanonicalUuid::from_network_bytes([4; 16]);
            let validity = KeyValidityWindow::starting_at(NOW);
            prop_assert!(selector.is_ok());
            prop_assert!(device.is_ok());
            prop_assert!(conversation.is_ok());
            prop_assert!(asset.is_ok());
            prop_assert!(validity.is_ok());
            if let (Ok(selector), Ok(device), Ok(conversation), Ok(asset), Ok(validity)) =
                (selector, device, conversation, asset, validity)
            {
                let local = LocalAgreementKey::from_protected_secret(
                    Zeroizing::new([0x42; KEY_BYTES]),
                    device,
                    selector,
                    validity,
                );
                prop_assert!(local.is_ok());
                if let Ok(local) = local {
                    let sealed = SealedManifest::parse(selector, &blob);
                    prop_assert!(sealed.is_ok());
                    if let Ok(sealed) = sealed {
                        let result = open_manifest(
                            &sealed,
                            &local,
                            TrustedSender {
                                device_id: device,
                                identity_public_key: [7; KEY_BYTES],
                            },
                            conversation,
                            asset,
                            NOW,
                        );
                        prop_assert!(result.is_err());
                    }
                }
            }
        }
    }
}
