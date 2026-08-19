//! Canonical signed device-key bundles and their public-only pin repository.
//!
//! A bundle self-signs one rotating X25519 public key with the device's
//! long-lived Ed25519 identity. P2 deliberately does not bind that self-signed
//! identity to an account; P3 human verification remains a separate gate.

use std::path::Path;

use libsodium_rs::{
    crypto_box, crypto_scalarmult, crypto_sign, crypto_verify, ensure_init, random,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::key_material::RootKeyMaterial;

const DOMAIN: &[u8; 19] = b"MOWY-DEVICE-KEY-V1\0";
const SIGNED_BYTES: usize = 115;
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const UUID_BYTES: usize = 16;
const TIMESTAMP_BYTES: usize = 8;
const KEY_VALIDITY_SECONDS: u64 = 30 * 24 * 60 * 60;
const RETENTION_GRACE_SECONDS: u64 = 7 * 24 * 60 * 60;
const PUBLIC_KEY_VALIDATION_SCALAR: [u8; KEY_BYTES] = [0x42; KEY_BYTES];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyBundleError {
    InvalidInput,
    NotYetValid,
    Expired,
    Signature,
    IdentityChanged,
    Rollback,
    Storage,
    Cryptography,
}

/// A UUID that is already in RFC 4122 network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalUuid([u8; UUID_BYTES]);

impl CanonicalUuid {
    pub(crate) fn from_network_bytes(bytes: [u8; UUID_BYTES]) -> Result<Self, KeyBundleError> {
        if crypto_verify::verify_16(&bytes, &[0; UUID_BYTES]) {
            return Err(KeyBundleError::InvalidInput);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_network_bytes(&self) -> &[u8; UUID_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyValidityWindow {
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

impl KeyValidityWindow {
    pub(crate) fn starting_at(not_before: u64) -> Result<Self, KeyBundleError> {
        let not_after = not_before
            .checked_add(KEY_VALIDITY_SECONDS)
            .ok_or(KeyBundleError::InvalidInput)?;
        Ok(Self {
            not_before,
            not_after,
        })
    }

    pub(crate) fn from_bounds(not_before: u64, not_after: u64) -> Result<Self, KeyBundleError> {
        if not_before >= not_after
            || not_after.checked_sub(not_before) != Some(KEY_VALIDITY_SECONDS)
        {
            return Err(KeyBundleError::InvalidInput);
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    pub(crate) fn require_active_at(&self, now: u64) -> Result<(), KeyBundleError> {
        if now < self.not_before {
            return Err(KeyBundleError::NotYetValid);
        }
        if now >= self.not_after {
            return Err(KeyBundleError::Expired);
        }
        Ok(())
    }
}

/// Every field is public metadata; private keys are never part of this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceKeyBundle {
    pub(crate) account_id: CanonicalUuid,
    pub(crate) device_id: CanonicalUuid,
    pub(crate) agreement_key_id: CanonicalUuid,
    pub(crate) identity_public_key: [u8; KEY_BYTES],
    pub(crate) agreement_public_key: [u8; KEY_BYTES],
    pub(crate) validity: KeyValidityWindow,
    pub(crate) signature: [u8; SIGNATURE_BYTES],
}

impl DeviceKeyBundle {
    fn signed_bytes(&self) -> [u8; SIGNED_BYTES] {
        canonical_signed_bytes(
            self.account_id,
            self.device_id,
            self.agreement_key_id,
            self.validity,
            &self.agreement_public_key,
        )
    }
}

/// A newly generated agreement secret awaiting platform-protected persistence.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct GeneratedAgreementKey {
    secret: [u8; KEY_BYTES],
    #[zeroize(skip)]
    pub(crate) key_id: CanonicalUuid,
    #[zeroize(skip)]
    pub(crate) validity: KeyValidityWindow,
}

impl GeneratedAgreementKey {
    /// This view is consumed only by the native protected-storage adapter.
    pub(crate) fn expose_for_protected_storage(&self) -> &[u8; KEY_BYTES] {
        &self.secret
    }
}

/// Platform storage must durably accept a rotated secret before publication.
pub(crate) trait RotatedAgreementKeyStore {
    fn store_new(&mut self, key: &GeneratedAgreementKey) -> Result<(), KeyBundleError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionDecision {
    Retain,
    Delete,
}

pub(crate) fn rotation_due(validity: KeyValidityWindow, now: u64) -> bool {
    now >= validity.not_after
}

pub(crate) fn retention_decision(
    validity: KeyValidityWindow,
    now: u64,
    unconsumed_manifest_count: u64,
) -> Result<RetentionDecision, KeyBundleError> {
    let delete_after = validity
        .not_after
        .checked_add(RETENTION_GRACE_SECONDS)
        .ok_or(KeyBundleError::InvalidInput)?;
    if now < delete_after || unconsumed_manifest_count != 0 {
        return Ok(RetentionDecision::Retain);
    }
    Ok(RetentionDecision::Delete)
}

/// Publishes the X25519 key currently held in the exact 96-byte root item.
pub(crate) fn sign_current_bundle(
    root: &RootKeyMaterial,
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    validity: KeyValidityWindow,
) -> Result<DeviceKeyBundle, KeyBundleError> {
    ensure_init().map_err(|_| KeyBundleError::Cryptography)?;
    let identity = crypto_sign::KeyPair::from_seed(root.identity_seed())
        .map_err(|_| KeyBundleError::Cryptography)?;
    let agreement_secret = crypto_box::SecretKey::from_bytes(root.agreement_secret())
        .map_err(|_| KeyBundleError::Cryptography)?;
    let agreement_public =
        crypto_scalarmult::curve25519::scalarmult_base(agreement_secret.as_bytes())
            .map_err(|_| KeyBundleError::Cryptography)?;

    sign_with_identity(
        &identity,
        account_id,
        device_id,
        agreement_key_id,
        validity,
        agreement_public,
    )
}

/// Persists a fresh X25519 secret before returning its publishable bundle.
pub(crate) fn rotate_and_sign_bundle<S: RotatedAgreementKeyStore>(
    store: &mut S,
    root: &RootKeyMaterial,
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    previous_validity: KeyValidityWindow,
    now: u64,
) -> Result<DeviceKeyBundle, KeyBundleError> {
    let (generated, bundle) = prepare_rotated_bundle(
        root,
        account_id,
        device_id,
        agreement_key_id,
        previous_validity,
        now,
    )?;
    store.store_new(&generated)?;
    Ok(bundle)
}

fn prepare_rotated_bundle(
    root: &RootKeyMaterial,
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    previous_validity: KeyValidityWindow,
    now: u64,
) -> Result<(GeneratedAgreementKey, DeviceKeyBundle), KeyBundleError> {
    if !rotation_due(previous_validity, now) {
        return Err(KeyBundleError::NotYetValid);
    }
    ensure_init().map_err(|_| KeyBundleError::Cryptography)?;
    let identity = crypto_sign::KeyPair::from_seed(root.identity_seed())
        .map_err(|_| KeyBundleError::Cryptography)?;
    let mut agreement_seed = Zeroizing::new([0_u8; KEY_BYTES]);
    random::fill_bytes(agreement_seed.as_mut());
    let agreement = crypto_box::KeyPair::from_seed(agreement_seed.as_ref())
        .map_err(|_| KeyBundleError::Cryptography)?;
    let validity = KeyValidityWindow::starting_at(now)?;
    let bundle = sign_with_identity(
        &identity,
        account_id,
        device_id,
        agreement_key_id,
        validity,
        *agreement.public_key.as_bytes(),
    )?;
    let generated = GeneratedAgreementKey {
        secret: *agreement.secret_key.as_bytes(),
        key_id: agreement_key_id,
        validity,
    };
    Ok((generated, bundle))
}

fn sign_with_identity(
    identity: &crypto_sign::KeyPair,
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    validity: KeyValidityWindow,
    agreement_public_key: [u8; KEY_BYTES],
) -> Result<DeviceKeyBundle, KeyBundleError> {
    KeyValidityWindow::from_bounds(validity.not_before, validity.not_after)?;
    validate_agreement_public_key(&agreement_public_key)?;
    let mut bundle = DeviceKeyBundle {
        account_id,
        device_id,
        agreement_key_id,
        identity_public_key: *identity.public_key.as_bytes(),
        agreement_public_key,
        validity,
        signature: [0; SIGNATURE_BYTES],
    };
    bundle.signature = crypto_sign::sign_detached(&bundle.signed_bytes(), &identity.secret_key)
        .map_err(|_| KeyBundleError::Cryptography)?;
    Ok(bundle)
}

pub(crate) fn verify_bundle_at(bundle: &DeviceKeyBundle, now: u64) -> Result<(), KeyBundleError> {
    ensure_init().map_err(|_| KeyBundleError::Cryptography)?;
    KeyValidityWindow::from_bounds(bundle.validity.not_before, bundle.validity.not_after)?;
    validate_agreement_public_key(&bundle.agreement_public_key)?;
    let identity = crypto_sign::PublicKey::from_bytes_exact(bundle.identity_public_key);
    if !crypto_sign::verify_detached(&bundle.signature, &bundle.signed_bytes(), &identity) {
        return Err(KeyBundleError::Signature);
    }
    bundle.validity.require_active_at(now)
}

fn validate_agreement_public_key(public_key: &[u8; KEY_BYTES]) -> Result<(), KeyBundleError> {
    let _validation_result = Zeroizing::new(
        crypto_scalarmult::curve25519::scalarmult(&PUBLIC_KEY_VALIDATION_SCALAR, public_key)
            .map_err(|_| KeyBundleError::InvalidInput)?,
    );
    Ok(())
}

fn canonical_signed_bytes(
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    validity: KeyValidityWindow,
    agreement_public_key: &[u8; KEY_BYTES],
) -> [u8; SIGNED_BYTES] {
    let mut bytes = [0_u8; SIGNED_BYTES];
    let mut offset = 0;
    append(&mut bytes, &mut offset, DOMAIN);
    append(&mut bytes, &mut offset, account_id.as_network_bytes());
    append(&mut bytes, &mut offset, device_id.as_network_bytes());
    append(&mut bytes, &mut offset, agreement_key_id.as_network_bytes());
    append(&mut bytes, &mut offset, &validity.not_before.to_be_bytes());
    append(&mut bytes, &mut offset, &validity.not_after.to_be_bytes());
    append(&mut bytes, &mut offset, agreement_public_key);
    bytes
}

fn append<const N: usize>(output: &mut [u8], offset: &mut usize, field: &[u8; N]) {
    let end = *offset + N;
    output[*offset..end].copy_from_slice(field);
    *offset = end;
}

/// Plain SQLite storage for public bundle fields only.
pub(crate) struct PublishedKeyRepository {
    connection: Connection,
}

impl PublishedKeyRepository {
    pub(crate) fn open(path: &Path) -> Result<Self, KeyBundleError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection =
            Connection::open_with_flags(path, flags).map_err(|_| KeyBundleError::Storage)?;
        Self::from_connection(connection)
    }

    #[cfg(test)]
    fn in_memory() -> Result<Self, KeyBundleError> {
        let connection = Connection::open_in_memory().map_err(|_| KeyBundleError::Storage)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, KeyBundleError> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = DELETE;
                 PRAGMA synchronous = FULL;
                 PRAGMA secure_delete = ON;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA trusted_schema = OFF;
                 CREATE TABLE IF NOT EXISTS published_device_key_bundles (
                   account_id BLOB NOT NULL CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16 AND account_id != zeroblob(16)),
                   device_id BLOB NOT NULL CHECK(typeof(device_id) = 'blob' AND length(device_id) = 16 AND device_id != zeroblob(16)),
                   agreement_key_id BLOB NOT NULL CHECK(typeof(agreement_key_id) = 'blob' AND length(agreement_key_id) = 16 AND agreement_key_id != zeroblob(16)),
                   not_before BLOB NOT NULL CHECK(typeof(not_before) = 'blob' AND length(not_before) = 8),
                   not_after BLOB NOT NULL CHECK(typeof(not_after) = 'blob' AND length(not_after) = 8),
                   identity_public_key BLOB NOT NULL CHECK(typeof(identity_public_key) = 'blob' AND length(identity_public_key) = 32),
                   agreement_public_key BLOB NOT NULL CHECK(typeof(agreement_public_key) = 'blob' AND length(agreement_public_key) = 32),
                   signature BLOB NOT NULL CHECK(typeof(signature) = 'blob' AND length(signature) = 64),
                   PRIMARY KEY (account_id, device_id)
                 ) WITHOUT ROWID, STRICT;",
            )
            .map_err(|_| KeyBundleError::Storage)?;
        Ok(Self { connection })
    }

    /// Pins the first self-signed identity for an account/device tuple.
    ///
    /// Later P3 identity binding is deliberately absent. Once locally pinned,
    /// however, a different identity, a rollback, or same-time equivocation is
    /// blocked without changing the stored row.
    pub(crate) fn pin_verified(
        &mut self,
        bundle: &DeviceKeyBundle,
        now: u64,
    ) -> Result<(), KeyBundleError> {
        verify_bundle_at(bundle, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| KeyBundleError::Storage)?;
        let existing = load_bundle(&transaction, bundle.account_id, bundle.device_id)?;

        if let Some(current) = existing {
            if !crypto_verify::verify_32(&current.identity_public_key, &bundle.identity_public_key)
            {
                return Err(KeyBundleError::IdentityChanged);
            }
            if bundle.validity.not_before < current.validity.not_before {
                return Err(KeyBundleError::Rollback);
            }
            if bundle.validity.not_before == current.validity.not_before {
                if same_public_bundle(&current, bundle) {
                    transaction.commit().map_err(|_| KeyBundleError::Storage)?;
                    return Ok(());
                }
                return Err(KeyBundleError::Rollback);
            }
        }

        transaction
            .execute(
                "INSERT INTO published_device_key_bundles (
                   account_id, device_id, agreement_key_id, not_before, not_after,
                   identity_public_key, agreement_public_key, signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(account_id, device_id) DO UPDATE SET
                   agreement_key_id = excluded.agreement_key_id,
                   not_before = excluded.not_before,
                   not_after = excluded.not_after,
                   identity_public_key = excluded.identity_public_key,
                   agreement_public_key = excluded.agreement_public_key,
                   signature = excluded.signature",
                params![
                    bundle.account_id.as_network_bytes().as_slice(),
                    bundle.device_id.as_network_bytes().as_slice(),
                    bundle.agreement_key_id.as_network_bytes().as_slice(),
                    bundle.validity.not_before.to_be_bytes().as_slice(),
                    bundle.validity.not_after.to_be_bytes().as_slice(),
                    bundle.identity_public_key.as_slice(),
                    bundle.agreement_public_key.as_slice(),
                    bundle.signature.as_slice(),
                ],
            )
            .map_err(|_| KeyBundleError::Storage)?;
        transaction.commit().map_err(|_| KeyBundleError::Storage)
    }

    pub(crate) fn load_verified_at(
        &self,
        account_id: CanonicalUuid,
        device_id: CanonicalUuid,
        now: u64,
    ) -> Result<Option<DeviceKeyBundle>, KeyBundleError> {
        let bundle = load_bundle(&self.connection, account_id, device_id)?;
        if let Some(stored) = &bundle {
            verify_bundle_at(stored, now)?;
        }
        Ok(bundle)
    }
}

fn load_bundle(
    connection: &Connection,
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
) -> Result<Option<DeviceKeyBundle>, KeyBundleError> {
    connection
        .query_row(
            "SELECT account_id, device_id, agreement_key_id, not_before, not_after,
                    identity_public_key, agreement_public_key, signature
             FROM published_device_key_bundles
             WHERE account_id = ?1 AND device_id = ?2",
            params![
                account_id.as_network_bytes().as_slice(),
                device_id.as_network_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| KeyBundleError::Storage)?
        .map(decode_bundle_row)
        .transpose()
}

type BundleRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn decode_bundle_row(row: BundleRow) -> Result<DeviceKeyBundle, KeyBundleError> {
    let account_id = decode_stored_uuid(row.0)?;
    let device_id = decode_stored_uuid(row.1)?;
    let agreement_key_id = decode_stored_uuid(row.2)?;
    let not_before = u64::from_be_bytes(exact_array(row.3)?);
    let not_after = u64::from_be_bytes(exact_array(row.4)?);
    Ok(DeviceKeyBundle {
        account_id,
        device_id,
        agreement_key_id,
        identity_public_key: exact_array(row.5)?,
        agreement_public_key: exact_array(row.6)?,
        validity: KeyValidityWindow::from_bounds(not_before, not_after)
            .map_err(|_| KeyBundleError::Storage)?,
        signature: exact_array(row.7)?,
    })
}

fn decode_stored_uuid(bytes: Vec<u8>) -> Result<CanonicalUuid, KeyBundleError> {
    CanonicalUuid::from_network_bytes(exact_array(bytes)?).map_err(|_| KeyBundleError::Storage)
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], KeyBundleError> {
    bytes.try_into().map_err(|_| KeyBundleError::Storage)
}

fn same_public_bundle(left: &DeviceKeyBundle, right: &DeviceKeyBundle) -> bool {
    crypto_verify::verify_16(
        left.account_id.as_network_bytes(),
        right.account_id.as_network_bytes(),
    ) && crypto_verify::verify_16(
        left.device_id.as_network_bytes(),
        right.device_id.as_network_bytes(),
    ) && crypto_verify::verify_16(
        left.agreement_key_id.as_network_bytes(),
        right.agreement_key_id.as_network_bytes(),
    ) && left.validity == right.validity
        && crypto_verify::verify_32(&left.identity_public_key, &right.identity_public_key)
        && crypto_verify::verify_32(&left.agreement_public_key, &right.agreement_public_key)
        && crypto_verify::verify_64(&left.signature, &right.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; UUID_BYTES] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const DEVICE: [u8; UUID_BYTES] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    const KEY_ID: [u8; UUID_BYTES] = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];
    const NOT_BEFORE: u64 = 1_770_000_000;

    fn uuid(bytes: [u8; UUID_BYTES]) -> Result<CanonicalUuid, KeyBundleError> {
        CanonicalUuid::from_network_bytes(bytes)
    }

    fn identity(seed_start: u8) -> Result<crypto_sign::KeyPair, KeyBundleError> {
        let seed: [u8; KEY_BYTES] =
            std::array::from_fn(|index| seed_start.wrapping_add(index as u8));
        crypto_sign::KeyPair::from_seed(&seed).map_err(|_| KeyBundleError::Cryptography)
    }

    struct StoredTestAgreementKey {
        secret: Zeroizing<[u8; KEY_BYTES]>,
        key_id: CanonicalUuid,
        validity: KeyValidityWindow,
    }

    #[derive(Default)]
    struct MemoryRotatedKeyStore {
        stored: Vec<StoredTestAgreementKey>,
        fail: bool,
    }

    impl RotatedAgreementKeyStore for MemoryRotatedKeyStore {
        fn store_new(&mut self, key: &GeneratedAgreementKey) -> Result<(), KeyBundleError> {
            if self.fail {
                return Err(KeyBundleError::Storage);
            }
            let mut secret = Zeroizing::new([0_u8; KEY_BYTES]);
            secret.copy_from_slice(key.expose_for_protected_storage());
            self.stored.push(StoredTestAgreementKey {
                secret,
                key_id: key.key_id,
                validity: key.validity,
            });
            Ok(())
        }
    }

    fn bundle(
        identity: &crypto_sign::KeyPair,
        agreement_byte: u8,
        key_id: [u8; UUID_BYTES],
        not_before: u64,
    ) -> Result<DeviceKeyBundle, KeyBundleError> {
        sign_with_identity(
            identity,
            uuid(ACCOUNT)?,
            uuid(DEVICE)?,
            uuid(key_id)?,
            KeyValidityWindow::starting_at(not_before)?,
            [agreement_byte; KEY_BYTES],
        )
    }

    #[test]
    fn canonical_vector_matches_exact_bytes_and_signature() -> Result<(), KeyBundleError> {
        let identity = identity(0)?;
        let agreement_seed: [u8; KEY_BYTES] = std::array::from_fn(|index| 0x20 + index as u8);
        let agreement = crypto_box::KeyPair::from_seed(&agreement_seed)
            .map_err(|_| KeyBundleError::Cryptography)?;
        let bundle = sign_with_identity(
            &identity,
            uuid(ACCOUNT)?,
            uuid(DEVICE)?,
            uuid(KEY_ID)?,
            KeyValidityWindow::starting_at(NOT_BEFORE)?,
            *agreement.public_key.as_bytes(),
        )?;

        const EXPECTED_AGREEMENT_PUBLIC: [u8; KEY_BYTES] = [
            0x57, 0x30, 0x80, 0x0a, 0xb3, 0x40, 0xfc, 0xb1, 0x8c, 0xe5, 0x11, 0x1e, 0xda, 0x9d,
            0x70, 0x5f, 0x91, 0x38, 0x8b, 0x41, 0xe4, 0x54, 0x4c, 0xbd, 0x10, 0x3b, 0xa5, 0x94,
            0x2d, 0xb2, 0x23, 0x3e,
        ];
        const EXPECTED_IDENTITY_PUBLIC: [u8; KEY_BYTES] = [
            0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b,
            0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64,
            0x12, 0x55, 0x31, 0xb8,
        ];
        const EXPECTED_SIGNATURE: [u8; SIGNATURE_BYTES] = [
            0xb1, 0x61, 0xee, 0xc1, 0x1c, 0xbd, 0x62, 0xf8, 0x73, 0x36, 0x0b, 0x1b, 0xb8, 0x92,
            0x88, 0x21, 0x88, 0x04, 0xbb, 0xec, 0xf9, 0x50, 0xcd, 0xee, 0x85, 0x5c, 0xdd, 0x9a,
            0xb3, 0x54, 0x27, 0xc2, 0x65, 0x0d, 0xd6, 0xca, 0xf8, 0x14, 0x64, 0x10, 0x11, 0x11,
            0x39, 0x0b, 0xfe, 0xc9, 0x0b, 0xf3, 0x4c, 0x14, 0x4a, 0x72, 0xb6, 0x8f, 0xb7, 0x98,
            0x76, 0x2c, 0x6f, 0xc9, 0xa5, 0x73, 0x1c, 0x0e,
        ];
        assert_eq!(bundle.signed_bytes().len(), SIGNED_BYTES);
        assert_eq!(bundle.identity_public_key, EXPECTED_IDENTITY_PUBLIC);
        assert_eq!(bundle.agreement_public_key, EXPECTED_AGREEMENT_PUBLIC);
        assert_eq!(bundle.signature, EXPECTED_SIGNATURE);
        assert_eq!(
            include_str!("../vectors/device-key-bundle-v1.txt"),
            "# Mowy device key bundle v1 public test vector\n\
identity_seed=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
identity_public_key=03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8\n\
agreement_seed=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n\
agreement_public_key=5730800ab340fcb18ce5111eda9d705f91388b41e4544cbd103ba5942db2233e\n\
account_uuid=00112233445566778899aabbccddeeff\n\
device_uuid=102132435465768798a9bacbdcedfe0f\n\
agreement_key_uuid=ffeeddccbbaa99887766554433221100\n\
not_before_u64be=0000000069800e80\n\
not_after_u64be=0000000069a79b80\n\
signed_bytes=4d4f57592d4445564943452d4b45592d56310000112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0fffeeddccbbaa998877665544332211000000000069800e800000000069a79b805730800ab340fcb18ce5111eda9d705f91388b41e4544cbd103ba5942db2233e\n\
signature=b161eec11cbd62f873360b1bb89288218804bbecf950cdee855cdd9ab35427c2650dd6caf81464101111390bfec90bf34c144a72b68fb798762c6fc9a5731c0e\n"
        );
        Ok(())
    }

    #[test]
    fn verifies_signature_and_rejects_tampering_or_wrong_signer() -> Result<(), KeyBundleError> {
        let signer = identity(1)?;
        let original = bundle(&signer, 7, KEY_ID, NOT_BEFORE)?;
        verify_bundle_at(&original, NOT_BEFORE)?;

        let mut tampered_key = original;
        tampered_key.agreement_public_key[0] ^= 1;
        assert_eq!(
            verify_bundle_at(&tampered_key, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );

        let mut tampered_account = original;
        tampered_account.account_id.0[0] ^= 1;
        assert_eq!(
            verify_bundle_at(&tampered_account, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );

        let mut tampered_device = original;
        tampered_device.device_id.0[0] ^= 1;
        assert_eq!(
            verify_bundle_at(&tampered_device, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );

        let mut tampered_key_id = original;
        tampered_key_id.agreement_key_id.0[0] ^= 1;
        assert_eq!(
            verify_bundle_at(&tampered_key_id, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );

        let mut tampered_window = original;
        tampered_window.validity.not_before += 1;
        tampered_window.validity.not_after += 1;
        assert_eq!(
            verify_bundle_at(&tampered_window, NOT_BEFORE + 1),
            Err(KeyBundleError::Signature)
        );

        let mut tampered_signature = original;
        tampered_signature.signature[63] ^= 1;
        assert_eq!(
            verify_bundle_at(&tampered_signature, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );

        let mut low_order_agreement = original;
        low_order_agreement.agreement_public_key = [0; KEY_BYTES];
        assert_eq!(
            verify_bundle_at(&low_order_agreement, NOT_BEFORE),
            Err(KeyBundleError::InvalidInput)
        );

        let wrong_signer = identity(2)?;
        let mut substituted = original;
        substituted.identity_public_key = *wrong_signer.public_key.as_bytes();
        assert_eq!(
            verify_bundle_at(&substituted, NOT_BEFORE),
            Err(KeyBundleError::Signature)
        );
        Ok(())
    }

    #[test]
    fn enforces_exact_window_and_active_boundaries() -> Result<(), KeyBundleError> {
        let signer = identity(3)?;
        let current = bundle(&signer, 8, KEY_ID, NOT_BEFORE)?;

        assert_eq!(
            verify_bundle_at(&current, NOT_BEFORE - 1),
            Err(KeyBundleError::NotYetValid)
        );
        verify_bundle_at(&current, NOT_BEFORE)?;
        verify_bundle_at(&current, current.validity.not_after - 1)?;
        assert_eq!(
            verify_bundle_at(&current, current.validity.not_after),
            Err(KeyBundleError::Expired)
        );
        assert_eq!(
            KeyValidityWindow::from_bounds(NOT_BEFORE, NOT_BEFORE),
            Err(KeyBundleError::InvalidInput)
        );
        assert_eq!(
            KeyValidityWindow::from_bounds(NOT_BEFORE, NOT_BEFORE + KEY_VALIDITY_SECONDS - 1),
            Err(KeyBundleError::InvalidInput)
        );
        assert_eq!(
            KeyValidityWindow::starting_at(u64::MAX),
            Err(KeyBundleError::InvalidInput)
        );
        Ok(())
    }

    #[test]
    fn rejects_nil_identifiers() {
        assert_eq!(
            CanonicalUuid::from_network_bytes([0; UUID_BYTES]),
            Err(KeyBundleError::InvalidInput)
        );
    }

    #[test]
    fn pins_reverifies_and_rotates_same_identity() -> Result<(), KeyBundleError> {
        let signer = identity(4)?;
        let first = bundle(&signer, 9, KEY_ID, NOT_BEFORE)?;
        let second_key_id = [0x55; UUID_BYTES];
        let second = bundle(
            &signer,
            10,
            second_key_id,
            NOT_BEFORE + KEY_VALIDITY_SECONDS,
        )?;
        let mut repository = PublishedKeyRepository::in_memory()?;

        repository.pin_verified(&first, NOT_BEFORE)?;
        repository.pin_verified(&first, NOT_BEFORE)?;
        let stored_first = repository
            .load_verified_at(first.account_id, first.device_id, NOT_BEFORE)?
            .ok_or(KeyBundleError::Storage)?;
        verify_bundle_at(&stored_first, NOT_BEFORE)?;

        repository.pin_verified(&second, second.validity.not_before)?;
        let stored_second = repository
            .load_verified_at(
                second.account_id,
                second.device_id,
                second.validity.not_before,
            )?
            .ok_or(KeyBundleError::Storage)?;
        assert!(same_public_bundle(&stored_second, &second));
        verify_bundle_at(&stored_second, second.validity.not_before)?;
        Ok(())
    }

    #[test]
    fn identity_change_and_rollback_leave_pin_unchanged() -> Result<(), KeyBundleError> {
        let original_signer = identity(5)?;
        let replacement_signer = identity(6)?;
        let original = bundle(&original_signer, 11, KEY_ID, NOT_BEFORE)?;
        let changed = bundle(&replacement_signer, 12, [0x66; UUID_BYTES], NOT_BEFORE + 1)?;
        let equivocation = bundle(&original_signer, 13, [0x77; UUID_BYTES], NOT_BEFORE)?;
        let mut repository = PublishedKeyRepository::in_memory()?;
        repository.pin_verified(&original, NOT_BEFORE)?;

        assert_eq!(
            repository.pin_verified(&changed, NOT_BEFORE + 1),
            Err(KeyBundleError::IdentityChanged)
        );
        assert_eq!(
            repository.pin_verified(&equivocation, NOT_BEFORE),
            Err(KeyBundleError::Rollback)
        );
        let stored = repository
            .load_verified_at(original.account_id, original.device_id, NOT_BEFORE)?
            .ok_or(KeyBundleError::Storage)?;
        assert!(same_public_bundle(&stored, &original));
        Ok(())
    }

    #[test]
    fn invalid_or_expired_bundle_never_mutates_pin() -> Result<(), KeyBundleError> {
        let signer = identity(7)?;
        let first = bundle(&signer, 14, KEY_ID, NOT_BEFORE)?;
        let mut invalid = bundle(
            &signer,
            15,
            [0x88; UUID_BYTES],
            NOT_BEFORE + KEY_VALIDITY_SECONDS,
        )?;
        invalid.signature[0] ^= 1;
        let mut repository = PublishedKeyRepository::in_memory()?;
        repository.pin_verified(&first, NOT_BEFORE)?;

        assert_eq!(
            repository.pin_verified(&invalid, invalid.validity.not_before),
            Err(KeyBundleError::Signature)
        );
        assert_eq!(
            repository.pin_verified(&first, first.validity.not_after),
            Err(KeyBundleError::Expired)
        );
        let stored = repository
            .load_verified_at(first.account_id, first.device_id, NOT_BEFORE)?
            .ok_or(KeyBundleError::Storage)?;
        assert!(same_public_bundle(&stored, &first));
        Ok(())
    }

    #[test]
    fn generates_fresh_rotation_only_after_schedule_boundary() -> Result<(), KeyBundleError> {
        let (root, _) =
            crate::key_material::generate().map_err(|_| KeyBundleError::Cryptography)?;
        let previous = KeyValidityWindow::starting_at(NOT_BEFORE)?;
        let mut store = MemoryRotatedKeyStore::default();
        assert!(matches!(
            rotate_and_sign_bundle(
                &mut store,
                &root,
                uuid(ACCOUNT)?,
                uuid(DEVICE)?,
                uuid(KEY_ID)?,
                previous,
                previous.not_after - 1,
            ),
            Err(KeyBundleError::NotYetValid)
        ));
        assert!(store.stored.is_empty());

        let mut failing_store = MemoryRotatedKeyStore {
            stored: Vec::new(),
            fail: true,
        };
        assert!(matches!(
            rotate_and_sign_bundle(
                &mut failing_store,
                &root,
                uuid(ACCOUNT)?,
                uuid(DEVICE)?,
                uuid(KEY_ID)?,
                previous,
                previous.not_after,
            ),
            Err(KeyBundleError::Storage)
        ));
        assert!(failing_store.stored.is_empty());

        let first_bundle = rotate_and_sign_bundle(
            &mut store,
            &root,
            uuid(ACCOUNT)?,
            uuid(DEVICE)?,
            uuid(KEY_ID)?,
            previous,
            previous.not_after,
        )?;
        let second_bundle = rotate_and_sign_bundle(
            &mut store,
            &root,
            uuid(ACCOUNT)?,
            uuid(DEVICE)?,
            uuid([0x44; UUID_BYTES])?,
            previous,
            previous.not_after,
        )?;
        let first_key = store.stored.first().ok_or(KeyBundleError::Storage)?;
        let second_key = store.stored.get(1).ok_or(KeyBundleError::Storage)?;
        let first_derived =
            crypto_scalarmult::curve25519::scalarmult_base(first_key.secret.as_ref())
                .map_err(|_| KeyBundleError::Cryptography)?;

        assert_eq!(first_key.key_id, first_bundle.agreement_key_id);
        assert_eq!(first_key.validity, first_bundle.validity);
        assert_eq!(first_bundle.validity.not_before, previous.not_after);
        assert_eq!(first_derived, first_bundle.agreement_public_key);
        assert!(!crypto_verify::verify_32(
            first_key.secret.as_ref(),
            second_key.secret.as_ref(),
        ));
        assert!(!crypto_verify::verify_32(
            &first_bundle.agreement_public_key,
            &second_bundle.agreement_public_key,
        ));
        verify_bundle_at(&first_bundle, first_bundle.validity.not_before)?;
        verify_bundle_at(&second_bundle, second_bundle.validity.not_before)?;
        Ok(())
    }

    #[test]
    fn sqlite_schema_is_public_only_strict_and_correctness_hardened() -> Result<(), KeyBundleError>
    {
        let path = std::env::temp_dir().join(format!(
            "mowy-p2-public-key-schema-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let repository = PublishedKeyRepository::open(&path)?;

        let foreign_keys: u8 = repository
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        let journal_mode: String = repository
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        let synchronous: u8 = repository
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        let secure_delete: u8 = repository
            .connection
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        let temp_store: u8 = repository
            .connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        let trusted_schema: u8 = repository
            .connection
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .map_err(|_| KeyBundleError::Storage)?;
        assert_eq!(foreign_keys, 1);
        assert_eq!(journal_mode, "delete");
        assert_eq!(synchronous, 2);
        assert_eq!(secure_delete, 1);
        assert_eq!(temp_store, 2);
        assert_eq!(trusted_schema, 0);

        let column_names = {
            let mut statement = repository
                .connection
                .prepare("PRAGMA table_info(published_device_key_bundles)")
                .map_err(|_| KeyBundleError::Storage)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|_| KeyBundleError::Storage)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| KeyBundleError::Storage)?
        };
        assert_eq!(
            column_names,
            [
                "account_id",
                "device_id",
                "agreement_key_id",
                "not_before",
                "not_after",
                "identity_public_key",
                "agreement_public_key",
                "signature",
            ]
        );

        let malformed = repository.connection.execute(
            "INSERT INTO published_device_key_bundles VALUES
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                [1_u8; UUID_BYTES - 1].as_slice(),
                [2_u8; UUID_BYTES].as_slice(),
                [3_u8; UUID_BYTES].as_slice(),
                1_u64.to_be_bytes().as_slice(),
                (1_u64 + KEY_VALIDITY_SECONDS).to_be_bytes().as_slice(),
                [4_u8; KEY_BYTES].as_slice(),
                [5_u8; KEY_BYTES].as_slice(),
                [6_u8; SIGNATURE_BYTES].as_slice(),
            ],
        );
        assert!(malformed.is_err());

        let nil_identifier = repository.connection.execute(
            "INSERT INTO published_device_key_bundles VALUES
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                [0_u8; UUID_BYTES].as_slice(),
                [2_u8; UUID_BYTES].as_slice(),
                [3_u8; UUID_BYTES].as_slice(),
                1_u64.to_be_bytes().as_slice(),
                (1_u64 + KEY_VALIDITY_SECONDS).to_be_bytes().as_slice(),
                [4_u8; KEY_BYTES].as_slice(),
                [5_u8; KEY_BYTES].as_slice(),
                [6_u8; SIGNATURE_BYTES].as_slice(),
            ],
        );
        assert!(nil_identifier.is_err());

        drop(repository);
        std::fs::remove_file(path).map_err(|_| KeyBundleError::Storage)?;
        Ok(())
    }

    #[test]
    fn rotation_and_retention_use_exact_boundaries() -> Result<(), KeyBundleError> {
        let validity = KeyValidityWindow::starting_at(NOT_BEFORE)?;
        let grace_end = validity.not_after + RETENTION_GRACE_SECONDS;

        assert!(!rotation_due(validity, validity.not_after - 1));
        assert!(rotation_due(validity, validity.not_after));
        assert_eq!(
            retention_decision(validity, grace_end - 1, 0)?,
            RetentionDecision::Retain
        );
        assert_eq!(
            retention_decision(validity, grace_end, 1)?,
            RetentionDecision::Retain
        );
        assert_eq!(
            retention_decision(validity, grace_end, 0)?,
            RetentionDecision::Delete
        );
        let overflow_validity = KeyValidityWindow::starting_at(u64::MAX - KEY_VALIDITY_SECONDS)?;
        assert_eq!(
            retention_decision(overflow_validity, u64::MAX, 0),
            Err(KeyBundleError::InvalidInput)
        );
        Ok(())
    }
}
