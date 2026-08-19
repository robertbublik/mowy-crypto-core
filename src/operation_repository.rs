//! Durable public operation state for the attachment file lifecycle.

use std::path::Path;

use libsodium_rs::{crypto_verify, utils};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::attachment_manifest::{AttachmentManifest, AttachmentManifestError, DIGEST_BYTES};
use crate::key_bundle::CanonicalUuid;
use crate::sealed_manifest::{OpenedManifest, SEALED_BYTES, SealedManifest};

const SENDER_ENCRYPTING: i64 = 1;
const SENDER_OUTBOX: i64 = 2;
const RECEIVER_WAITING: i64 = 1;
const WAITING_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationRepositoryError {
    InvalidInput,
    Conflict,
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SenderState {
    Encrypting,
    Outbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiverCommit {
    Created,
    Existing(CanonicalUuid),
}

pub(crate) struct StoredOutbox {
    pub(crate) sealed: SealedManifest,
    pub(crate) ciphertext_name: String,
    pub(crate) plaintext_length: u64,
    pub(crate) ciphertext_length: u64,
    pub(crate) ciphertext_digest: [u8; DIGEST_BYTES],
}

pub(crate) struct WaitingOperation {
    pub(crate) sealed: SealedManifest,
    pub(crate) conversation_id: CanonicalUuid,
    pub(crate) asset_id: CanonicalUuid,
    pub(crate) sender_device_id: CanonicalUuid,
    pub(crate) ciphertext_name: String,
    pub(crate) plaintext_temp_name: String,
    pub(crate) plaintext_length: u64,
    pub(crate) ciphertext_length: u64,
    pub(crate) ciphertext_digest: [u8; DIGEST_BYTES],
    pub(crate) expires_at: u64,
}

pub(crate) struct OperationRepository {
    connection: Connection,
}

impl OperationRepository {
    pub(crate) fn open(path: &Path) -> Result<Self, OperationRepositoryError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|_| OperationRepositoryError::Storage)?;
        Self::from_connection(connection)
    }

    #[cfg(test)]
    fn in_memory() -> Result<Self, OperationRepositoryError> {
        let connection =
            Connection::open_in_memory().map_err(|_| OperationRepositoryError::Storage)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, OperationRepositoryError> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = DELETE;
                 PRAGMA synchronous = FULL;
                 PRAGMA secure_delete = ON;
                 PRAGMA temp_store = MEMORY;
                 PRAGMA trusted_schema = OFF;
                 CREATE TABLE IF NOT EXISTS sender_operations (
                   operation_id BLOB PRIMARY KEY CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id != zeroblob(16)),
                   conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16 AND conversation_id != zeroblob(16)),
                   asset_id BLOB NOT NULL CHECK(typeof(asset_id) = 'blob' AND length(asset_id) = 16 AND asset_id != zeroblob(16)),
                   sender_device_id BLOB NOT NULL CHECK(typeof(sender_device_id) = 'blob' AND length(sender_device_id) = 16 AND sender_device_id != zeroblob(16)),
                   state INTEGER NOT NULL CHECK(state IN (1, 2)),
                   source_name TEXT NOT NULL CHECK(typeof(source_name) = 'text' AND length(source_name) = 39),
                   ciphertext_name TEXT CHECK(ciphertext_name IS NULL OR (typeof(ciphertext_name) = 'text' AND length(ciphertext_name) = 37)),
                   plaintext_length BLOB CHECK(plaintext_length IS NULL OR (typeof(plaintext_length) = 'blob' AND length(plaintext_length) = 8)),
                   ciphertext_length BLOB CHECK(ciphertext_length IS NULL OR (typeof(ciphertext_length) = 'blob' AND length(ciphertext_length) = 8)),
                   ciphertext_digest BLOB CHECK(ciphertext_digest IS NULL OR (typeof(ciphertext_digest) = 'blob' AND length(ciphertext_digest) = 32)),
                   UNIQUE(conversation_id, asset_id, sender_device_id)
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE IF NOT EXISTS sealed_manifest_outbox (
                   operation_id BLOB PRIMARY KEY REFERENCES sender_operations(operation_id) ON DELETE CASCADE,
                   recipient_key_id BLOB NOT NULL CHECK(typeof(recipient_key_id) = 'blob' AND length(recipient_key_id) = 16 AND recipient_key_id != zeroblob(16)),
                   sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob) = 'blob' AND length(sealed_blob) = 408)
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE IF NOT EXISTS receiver_operations (
                   operation_id BLOB PRIMARY KEY CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id != zeroblob(16)),
                   conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16 AND conversation_id != zeroblob(16)),
                   asset_id BLOB NOT NULL CHECK(typeof(asset_id) = 'blob' AND length(asset_id) = 16 AND asset_id != zeroblob(16)),
                   sender_device_id BLOB NOT NULL CHECK(typeof(sender_device_id) = 'blob' AND length(sender_device_id) = 16 AND sender_device_id != zeroblob(16)),
                   state INTEGER NOT NULL CHECK(state = 1),
                   recipient_key_id BLOB NOT NULL CHECK(typeof(recipient_key_id) = 'blob' AND length(recipient_key_id) = 16 AND recipient_key_id != zeroblob(16)),
                   sealed_blob BLOB NOT NULL CHECK(typeof(sealed_blob) = 'blob' AND length(sealed_blob) = 408),
                   ciphertext_name TEXT NOT NULL CHECK(typeof(ciphertext_name) = 'text' AND length(ciphertext_name) = 37),
                   plaintext_temp_name TEXT NOT NULL CHECK(typeof(plaintext_temp_name) = 'text' AND length(plaintext_temp_name) = 50),
                   plaintext_length BLOB NOT NULL CHECK(typeof(plaintext_length) = 'blob' AND length(plaintext_length) = 8),
                   ciphertext_length BLOB NOT NULL CHECK(typeof(ciphertext_length) = 'blob' AND length(ciphertext_length) = 8),
                   ciphertext_digest BLOB NOT NULL CHECK(typeof(ciphertext_digest) = 'blob' AND length(ciphertext_digest) = 32),
                   created_at BLOB NOT NULL CHECK(typeof(created_at) = 'blob' AND length(created_at) = 8),
                   expires_at BLOB NOT NULL CHECK(typeof(expires_at) = 'blob' AND length(expires_at) = 8)
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE IF NOT EXISTS attachment_replay_ledger (
                   conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16 AND conversation_id != zeroblob(16)),
                   asset_id BLOB NOT NULL CHECK(typeof(asset_id) = 'blob' AND length(asset_id) = 16 AND asset_id != zeroblob(16)),
                   sender_device_id BLOB NOT NULL CHECK(typeof(sender_device_id) = 'blob' AND length(sender_device_id) = 16 AND sender_device_id != zeroblob(16)),
                   operation_id BLOB NOT NULL UNIQUE REFERENCES receiver_operations(operation_id) ON DELETE CASCADE,
                   PRIMARY KEY(conversation_id, asset_id, sender_device_id)
                 ) WITHOUT ROWID, STRICT;",
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(Self { connection })
    }

    pub(crate) fn begin_sender(
        &mut self,
        operation_id: CanonicalUuid,
        conversation_id: CanonicalUuid,
        asset_id: CanonicalUuid,
        sender_device_id: CanonicalUuid,
    ) -> Result<SenderState, OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        if let Some(existing) = load_sender_identity(&transaction, operation_id)? {
            if sender_identity_matches(&existing, conversation_id, asset_id, sender_device_id) {
                transaction
                    .commit()
                    .map_err(|_| OperationRepositoryError::Storage)?;
                return decode_sender_state(existing.3);
            }
            return Err(OperationRepositoryError::Conflict);
        }
        if sender_tuple_exists(&transaction, conversation_id, asset_id, sender_device_id)? {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO sender_operations (
                   operation_id, conversation_id, asset_id, sender_device_id, state, source_name
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    uuid_bytes(operation_id),
                    uuid_bytes(conversation_id),
                    uuid_bytes(asset_id),
                    uuid_bytes(sender_device_id),
                    SENDER_ENCRYPTING,
                    source_name(asset_id),
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(SenderState::Encrypting)
    }

    pub(crate) fn commit_sender_outbox(
        &mut self,
        operation_id: CanonicalUuid,
        manifest: &AttachmentManifest,
        sealed: &SealedManifest,
    ) -> Result<(), OperationRepositoryError> {
        let conversation_id = manifest.conversation_id().map_err(map_manifest_error)?;
        let asset_id = manifest.asset_id().map_err(map_manifest_error)?;
        let plaintext_length = manifest.plaintext_length().map_err(map_manifest_error)?;
        let ciphertext_length = manifest.ciphertext_length().map_err(map_manifest_error)?;
        let ciphertext_digest = manifest.ciphertext_digest().map_err(map_manifest_error)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let existing = load_sender_identity(&transaction, operation_id)?
            .ok_or(OperationRepositoryError::Conflict)?;
        if !uuid_equal(existing.0, conversation_id) || !uuid_equal(existing.1, asset_id) {
            return Err(OperationRepositoryError::Conflict);
        }
        if existing.3 == SENDER_OUTBOX {
            let matches = sender_outbox_matches(&transaction, operation_id, manifest, sealed)?;
            if !matches {
                return Err(OperationRepositoryError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| OperationRepositoryError::Storage)?;
            return Ok(());
        }
        if existing.3 != SENDER_ENCRYPTING {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO sealed_manifest_outbox(operation_id, recipient_key_id, sealed_blob)
                 VALUES (?1, ?2, ?3)",
                params![
                    uuid_bytes(operation_id),
                    uuid_bytes(sealed.recipient_key_id),
                    sealed.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .execute(
                "UPDATE sender_operations
                 SET state = ?2, ciphertext_name = ?3, plaintext_length = ?4,
                     ciphertext_length = ?5, ciphertext_digest = ?6
                 WHERE operation_id = ?1 AND state = ?7",
                params![
                    uuid_bytes(operation_id),
                    SENDER_OUTBOX,
                    ciphertext_name(asset_id),
                    u64_bytes(plaintext_length),
                    u64_bytes(ciphertext_length),
                    ciphertext_digest.as_slice(),
                    SENDER_ENCRYPTING,
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)
    }

    pub(crate) fn load_sender_outbox(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<StoredOutbox>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT o.recipient_key_id, o.sealed_blob, s.ciphertext_name,
                        s.plaintext_length, s.ciphertext_length, s.ciphertext_digest
                 FROM sender_operations s
                 JOIN sealed_manifest_outbox o ON o.operation_id = s.operation_id
                 WHERE s.operation_id = ?1 AND s.state = ?2",
                params![uuid_bytes(operation_id), SENDER_OUTBOX],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(decode_stored_outbox)
            .transpose()
    }

    pub(crate) fn commit_received_manifest(
        &mut self,
        operation_id: CanonicalUuid,
        opened: &OpenedManifest,
        now: u64,
    ) -> Result<ReceiverCommit, OperationRepositoryError> {
        let sealed = opened.source_sealed();
        let manifest = opened.manifest();
        let conversation_id = manifest.conversation_id().map_err(map_manifest_error)?;
        let asset_id = manifest.asset_id().map_err(map_manifest_error)?;
        let plaintext_length = manifest.plaintext_length().map_err(map_manifest_error)?;
        let ciphertext_length = manifest.ciphertext_length().map_err(map_manifest_error)?;
        let ciphertext_digest = manifest.ciphertext_digest().map_err(map_manifest_error)?;
        let expires_at = now
            .checked_add(WAITING_SECONDS)
            .ok_or(OperationRepositoryError::InvalidInput)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        if let Some(existing_id) = load_replay_operation(
            &transaction,
            conversation_id,
            asset_id,
            opened.sender_device_id,
        )? {
            if !receiver_operation_matches(&transaction, existing_id, sealed, manifest)? {
                return Err(OperationRepositoryError::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| OperationRepositoryError::Storage)?;
            return Ok(ReceiverCommit::Existing(existing_id));
        }
        if receiver_operation_exists(&transaction, operation_id)? {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO receiver_operations (
                   operation_id, conversation_id, asset_id, sender_device_id, state,
                   recipient_key_id, sealed_blob, ciphertext_name, plaintext_temp_name,
                   plaintext_length, ciphertext_length, ciphertext_digest, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    uuid_bytes(operation_id),
                    uuid_bytes(conversation_id),
                    uuid_bytes(asset_id),
                    uuid_bytes(opened.sender_device_id),
                    RECEIVER_WAITING,
                    uuid_bytes(sealed.recipient_key_id),
                    sealed.as_bytes().as_slice(),
                    ciphertext_name(asset_id),
                    plaintext_temp_name(asset_id),
                    u64_bytes(plaintext_length),
                    u64_bytes(ciphertext_length),
                    ciphertext_digest.as_slice(),
                    u64_bytes(now),
                    u64_bytes(expires_at),
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .execute(
                "INSERT INTO attachment_replay_ledger(
                   conversation_id, asset_id, sender_device_id, operation_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    uuid_bytes(conversation_id),
                    uuid_bytes(asset_id),
                    uuid_bytes(opened.sender_device_id),
                    uuid_bytes(operation_id),
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(ReceiverCommit::Created)
    }

    pub(crate) fn load_waiting(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<WaitingOperation>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT recipient_key_id, sealed_blob, conversation_id, asset_id,
                        sender_device_id, ciphertext_name, plaintext_temp_name,
                        plaintext_length, ciphertext_length, ciphertext_digest, expires_at
                 FROM receiver_operations
                 WHERE operation_id = ?1 AND state = ?2",
                params![uuid_bytes(operation_id), RECEIVER_WAITING],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(decode_waiting)
            .transpose()
    }
}

type SenderIdentityRow = (CanonicalUuid, CanonicalUuid, CanonicalUuid, i64);

fn load_sender_identity(
    connection: &Connection,
    operation_id: CanonicalUuid,
) -> Result<Option<SenderIdentityRow>, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT conversation_id, asset_id, sender_device_id, state
             FROM sender_operations WHERE operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| OperationRepositoryError::Storage)?
        .map(|row| {
            Ok((
                decode_uuid(row.0)?,
                decode_uuid(row.1)?,
                decode_uuid(row.2)?,
                row.3,
            ))
        })
        .transpose()
}

fn sender_tuple_exists(
    connection: &Connection,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    sender_device_id: CanonicalUuid,
) -> Result<bool, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT 1 FROM sender_operations
             WHERE conversation_id = ?1 AND asset_id = ?2 AND sender_device_id = ?3",
            params![
                uuid_bytes(conversation_id),
                uuid_bytes(asset_id),
                uuid_bytes(sender_device_id),
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|_| OperationRepositoryError::Storage)
}

fn sender_identity_matches(
    existing: &SenderIdentityRow,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    sender_device_id: CanonicalUuid,
) -> bool {
    uuid_equal(existing.0, conversation_id)
        && uuid_equal(existing.1, asset_id)
        && uuid_equal(existing.2, sender_device_id)
}

fn decode_sender_state(state: i64) -> Result<SenderState, OperationRepositoryError> {
    match state {
        SENDER_ENCRYPTING => Ok(SenderState::Encrypting),
        SENDER_OUTBOX => Ok(SenderState::Outbox),
        _ => Err(OperationRepositoryError::Storage),
    }
}

fn sender_outbox_matches(
    connection: &Connection,
    operation_id: CanonicalUuid,
    manifest: &AttachmentManifest,
    sealed: &SealedManifest,
) -> Result<bool, OperationRepositoryError> {
    let stored = connection
        .query_row(
            "SELECT o.recipient_key_id, o.sealed_blob, s.plaintext_length,
                    s.ciphertext_length, s.ciphertext_digest
             FROM sender_operations s
             JOIN sealed_manifest_outbox o ON o.operation_id = s.operation_id
             WHERE s.operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| OperationRepositoryError::Storage)?;
    let Some(row) = stored else {
        return Err(OperationRepositoryError::Storage);
    };
    let recipient_key_id = decode_uuid(row.0)?;
    let stored_sealed: [u8; SEALED_BYTES] = exact_array(row.1)?;
    let plaintext_length = decode_u64(row.2)?;
    let ciphertext_length = decode_u64(row.3)?;
    let digest: [u8; DIGEST_BYTES] = exact_array(row.4)?;
    Ok(uuid_equal(recipient_key_id, sealed.recipient_key_id)
        && utils::memcmp(&stored_sealed, sealed.as_bytes())
        && plaintext_length == manifest.plaintext_length().map_err(map_manifest_error)?
        && ciphertext_length == manifest.ciphertext_length().map_err(map_manifest_error)?
        && crypto_verify::verify_32(
            &digest,
            &manifest.ciphertext_digest().map_err(map_manifest_error)?,
        ))
}

fn load_replay_operation(
    connection: &Connection,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    sender_device_id: CanonicalUuid,
) -> Result<Option<CanonicalUuid>, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT operation_id FROM attachment_replay_ledger
             WHERE conversation_id = ?1 AND asset_id = ?2 AND sender_device_id = ?3",
            params![
                uuid_bytes(conversation_id),
                uuid_bytes(asset_id),
                uuid_bytes(sender_device_id),
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| OperationRepositoryError::Storage)?
        .map(decode_uuid)
        .transpose()
}

fn receiver_operation_exists(
    connection: &Connection,
    operation_id: CanonicalUuid,
) -> Result<bool, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT 1 FROM receiver_operations WHERE operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|_| OperationRepositoryError::Storage)
}

fn receiver_operation_matches(
    connection: &Connection,
    operation_id: CanonicalUuid,
    sealed: &SealedManifest,
    manifest: &AttachmentManifest,
) -> Result<bool, OperationRepositoryError> {
    let row = connection
        .query_row(
            "SELECT recipient_key_id, sealed_blob, plaintext_length,
                    ciphertext_length, ciphertext_digest
             FROM receiver_operations WHERE operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .map_err(|_| OperationRepositoryError::Storage)?;
    let recipient_key_id = decode_uuid(row.0)?;
    let stored_sealed: [u8; SEALED_BYTES] = exact_array(row.1)?;
    let plaintext_length = decode_u64(row.2)?;
    let ciphertext_length = decode_u64(row.3)?;
    let digest: [u8; DIGEST_BYTES] = exact_array(row.4)?;
    Ok(uuid_equal(recipient_key_id, sealed.recipient_key_id)
        && utils::memcmp(&stored_sealed, sealed.as_bytes())
        && plaintext_length == manifest.plaintext_length().map_err(map_manifest_error)?
        && ciphertext_length == manifest.ciphertext_length().map_err(map_manifest_error)?
        && crypto_verify::verify_32(
            &digest,
            &manifest.ciphertext_digest().map_err(map_manifest_error)?,
        ))
}

type StoredOutboxRow = (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn decode_stored_outbox(row: StoredOutboxRow) -> Result<StoredOutbox, OperationRepositoryError> {
    let recipient_key_id = decode_uuid(row.0)?;
    let sealed = SealedManifest::parse(recipient_key_id, &row.1)
        .map_err(|_| OperationRepositoryError::Storage)?;
    Ok(StoredOutbox {
        sealed,
        ciphertext_name: row.2,
        plaintext_length: decode_u64(row.3)?,
        ciphertext_length: decode_u64(row.4)?,
        ciphertext_digest: exact_array(row.5)?,
    })
}

type WaitingRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn decode_waiting(row: WaitingRow) -> Result<WaitingOperation, OperationRepositoryError> {
    let recipient_key_id = decode_uuid(row.0)?;
    Ok(WaitingOperation {
        sealed: SealedManifest::parse(recipient_key_id, &row.1)
            .map_err(|_| OperationRepositoryError::Storage)?,
        conversation_id: decode_uuid(row.2)?,
        asset_id: decode_uuid(row.3)?,
        sender_device_id: decode_uuid(row.4)?,
        ciphertext_name: row.5,
        plaintext_temp_name: row.6,
        plaintext_length: decode_u64(row.7)?,
        ciphertext_length: decode_u64(row.8)?,
        ciphertext_digest: exact_array(row.9)?,
        expires_at: decode_u64(row.10)?,
    })
}

fn uuid_bytes(uuid: CanonicalUuid) -> Vec<u8> {
    uuid.as_network_bytes().to_vec()
}

fn u64_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_uuid(bytes: Vec<u8>) -> Result<CanonicalUuid, OperationRepositoryError> {
    CanonicalUuid::from_network_bytes(exact_array(bytes)?)
        .map_err(|_| OperationRepositoryError::Storage)
}

fn decode_u64(bytes: Vec<u8>) -> Result<u64, OperationRepositoryError> {
    Ok(u64::from_be_bytes(exact_array(bytes)?))
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], OperationRepositoryError> {
    bytes
        .try_into()
        .map_err(|_| OperationRepositoryError::Storage)
}

fn uuid_equal(left: CanonicalUuid, right: CanonicalUuid) -> bool {
    crypto_verify::verify_16(left.as_network_bytes(), right.as_network_bytes())
}

fn map_manifest_error(_: AttachmentManifestError) -> OperationRepositoryError {
    OperationRepositoryError::InvalidInput
}

fn asset_prefix(asset_id: CanonicalUuid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in asset_id.as_network_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn source_name(asset_id: CanonicalUuid) -> String {
    format!("{}.source", asset_prefix(asset_id))
}

fn ciphertext_name(asset_id: CanonicalUuid) -> String {
    format!("{}.mowy", asset_prefix(asset_id))
}

fn plaintext_temp_name(asset_id: CanonicalUuid) -> String {
    format!("{}.plaintext.partial", asset_prefix(asset_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment_manifest::{
        ATTACHMENT_KEY_BYTES, AttachmentKey, canonical_ciphertext_length,
    };

    fn uuid(value: u8) -> Result<CanonicalUuid, OperationRepositoryError> {
        CanonicalUuid::from_network_bytes([value; 16])
            .map_err(|_| OperationRepositoryError::InvalidInput)
    }

    fn manifest(
        conversation: u8,
        asset: u8,
        digest: u8,
    ) -> Result<AttachmentManifest, OperationRepositoryError> {
        let plaintext_length = 65_537;
        AttachmentManifest::new(
            uuid(conversation)?,
            uuid(asset)?,
            plaintext_length,
            canonical_ciphertext_length(plaintext_length).map_err(map_manifest_error)?,
            [digest; DIGEST_BYTES],
            AttachmentKey::from_fixture([0xa0; ATTACHMENT_KEY_BYTES]),
        )
        .map_err(map_manifest_error)
    }

    fn sealed(selector: u8, blob: u8) -> Result<SealedManifest, OperationRepositoryError> {
        SealedManifest::parse(uuid(selector)?, &[blob; SEALED_BYTES])
            .map_err(|_| OperationRepositoryError::InvalidInput)
    }

    #[test]
    fn sender_transition_is_atomic_reloadable_and_idempotent()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(9)?;
        assert_eq!(
            repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?,
            SenderState::Encrypting
        );
        assert!(repository.load_sender_outbox(operation_id)?.is_none());
        let manifest = manifest(1, 2, 0x80)?;
        let sealed = sealed(4, 0x90)?;
        repository.commit_sender_outbox(operation_id, &manifest, &sealed)?;
        repository.commit_sender_outbox(operation_id, &manifest, &sealed)?;
        assert_eq!(
            repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?,
            SenderState::Outbox
        );
        let stored = repository
            .load_sender_outbox(operation_id)?
            .ok_or(OperationRepositoryError::Storage)?;
        assert_eq!(stored.sealed, sealed);
        assert_eq!(stored.ciphertext_name, ciphertext_name(uuid(2)?));
        assert_eq!(stored.plaintext_length, 65_537);
        assert_eq!(stored.ciphertext_length, 65_627);
        assert_eq!(stored.ciphertext_digest, [0x80; DIGEST_BYTES]);
        Ok(())
    }

    #[test]
    fn sender_mismatch_leaves_encrypting_without_partial_outbox()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(9)?;
        repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?;
        assert_eq!(
            repository
                .commit_sender_outbox(operation_id, &manifest(1, 5, 0x80)?, &sealed(4, 0x90)?)
                .err(),
            Some(OperationRepositoryError::Conflict)
        );
        assert!(repository.load_sender_outbox(operation_id)?.is_none());
        assert_eq!(
            repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?,
            SenderState::Encrypting
        );
        Ok(())
    }

    #[test]
    fn sender_transaction_failure_rolls_back_every_outbox_field()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(9)?;
        repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?;
        repository
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_sender_commit
                 BEFORE UPDATE ON sender_operations
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(
            repository
                .commit_sender_outbox(operation_id, &manifest(1, 2, 0x80)?, &sealed(4, 0x90)?)
                .err(),
            Some(OperationRepositoryError::Storage)
        );
        assert!(repository.load_sender_outbox(operation_id)?.is_none());
        let outbox_count: i64 = repository
            .connection
            .query_row("SELECT count(*) FROM sealed_manifest_outbox", [], |row| {
                row.get(0)
            })
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(outbox_count, 0);
        assert_eq!(
            repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?,
            SenderState::Encrypting
        );
        Ok(())
    }

    #[test]
    fn receiver_exact_replay_resumes_and_conflicting_reuse_is_rejected()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let first_operation = uuid(8)?;
        let second_operation = uuid(9)?;
        let fixture_manifest = manifest(1, 2, 0x80)?;
        let sealed_message = sealed(4, 0x90)?;
        let opened = OpenedManifest::from_fixture(uuid(3)?, fixture_manifest, sealed_message);
        assert_eq!(
            repository.commit_received_manifest(first_operation, &opened, 100)?,
            ReceiverCommit::Created
        );
        assert_eq!(
            repository.commit_received_manifest(second_operation, &opened, 101)?,
            ReceiverCommit::Existing(first_operation)
        );
        let conflicting =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x91)?);
        assert_eq!(
            repository
                .commit_received_manifest(second_operation, &conflicting, 101)
                .err(),
            Some(OperationRepositoryError::Conflict)
        );
        let waiting = repository
            .load_waiting(first_operation)?
            .ok_or(OperationRepositoryError::Storage)?;
        assert_eq!(waiting.sealed, sealed_message);
        assert_eq!(waiting.conversation_id, uuid(1)?);
        assert_eq!(waiting.asset_id, uuid(2)?);
        assert_eq!(waiting.sender_device_id, uuid(3)?);
        assert_eq!(waiting.ciphertext_name, ciphertext_name(uuid(2)?));
        assert_eq!(waiting.plaintext_temp_name, plaintext_temp_name(uuid(2)?));
        assert_eq!(waiting.plaintext_length, 65_537);
        assert_eq!(waiting.ciphertext_length, 65_627);
        assert_eq!(waiting.ciphertext_digest, [0x80; DIGEST_BYTES]);
        assert_eq!(waiting.expires_at, 86_500);
        Ok(())
    }

    #[test]
    fn duplicate_handles_and_replay_tuples_fail_closed() -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(9)?;
        repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?;
        assert_eq!(
            repository
                .begin_sender(operation_id, uuid(1)?, uuid(5)?, uuid(3)?)
                .err(),
            Some(OperationRepositoryError::Conflict)
        );
        assert_eq!(
            repository
                .begin_sender(uuid(8)?, uuid(1)?, uuid(2)?, uuid(3)?)
                .err(),
            Some(OperationRepositoryError::Conflict)
        );

        let opened =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x90)?);
        repository.commit_received_manifest(uuid(7)?, &opened, 100)?;
        let other = OpenedManifest::from_fixture(uuid(6)?, manifest(1, 5, 0x81)?, sealed(4, 0x92)?);
        assert_eq!(
            repository
                .commit_received_manifest(uuid(7)?, &other, 100)
                .err(),
            Some(OperationRepositoryError::Conflict)
        );
        Ok(())
    }

    #[test]
    fn receiver_transaction_failure_rolls_back_operation_and_replay()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        repository
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_replay_commit
                 BEFORE INSERT ON attachment_replay_ledger
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        let opened =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x90)?);
        assert_eq!(
            repository
                .commit_received_manifest(uuid(7)?, &opened, 100)
                .err(),
            Some(OperationRepositoryError::Storage)
        );
        assert!(repository.load_waiting(uuid(7)?)?.is_none());
        let replay_count: i64 = repository
            .connection
            .query_row("SELECT count(*) FROM attachment_replay_ledger", [], |row| {
                row.get(0)
            })
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(replay_count, 0);
        Ok(())
    }

    #[test]
    fn committed_rows_survive_repository_reload() -> Result<(), OperationRepositoryError> {
        let path = std::env::temp_dir().join(format!(
            "mowy-p2-operation-reload-{}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let operation_id = uuid(9)?;
        {
            let mut repository = OperationRepository::open(&path)?;
            repository.begin_sender(operation_id, uuid(1)?, uuid(2)?, uuid(3)?)?;
            repository.commit_sender_outbox(
                operation_id,
                &manifest(1, 2, 0x80)?,
                &sealed(4, 0x90)?,
            )?;
        }
        {
            let repository = OperationRepository::open(&path)?;
            let stored = repository
                .load_sender_outbox(operation_id)?
                .ok_or(OperationRepositoryError::Storage)?;
            assert_eq!(stored.ciphertext_digest, [0x80; DIGEST_BYTES]);
        }
        std::fs::remove_file(path).map_err(|_| OperationRepositoryError::Storage)
    }

    #[test]
    fn schema_contains_only_public_or_sealed_material() -> Result<(), OperationRepositoryError> {
        let repository = OperationRepository::in_memory()?;
        let schema: String = repository
            .connection
            .query_row(
                "SELECT group_concat(sql, ' ') FROM sqlite_schema WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        let lowered = schema.to_ascii_lowercase();
        for forbidden in [
            "attachment_key",
            "archive_key",
            "identity_secret",
            "agreement_secret",
            "opened_manifest",
            "plaintext_bytes",
        ] {
            assert!(!lowered.contains(forbidden));
        }
        assert!(lowered.contains("sealed_blob"));
        assert!(lowered.contains("strict"));
        Ok(())
    }
}
