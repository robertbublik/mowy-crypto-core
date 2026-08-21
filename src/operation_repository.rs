//! Durable public operation state for the attachment file lifecycle.

use std::path::Path;

use libsodium_rs::{crypto_hash::sha256, crypto_verify, utils};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::archive::{ArchiveDescriptor, ArchiveError, VerifiedArchive};
use crate::attachment_manifest::{AttachmentManifest, AttachmentManifestError, DIGEST_BYTES};
use crate::key_bundle::CanonicalUuid;
use crate::sealed_manifest::{OpenedManifest, SEALED_BYTES, SealedManifest};

const SENDER_ENCRYPTING: i64 = 1;
const SENDER_OUTBOX: i64 = 2;
const RECEIVER_WAITING: i64 = 1;
const RECEIVER_VERIFIED_TEMP: i64 = 2;
const RECEIVER_AVAILABLE: i64 = 3;
const RECEIVER_UNAVAILABLE: i64 = 4;
const DEVELOPMENT_TRANSFER_STAGED: i64 = 1;
const DEVELOPMENT_TRANSFER_PROMOTED: i64 = 2;
const OUTCOME_RESEND: i64 = 1;
const WAITING_SECONDS: u64 = 24 * 60 * 60;
const OPERATION_SCHEMA_VERSION: i64 = 3;
const PREVIOUS_OPERATION_SCHEMA_VERSION: i64 = 2;
const LEGACY_OPERATION_SCHEMA_VERSION: i64 = 1;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiverState {
    WaitingForCiphertext,
    VerifiedTemp,
    Available,
    UnavailableResend,
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

pub(crate) struct AvailableOperation {
    pub(crate) archive_name: String,
    pub(crate) descriptor: ArchiveDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpiredOperation {
    pub(crate) operation_id: CanonicalUuid,
    pub(crate) asset_id: CanonicalUuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DevelopmentProfile {
    pub(crate) account_id: CanonicalUuid,
    pub(crate) device_id: CanonicalUuid,
    pub(crate) agreement_key_id: CanonicalUuid,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevelopmentTransferState {
    Staged,
    Promoted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DevelopmentTransferInbox {
    pub(crate) operation_id: CanonicalUuid,
    pub(crate) sender_account_id: CanonicalUuid,
    pub(crate) sender_device_id: CanonicalUuid,
    pub(crate) conversation_id: CanonicalUuid,
    pub(crate) asset_id: CanonicalUuid,
    pub(crate) recipient_key_id: CanonicalUuid,
    pub(crate) sealed: Option<SealedManifest>,
    pub(crate) plaintext_length: u64,
    pub(crate) ciphertext_length: u64,
    pub(crate) ciphertext_digest: [u8; DIGEST_BYTES],
    pub(crate) received_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) state: DevelopmentTransferState,
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
    pub(crate) fn in_memory() -> Result<Self, OperationRepositoryError> {
        let connection =
            Connection::open_in_memory().map_err(|_| OperationRepositoryError::Storage)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, OperationRepositoryError> {
        let schema_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| OperationRepositoryError::Storage)?;
        let existing_operation_tables: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN (
                   'sender_operations', 'sealed_manifest_outbox',
                   'receiver_operations', 'attachment_replay_ledger'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        if existing_operation_tables != 0
            && schema_version != OPERATION_SCHEMA_VERSION
            && schema_version != PREVIOUS_OPERATION_SCHEMA_VERSION
            && schema_version != LEGACY_OPERATION_SCHEMA_VERSION
        {
            return Err(OperationRepositoryError::Storage);
        }
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
                   state INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
                   recipient_key_id BLOB NOT NULL CHECK(typeof(recipient_key_id) = 'blob' AND length(recipient_key_id) = 16 AND recipient_key_id != zeroblob(16)),
                   sealed_blob BLOB CHECK((state IN (1, 2) AND typeof(sealed_blob) = 'blob' AND length(sealed_blob) = 408) OR (state IN (3, 4) AND sealed_blob IS NULL)),
                   manifest_digest BLOB NOT NULL CHECK(typeof(manifest_digest) = 'blob' AND length(manifest_digest) = 32),
                   ciphertext_name TEXT NOT NULL CHECK(typeof(ciphertext_name) = 'text' AND length(ciphertext_name) = 37),
                   plaintext_temp_name TEXT NOT NULL CHECK(typeof(plaintext_temp_name) = 'text' AND length(plaintext_temp_name) = 50),
                   plaintext_final_name TEXT NOT NULL CHECK(typeof(plaintext_final_name) = 'text' AND length(plaintext_final_name) = 41),
                   plaintext_length BLOB NOT NULL CHECK(typeof(plaintext_length) = 'blob' AND length(plaintext_length) = 8),
                   ciphertext_length BLOB NOT NULL CHECK(typeof(ciphertext_length) = 'blob' AND length(ciphertext_length) = 8),
                   ciphertext_digest BLOB NOT NULL CHECK(typeof(ciphertext_digest) = 'blob' AND length(ciphertext_digest) = 32),
                   created_at BLOB NOT NULL CHECK(typeof(created_at) = 'blob' AND length(created_at) = 8),
                   expires_at BLOB NOT NULL CHECK(typeof(expires_at) = 'blob' AND length(expires_at) = 8),
                   archive_name TEXT CHECK((state = 3 AND typeof(archive_name) = 'text' AND length(archive_name) = 40) OR (state != 3 AND archive_name IS NULL)),
                   archive_ciphertext_length BLOB CHECK((state = 3 AND typeof(archive_ciphertext_length) = 'blob' AND length(archive_ciphertext_length) = 8) OR (state != 3 AND archive_ciphertext_length IS NULL)),
                   archive_ciphertext_digest BLOB CHECK((state = 3 AND typeof(archive_ciphertext_digest) = 'blob' AND length(archive_ciphertext_digest) = 32) OR (state != 3 AND archive_ciphertext_digest IS NULL)),
                   unavailable_outcome INTEGER CHECK((state = 4 AND unavailable_outcome = 1) OR (state != 4 AND unavailable_outcome IS NULL))
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE IF NOT EXISTS attachment_replay_ledger (
                   conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16 AND conversation_id != zeroblob(16)),
                   asset_id BLOB NOT NULL CHECK(typeof(asset_id) = 'blob' AND length(asset_id) = 16 AND asset_id != zeroblob(16)),
                   sender_device_id BLOB NOT NULL CHECK(typeof(sender_device_id) = 'blob' AND length(sender_device_id) = 16 AND sender_device_id != zeroblob(16)),
                   operation_id BLOB NOT NULL UNIQUE REFERENCES receiver_operations(operation_id) ON DELETE CASCADE,
                   PRIMARY KEY(conversation_id, asset_id, sender_device_id)
                 ) WITHOUT ROWID, STRICT;
                 CREATE TABLE IF NOT EXISTS development_profile (
                   singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                   account_id BLOB NOT NULL CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16 AND account_id != zeroblob(16)),
                   device_id BLOB NOT NULL CHECK(typeof(device_id) = 'blob' AND length(device_id) = 16 AND device_id != zeroblob(16)),
                   agreement_key_id BLOB NOT NULL CHECK(typeof(agreement_key_id) = 'blob' AND length(agreement_key_id) = 16 AND agreement_key_id != zeroblob(16)),
                   not_before BLOB NOT NULL CHECK(typeof(not_before) = 'blob' AND length(not_before) = 8),
                   not_after BLOB NOT NULL CHECK(typeof(not_after) = 'blob' AND length(not_after) = 8)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS development_transfer_inbox (
                   operation_id BLOB PRIMARY KEY CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id != zeroblob(16)),
                   sender_account_id BLOB NOT NULL CHECK(typeof(sender_account_id) = 'blob' AND length(sender_account_id) = 16 AND sender_account_id != zeroblob(16)),
                   sender_device_id BLOB NOT NULL CHECK(typeof(sender_device_id) = 'blob' AND length(sender_device_id) = 16 AND sender_device_id != zeroblob(16)),
                   conversation_id BLOB NOT NULL CHECK(typeof(conversation_id) = 'blob' AND length(conversation_id) = 16 AND conversation_id != zeroblob(16)),
                   asset_id BLOB NOT NULL CHECK(typeof(asset_id) = 'blob' AND length(asset_id) = 16 AND asset_id != zeroblob(16)),
                   recipient_key_id BLOB NOT NULL CHECK(typeof(recipient_key_id) = 'blob' AND length(recipient_key_id) = 16 AND recipient_key_id != zeroblob(16)),
                   state INTEGER NOT NULL CHECK(state IN (1, 2)),
                   sealed_blob BLOB CHECK((state = 1 AND typeof(sealed_blob) = 'blob' AND length(sealed_blob) = 408) OR (state = 2 AND sealed_blob IS NULL)),
                   plaintext_length BLOB NOT NULL CHECK(typeof(plaintext_length) = 'blob' AND length(plaintext_length) = 8),
                   ciphertext_length BLOB NOT NULL CHECK(typeof(ciphertext_length) = 'blob' AND length(ciphertext_length) = 8),
                   ciphertext_digest BLOB NOT NULL CHECK(typeof(ciphertext_digest) = 'blob' AND length(ciphertext_digest) = 32),
                   received_at BLOB NOT NULL CHECK(typeof(received_at) = 'blob' AND length(received_at) = 8),
                   expires_at BLOB NOT NULL CHECK(typeof(expires_at) = 'blob' AND length(expires_at) = 8),
                   UNIQUE(conversation_id, asset_id, sender_device_id)
                 ) WITHOUT ROWID, STRICT;
                 PRAGMA user_version = 3;",
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

    pub(crate) fn development_sender_matches(
        &self,
        operation_id: CanonicalUuid,
        conversation_id: CanonicalUuid,
        asset_id: CanonicalUuid,
        sender_device_id: CanonicalUuid,
    ) -> Result<bool, OperationRepositoryError> {
        let Some(existing) = load_sender_identity(&self.connection, operation_id)? else {
            return Ok(false);
        };
        Ok(existing.3 == SENDER_OUTBOX
            && sender_identity_matches(&existing, conversation_id, asset_id, sender_device_id))
    }

    pub(crate) fn commit_received_manifest(
        &mut self,
        operation_id: CanonicalUuid,
        opened: &OpenedManifest,
        now: u64,
    ) -> Result<ReceiverCommit, OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let committed =
            commit_received_manifest_transaction(&transaction, operation_id, opened, now)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(committed)
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

    pub(crate) fn load_development_resumable(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<WaitingOperation>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT recipient_key_id, sealed_blob, conversation_id, asset_id,
                        sender_device_id, ciphertext_name, plaintext_temp_name,
                        plaintext_length, ciphertext_length, ciphertext_digest, expires_at
                 FROM receiver_operations
                 WHERE operation_id = ?1 AND state IN (?2, ?3)",
                params![
                    uuid_bytes(operation_id),
                    RECEIVER_WAITING,
                    RECEIVER_VERIFIED_TEMP,
                ],
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

    pub(crate) fn receiver_state(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<ReceiverState>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT state FROM receiver_operations WHERE operation_id = ?1",
                params![uuid_bytes(operation_id)],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(decode_receiver_state)
            .transpose()
    }

    pub(crate) fn require_exact_receiver(
        &self,
        operation_id: CanonicalUuid,
        opened: &OpenedManifest,
    ) -> Result<(), OperationRepositoryError> {
        let manifest = opened.manifest();
        let conversation_id = manifest.conversation_id().map_err(map_manifest_error)?;
        let asset_id = manifest.asset_id().map_err(map_manifest_error)?;
        let existing = load_replay_operation(
            &self.connection,
            conversation_id,
            asset_id,
            opened.sender_device_id,
        )?
        .ok_or(OperationRepositoryError::Conflict)?;
        if !uuid_equal(existing, operation_id)
            || !receiver_operation_matches(
                &self.connection,
                operation_id,
                opened.source_sealed(),
                manifest,
            )?
        {
            return Err(OperationRepositoryError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn mark_verified_temp(
        &mut self,
        operation_id: CanonicalUuid,
    ) -> Result<(), OperationRepositoryError> {
        transition_receiver_state(
            &mut self.connection,
            operation_id,
            RECEIVER_WAITING,
            RECEIVER_VERIFIED_TEMP,
        )
    }

    pub(crate) fn reset_verified_temp_to_waiting(
        &mut self,
        operation_id: CanonicalUuid,
    ) -> Result<(), OperationRepositoryError> {
        transition_receiver_state(
            &mut self.connection,
            operation_id,
            RECEIVER_VERIFIED_TEMP,
            RECEIVER_WAITING,
        )
    }

    pub(crate) fn commit_available(
        &mut self,
        operation_id: CanonicalUuid,
        verified_archive: &VerifiedArchive,
    ) -> Result<(), OperationRepositoryError> {
        let archive = verified_archive.descriptor();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let identity = load_receiver_archive_identity(&transaction, operation_id)?
            .ok_or(OperationRepositoryError::Conflict)?;
        if identity.3 == RECEIVER_AVAILABLE {
            if available_matches(&transaction, operation_id, archive)? {
                transaction
                    .commit()
                    .map_err(|_| OperationRepositoryError::Storage)?;
                return Ok(());
            }
            return Err(OperationRepositoryError::Conflict);
        }
        if identity.3 != RECEIVER_VERIFIED_TEMP
            || !uuid_equal(identity.0, archive.conversation_id())
            || !uuid_equal(identity.1, archive.asset_id())
            || identity.2 != archive.plaintext_length()
        {
            return Err(OperationRepositoryError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE receiver_operations
                 SET state = ?2, sealed_blob = NULL, archive_name = ?3,
                     archive_ciphertext_length = ?4, archive_ciphertext_digest = ?5
                 WHERE operation_id = ?1 AND state = ?6",
                params![
                    uuid_bytes(operation_id),
                    RECEIVER_AVAILABLE,
                    archive_name(archive.asset_id()),
                    u64_bytes(archive.ciphertext_length()),
                    archive.ciphertext_digest().as_slice(),
                    RECEIVER_VERIFIED_TEMP,
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        if changed != 1 {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)
    }

    pub(crate) fn load_available(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<AvailableOperation>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT conversation_id, asset_id, plaintext_length, archive_name,
                        archive_ciphertext_length, archive_ciphertext_digest
                 FROM receiver_operations
                 WHERE operation_id = ?1 AND state = ?2 AND sealed_blob IS NULL",
                params![uuid_bytes(operation_id), RECEIVER_AVAILABLE],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(decode_available)
            .transpose()
    }

    pub(crate) fn expire_waiting(
        &mut self,
        now: u64,
    ) -> Result<Vec<ExpiredOperation>, OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let expired = {
            let mut statement = transaction
                .prepare(
                    "SELECT operation_id, asset_id FROM receiver_operations
                     WHERE state = ?1 AND expires_at <= ?2",
                )
                .map_err(|_| OperationRepositoryError::Storage)?;
            let rows = statement
                .query_map(params![RECEIVER_WAITING, u64_bytes(now)], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|_| OperationRepositoryError::Storage)?;
            let encoded = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| OperationRepositoryError::Storage)?;
            encoded
                .into_iter()
                .map(|row| {
                    Ok(ExpiredOperation {
                        operation_id: decode_uuid(row.0)?,
                        asset_id: decode_uuid(row.1)?,
                    })
                })
                .collect::<Result<Vec<_>, OperationRepositoryError>>()?
        };
        transaction
            .execute(
                "UPDATE receiver_operations
                 SET state = ?1, sealed_blob = NULL, unavailable_outcome = ?2
                 WHERE state = ?3 AND expires_at <= ?4",
                params![
                    RECEIVER_UNAVAILABLE,
                    OUTCOME_RESEND,
                    RECEIVER_WAITING,
                    u64_bytes(now),
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(expired)
    }

    pub(crate) fn unconsumed_for_recipient_key(
        &self,
        recipient_key_id: CanonicalUuid,
    ) -> Result<u64, OperationRepositoryError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT count(*) FROM receiver_operations
                 WHERE recipient_key_id = ?1 AND state IN (?2, ?3)",
                params![
                    uuid_bytes(recipient_key_id),
                    RECEIVER_WAITING,
                    RECEIVER_VERIFIED_TEMP,
                ],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        u64::try_from(count).map_err(|_| OperationRepositoryError::Storage)
    }

    pub(crate) fn unavailable_asset(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<CanonicalUuid>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT asset_id FROM receiver_operations
                 WHERE operation_id = ?1 AND state = ?2 AND unavailable_outcome = ?3",
                params![
                    uuid_bytes(operation_id),
                    RECEIVER_UNAVAILABLE,
                    OUTCOME_RESEND,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(decode_uuid)
            .transpose()
    }

    pub(crate) fn load_development_profile(
        &self,
    ) -> Result<Option<DevelopmentProfile>, OperationRepositoryError> {
        self.connection
            .query_row(
                "SELECT account_id, device_id, agreement_key_id, not_before, not_after
                 FROM development_profile WHERE singleton = 1",
                [],
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
            .map_err(|_| OperationRepositoryError::Storage)?
            .map(|row| {
                Ok(DevelopmentProfile {
                    account_id: decode_uuid(row.0)?,
                    device_id: decode_uuid(row.1)?,
                    agreement_key_id: decode_uuid(row.2)?,
                    not_before: decode_u64(row.3)?,
                    not_after: decode_u64(row.4)?,
                })
            })
            .transpose()
    }

    pub(crate) fn create_development_profile(
        &mut self,
        profile: DevelopmentProfile,
    ) -> Result<(), OperationRepositoryError> {
        self.connection
            .execute(
                "INSERT INTO development_profile (
                   singleton, account_id, device_id, agreement_key_id, not_before, not_after
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    uuid_bytes(profile.account_id),
                    uuid_bytes(profile.device_id),
                    uuid_bytes(profile.agreement_key_id),
                    u64_bytes(profile.not_before),
                    u64_bytes(profile.not_after),
                ],
            )
            .map(|_| ())
            .map_err(|_| OperationRepositoryError::Conflict)
    }

    pub(crate) fn stage_development_transfer(
        &mut self,
        transfer: DevelopmentTransferInbox,
    ) -> Result<(), OperationRepositoryError> {
        if transfer.state != DevelopmentTransferState::Staged
            || transfer.sealed.is_none()
            || transfer.received_at >= transfer.expires_at
            || transfer.expires_at.checked_sub(transfer.received_at) != Some(WAITING_SECONDS)
        {
            return Err(OperationRepositoryError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        if let Some(existing) =
            load_development_transfer_connection(&transaction, transfer.operation_id)?
        {
            if development_transfer_equal(&existing, &transfer) {
                transaction
                    .commit()
                    .map_err(|_| OperationRepositoryError::Storage)?;
                return Ok(());
            }
            return Err(OperationRepositoryError::Conflict);
        }
        let sealed = transfer
            .sealed
            .as_ref()
            .ok_or(OperationRepositoryError::InvalidInput)?;
        transaction
            .execute(
                "INSERT INTO development_transfer_inbox (
                   operation_id, sender_account_id, sender_device_id,
                   conversation_id, asset_id, recipient_key_id, state,
                   sealed_blob, plaintext_length, ciphertext_length,
                   ciphertext_digest, received_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    uuid_bytes(transfer.operation_id),
                    uuid_bytes(transfer.sender_account_id),
                    uuid_bytes(transfer.sender_device_id),
                    uuid_bytes(transfer.conversation_id),
                    uuid_bytes(transfer.asset_id),
                    uuid_bytes(transfer.recipient_key_id),
                    DEVELOPMENT_TRANSFER_STAGED,
                    sealed.as_bytes().as_slice(),
                    u64_bytes(transfer.plaintext_length),
                    u64_bytes(transfer.ciphertext_length),
                    transfer.ciphertext_digest.as_slice(),
                    u64_bytes(transfer.received_at),
                    u64_bytes(transfer.expires_at),
                ],
            )
            .map_err(|_| OperationRepositoryError::Conflict)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)
    }

    pub(crate) fn load_development_transfer(
        &self,
        operation_id: CanonicalUuid,
    ) -> Result<Option<DevelopmentTransferInbox>, OperationRepositoryError> {
        load_development_transfer_connection(&self.connection, operation_id)
    }

    pub(crate) fn promote_development_transfer(
        &mut self,
        operation_id: CanonicalUuid,
        opened: &OpenedManifest,
        now: u64,
    ) -> Result<ReceiverCommit, OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let staged = load_development_transfer_connection(&transaction, operation_id)?
            .ok_or(OperationRepositoryError::Conflict)?;
        if staged.state != DevelopmentTransferState::Staged
            || !development_transfer_matches_opened(&staged, opened)?
        {
            return Err(OperationRepositoryError::Conflict);
        }
        let committed =
            commit_received_manifest_transaction(&transaction, operation_id, opened, now)?;
        if matches!(committed, ReceiverCommit::Existing(existing) if !uuid_equal(existing, operation_id))
        {
            return Err(OperationRepositoryError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE development_transfer_inbox
                 SET state = ?2, sealed_blob = NULL
                 WHERE operation_id = ?1 AND state = ?3",
                params![
                    uuid_bytes(operation_id),
                    DEVELOPMENT_TRANSFER_PROMOTED,
                    DEVELOPMENT_TRANSFER_STAGED,
                ],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        if changed != 1 {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        Ok(committed)
    }

    pub(crate) fn cleanup_development_sender(
        &mut self,
        operation_id: CanonicalUuid,
    ) -> Result<(), OperationRepositoryError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM sender_operations WHERE operation_id = ?1",
                params![uuid_bytes(operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(OperationRepositoryError::Conflict)
        }
    }

    pub(crate) fn cleanup_development_receiver(
        &mut self,
        operation_id: CanonicalUuid,
    ) -> Result<(), OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        let transfer_changed = transaction
            .execute(
                "DELETE FROM development_transfer_inbox WHERE operation_id = ?1",
                params![uuid_bytes(operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        let receiver_changed = transaction
            .execute(
                "DELETE FROM receiver_operations WHERE operation_id = ?1",
                params![uuid_bytes(operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        if transfer_changed != 1 || receiver_changed != 1 {
            return Err(OperationRepositoryError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)
    }

    pub(crate) fn cleanup_development_proof(
        &mut self,
        sender_operation_id: CanonicalUuid,
        receiver_operation_id: CanonicalUuid,
    ) -> Result<(), OperationRepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .execute(
                "DELETE FROM receiver_operations WHERE operation_id = ?1",
                params![uuid_bytes(receiver_operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .execute(
                "DELETE FROM development_transfer_inbox WHERE operation_id = ?1",
                params![uuid_bytes(receiver_operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .execute(
                "DELETE FROM sender_operations WHERE operation_id = ?1",
                params![uuid_bytes(sender_operation_id)],
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)
    }
}

fn commit_received_manifest_transaction(
    connection: &Connection,
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
    let manifest_digest = sha256::hash(manifest.as_bytes());
    let expires_at = now
        .checked_add(WAITING_SECONDS)
        .ok_or(OperationRepositoryError::InvalidInput)?;
    if let Some(existing_id) = load_replay_operation(
        connection,
        conversation_id,
        asset_id,
        opened.sender_device_id,
    )? {
        if !receiver_operation_matches(connection, existing_id, sealed, manifest)? {
            return Err(OperationRepositoryError::Conflict);
        }
        return Ok(ReceiverCommit::Existing(existing_id));
    }
    if receiver_operation_exists(connection, operation_id)? {
        return Err(OperationRepositoryError::Conflict);
    }
    connection
        .execute(
            "INSERT INTO receiver_operations (
               operation_id, conversation_id, asset_id, sender_device_id, state,
               recipient_key_id, sealed_blob, manifest_digest, ciphertext_name,
               plaintext_temp_name, plaintext_final_name, plaintext_length,
               ciphertext_length, ciphertext_digest, created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                uuid_bytes(operation_id),
                uuid_bytes(conversation_id),
                uuid_bytes(asset_id),
                uuid_bytes(opened.sender_device_id),
                RECEIVER_WAITING,
                uuid_bytes(sealed.recipient_key_id),
                sealed.as_bytes().as_slice(),
                manifest_digest.as_slice(),
                ciphertext_name(asset_id),
                plaintext_temp_name(asset_id),
                plaintext_final_name(asset_id),
                u64_bytes(plaintext_length),
                u64_bytes(ciphertext_length),
                ciphertext_digest.as_slice(),
                u64_bytes(now),
                u64_bytes(expires_at),
            ],
        )
        .map_err(|_| OperationRepositoryError::Storage)?;
    connection
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
    Ok(ReceiverCommit::Created)
}

type DevelopmentTransferRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn load_development_transfer_connection(
    connection: &Connection,
    operation_id: CanonicalUuid,
) -> Result<Option<DevelopmentTransferInbox>, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT sender_account_id, sender_device_id, conversation_id, asset_id,
                    recipient_key_id, state, sealed_blob, plaintext_length,
                    ciphertext_length, ciphertext_digest, received_at, expires_at
             FROM development_transfer_inbox WHERE operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()
        .map_err(|_| OperationRepositoryError::Storage)?
        .map(|row| decode_development_transfer(operation_id, row))
        .transpose()
}

fn decode_development_transfer(
    operation_id: CanonicalUuid,
    row: DevelopmentTransferRow,
) -> Result<DevelopmentTransferInbox, OperationRepositoryError> {
    let recipient_key_id = decode_uuid(row.4)?;
    let state = match row.5 {
        DEVELOPMENT_TRANSFER_STAGED => DevelopmentTransferState::Staged,
        DEVELOPMENT_TRANSFER_PROMOTED => DevelopmentTransferState::Promoted,
        _ => return Err(OperationRepositoryError::Storage),
    };
    let sealed = match (state, row.6) {
        (DevelopmentTransferState::Staged, Some(bytes)) => Some(
            SealedManifest::parse(recipient_key_id, &bytes)
                .map_err(|_| OperationRepositoryError::Storage)?,
        ),
        (DevelopmentTransferState::Promoted, None) => None,
        _ => return Err(OperationRepositoryError::Storage),
    };
    Ok(DevelopmentTransferInbox {
        operation_id,
        sender_account_id: decode_uuid(row.0)?,
        sender_device_id: decode_uuid(row.1)?,
        conversation_id: decode_uuid(row.2)?,
        asset_id: decode_uuid(row.3)?,
        recipient_key_id,
        sealed,
        plaintext_length: decode_u64(row.7)?,
        ciphertext_length: decode_u64(row.8)?,
        ciphertext_digest: exact_array(row.9)?,
        received_at: decode_u64(row.10)?,
        expires_at: decode_u64(row.11)?,
        state,
    })
}

fn development_transfer_equal(
    left: &DevelopmentTransferInbox,
    right: &DevelopmentTransferInbox,
) -> bool {
    let sealed_equal = match (&left.sealed, &right.sealed) {
        (Some(left), Some(right)) => utils::memcmp(left.as_bytes(), right.as_bytes()),
        (None, None) => true,
        _ => false,
    };
    uuid_equal(left.operation_id, right.operation_id)
        && uuid_equal(left.sender_account_id, right.sender_account_id)
        && uuid_equal(left.sender_device_id, right.sender_device_id)
        && uuid_equal(left.conversation_id, right.conversation_id)
        && uuid_equal(left.asset_id, right.asset_id)
        && uuid_equal(left.recipient_key_id, right.recipient_key_id)
        && sealed_equal
        && left.plaintext_length == right.plaintext_length
        && left.ciphertext_length == right.ciphertext_length
        && crypto_verify::verify_32(&left.ciphertext_digest, &right.ciphertext_digest)
        && left.state == right.state
}

fn development_transfer_matches_opened(
    staged: &DevelopmentTransferInbox,
    opened: &OpenedManifest,
) -> Result<bool, OperationRepositoryError> {
    let Some(staged_sealed) = staged.sealed.as_ref() else {
        return Ok(false);
    };
    let manifest = opened.manifest();
    Ok(uuid_equal(staged.sender_device_id, opened.sender_device_id)
        && uuid_equal(
            staged.recipient_key_id,
            opened.source_sealed().recipient_key_id,
        )
        && utils::memcmp(staged_sealed.as_bytes(), opened.source_sealed().as_bytes())
        && uuid_equal(
            staged.conversation_id,
            manifest.conversation_id().map_err(map_manifest_error)?,
        )
        && uuid_equal(
            staged.asset_id,
            manifest.asset_id().map_err(map_manifest_error)?,
        )
        && staged.plaintext_length == manifest.plaintext_length().map_err(map_manifest_error)?
        && staged.ciphertext_length == manifest.ciphertext_length().map_err(map_manifest_error)?
        && crypto_verify::verify_32(
            &staged.ciphertext_digest,
            &manifest.ciphertext_digest().map_err(map_manifest_error)?,
        ))
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

fn decode_receiver_state(state: i64) -> Result<ReceiverState, OperationRepositoryError> {
    match state {
        RECEIVER_WAITING => Ok(ReceiverState::WaitingForCiphertext),
        RECEIVER_VERIFIED_TEMP => Ok(ReceiverState::VerifiedTemp),
        RECEIVER_AVAILABLE => Ok(ReceiverState::Available),
        RECEIVER_UNAVAILABLE => Ok(ReceiverState::UnavailableResend),
        _ => Err(OperationRepositoryError::Storage),
    }
}

fn transition_receiver_state(
    connection: &mut Connection,
    operation_id: CanonicalUuid,
    from: i64,
    to: i64,
) -> Result<(), OperationRepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| OperationRepositoryError::Storage)?;
    let state = transaction
        .query_row(
            "SELECT state FROM receiver_operations WHERE operation_id = ?1",
            params![uuid_bytes(operation_id)],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| OperationRepositoryError::Storage)?
        .ok_or(OperationRepositoryError::Conflict)?;
    if state == to {
        transaction
            .commit()
            .map_err(|_| OperationRepositoryError::Storage)?;
        return Ok(());
    }
    if state != from {
        return Err(OperationRepositoryError::Conflict);
    }
    let changed = transaction
        .execute(
            "UPDATE receiver_operations SET state = ?2
             WHERE operation_id = ?1 AND state = ?3",
            params![uuid_bytes(operation_id), to, from],
        )
        .map_err(|_| OperationRepositoryError::Storage)?;
    if changed != 1 {
        return Err(OperationRepositoryError::Conflict);
    }
    transaction
        .commit()
        .map_err(|_| OperationRepositoryError::Storage)
}

type ReceiverArchiveIdentity = (CanonicalUuid, CanonicalUuid, u64, i64);

fn load_receiver_archive_identity(
    connection: &Connection,
    operation_id: CanonicalUuid,
) -> Result<Option<ReceiverArchiveIdentity>, OperationRepositoryError> {
    connection
        .query_row(
            "SELECT conversation_id, asset_id, plaintext_length, state
             FROM receiver_operations WHERE operation_id = ?1",
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
                decode_u64(row.2)?,
                row.3,
            ))
        })
        .transpose()
}

fn available_matches(
    connection: &Connection,
    operation_id: CanonicalUuid,
    archive: &ArchiveDescriptor,
) -> Result<bool, OperationRepositoryError> {
    let stored = connection
        .query_row(
            "SELECT conversation_id, asset_id, plaintext_length,
                    archive_ciphertext_length, archive_ciphertext_digest
             FROM receiver_operations WHERE operation_id = ?1 AND state = ?2",
            params![uuid_bytes(operation_id), RECEIVER_AVAILABLE],
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
    let digest: [u8; DIGEST_BYTES] = exact_array(row.4)?;
    Ok(uuid_equal(decode_uuid(row.0)?, archive.conversation_id())
        && uuid_equal(decode_uuid(row.1)?, archive.asset_id())
        && decode_u64(row.2)? == archive.plaintext_length()
        && decode_u64(row.3)? == archive.ciphertext_length()
        && crypto_verify::verify_32(&digest, &archive.ciphertext_digest()))
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
            "SELECT recipient_key_id, manifest_digest, plaintext_length,
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
    let stored_manifest_digest: [u8; DIGEST_BYTES] = exact_array(row.1)?;
    let plaintext_length = decode_u64(row.2)?;
    let ciphertext_length = decode_u64(row.3)?;
    let digest: [u8; DIGEST_BYTES] = exact_array(row.4)?;
    Ok(uuid_equal(recipient_key_id, sealed.recipient_key_id)
        && crypto_verify::verify_32(&stored_manifest_digest, &sha256::hash(manifest.as_bytes()))
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

type AvailableRow = (Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>);

fn decode_available(row: AvailableRow) -> Result<AvailableOperation, OperationRepositoryError> {
    let descriptor = ArchiveDescriptor::new(
        decode_uuid(row.0)?,
        decode_uuid(row.1)?,
        decode_u64(row.2)?,
        decode_u64(row.4)?,
        exact_array(row.5)?,
    )
    .map_err(map_archive_error)?;
    Ok(AvailableOperation {
        archive_name: row.3,
        descriptor,
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

fn map_archive_error(_: ArchiveError) -> OperationRepositoryError {
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

fn plaintext_final_name(asset_id: CanonicalUuid) -> String {
    format!("{}.verified", asset_prefix(asset_id))
}

fn archive_name(asset_id: CanonicalUuid) -> String {
    format!("{}.archive", asset_prefix(asset_id))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::archive::{ArchiveKey, create_and_verify_archive};
    use crate::attachment_envelope::NeverCancelled;
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

    fn verified_archive() -> Result<VerifiedArchive, OperationRepositoryError> {
        let plaintext: Vec<u8> = (0..65_537).map(|index| (index % 251) as u8).collect();
        create_and_verify_archive(
            &mut Cursor::new(plaintext),
            &mut Cursor::new(Vec::new()),
            65_537,
            uuid(1)?,
            uuid(2)?,
            &ArchiveKey::from_fixture([0x31; ATTACHMENT_KEY_BYTES]),
            &mut NeverCancelled,
        )
        .map_err(map_archive_error)
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
        let resealed =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x91)?);
        assert_eq!(
            repository.commit_received_manifest(second_operation, &resealed, 101)?,
            ReceiverCommit::Existing(first_operation)
        );
        let conflicting =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x81)?, sealed(4, 0x91)?);
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
    fn archive_commit_erases_sealed_blob_and_is_exactly_idempotent()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(7)?;
        let opened =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x90)?);
        repository.commit_received_manifest(operation_id, &opened, 100)?;
        assert_eq!(repository.unconsumed_for_recipient_key(uuid(4)?)?, 1);
        repository.mark_verified_temp(operation_id)?;
        repository.mark_verified_temp(operation_id)?;
        assert_eq!(
            repository.receiver_state(operation_id)?,
            Some(ReceiverState::VerifiedTemp)
        );
        let verified_archive = verified_archive()?;
        let archive = *verified_archive.descriptor();
        repository.commit_available(operation_id, &verified_archive)?;
        repository.commit_available(operation_id, &verified_archive)?;
        assert_eq!(
            repository.receiver_state(operation_id)?,
            Some(ReceiverState::Available)
        );
        assert!(repository.load_waiting(operation_id)?.is_none());
        let available = repository
            .load_available(operation_id)?
            .ok_or(OperationRepositoryError::Storage)?;
        assert_eq!(available.archive_name, archive_name(uuid(2)?));
        assert_eq!(available.descriptor, archive);
        assert_eq!(repository.unconsumed_for_recipient_key(uuid(4)?)?, 0);
        let sealed_count: i64 = repository
            .connection
            .query_row(
                "SELECT count(*) FROM receiver_operations
                 WHERE operation_id = ?1 AND sealed_blob IS NOT NULL",
                params![uuid_bytes(operation_id)],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(sealed_count, 0);

        let replay =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x91)?);
        assert_eq!(
            repository.commit_received_manifest(uuid(8)?, &replay, 200)?,
            ReceiverCommit::Existing(operation_id)
        );
        Ok(())
    }

    #[test]
    fn available_transaction_failure_retains_transport_state()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(7)?;
        let opened =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x90)?);
        repository.commit_received_manifest(operation_id, &opened, 100)?;
        repository.mark_verified_temp(operation_id)?;
        repository
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_available_commit
                 BEFORE UPDATE ON receiver_operations
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        let archive = verified_archive()?;
        assert_eq!(
            repository.commit_available(operation_id, &archive).err(),
            Some(OperationRepositoryError::Storage)
        );
        assert_eq!(
            repository.receiver_state(operation_id)?,
            Some(ReceiverState::VerifiedTemp)
        );
        let retained: i64 = repository
            .connection
            .query_row(
                "SELECT count(*) FROM receiver_operations
                 WHERE operation_id = ?1 AND sealed_blob IS NOT NULL AND archive_name IS NULL",
                params![uuid_bytes(operation_id)],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(retained, 1);
        Ok(())
    }

    #[test]
    fn waiting_expiry_erases_sealed_blob_and_records_resend() -> Result<(), OperationRepositoryError>
    {
        let mut repository = OperationRepository::in_memory()?;
        let waiting_id = uuid(7)?;
        let verified_id = uuid(8)?;
        let waiting =
            OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed(4, 0x90)?);
        let verified =
            OpenedManifest::from_fixture(uuid(6)?, manifest(1, 5, 0x81)?, sealed(4, 0x91)?);
        repository.commit_received_manifest(waiting_id, &waiting, 100)?;
        repository.commit_received_manifest(verified_id, &verified, 100)?;
        repository.mark_verified_temp(verified_id)?;
        assert!(repository.expire_waiting(86_499)?.is_empty());
        assert_eq!(
            repository.expire_waiting(86_500)?,
            vec![ExpiredOperation {
                operation_id: waiting_id,
                asset_id: uuid(2)?,
            }]
        );
        assert_eq!(
            repository.receiver_state(waiting_id)?,
            Some(ReceiverState::UnavailableResend)
        );
        assert_eq!(
            repository.receiver_state(verified_id)?,
            Some(ReceiverState::VerifiedTemp)
        );
        let erased: i64 = repository
            .connection
            .query_row(
                "SELECT count(*) FROM receiver_operations
                 WHERE operation_id = ?1 AND sealed_blob IS NULL AND unavailable_outcome = ?2",
                params![uuid_bytes(waiting_id), OUTCOME_RESEND],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(erased, 1);
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

    #[test]
    fn rejects_unversioned_operation_schema_and_marks_current_schema()
    -> Result<(), OperationRepositoryError> {
        let repository = OperationRepository::in_memory()?;
        let version: i64 = repository
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert_eq!(version, OPERATION_SCHEMA_VERSION);

        let legacy = Connection::open_in_memory().map_err(|_| OperationRepositoryError::Storage)?;
        legacy
            .execute_batch("CREATE TABLE receiver_operations(legacy INTEGER);")
            .map_err(|_| OperationRepositoryError::Storage)?;
        assert!(matches!(
            OperationRepository::from_connection(legacy),
            Err(OperationRepositoryError::Storage)
        ));
        Ok(())
    }

    #[test]
    fn migrates_v1_state_to_v3_without_rewriting_operation_rows()
    -> Result<(), OperationRepositoryError> {
        let path = std::env::temp_dir().join(format!(
            "mowy-p2-operation-v1-migration-{}.sqlite3",
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
            repository
                .connection
                .execute_batch(
                    "DROP TABLE development_profile;
                     PRAGMA user_version = 1;",
                )
                .map_err(|_| OperationRepositoryError::Storage)?;
        }
        {
            let repository = OperationRepository::open(&path)?;
            assert_eq!(
                repository
                    .load_sender_outbox(operation_id)?
                    .ok_or(OperationRepositoryError::Storage)?
                    .ciphertext_digest,
                [0x80; DIGEST_BYTES]
            );
            assert!(repository.load_development_profile()?.is_none());
            let version: i64 = repository
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(|_| OperationRepositoryError::Storage)?;
            assert_eq!(version, OPERATION_SCHEMA_VERSION);
        }
        std::fs::remove_file(path).map_err(|_| OperationRepositoryError::Storage)
    }

    #[test]
    fn development_profile_is_singleton_reloadable_and_public_only()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let profile = DevelopmentProfile {
            account_id: uuid(1)?,
            device_id: uuid(2)?,
            agreement_key_id: uuid(3)?,
            not_before: 1_780_000_000,
            not_after: 1_782_592_000,
        };
        assert!(repository.load_development_profile()?.is_none());
        repository.create_development_profile(profile)?;
        assert_eq!(repository.load_development_profile()?, Some(profile));
        assert_eq!(
            repository.create_development_profile(profile).err(),
            Some(OperationRepositoryError::Conflict)
        );

        let schema: String = repository
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'development_profile'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        for forbidden in ["secret", "private", "attachment_key", "archive_key"] {
            assert!(!schema.to_ascii_lowercase().contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn development_transfer_is_staged_unopened_then_atomically_promoted()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(7)?;
        let sealed_message = sealed(4, 0x90)?;
        let transfer = DevelopmentTransferInbox {
            operation_id,
            sender_account_id: uuid(5)?,
            sender_device_id: uuid(3)?,
            conversation_id: uuid(1)?,
            asset_id: uuid(2)?,
            recipient_key_id: uuid(4)?,
            sealed: Some(sealed_message),
            plaintext_length: 65_537,
            ciphertext_length: 65_627,
            ciphertext_digest: [0x80; DIGEST_BYTES],
            received_at: 100,
            expires_at: 86_500,
            state: DevelopmentTransferState::Staged,
        };
        repository.stage_development_transfer(transfer)?;
        repository.stage_development_transfer(transfer)?;
        assert_eq!(
            repository.load_development_transfer(operation_id)?,
            Some(transfer)
        );
        assert_eq!(repository.receiver_state(operation_id)?, None);

        let opened = OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed_message);
        assert_eq!(
            repository.promote_development_transfer(operation_id, &opened, 101)?,
            ReceiverCommit::Created
        );
        let promoted = repository
            .load_development_transfer(operation_id)?
            .ok_or(OperationRepositoryError::Storage)?;
        assert_eq!(promoted.state, DevelopmentTransferState::Promoted);
        assert!(promoted.sealed.is_none());
        assert_eq!(
            repository.receiver_state(operation_id)?,
            Some(ReceiverState::WaitingForCiphertext)
        );
        assert_eq!(
            repository
                .load_waiting(operation_id)?
                .ok_or(OperationRepositoryError::Storage)?
                .sealed,
            sealed_message
        );
        Ok(())
    }

    #[test]
    fn failed_development_promotion_retains_only_staged_state()
    -> Result<(), OperationRepositoryError> {
        let mut repository = OperationRepository::in_memory()?;
        let operation_id = uuid(7)?;
        let sealed_message = sealed(4, 0x90)?;
        repository.stage_development_transfer(DevelopmentTransferInbox {
            operation_id,
            sender_account_id: uuid(5)?,
            sender_device_id: uuid(3)?,
            conversation_id: uuid(1)?,
            asset_id: uuid(2)?,
            recipient_key_id: uuid(4)?,
            sealed: Some(sealed_message),
            plaintext_length: 65_537,
            ciphertext_length: 65_627,
            ciphertext_digest: [0x80; DIGEST_BYTES],
            received_at: 100,
            expires_at: 86_500,
            state: DevelopmentTransferState::Staged,
        })?;
        repository
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_development_promotion
                 BEFORE UPDATE ON development_transfer_inbox
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .map_err(|_| OperationRepositoryError::Storage)?;
        let opened = OpenedManifest::from_fixture(uuid(3)?, manifest(1, 2, 0x80)?, sealed_message);
        assert_eq!(
            repository
                .promote_development_transfer(operation_id, &opened, 101)
                .err(),
            Some(OperationRepositoryError::Storage)
        );
        assert_eq!(repository.receiver_state(operation_id)?, None);
        let staged = repository
            .load_development_transfer(operation_id)?
            .ok_or(OperationRepositoryError::Storage)?;
        assert_eq!(staged.state, DevelopmentTransferState::Staged);
        assert_eq!(staged.sealed, Some(sealed_message));
        Ok(())
    }
}
