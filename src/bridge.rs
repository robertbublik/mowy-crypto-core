//! Fixture-only semantic façade for the signed physical development builds.

use std::fmt;
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, TryLockError};

use libsodium_rs::{crypto_verify, ensure_init, random};
use zeroize::Zeroizing;

use crate::archive::{ArchiveError, ArchiveKey, open_archive};
use crate::attachment_envelope::CancellationCheck;
use crate::attachment_manifest::{
    AttachmentManifestError, DIGEST_BYTES, canonical_ciphertext_length,
};
use crate::key_bundle::{
    CanonicalUuid, DeviceKeyBundle, KeyBundleError, KeyValidityWindow, PublishedKeyRepository,
    sign_current_bundle,
};
use crate::key_material::{
    CompanionState, InitializationState, KeyMaterialError, ProtectedKeyState, ProtectedKeyStore,
    ROOT_KEY_MATERIAL_BYTES, RootKeyMaterial, classify_initialization, initialize,
};
use crate::operation_repository::{
    DevelopmentProfile, DevelopmentTransferInbox, DevelopmentTransferState, OperationRepository,
    OperationRepositoryError, ReceiverCommit, ReceiverState,
};
use crate::private_files::{PrivateFileError, PrivateFileStore};
use crate::receiver_lifecycle::{
    AvailabilityCheck, ReceiverLifecycleError, complete_or_recover, recover_available,
};
use crate::sealed_manifest::{
    LocalAgreementKey, SealedManifestError, TrustedSender, open_manifest, seal_manifest,
};

const PROOF_DATABASE_NAME: &str = "operations.sqlite3";
const ROOT_WORDS: usize = ROOT_KEY_MATERIAL_BYTES / 8;
const FILE_MODE_MASK: u32 = 0o077;
const DEVELOPMENT_TRANSFER_SECONDS: u64 = 24 * 60 * 60;
const MAXIMUM_DEVELOPMENT_PLAINTEXT_BYTES: u64 = 25 * 1_024 * 1_024;

static PROOF_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MowyCoreCode {
    Success,
    InvalidInput,
    Unavailable,
    Conflict,
    Storage,
    Authentication,
    Cryptography,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MowyCoreError {
    InvalidInput,
    Unavailable,
    Conflict,
    Storage,
    Authentication,
    Cryptography,
    Cancelled,
}

impl fmt::Display for MowyCoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid input",
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::Storage => "storage failure",
            Self::Authentication => "authentication failure",
            Self::Cryptography => "cryptography failure",
            Self::Cancelled => "cancelled",
        })
    }
}

impl std::error::Error for MowyCoreError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProtectedKeyState {
    Absent,
    Present,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyProofReceipt {
    pub proof_id: String,
    pub plaintext_length: u64,
    pub ciphertext_length: u64,
    pub ciphertext_sha256: String,
    pub archive_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyProofResult {
    pub code: MowyCoreCode,
    pub receipt: Option<MowyProofReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyPublicBundle {
    pub account_id: String,
    pub device_id: String,
    pub agreement_key_id: String,
    pub identity_public_key: String,
    pub agreement_public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyPublicBundleResult {
    pub code: MowyCoreCode,
    pub bundle: Option<MowyPublicBundle>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyDevelopmentTransfer {
    pub sender_operation_id: String,
    pub receiver_operation_id: String,
    pub conversation_id: String,
    pub asset_id: String,
    pub recipient_key_id: String,
    pub sealed_manifest: String,
    pub plaintext_length: u64,
    pub ciphertext_length: u64,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyPreparedTransferResult {
    pub code: MowyCoreCode,
    pub transfer: Option<MowyDevelopmentTransfer>,
    pub ciphertext_source_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyStagedTransferResult {
    pub code: MowyCoreCode,
    pub ciphertext_destination_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MowyCodeResult {
    pub code: MowyCoreCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBridgeResponse {
    pub code: MowyCoreCode,
    pub flag: bool,
    pub number: u64,
    pub key_state: NativeProtectedKeyState,
    pub path: String,
}

#[cfg(test)]
fn success_response() -> NativeBridgeResponse {
    NativeBridgeResponse {
        code: MowyCoreCode::Success,
        flag: false,
        number: 0,
        key_state: NativeProtectedKeyState::Absent,
        path: String::new(),
    }
}

#[cfg(test)]
fn error_response(error: MowyCoreError) -> NativeBridgeResponse {
    NativeBridgeResponse {
        code: map_error_code(error),
        ..success_response()
    }
}

/// Internal platform-TCB plumbing; semantic callers never receive these words.
pub trait NativeProtectedKeyStore: Send + Sync {
    fn protected_data_available(&self) -> NativeBridgeResponse;
    fn key_state(&self) -> NativeBridgeResponse;
    fn installation_marker_exists(&self) -> NativeBridgeResponse;
    fn database_exists(&self) -> NativeBridgeResponse;
    fn prepare_namespaces(&self) -> NativeBridgeResponse;
    fn commit_companions(&self) -> NativeBridgeResponse;
    #[allow(clippy::too_many_arguments, reason = "fixed protected-key layout")]
    fn store_new(
        &self,
        word_0: u64,
        word_1: u64,
        word_2: u64,
        word_3: u64,
        word_4: u64,
        word_5: u64,
        word_6: u64,
        word_7: u64,
        word_8: u64,
        word_9: u64,
        word_10: u64,
        word_11: u64,
    ) -> NativeBridgeResponse;
    fn begin_load(&self) -> NativeBridgeResponse;
    fn load_word(&self, token: u64, index: u8) -> NativeBridgeResponse;
    fn finish_load(&self, token: u64) -> NativeBridgeResponse;
}

pub trait MowyCancellation: Send + Sync {
    fn is_cancelled(&self) -> NativeBridgeResponse;
}

pub fn publish_development_bundle(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
) -> MowyPublicBundleResult {
    match publish_development_bundle_inner(protected_store, now) {
        Ok(bundle) => MowyPublicBundleResult {
            code: MowyCoreCode::Success,
            bundle: Some(bundle),
        },
        Err(error) => MowyPublicBundleResult {
            code: map_error_code(error),
            bundle: None,
        },
    }
}

pub fn prepare_development_transfer(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    plaintext_length: u64,
    recipient_bundle: MowyPublicBundle,
) -> MowyPreparedTransferResult {
    match prepare_development_transfer_inner(
        protected_store,
        cancellation,
        now,
        plaintext_length,
        recipient_bundle,
    ) {
        Ok((transfer, path)) => MowyPreparedTransferResult {
            code: MowyCoreCode::Success,
            transfer: Some(transfer),
            ciphertext_source_path: path,
        },
        Err(error) => MowyPreparedTransferResult {
            code: map_error_code(error),
            transfer: None,
            ciphertext_source_path: String::new(),
        },
    }
}

pub fn stage_development_transfer(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
    sender_bundle: MowyPublicBundle,
    transfer: MowyDevelopmentTransfer,
) -> MowyStagedTransferResult {
    match stage_development_transfer_inner(protected_store, now, sender_bundle, transfer) {
        Ok(path) => MowyStagedTransferResult {
            code: MowyCoreCode::Success,
            ciphertext_destination_path: path,
        },
        Err(error) => MowyStagedTransferResult {
            code: map_error_code(error),
            ciphertext_destination_path: String::new(),
        },
    }
}

pub fn resume_development_transfer(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    receiver_operation_id: String,
) -> MowyProofResult {
    match resume_development_transfer_inner(
        protected_store,
        cancellation,
        now,
        &receiver_operation_id,
    ) {
        Ok(receipt) => MowyProofResult {
            code: MowyCoreCode::Success,
            receipt: Some(receipt),
        },
        Err(error) => MowyProofResult {
            code: map_error_code(error),
            receipt: None,
        },
    }
}

pub fn cleanup_development_sender(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
    transfer: MowyDevelopmentTransfer,
) -> MowyCodeResult {
    let code = match cleanup_development_sender_inner(protected_store, now, transfer) {
        Ok(()) => MowyCoreCode::Success,
        Err(error) => map_error_code(error),
    };
    MowyCodeResult { code }
}

struct DevelopmentContext {
    root: PathBuf,
    root_keys: RootKeyMaterial,
    profile: DevelopmentProfile,
    bundle: DeviceKeyBundle,
}

#[derive(Clone, Copy)]
struct ParsedDevelopmentTransfer {
    sender_operation_id: CanonicalUuid,
    receiver_operation_id: CanonicalUuid,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    recipient_key_id: CanonicalUuid,
    sealed: crate::sealed_manifest::SealedManifest,
    plaintext_length: u64,
    ciphertext_length: u64,
    ciphertext_digest: [u8; DIGEST_BYTES],
}

fn publish_development_bundle_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
) -> Result<MowyPublicBundle, MowyCoreError> {
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    Ok(encode_public_bundle(context.bundle))
}

fn prepare_development_transfer_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    plaintext_length: u64,
    recipient_bundle: MowyPublicBundle,
) -> Result<(MowyDevelopmentTransfer, String), MowyCoreError> {
    require_development_plaintext_length(plaintext_length)?;
    let recipient_bundle = decode_public_bundle(&recipient_bundle)?;
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    if uuid_equal_bridge(recipient_bundle.device_id, context.profile.device_id)
        || uuid_equal_bridge(
            recipient_bundle.agreement_key_id,
            context.profile.agreement_key_id,
        )
    {
        return Err(MowyCoreError::InvalidInput);
    }

    let database_path = context.root.join(PROOF_DATABASE_NAME);
    let mut published =
        PublishedKeyRepository::open(&database_path).map_err(map_key_bundle_error)?;
    published
        .pin_verified(&recipient_bundle, now)
        .map_err(map_key_bundle_error)?;
    let recipient_bundle = published
        .load_verified_at(recipient_bundle.account_id, recipient_bundle.device_id, now)
        .map_err(map_key_bundle_error)?
        .ok_or(MowyCoreError::Storage)?;
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    let mut files = PrivateFileStore::open(&context.root).map_err(map_file_error)?;
    let mut cancellation = ForeignCancellation::new(cancellation.as_ref());
    cancellation.require_active()?;
    let identifiers = ProofIdentifiers::generate()?;

    files
        .create_development_source(identifiers.asset_id, plaintext_length, &mut cancellation)
        .map_err(|error| cancellation.map_private_error(error))?;
    if let Err(error) = operations.begin_sender(
        identifiers.sender_operation_id,
        identifiers.conversation_id,
        identifiers.asset_id,
        context.profile.device_id,
    ) {
        let cleanup = files.cleanup_development_artifacts(identifiers.asset_id);
        return match cleanup {
            Ok(()) => Err(map_repository_error(error)),
            Err(cleanup_error) => Err(map_file_error(cleanup_error)),
        };
    }

    let result = (|| {
        require_protected(protected_store.as_ref())?;
        let encrypted = files
            .encrypt_asset(
                identifiers.conversation_id,
                identifiers.asset_id,
                &mut cancellation,
            )
            .map_err(|error| cancellation.map_private_error(error))?;
        require_protected(protected_store.as_ref())?;
        let sealed = seal_manifest(
            &context.root_keys,
            context.profile.device_id,
            &recipient_bundle,
            &encrypted.encrypted.manifest,
            now,
        )
        .map_err(map_sealed_error)?;
        operations
            .commit_sender_outbox(
                identifiers.sender_operation_id,
                &encrypted.encrypted.manifest,
                &sealed,
            )
            .map_err(map_repository_error)?;
        let durable = operations
            .load_sender_outbox(identifiers.sender_operation_id)
            .map_err(map_repository_error)?
            .ok_or(MowyCoreError::Storage)?;
        let path = encrypted
            .ciphertext_path
            .to_str()
            .map(str::to_owned)
            .ok_or(MowyCoreError::Storage)?;
        let transfer = MowyDevelopmentTransfer {
            sender_operation_id: uuid_hex(identifiers.sender_operation_id),
            receiver_operation_id: uuid_hex(identifiers.receiver_operation_id),
            conversation_id: uuid_hex(identifiers.conversation_id),
            asset_id: uuid_hex(identifiers.asset_id),
            recipient_key_id: uuid_hex(durable.sealed.recipient_key_id),
            sealed_manifest: bytes_hex(durable.sealed.as_bytes()),
            plaintext_length: durable.plaintext_length,
            ciphertext_length: durable.ciphertext_length,
            ciphertext_sha256: digest_hex(&durable.ciphertext_digest),
        };
        require_protected(protected_store.as_ref())?;
        cancellation.require_active()?;
        Ok((transfer, path))
    })();

    if result.is_err() {
        let operation_cleanup = operations
            .cleanup_development_sender(identifiers.sender_operation_id)
            .map_err(map_repository_error);
        let file_cleanup = files
            .cleanup_development_artifacts(identifiers.asset_id)
            .map_err(map_file_error);
        operation_cleanup.and(file_cleanup)?;
    }
    result
}

fn stage_development_transfer_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
    sender_bundle: MowyPublicBundle,
    transfer: MowyDevelopmentTransfer,
) -> Result<String, MowyCoreError> {
    let sender_bundle = decode_public_bundle(&sender_bundle)?;
    let transfer = decode_development_transfer(&transfer)?;
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    if !uuid_equal_bridge(transfer.recipient_key_id, context.profile.agreement_key_id)
        || uuid_equal_bridge(sender_bundle.device_id, context.profile.device_id)
    {
        return Err(MowyCoreError::InvalidInput);
    }
    let expires_at = now
        .checked_add(DEVELOPMENT_TRANSFER_SECONDS)
        .ok_or(MowyCoreError::InvalidInput)?;
    let database_path = context.root.join(PROOF_DATABASE_NAME);
    let mut published =
        PublishedKeyRepository::open(&database_path).map_err(map_key_bundle_error)?;
    published
        .pin_verified(&sender_bundle, now)
        .map_err(map_key_bundle_error)?;
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    operations
        .stage_development_transfer(DevelopmentTransferInbox {
            operation_id: transfer.receiver_operation_id,
            sender_account_id: sender_bundle.account_id,
            sender_device_id: sender_bundle.device_id,
            conversation_id: transfer.conversation_id,
            asset_id: transfer.asset_id,
            recipient_key_id: transfer.recipient_key_id,
            sealed: Some(transfer.sealed),
            plaintext_length: transfer.plaintext_length,
            ciphertext_length: transfer.ciphertext_length,
            ciphertext_digest: transfer.ciphertext_digest,
            received_at: now,
            expires_at,
            state: DevelopmentTransferState::Staged,
        })
        .map_err(map_repository_error)?;
    let files = PrivateFileStore::open(&context.root).map_err(map_file_error)?;
    files
        .ciphertext_path(transfer.asset_id)
        .to_str()
        .map(str::to_owned)
        .ok_or(MowyCoreError::Storage)
}

fn resume_development_transfer_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    receiver_operation_id: &str,
) -> Result<MowyProofReceipt, MowyCoreError> {
    let receiver_operation_id = decode_uuid_hex(receiver_operation_id)?;
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    let database_path = context.root.join(PROOF_DATABASE_NAME);
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    let transfer = operations
        .load_development_transfer(receiver_operation_id)
        .map_err(map_repository_error)?
        .ok_or(MowyCoreError::Unavailable)?;
    if !uuid_equal_bridge(transfer.recipient_key_id, context.profile.agreement_key_id)
        || now >= transfer.expires_at
    {
        return Err(MowyCoreError::Unavailable);
    }
    let published = PublishedKeyRepository::open(&database_path).map_err(map_key_bundle_error)?;
    let sender_bundle = published
        .load_verified_at(transfer.sender_account_id, transfer.sender_device_id, now)
        .map_err(map_key_bundle_error)?
        .ok_or(MowyCoreError::Authentication)?;
    let mut files = PrivateFileStore::open(&context.root).map_err(map_file_error)?;
    let mut cancellation = ForeignCancellation::new(cancellation.as_ref());
    cancellation.require_active()?;
    require_protected(protected_store.as_ref())?;

    let receiver_state = operations
        .receiver_state(receiver_operation_id)
        .map_err(map_repository_error)?;
    let available = if receiver_state == Some(ReceiverState::Available) {
        let mut availability = ForeignAvailability::new(protected_store.as_ref());
        let result = recover_available(
            &operations,
            &mut files,
            receiver_operation_id,
            &mut availability,
        );
        if let Some(error) = availability.take_error() {
            return Err(error);
        }
        result.map_err(map_receiver_error)?
    } else {
        if receiver_state == Some(ReceiverState::UnavailableResend) {
            return Err(MowyCoreError::Unavailable);
        }
        let sealed = match transfer.state {
            DevelopmentTransferState::Staged => {
                if receiver_state.is_some() {
                    return Err(MowyCoreError::Conflict);
                }
                transfer.sealed.ok_or(MowyCoreError::Storage)?
            }
            DevelopmentTransferState::Promoted => {
                let resumable = operations
                    .load_development_resumable(receiver_operation_id)
                    .map_err(map_repository_error)?
                    .ok_or(MowyCoreError::Conflict)?;
                if !uuid_equal_bridge(resumable.conversation_id, transfer.conversation_id)
                    || !uuid_equal_bridge(resumable.asset_id, transfer.asset_id)
                    || !uuid_equal_bridge(resumable.sender_device_id, transfer.sender_device_id)
                    || resumable.plaintext_length != transfer.plaintext_length
                    || resumable.ciphertext_length != transfer.ciphertext_length
                    || !crypto_verify::verify_32(
                        &resumable.ciphertext_digest,
                        &transfer.ciphertext_digest,
                    )
                {
                    return Err(MowyCoreError::Conflict);
                }
                resumable.sealed
            }
        };
        let local_key = LocalAgreementKey::from_current_root(
            &context.root_keys,
            context.profile.device_id,
            context.profile.agreement_key_id,
            context.bundle.validity,
        )
        .map_err(map_sealed_error)?;
        let opened = open_manifest(
            &sealed,
            &local_key,
            TrustedSender {
                device_id: transfer.sender_device_id,
                identity_public_key: sender_bundle.identity_public_key,
            },
            transfer.conversation_id,
            transfer.asset_id,
            now,
        )
        .map_err(map_sealed_error)?;
        require_protected(protected_store.as_ref())?;
        if transfer.state == DevelopmentTransferState::Staged {
            let committed = operations
                .promote_development_transfer(receiver_operation_id, &opened, transfer.received_at)
                .map_err(map_repository_error)?;
            if !matches!(
                committed,
                ReceiverCommit::Created | ReceiverCommit::Existing(_)
            ) {
                return Err(MowyCoreError::Conflict);
            }
        }
        let archive_key = ArchiveKey::from_root(&context.root_keys).map_err(map_archive_error)?;
        let mut availability = ForeignAvailability::new(protected_store.as_ref());
        let result = complete_or_recover(
            &mut operations,
            &mut files,
            receiver_operation_id,
            opened,
            &archive_key,
            &mut availability,
            &mut cancellation,
        );
        if let Some(error) = availability.take_error() {
            return Err(error);
        }
        result.map_err(map_receiver_error)?
    };
    if let Some(error) = cancellation.take_error() {
        return Err(error);
    }

    let archive_key = ArchiveKey::from_root(&context.root_keys).map_err(map_archive_error)?;
    let mut archive = files
        .open_archive_file(transfer.asset_id)
        .map_err(map_file_error)?;
    let mut verifier = FixtureVerifier::new(transfer.plaintext_length);
    open_archive(
        &mut archive,
        &mut verifier,
        &available.descriptor,
        &archive_key,
        &mut cancellation,
    )
    .map_err(|error| cancellation.map_archive_error(error))?;
    verifier.finish()?;
    require_protected(protected_store.as_ref())?;
    cancellation.require_active()?;
    Ok(MowyProofReceipt {
        proof_id: uuid_hex(receiver_operation_id),
        plaintext_length: transfer.plaintext_length,
        ciphertext_length: transfer.ciphertext_length,
        ciphertext_sha256: digest_hex(&transfer.ciphertext_digest),
        archive_sha256: digest_hex(&available.descriptor.ciphertext_digest()),
    })
}

fn cleanup_development_sender_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
    transfer: MowyDevelopmentTransfer,
) -> Result<(), MowyCoreError> {
    let transfer = decode_development_transfer(&transfer)?;
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    let database_path = context.root.join(PROOF_DATABASE_NAME);
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    if !operations
        .development_sender_matches(
            transfer.sender_operation_id,
            transfer.conversation_id,
            transfer.asset_id,
            context.profile.device_id,
        )
        .map_err(map_repository_error)?
    {
        return Err(MowyCoreError::Conflict);
    }
    let durable = operations
        .load_sender_outbox(transfer.sender_operation_id)
        .map_err(map_repository_error)?
        .ok_or(MowyCoreError::Conflict)?;
    if !stored_outbox_matches_transfer(&durable, &transfer) {
        return Err(MowyCoreError::Conflict);
    }
    let mut files = PrivateFileStore::open(&context.root).map_err(map_file_error)?;
    files
        .cleanup_development_artifacts(transfer.asset_id)
        .map_err(map_file_error)?;
    operations
        .cleanup_development_sender(transfer.sender_operation_id)
        .map_err(map_repository_error)
}

#[cfg(test)]
fn cleanup_development_receiver_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    now: u64,
    transfer: MowyDevelopmentTransfer,
) -> Result<(), MowyCoreError> {
    let transfer = decode_development_transfer(&transfer)?;
    let _guard = acquire_proof_lock()?;
    let context = initialize_development_context(protected_store.as_ref(), now)?;
    if !uuid_equal_bridge(transfer.recipient_key_id, context.profile.agreement_key_id) {
        return Err(MowyCoreError::InvalidInput);
    }
    let database_path = context.root.join(PROOF_DATABASE_NAME);
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    let durable = operations
        .load_development_transfer(transfer.receiver_operation_id)
        .map_err(map_repository_error)?
        .ok_or(MowyCoreError::Conflict)?;
    if durable.state != DevelopmentTransferState::Promoted
        || !development_inbox_matches_transfer(&durable, &transfer)
        || operations
            .receiver_state(transfer.receiver_operation_id)
            .map_err(map_repository_error)?
            != Some(ReceiverState::Available)
    {
        return Err(MowyCoreError::Conflict);
    }
    let available = operations
        .load_available(transfer.receiver_operation_id)
        .map_err(map_repository_error)?
        .ok_or(MowyCoreError::Conflict)?;
    if !uuid_equal_bridge(
        available.descriptor.conversation_id(),
        transfer.conversation_id,
    ) || !uuid_equal_bridge(available.descriptor.asset_id(), transfer.asset_id)
        || available.descriptor.plaintext_length() != transfer.plaintext_length
    {
        return Err(MowyCoreError::Conflict);
    }
    let mut files = PrivateFileStore::open(&context.root).map_err(map_file_error)?;
    files
        .cleanup_development_artifacts(transfer.asset_id)
        .map_err(map_file_error)?;
    operations
        .cleanup_development_receiver(transfer.receiver_operation_id)
        .map_err(map_repository_error)
}

fn initialize_development_context(
    protected_store: &dyn NativeProtectedKeyStore,
    now: u64,
) -> Result<DevelopmentContext, MowyCoreError> {
    let root_text = response_path(protected_store.prepare_namespaces())?;
    let root = validate_root(&root_text)?;
    let protected_state = map_native_key_state(response_key_state(protected_store.key_state())?);
    let companions = CompanionState {
        installation_marker_exists: response_flag(protected_store.installation_marker_exists())?,
        database_exists: response_flag(protected_store.database_exists())?,
    };
    let initialization = classify_initialization(protected_state, companions);
    if initialization == InitializationState::Unavailable {
        return Err(MowyCoreError::Unavailable);
    }
    let mut key_store = ProtectedStoreAdapter::new(protected_store);
    let public_keys = initialize(&mut key_store, companions).map_err(map_key_material_error)?;
    if initialization == InitializationState::Empty {
        response_unit(protected_store.commit_companions())?;
    }
    require_ready(protected_store)?;
    validate_database(&root)?;
    let root_keys = key_store.load().map_err(map_key_material_error)?;
    require_protected(protected_store)?;
    let database_path = root.join(PROOF_DATABASE_NAME);
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    let profile = match operations
        .load_development_profile()
        .map_err(map_repository_error)?
    {
        Some(profile) => profile,
        None => {
            let validity = KeyValidityWindow::starting_at(now).map_err(map_key_bundle_error)?;
            let profile = DevelopmentProfile {
                account_id: random_uuid()?,
                device_id: random_uuid()?,
                agreement_key_id: random_uuid()?,
                not_before: validity.not_before,
                not_after: validity.not_after,
            };
            operations
                .create_development_profile(profile)
                .map_err(map_repository_error)?;
            profile
        }
    };
    let validity = KeyValidityWindow::from_bounds(profile.not_before, profile.not_after)
        .map_err(map_key_bundle_error)?;
    validity
        .require_active_at(now)
        .map_err(map_key_bundle_error)?;
    let bundle = sign_current_bundle(
        &root_keys,
        profile.account_id,
        profile.device_id,
        profile.agreement_key_id,
        validity,
    )
    .map_err(map_key_bundle_error)?;
    if !crypto_verify::verify_32(&public_keys.identity, &bundle.identity_public_key)
        || !crypto_verify::verify_32(&public_keys.key_agreement, &bundle.agreement_public_key)
    {
        return Err(MowyCoreError::Authentication);
    }
    Ok(DevelopmentContext {
        root,
        root_keys,
        profile,
        bundle,
    })
}

fn acquire_proof_lock() -> Result<std::sync::MutexGuard<'static, ()>, MowyCoreError> {
    match PROOF_LOCK.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
            Err(MowyCoreError::Conflict)
        }
    }
}

fn encode_public_bundle(bundle: DeviceKeyBundle) -> MowyPublicBundle {
    MowyPublicBundle {
        account_id: uuid_hex(bundle.account_id),
        device_id: uuid_hex(bundle.device_id),
        agreement_key_id: uuid_hex(bundle.agreement_key_id),
        identity_public_key: bytes_hex(&bundle.identity_public_key),
        agreement_public_key: bytes_hex(&bundle.agreement_public_key),
        not_before: bundle.validity.not_before,
        not_after: bundle.validity.not_after,
        signature: bytes_hex(&bundle.signature),
    }
}

fn decode_public_bundle(bundle: &MowyPublicBundle) -> Result<DeviceKeyBundle, MowyCoreError> {
    Ok(DeviceKeyBundle {
        account_id: decode_uuid_hex(&bundle.account_id)?,
        device_id: decode_uuid_hex(&bundle.device_id)?,
        agreement_key_id: decode_uuid_hex(&bundle.agreement_key_id)?,
        identity_public_key: decode_lower_hex(&bundle.identity_public_key)?,
        agreement_public_key: decode_lower_hex(&bundle.agreement_public_key)?,
        validity: KeyValidityWindow::from_bounds(bundle.not_before, bundle.not_after)
            .map_err(map_key_bundle_error)?,
        signature: decode_lower_hex(&bundle.signature)?,
    })
}

fn decode_development_transfer(
    transfer: &MowyDevelopmentTransfer,
) -> Result<ParsedDevelopmentTransfer, MowyCoreError> {
    require_development_plaintext_length(transfer.plaintext_length)?;
    if canonical_ciphertext_length(transfer.plaintext_length).map_err(map_manifest_error)?
        != transfer.ciphertext_length
    {
        return Err(MowyCoreError::InvalidInput);
    }
    let recipient_key_id = decode_uuid_hex(&transfer.recipient_key_id)?;
    Ok(ParsedDevelopmentTransfer {
        sender_operation_id: decode_uuid_hex(&transfer.sender_operation_id)?,
        receiver_operation_id: decode_uuid_hex(&transfer.receiver_operation_id)?,
        conversation_id: decode_uuid_hex(&transfer.conversation_id)?,
        asset_id: decode_uuid_hex(&transfer.asset_id)?,
        recipient_key_id,
        sealed: crate::sealed_manifest::SealedManifest::parse(
            recipient_key_id,
            &decode_lower_hex::<{ crate::sealed_manifest::SEALED_BYTES }>(
                &transfer.sealed_manifest,
            )?,
        )
        .map_err(map_sealed_error)?,
        plaintext_length: transfer.plaintext_length,
        ciphertext_length: transfer.ciphertext_length,
        ciphertext_digest: decode_lower_hex(&transfer.ciphertext_sha256)?,
    })
}

fn require_development_plaintext_length(value: u64) -> Result<(), MowyCoreError> {
    if value == 0 || value > MAXIMUM_DEVELOPMENT_PLAINTEXT_BYTES {
        Err(MowyCoreError::InvalidInput)
    } else {
        canonical_ciphertext_length(value)
            .map(|_| ())
            .map_err(map_manifest_error)
    }
}

fn decode_uuid_hex(value: &str) -> Result<CanonicalUuid, MowyCoreError> {
    CanonicalUuid::from_network_bytes(decode_lower_hex(value)?).map_err(map_key_bundle_error)
}

fn decode_lower_hex<const N: usize>(value: &str) -> Result<[u8; N], MowyCoreError> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(MowyCoreError::InvalidInput);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        output[index] = high * 16 + low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8, MowyCoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(MowyCoreError::InvalidInput),
    }
}

fn uuid_equal_bridge(left: CanonicalUuid, right: CanonicalUuid) -> bool {
    crypto_verify::verify_16(left.as_network_bytes(), right.as_network_bytes())
}

fn stored_outbox_matches_transfer(
    stored: &crate::operation_repository::StoredOutbox,
    transfer: &ParsedDevelopmentTransfer,
) -> bool {
    uuid_equal_bridge(stored.sealed.recipient_key_id, transfer.recipient_key_id)
        && libsodium_rs::utils::memcmp(stored.sealed.as_bytes(), transfer.sealed.as_bytes())
        && stored.ciphertext_name == format!("{}.mowy", uuid_hex(transfer.asset_id))
        && stored.plaintext_length == transfer.plaintext_length
        && stored.ciphertext_length == transfer.ciphertext_length
        && crypto_verify::verify_32(&stored.ciphertext_digest, &transfer.ciphertext_digest)
}

#[cfg(test)]
fn development_inbox_matches_transfer(
    stored: &DevelopmentTransferInbox,
    transfer: &ParsedDevelopmentTransfer,
) -> bool {
    uuid_equal_bridge(stored.operation_id, transfer.receiver_operation_id)
        && uuid_equal_bridge(stored.conversation_id, transfer.conversation_id)
        && uuid_equal_bridge(stored.asset_id, transfer.asset_id)
        && uuid_equal_bridge(stored.recipient_key_id, transfer.recipient_key_id)
        && stored.plaintext_length == transfer.plaintext_length
        && stored.ciphertext_length == transfer.ciphertext_length
        && crypto_verify::verify_32(&stored.ciphertext_digest, &transfer.ciphertext_digest)
}

pub fn run_development_proof(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    plaintext_length: u64,
) -> MowyProofResult {
    match run_development_proof_inner(protected_store, cancellation, now, plaintext_length) {
        Ok(receipt) => MowyProofResult {
            code: MowyCoreCode::Success,
            receipt: Some(receipt),
        },
        Err(error) => MowyProofResult {
            code: map_error_code(error),
            receipt: None,
        },
    }
}

fn run_development_proof_inner(
    protected_store: Box<dyn NativeProtectedKeyStore>,
    cancellation: Box<dyn MowyCancellation>,
    now: u64,
    plaintext_length: u64,
) -> Result<MowyProofReceipt, MowyCoreError> {
    canonical_ciphertext_length(plaintext_length).map_err(map_manifest_error)?;
    let _guard = match PROOF_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
            return Err(MowyCoreError::Conflict);
        }
    };
    let mut cancellation = ForeignCancellation::new(cancellation.as_ref());
    cancellation.require_active()?;
    let root_text = response_path(protected_store.prepare_namespaces())?;
    let root = validate_root(&root_text)?;

    let protected_state = map_native_key_state(response_key_state(protected_store.key_state())?);
    let companions = CompanionState {
        installation_marker_exists: response_flag(protected_store.installation_marker_exists())?,
        database_exists: response_flag(protected_store.database_exists())?,
    };
    let initialization = classify_initialization(protected_state, companions);
    if initialization == InitializationState::Unavailable {
        return Err(MowyCoreError::Unavailable);
    }

    let mut key_store = ProtectedStoreAdapter::new(protected_store.as_ref());
    let public_keys = initialize(&mut key_store, companions).map_err(map_key_material_error)?;
    if initialization == InitializationState::Empty {
        response_unit(protected_store.commit_companions())?;
    }
    require_ready(protected_store.as_ref())?;
    validate_database(&root)?;
    cancellation.require_active()?;

    let root_keys = key_store.load().map_err(map_key_material_error)?;
    if !response_flag(protected_store.protected_data_available())? {
        return Err(MowyCoreError::Unavailable);
    }

    let identifiers = ProofIdentifiers::generate()?;
    let validity = KeyValidityWindow::starting_at(now).map_err(map_key_bundle_error)?;
    let bundle = sign_current_bundle(
        &root_keys,
        identifiers.account_id,
        identifiers.device_id,
        identifiers.agreement_key_id,
        validity,
    )
    .map_err(map_key_bundle_error)?;
    if !crypto_verify::verify_32(&public_keys.identity, &bundle.identity_public_key)
        || !crypto_verify::verify_32(&public_keys.key_agreement, &bundle.agreement_public_key)
    {
        return Err(MowyCoreError::Authentication);
    }

    let database_path = root.join(PROOF_DATABASE_NAME);
    let mut operations = OperationRepository::open(&database_path).map_err(map_repository_error)?;
    let mut published =
        PublishedKeyRepository::open(&database_path).map_err(map_key_bundle_error)?;
    published
        .pin_verified(&bundle, now)
        .map_err(map_key_bundle_error)?;
    let pinned = published
        .load_verified_at(identifiers.account_id, identifiers.device_id, now)
        .map_err(map_key_bundle_error)?
        .ok_or(MowyCoreError::Storage)?;
    let mut files = PrivateFileStore::open(&root).map_err(map_file_error)?;

    let result = execute_fixture(
        &mut operations,
        &mut files,
        protected_store.as_ref(),
        &mut cancellation,
        &root_keys,
        identifiers,
        pinned,
        now,
        plaintext_length,
    );
    let operation_cleanup = operations.cleanup_development_proof(
        identifiers.sender_operation_id,
        identifiers.receiver_operation_id,
    );
    let bundle_cleanup = published
        .remove_development_bundle(identifiers.account_id, identifiers.device_id)
        .map_err(map_key_bundle_error);
    let file_cleanup = files
        .cleanup_development_artifacts(identifiers.asset_id)
        .map_err(map_file_error);

    let cleanup = operation_cleanup
        .map_err(map_repository_error)
        .and(bundle_cleanup)
        .and(file_cleanup);
    match cleanup {
        Ok(()) => result,
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments, reason = "one fixed proof coordinator")]
fn execute_fixture(
    operations: &mut OperationRepository,
    files: &mut PrivateFileStore,
    protected_store: &dyn NativeProtectedKeyStore,
    cancellation: &mut ForeignCancellation<'_>,
    root_keys: &RootKeyMaterial,
    identifiers: ProofIdentifiers,
    recipient_bundle: crate::key_bundle::DeviceKeyBundle,
    now: u64,
    plaintext_length: u64,
) -> Result<MowyProofReceipt, MowyCoreError> {
    files
        .create_development_source(identifiers.asset_id, plaintext_length, cancellation)
        .map_err(|error| cancellation.map_private_error(error))?;
    operations
        .begin_sender(
            identifiers.sender_operation_id,
            identifiers.conversation_id,
            identifiers.asset_id,
            identifiers.device_id,
        )
        .map_err(map_repository_error)?;
    require_protected(protected_store)?;
    let encrypted = files
        .encrypt_asset(
            identifiers.conversation_id,
            identifiers.asset_id,
            cancellation,
        )
        .map_err(|error| cancellation.map_private_error(error))?;
    require_protected(protected_store)?;
    let transport_digest = encrypted
        .encrypted
        .manifest
        .ciphertext_digest()
        .map_err(map_manifest_error)?;
    let transport_length = encrypted
        .encrypted
        .manifest
        .ciphertext_length()
        .map_err(map_manifest_error)?;
    let sealed = seal_manifest(
        root_keys,
        identifiers.device_id,
        &recipient_bundle,
        &encrypted.encrypted.manifest,
        now,
    )
    .map_err(map_sealed_error)?;
    operations
        .commit_sender_outbox(
            identifiers.sender_operation_id,
            &encrypted.encrypted.manifest,
            &sealed,
        )
        .map_err(map_repository_error)?;
    let durable = operations
        .load_sender_outbox(identifiers.sender_operation_id)
        .map_err(map_repository_error)?
        .ok_or(MowyCoreError::Storage)?;
    require_protected(protected_store)?;

    let local_key = LocalAgreementKey::from_current_root(
        root_keys,
        identifiers.device_id,
        identifiers.agreement_key_id,
        recipient_bundle.validity,
    )
    .map_err(map_sealed_error)?;
    let opened = open_manifest(
        &durable.sealed,
        &local_key,
        TrustedSender {
            device_id: identifiers.device_id,
            identity_public_key: recipient_bundle.identity_public_key,
        },
        identifiers.conversation_id,
        identifiers.asset_id,
        now,
    )
    .map_err(map_sealed_error)?;
    require_protected(protected_store)?;
    if operations
        .commit_received_manifest(identifiers.receiver_operation_id, &opened, now)
        .map_err(map_repository_error)?
        != ReceiverCommit::Created
    {
        return Err(MowyCoreError::Conflict);
    }

    let archive_key = ArchiveKey::from_root(root_keys).map_err(map_archive_error)?;
    let mut availability = ForeignAvailability::new(protected_store);
    let available_result = complete_or_recover(
        operations,
        files,
        identifiers.receiver_operation_id,
        opened,
        &archive_key,
        &mut availability,
        cancellation,
    );
    if let Some(error) = availability.take_error() {
        return Err(error);
    }
    let available = available_result.map_err(map_receiver_error)?;
    if let Some(error) = cancellation.take_error() {
        return Err(error);
    }

    let mut relaunch_availability = ForeignAvailability::new(protected_store);
    let recovered = recover_available(
        operations,
        files,
        identifiers.receiver_operation_id,
        &mut relaunch_availability,
    );
    if let Some(error) = relaunch_availability.take_error() {
        return Err(error);
    }
    let recovered = recovered.map_err(map_receiver_error)?;
    if recovered.descriptor != available.descriptor || recovered.path != available.path {
        return Err(MowyCoreError::Conflict);
    }

    let mut archive = files
        .open_archive_file(identifiers.asset_id)
        .map_err(map_file_error)?;
    let mut verifier = FixtureVerifier::new(plaintext_length);
    open_archive(
        &mut archive,
        &mut verifier,
        &recovered.descriptor,
        &archive_key,
        cancellation,
    )
    .map_err(|error| cancellation.map_archive_error(error))?;
    verifier.finish()?;
    require_protected(protected_store)?;
    cancellation.require_active()?;

    Ok(MowyProofReceipt {
        proof_id: uuid_hex(identifiers.receiver_operation_id),
        plaintext_length,
        ciphertext_length: transport_length,
        ciphertext_sha256: digest_hex(&transport_digest),
        archive_sha256: digest_hex(&recovered.descriptor.ciphertext_digest()),
    })
}

#[derive(Clone, Copy)]
struct ProofIdentifiers {
    account_id: CanonicalUuid,
    device_id: CanonicalUuid,
    agreement_key_id: CanonicalUuid,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    sender_operation_id: CanonicalUuid,
    receiver_operation_id: CanonicalUuid,
}

impl ProofIdentifiers {
    fn generate() -> Result<Self, MowyCoreError> {
        Ok(Self {
            account_id: random_uuid()?,
            device_id: random_uuid()?,
            agreement_key_id: random_uuid()?,
            conversation_id: random_uuid()?,
            asset_id: random_uuid()?,
            sender_operation_id: random_uuid()?,
            receiver_operation_id: random_uuid()?,
        })
    }
}

struct ProtectedStoreAdapter<'a> {
    foreign: &'a dyn NativeProtectedKeyStore,
}

impl<'a> ProtectedStoreAdapter<'a> {
    fn new(foreign: &'a dyn NativeProtectedKeyStore) -> Self {
        Self { foreign }
    }
}

impl ProtectedKeyStore for ProtectedStoreAdapter<'_> {
    fn protected_data_available(&self) -> Result<bool, KeyMaterialError> {
        response_flag(self.foreign.protected_data_available()).map_err(map_bridge_key_error)
    }

    fn state(&self) -> Result<ProtectedKeyState, KeyMaterialError> {
        response_key_state(self.foreign.key_state())
            .map(map_native_key_state)
            .map_err(map_bridge_key_error)
    }

    fn store_new(&mut self, material: &RootKeyMaterial) -> Result<(), KeyMaterialError> {
        let mut words = Zeroizing::new([0_u64; ROOT_WORDS]);
        for (index, chunk) in material
            .expose_for_protected_storage()
            .chunks_exact(8)
            .enumerate()
        {
            words[index] = u64::from_be_bytes(
                chunk
                    .try_into()
                    .map_err(|_| KeyMaterialError::CorruptState)?,
            );
        }
        response_unit(self.foreign.store_new(
            words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7],
            words[8], words[9], words[10], words[11],
        ))
        .map_err(map_bridge_key_error)
    }

    fn load(&self) -> Result<RootKeyMaterial, KeyMaterialError> {
        let token = response_number(self.foreign.begin_load()).map_err(map_bridge_key_error)?;
        let mut material = Zeroizing::new([0_u8; ROOT_KEY_MATERIAL_BYTES]);
        for index in 0..ROOT_WORDS {
            let word = match response_number(self.foreign.load_word(
                token,
                u8::try_from(index).map_err(|_| KeyMaterialError::CorruptState)?,
            )) {
                Ok(word) => word,
                Err(error) => {
                    let _ = response_unit(self.foreign.finish_load(token));
                    return Err(map_bridge_key_error(error));
                }
            };
            let start = index * 8;
            material[start..start + 8].copy_from_slice(&word.to_be_bytes());
        }
        response_unit(self.foreign.finish_load(token)).map_err(map_bridge_key_error)?;
        Ok(RootKeyMaterial::from_protected_storage(&material))
    }
}

struct ForeignCancellation<'a> {
    foreign: &'a dyn MowyCancellation,
    error: Option<MowyCoreError>,
}

impl<'a> ForeignCancellation<'a> {
    fn new(foreign: &'a dyn MowyCancellation) -> Self {
        Self {
            foreign,
            error: None,
        }
    }

    fn require_active(&mut self) -> Result<(), MowyCoreError> {
        if self.is_cancelled() {
            Err(self.take_error().unwrap_or(MowyCoreError::Cancelled))
        } else {
            Ok(())
        }
    }

    fn take_error(&mut self) -> Option<MowyCoreError> {
        self.error.take()
    }

    fn map_private_error(&mut self, error: PrivateFileError) -> MowyCoreError {
        self.take_error().unwrap_or_else(|| map_file_error(error))
    }

    fn map_archive_error(&mut self, error: ArchiveError) -> MowyCoreError {
        self.take_error()
            .unwrap_or_else(|| map_archive_error(error))
    }
}

impl CancellationCheck for ForeignCancellation<'_> {
    fn is_cancelled(&mut self) -> bool {
        match response_flag(self.foreign.is_cancelled()) {
            Ok(cancelled) => cancelled,
            Err(error) => {
                self.error = Some(error);
                true
            }
        }
    }
}

struct ForeignAvailability<'a> {
    foreign: &'a dyn NativeProtectedKeyStore,
    error: Option<MowyCoreError>,
}

impl<'a> ForeignAvailability<'a> {
    fn new(foreign: &'a dyn NativeProtectedKeyStore) -> Self {
        Self {
            foreign,
            error: None,
        }
    }

    fn take_error(&mut self) -> Option<MowyCoreError> {
        self.error.take()
    }
}

impl AvailabilityCheck for ForeignAvailability<'_> {
    fn is_available(&mut self) -> bool {
        match response_flag(self.foreign.protected_data_available()) {
            Ok(available) => available,
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }
}

struct FixtureVerifier {
    expected_length: u64,
    offset: u64,
}

impl FixtureVerifier {
    fn new(expected_length: u64) -> Self {
        Self {
            expected_length,
            offset: 0,
        }
    }

    fn finish(&self) -> Result<(), MowyCoreError> {
        if self.offset == self.expected_length {
            Ok(())
        } else {
            Err(MowyCoreError::Authentication)
        }
    }
}

impl Write for FixtureVerifier {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        for (relative, byte) in input.iter().enumerate() {
            let index = self
                .offset
                .checked_add(relative as u64)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "fixture verification"))?;
            if *byte != (index % 251) as u8 {
                return Err(Error::new(ErrorKind::InvalidData, "fixture verification"));
            }
        }
        self.offset = self
            .offset
            .checked_add(input.len() as u64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "fixture verification"))?;
        if self.offset > self.expected_length {
            return Err(Error::new(ErrorKind::InvalidData, "fixture verification"));
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_root(root: &str) -> Result<PathBuf, MowyCoreError> {
    if root.is_empty() || root.len() > 4_096 {
        return Err(MowyCoreError::InvalidInput);
    }
    let path = Path::new(root);
    let metadata = std::fs::symlink_metadata(path).map_err(|_| MowyCoreError::Storage)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & FILE_MODE_MASK != 0
    {
        return Err(MowyCoreError::InvalidInput);
    }
    path.canonicalize().map_err(|_| MowyCoreError::Storage)
}

fn validate_database(root: &Path) -> Result<(), MowyCoreError> {
    let path = root.join(PROOF_DATABASE_NAME);
    let before = std::fs::symlink_metadata(&path).map_err(|_| MowyCoreError::Storage)?;
    if before.file_type().is_symlink()
        || !before.file_type().is_file()
        || before.permissions().mode() & FILE_MODE_MASK != 0
    {
        return Err(MowyCoreError::InvalidInput);
    }
    let opened = File::open(&path).map_err(|_| MowyCoreError::Storage)?;
    let after = opened.metadata().map_err(|_| MowyCoreError::Storage)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(MowyCoreError::Conflict);
    }
    Ok(())
}

fn response_unit(response: NativeBridgeResponse) -> Result<(), MowyCoreError> {
    require_response_success(&response)?;
    if response.path.is_empty() {
        Ok(())
    } else {
        Err(MowyCoreError::InvalidInput)
    }
}

fn response_flag(response: NativeBridgeResponse) -> Result<bool, MowyCoreError> {
    require_response_success(&response)?;
    if response.path.is_empty() {
        Ok(response.flag)
    } else {
        Err(MowyCoreError::InvalidInput)
    }
}

fn response_number(response: NativeBridgeResponse) -> Result<u64, MowyCoreError> {
    require_response_success(&response)?;
    if response.path.is_empty() {
        Ok(response.number)
    } else {
        Err(MowyCoreError::InvalidInput)
    }
}

fn response_key_state(
    response: NativeBridgeResponse,
) -> Result<NativeProtectedKeyState, MowyCoreError> {
    require_response_success(&response)?;
    if response.path.is_empty() {
        Ok(response.key_state)
    } else {
        Err(MowyCoreError::InvalidInput)
    }
}

fn response_path(response: NativeBridgeResponse) -> Result<String, MowyCoreError> {
    require_response_success(&response)?;
    Ok(response.path)
}

fn require_response_success(response: &NativeBridgeResponse) -> Result<(), MowyCoreError> {
    if response.code == MowyCoreCode::Success {
        Ok(())
    } else if response.path.is_empty() {
        Err(map_core_code(response.code))
    } else {
        Err(MowyCoreError::InvalidInput)
    }
}

fn map_core_code(code: MowyCoreCode) -> MowyCoreError {
    match code {
        MowyCoreCode::Success => MowyCoreError::Storage,
        MowyCoreCode::InvalidInput => MowyCoreError::InvalidInput,
        MowyCoreCode::Unavailable => MowyCoreError::Unavailable,
        MowyCoreCode::Conflict => MowyCoreError::Conflict,
        MowyCoreCode::Storage => MowyCoreError::Storage,
        MowyCoreCode::Authentication => MowyCoreError::Authentication,
        MowyCoreCode::Cryptography => MowyCoreError::Cryptography,
        MowyCoreCode::Cancelled => MowyCoreError::Cancelled,
    }
}

fn map_error_code(error: MowyCoreError) -> MowyCoreCode {
    match error {
        MowyCoreError::InvalidInput => MowyCoreCode::InvalidInput,
        MowyCoreError::Unavailable => MowyCoreCode::Unavailable,
        MowyCoreError::Conflict => MowyCoreCode::Conflict,
        MowyCoreError::Storage => MowyCoreCode::Storage,
        MowyCoreError::Authentication => MowyCoreCode::Authentication,
        MowyCoreError::Cryptography => MowyCoreCode::Cryptography,
        MowyCoreError::Cancelled => MowyCoreCode::Cancelled,
    }
}

fn require_ready(store: &dyn NativeProtectedKeyStore) -> Result<(), MowyCoreError> {
    if response_key_state(store.key_state())? != NativeProtectedKeyState::Present
        || !response_flag(store.installation_marker_exists())?
        || !response_flag(store.database_exists())?
        || !response_flag(store.protected_data_available())?
    {
        return Err(MowyCoreError::Unavailable);
    }
    Ok(())
}

fn require_protected(store: &dyn NativeProtectedKeyStore) -> Result<(), MowyCoreError> {
    if response_flag(store.protected_data_available())? {
        Ok(())
    } else {
        Err(MowyCoreError::Unavailable)
    }
}

fn random_uuid() -> Result<CanonicalUuid, MowyCoreError> {
    ensure_init().map_err(|_| MowyCoreError::Cryptography)?;
    let mut bytes = [0_u8; 16];
    random::fill_bytes(&mut bytes);
    CanonicalUuid::from_network_bytes(bytes).map_err(map_key_bundle_error)
}

fn map_native_key_state(state: NativeProtectedKeyState) -> ProtectedKeyState {
    match state {
        NativeProtectedKeyState::Absent => ProtectedKeyState::Absent,
        NativeProtectedKeyState::Present => ProtectedKeyState::Present,
        NativeProtectedKeyState::Partial => ProtectedKeyState::Partial,
    }
}

fn map_bridge_key_error(error: MowyCoreError) -> KeyMaterialError {
    match error {
        MowyCoreError::Unavailable => KeyMaterialError::Unavailable,
        MowyCoreError::Conflict => KeyMaterialError::Conflict,
        MowyCoreError::Cryptography => KeyMaterialError::Cryptography,
        MowyCoreError::InvalidInput | MowyCoreError::Authentication | MowyCoreError::Cancelled => {
            KeyMaterialError::CorruptState
        }
        MowyCoreError::Storage => KeyMaterialError::Storage,
    }
}

fn map_key_material_error(error: KeyMaterialError) -> MowyCoreError {
    match error {
        KeyMaterialError::Unavailable => MowyCoreError::Unavailable,
        KeyMaterialError::CorruptState => MowyCoreError::Unavailable,
        KeyMaterialError::Conflict => MowyCoreError::Conflict,
        KeyMaterialError::Storage => MowyCoreError::Storage,
        KeyMaterialError::Cryptography => MowyCoreError::Cryptography,
    }
}

fn map_key_bundle_error(error: KeyBundleError) -> MowyCoreError {
    match error {
        KeyBundleError::InvalidInput => MowyCoreError::InvalidInput,
        KeyBundleError::NotYetValid | KeyBundleError::Expired => MowyCoreError::Unavailable,
        KeyBundleError::Signature | KeyBundleError::IdentityChanged | KeyBundleError::Rollback => {
            MowyCoreError::Authentication
        }
        KeyBundleError::Storage => MowyCoreError::Storage,
        KeyBundleError::Cryptography => MowyCoreError::Cryptography,
    }
}

fn map_manifest_error(error: AttachmentManifestError) -> MowyCoreError {
    match error {
        AttachmentManifestError::InvalidInput => MowyCoreError::InvalidInput,
        AttachmentManifestError::Cryptography => MowyCoreError::Cryptography,
    }
}

fn map_sealed_error(error: SealedManifestError) -> MowyCoreError {
    match error {
        SealedManifestError::InvalidInput | SealedManifestError::IdentifierMismatch => {
            MowyCoreError::InvalidInput
        }
        SealedManifestError::Unavailable | SealedManifestError::ExpiredKey => {
            MowyCoreError::Unavailable
        }
        SealedManifestError::Cryptography => MowyCoreError::Cryptography,
        SealedManifestError::Signature
        | SealedManifestError::IdentityChanged
        | SealedManifestError::RecipientMismatch => MowyCoreError::Authentication,
    }
}

fn map_file_error(error: PrivateFileError) -> MowyCoreError {
    match error {
        PrivateFileError::InvalidInput | PrivateFileError::UnsafePath => {
            MowyCoreError::InvalidInput
        }
        PrivateFileError::Conflict => MowyCoreError::Conflict,
        PrivateFileError::Io => MowyCoreError::Storage,
        PrivateFileError::Cryptography => MowyCoreError::Cryptography,
        PrivateFileError::Authentication => MowyCoreError::Authentication,
        PrivateFileError::Cancelled => MowyCoreError::Cancelled,
    }
}

fn map_repository_error(error: OperationRepositoryError) -> MowyCoreError {
    match error {
        OperationRepositoryError::InvalidInput => MowyCoreError::InvalidInput,
        OperationRepositoryError::Conflict => MowyCoreError::Conflict,
        OperationRepositoryError::Storage => MowyCoreError::Storage,
    }
}

fn map_receiver_error(error: ReceiverLifecycleError) -> MowyCoreError {
    match error {
        ReceiverLifecycleError::InvalidInput => MowyCoreError::InvalidInput,
        ReceiverLifecycleError::Unavailable => MowyCoreError::Unavailable,
        ReceiverLifecycleError::Conflict => MowyCoreError::Conflict,
        ReceiverLifecycleError::Storage | ReceiverLifecycleError::Io => MowyCoreError::Storage,
        ReceiverLifecycleError::Authentication => MowyCoreError::Authentication,
        ReceiverLifecycleError::Cryptography => MowyCoreError::Cryptography,
        ReceiverLifecycleError::Cancelled => MowyCoreError::Cancelled,
    }
}

fn map_archive_error(error: ArchiveError) -> MowyCoreError {
    match error {
        ArchiveError::InvalidInput => MowyCoreError::InvalidInput,
        ArchiveError::Authentication => MowyCoreError::Authentication,
        ArchiveError::Io => MowyCoreError::Storage,
        ArchiveError::Cryptography => MowyCoreError::Cryptography,
        ArchiveError::Cancelled => MowyCoreError::Cancelled,
    }
}

fn digest_hex(digest: &[u8; DIGEST_BYTES]) -> String {
    bytes_hex(digest)
}

fn uuid_hex(uuid: CanonicalUuid) -> String {
    bytes_hex(uuid.as_network_bytes())
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    static BRIDGE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone)]
    struct TestStore {
        inner: Arc<TestStoreInner>,
    }

    struct TestStoreInner {
        root: PathBuf,
        available: AtomicBool,
        protected_checks: AtomicU64,
        unavailable_on_check: AtomicU64,
        material: Mutex<Option<Zeroizing<[u8; ROOT_KEY_MATERIAL_BYTES]>>>,
        load_session: Mutex<Option<(u64, Zeroizing<[u8; ROOT_KEY_MATERIAL_BYTES]>)>>,
        next_token: AtomicU64,
    }

    impl TestStore {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("mowy-p2-bridge-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            Self {
                inner: Arc::new(TestStoreInner {
                    root,
                    available: AtomicBool::new(true),
                    protected_checks: AtomicU64::new(0),
                    unavailable_on_check: AtomicU64::new(0),
                    material: Mutex::new(None),
                    load_session: Mutex::new(None),
                    next_token: AtomicU64::new(1),
                }),
            }
        }

        fn cleanup(&self) -> Result<(), MowyCoreError> {
            std::fs::remove_dir_all(&self.inner.root).map_err(|_| MowyCoreError::Storage)
        }

        fn create_companions_without_key(&self) -> Result<(), MowyCoreError> {
            response_path(self.prepare_namespaces())?;
            response_unit(self.commit_companions())
        }

        fn relock_on_protected_check(&self, check: u64) {
            self.inner.protected_checks.store(0, Ordering::SeqCst);
            self.inner
                .unavailable_on_check
                .store(check, Ordering::SeqCst);
            self.inner.available.store(true, Ordering::SeqCst);
        }

        fn unlock(&self) {
            self.inner.available.store(true, Ordering::SeqCst);
            self.inner.unavailable_on_check.store(0, Ordering::SeqCst);
            self.inner.protected_checks.store(0, Ordering::SeqCst);
        }
    }

    impl NativeProtectedKeyStore for TestStore {
        fn protected_data_available(&self) -> NativeBridgeResponse {
            let check = self.inner.protected_checks.fetch_add(1, Ordering::SeqCst) + 1;
            if self.inner.unavailable_on_check.load(Ordering::SeqCst) == check {
                self.inner.available.store(false, Ordering::SeqCst);
            }
            NativeBridgeResponse {
                flag: self.inner.available.load(Ordering::SeqCst),
                ..success_response()
            }
        }

        fn key_state(&self) -> NativeBridgeResponse {
            match self.inner.material.lock() {
                Ok(material) => NativeBridgeResponse {
                    key_state: if material.is_some() {
                        NativeProtectedKeyState::Present
                    } else {
                        NativeProtectedKeyState::Absent
                    },
                    ..success_response()
                },
                Err(_) => error_response(MowyCoreError::Storage),
            }
        }

        fn installation_marker_exists(&self) -> NativeBridgeResponse {
            NativeBridgeResponse {
                flag: self.inner.root.join("installation.v1").is_file(),
                ..success_response()
            }
        }

        fn database_exists(&self) -> NativeBridgeResponse {
            NativeBridgeResponse {
                flag: self.inner.root.join(PROOF_DATABASE_NAME).is_file(),
                ..success_response()
            }
        }

        fn prepare_namespaces(&self) -> NativeBridgeResponse {
            let result = (|| -> Result<String, MowyCoreError> {
                if !self.inner.root.exists() {
                    std::fs::create_dir(&self.inner.root).map_err(|_| MowyCoreError::Storage)?;
                    std::fs::set_permissions(
                        &self.inner.root,
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .map_err(|_| MowyCoreError::Storage)?;
                }
                for name in [
                    "source",
                    "ciphertext",
                    "receive-temp",
                    "verified",
                    "archive",
                ] {
                    let path = self.inner.root.join(name);
                    if !path.exists() {
                        std::fs::create_dir(&path).map_err(|_| MowyCoreError::Storage)?;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .map_err(|_| MowyCoreError::Storage)?;
                    }
                }
                self.inner
                    .root
                    .to_str()
                    .map(str::to_owned)
                    .ok_or(MowyCoreError::Storage)
            })();
            match result {
                Ok(path) => NativeBridgeResponse {
                    path,
                    ..success_response()
                },
                Err(error) => error_response(error),
            }
        }

        fn commit_companions(&self) -> NativeBridgeResponse {
            let result = (|| -> Result<(), MowyCoreError> {
                for name in ["installation.v1", PROOF_DATABASE_NAME] {
                    let path = self.inner.root.join(name);
                    if !path.exists() {
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(path)
                            .and_then(|file| file.sync_all())
                            .map_err(|_| MowyCoreError::Storage)?;
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => success_response(),
                Err(error) => error_response(error),
            }
        }

        fn store_new(
            &self,
            word_0: u64,
            word_1: u64,
            word_2: u64,
            word_3: u64,
            word_4: u64,
            word_5: u64,
            word_6: u64,
            word_7: u64,
            word_8: u64,
            word_9: u64,
            word_10: u64,
            word_11: u64,
        ) -> NativeBridgeResponse {
            let result = (|| -> Result<(), MowyCoreError> {
                let words = [
                    word_0, word_1, word_2, word_3, word_4, word_5, word_6, word_7, word_8, word_9,
                    word_10, word_11,
                ];
                let mut material = Zeroizing::new([0_u8; ROOT_KEY_MATERIAL_BYTES]);
                for (index, word) in words.iter().enumerate() {
                    let start = index * 8;
                    material[start..start + 8].copy_from_slice(&word.to_be_bytes());
                }
                let mut stored = self
                    .inner
                    .material
                    .lock()
                    .map_err(|_| MowyCoreError::Storage)?;
                if stored.is_some() {
                    return Err(MowyCoreError::Conflict);
                }
                *stored = Some(material);
                Ok(())
            })();
            match result {
                Ok(()) => success_response(),
                Err(error) => error_response(error),
            }
        }

        fn begin_load(&self) -> NativeBridgeResponse {
            let result = (|| -> Result<u64, MowyCoreError> {
                let stored = self
                    .inner
                    .material
                    .lock()
                    .map_err(|_| MowyCoreError::Storage)?;
                let source = stored.as_ref().ok_or(MowyCoreError::Unavailable)?;
                let mut copy = Zeroizing::new([0_u8; ROOT_KEY_MATERIAL_BYTES]);
                copy.copy_from_slice(source.as_ref());
                drop(stored);
                let token = self.inner.next_token.fetch_add(1, Ordering::SeqCst);
                let mut session = self
                    .inner
                    .load_session
                    .lock()
                    .map_err(|_| MowyCoreError::Storage)?;
                if session.is_some() {
                    return Err(MowyCoreError::Conflict);
                }
                *session = Some((token, copy));
                Ok(token)
            })();
            match result {
                Ok(number) => NativeBridgeResponse {
                    number,
                    ..success_response()
                },
                Err(error) => error_response(error),
            }
        }

        fn load_word(&self, token: u64, index: u8) -> NativeBridgeResponse {
            let result = (|| -> Result<u64, MowyCoreError> {
                let session = self
                    .inner
                    .load_session
                    .lock()
                    .map_err(|_| MowyCoreError::Storage)?;
                let (active, material) = session.as_ref().ok_or(MowyCoreError::Unavailable)?;
                let index = usize::from(index);
                if *active != token || index >= ROOT_WORDS {
                    return Err(MowyCoreError::InvalidInput);
                }
                let start = index * 8;
                Ok(u64::from_be_bytes(
                    material[start..start + 8]
                        .try_into()
                        .map_err(|_| MowyCoreError::Storage)?,
                ))
            })();
            match result {
                Ok(number) => NativeBridgeResponse {
                    number,
                    ..success_response()
                },
                Err(error) => error_response(error),
            }
        }

        fn finish_load(&self, token: u64) -> NativeBridgeResponse {
            let result = (|| -> Result<(), MowyCoreError> {
                let mut session = self
                    .inner
                    .load_session
                    .lock()
                    .map_err(|_| MowyCoreError::Storage)?;
                if session.as_ref().map(|value| value.0) != Some(token) {
                    return Err(MowyCoreError::Conflict);
                }
                *session = None;
                Ok(())
            })();
            match result {
                Ok(()) => success_response(),
                Err(error) => error_response(error),
            }
        }
    }

    struct NeverCancel;

    impl MowyCancellation for NeverCancel {
        fn is_cancelled(&self) -> NativeBridgeResponse {
            success_response()
        }
    }

    struct AlwaysCancel;

    impl MowyCancellation for AlwaysCancel {
        fn is_cancelled(&self) -> NativeBridgeResponse {
            NativeBridgeResponse {
                flag: true,
                ..success_response()
            }
        }
    }

    fn run_test_proof(
        store: TestStore,
        cancellation: Box<dyn MowyCancellation>,
        now: u64,
        plaintext_length: u64,
    ) -> Result<MowyProofReceipt, MowyCoreError> {
        run_development_proof_inner(Box::new(store), cancellation, now, plaintext_length)
    }

    #[test]
    fn cross_device_transfer_stages_before_open_survives_relaunch_and_cleans_exactly()
    -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let sender = TestStore::new("cross-device-sender");
        let receiver = TestStore::new("cross-device-receiver");
        let now = 1_780_000_000;
        let sender_bundle = publish_development_bundle_inner(Box::new(sender.clone()), now)?;
        let receiver_bundle = publish_development_bundle_inner(Box::new(receiver.clone()), now)?;
        let (transfer, source_path) = prepare_development_transfer_inner(
            Box::new(sender.clone()),
            Box::new(NeverCancel),
            now,
            70_000,
            receiver_bundle,
        )?;
        let destination_path = stage_development_transfer_inner(
            Box::new(receiver.clone()),
            now + 1,
            sender_bundle.clone(),
            transfer.clone(),
        )?;
        assert_eq!(
            stage_development_transfer_inner(
                Box::new(receiver.clone()),
                now + 2,
                sender_bundle,
                transfer.clone(),
            )?,
            destination_path
        );
        let parsed = decode_development_transfer(&transfer)?;
        {
            let repository =
                OperationRepository::open(&receiver.inner.root.join(PROOF_DATABASE_NAME))
                    .map_err(map_repository_error)?;
            let staged = repository
                .load_development_transfer(parsed.receiver_operation_id)
                .map_err(map_repository_error)?
                .ok_or(MowyCoreError::Storage)?;
            assert_eq!(staged.state, DevelopmentTransferState::Staged);
            assert!(staged.sealed.is_some());
            assert_eq!(
                repository
                    .receiver_state(parsed.receiver_operation_id)
                    .map_err(map_repository_error)?,
                None
            );
        }
        assert!(!Path::new(&destination_path).exists());
        std::fs::copy(&source_path, &destination_path).map_err(|_| MowyCoreError::Storage)?;
        std::fs::set_permissions(&destination_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| MowyCoreError::Storage)?;

        let first = resume_development_transfer_inner(
            Box::new(receiver.clone()),
            Box::new(NeverCancel),
            now + 3,
            &transfer.receiver_operation_id,
        )?;
        let relaunched = resume_development_transfer_inner(
            Box::new(receiver.clone()),
            Box::new(NeverCancel),
            now + 4,
            &transfer.receiver_operation_id,
        )?;
        assert_eq!(first, relaunched);
        assert_eq!(first.plaintext_length, 70_000);
        assert_eq!(first.ciphertext_sha256, transfer.ciphertext_sha256);

        cleanup_development_receiver_inner(Box::new(receiver.clone()), now + 5, transfer.clone())?;
        cleanup_development_sender_inner(Box::new(sender.clone()), now + 5, transfer)?;
        {
            let sender_repository =
                OperationRepository::open(&sender.inner.root.join(PROOF_DATABASE_NAME))
                    .map_err(map_repository_error)?;
            assert!(
                sender_repository
                    .load_sender_outbox(parsed.sender_operation_id)
                    .map_err(map_repository_error)?
                    .is_none()
            );
            let receiver_repository =
                OperationRepository::open(&receiver.inner.root.join(PROOF_DATABASE_NAME))
                    .map_err(map_repository_error)?;
            assert!(
                receiver_repository
                    .load_development_transfer(parsed.receiver_operation_id)
                    .map_err(map_repository_error)?
                    .is_none()
            );
            assert!(
                receiver_repository
                    .receiver_state(parsed.receiver_operation_id)
                    .map_err(map_repository_error)?
                    .is_none()
            );
        }
        for store in [&sender, &receiver] {
            for name in [
                "source",
                "ciphertext",
                "receive-temp",
                "verified",
                "archive",
            ] {
                assert_eq!(
                    std::fs::read_dir(store.inner.root.join(name))
                        .map_err(|_| MowyCoreError::Storage)?
                        .count(),
                    0
                );
            }
        }
        sender.cleanup()?;
        receiver.cleanup()
    }

    #[test]
    fn semantic_receiver_relock_retries_by_opaque_operation_and_cleans_exactly()
    -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let sender = TestStore::new("relock-sender");
        let receiver = TestStore::new("relock-receiver");
        let now = 1_780_000_000;
        let sender_bundle = publish_development_bundle_inner(Box::new(sender.clone()), now)?;
        let receiver_bundle = publish_development_bundle_inner(Box::new(receiver.clone()), now)?;
        let (transfer, source_path) = prepare_development_transfer_inner(
            Box::new(sender.clone()),
            Box::new(NeverCancel),
            now,
            70_000,
            receiver_bundle,
        )?;
        let destination_path = stage_development_transfer_inner(
            Box::new(receiver.clone()),
            now + 1,
            sender_bundle,
            transfer.clone(),
        )?;
        std::fs::copy(&source_path, &destination_path).map_err(|_| MowyCoreError::Storage)?;
        std::fs::set_permissions(&destination_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| MowyCoreError::Storage)?;

        // In semantic resume, callback eight follows authenticated decryption
        // and sync but precedes plaintext promotion. The durable operation ID
        // must therefore recover the exact transfer after unlock.
        receiver.relock_on_protected_check(8);
        let unavailable = resume_development_transfer(
            Box::new(receiver.clone()),
            Box::new(NeverCancel),
            now + 2,
            transfer.receiver_operation_id.clone(),
        );
        assert_eq!(unavailable.code, MowyCoreCode::Unavailable);
        assert_eq!(unavailable.receipt, None);
        let parsed = decode_development_transfer(&transfer)?;
        {
            let repository =
                OperationRepository::open(&receiver.inner.root.join(PROOF_DATABASE_NAME))
                    .map_err(map_repository_error)?;
            let retained = repository
                .load_development_transfer(parsed.receiver_operation_id)
                .map_err(map_repository_error)?
                .ok_or(MowyCoreError::Storage)?;
            assert_eq!(retained.state, DevelopmentTransferState::Promoted);
            assert_eq!(retained.sealed, None);
            assert_eq!(
                repository
                    .receiver_state(parsed.receiver_operation_id)
                    .map_err(map_repository_error)?,
                Some(ReceiverState::WaitingForCiphertext)
            );
        }
        let files = PrivateFileStore::open(&receiver.inner.root).map_err(map_file_error)?;
        assert_eq!(
            files
                .verified_plaintext_state(parsed.asset_id)
                .map_err(map_file_error)?,
            crate::private_files::VerifiedPlaintextState::Missing
        );
        assert!(Path::new(&destination_path).is_file());
        assert!(!files.archive_path(parsed.asset_id).exists());
        for (name, expected) in [
            ("source", 0),
            ("ciphertext", 1),
            ("receive-temp", 0),
            ("verified", 0),
            ("archive", 0),
        ] {
            assert_eq!(
                std::fs::read_dir(receiver.inner.root.join(name))
                    .map_err(|_| MowyCoreError::Storage)?
                    .count(),
                expected
            );
        }

        receiver.unlock();
        let resumed = resume_development_transfer_inner(
            Box::new(receiver.clone()),
            Box::new(NeverCancel),
            now + 3,
            &transfer.receiver_operation_id,
        )?;
        let repeated = resume_development_transfer_inner(
            Box::new(receiver.clone()),
            Box::new(NeverCancel),
            now + 4,
            &transfer.receiver_operation_id,
        )?;
        assert_eq!(resumed, repeated);

        cleanup_development_receiver_inner(Box::new(receiver.clone()), now + 5, transfer.clone())?;
        cleanup_development_sender_inner(Box::new(sender.clone()), now + 5, transfer)?;
        for store in [&sender, &receiver] {
            for name in [
                "source",
                "ciphertext",
                "receive-temp",
                "verified",
                "archive",
            ] {
                assert_eq!(
                    std::fs::read_dir(store.inner.root.join(name))
                        .map_err(|_| MowyCoreError::Storage)?
                        .count(),
                    0
                );
            }
        }
        sender.cleanup()?;
        receiver.cleanup()
    }

    #[test]
    fn staged_transfer_is_not_opened_until_resume_and_tamper_remains_durable()
    -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let sender = TestStore::new("staged-tamper-sender");
        let receiver = TestStore::new("staged-tamper-receiver");
        let now = 1_780_000_000;
        let sender_bundle = publish_development_bundle_inner(Box::new(sender.clone()), now)?;
        let receiver_bundle = publish_development_bundle_inner(Box::new(receiver.clone()), now)?;
        let (mut transfer, _) = prepare_development_transfer_inner(
            Box::new(sender.clone()),
            Box::new(NeverCancel),
            now,
            64,
            receiver_bundle,
        )?;
        let replacement = if transfer.sealed_manifest.starts_with('0') {
            "1"
        } else {
            "0"
        };
        transfer.sealed_manifest.replace_range(0..1, replacement);
        stage_development_transfer_inner(
            Box::new(receiver.clone()),
            now + 1,
            sender_bundle,
            transfer.clone(),
        )?;
        assert!(matches!(
            resume_development_transfer_inner(
                Box::new(receiver.clone()),
                Box::new(NeverCancel),
                now + 2,
                &transfer.receiver_operation_id,
            ),
            Err(MowyCoreError::Authentication | MowyCoreError::Cryptography)
        ));
        let parsed = decode_development_transfer(&transfer)?;
        let repository = OperationRepository::open(&receiver.inner.root.join(PROOF_DATABASE_NAME))
            .map_err(map_repository_error)?;
        let retained = repository
            .load_development_transfer(parsed.receiver_operation_id)
            .map_err(map_repository_error)?
            .ok_or(MowyCoreError::Storage)?;
        assert_eq!(retained.state, DevelopmentTransferState::Staged);
        assert_eq!(retained.sealed, Some(parsed.sealed));
        assert_eq!(
            repository
                .receiver_state(parsed.receiver_operation_id)
                .map_err(map_repository_error)?,
            None
        );
        drop(repository);
        sender.cleanup()?;
        receiver.cleanup()
    }

    #[test]
    fn runs_twice_with_persistent_protected_keys_and_disposable_artifacts()
    -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let store = TestStore::new("round-trip");
        let first = run_test_proof(store.clone(), Box::new(NeverCancel), 1_780_000_000, 70_000)?;
        let second = run_test_proof(store.clone(), Box::new(NeverCancel), 1_780_000_001, 65_537)?;
        assert_ne!(first.proof_id, second.proof_id);
        assert_ne!(first.ciphertext_sha256, second.ciphertext_sha256);
        assert_ne!(first.archive_sha256, second.archive_sha256);
        assert_eq!(
            response_key_state(store.key_state())?,
            NativeProtectedKeyState::Present
        );
        assert!(response_flag(store.installation_marker_exists())?);
        assert!(response_flag(store.database_exists())?);
        for name in [
            "source",
            "ciphertext",
            "receive-temp",
            "verified",
            "archive",
        ] {
            assert_eq!(
                std::fs::read_dir(store.inner.root.join(name))
                    .map_err(|_| MowyCoreError::Storage)?
                    .count(),
                0
            );
        }
        store.cleanup()
    }

    #[test]
    fn rejects_partial_cancelled_and_concurrent_entry_without_success() -> Result<(), MowyCoreError>
    {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let partial = TestStore::new("partial");
        partial.create_companions_without_key()?;
        assert_eq!(
            run_test_proof(partial.clone(), Box::new(NeverCancel), 1_780_000_000, 64,).err(),
            Some(MowyCoreError::Unavailable)
        );
        partial.cleanup()?;

        let cancelled = TestStore::new("cancelled");
        assert_eq!(
            run_test_proof(cancelled.clone(), Box::new(AlwaysCancel), 1_780_000_000, 64,).err(),
            Some(MowyCoreError::Cancelled)
        );
        assert!(!cancelled.inner.root.exists());

        let concurrent = TestStore::new("concurrent");
        let lock = PROOF_LOCK.lock().map_err(|_| MowyCoreError::Storage)?;
        assert_eq!(
            run_test_proof(concurrent.clone(), Box::new(NeverCancel), 1_780_000_000, 64,).err(),
            Some(MowyCoreError::Conflict)
        );
        drop(lock);
        assert!(!concurrent.inner.root.exists());
        Ok(())
    }

    #[test]
    fn rejects_invalid_lengths_before_key_creation() -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        for (label, length) in [("zero", 0), ("oversized", 25 * 1024 * 1024 + 1)] {
            let store = TestStore::new(label);
            assert_eq!(
                run_test_proof(store.clone(), Box::new(NeverCancel), 1_780_000_000, length,).err(),
                Some(MowyCoreError::InvalidInput)
            );
        }
        Ok(())
    }

    #[test]
    fn public_result_exposes_only_a_coarse_code_or_public_receipt() -> Result<(), MowyCoreError> {
        let _test_guard = BRIDGE_TEST_LOCK
            .lock()
            .map_err(|_| MowyCoreError::Storage)?;
        let invalid_store = TestStore::new("public-invalid");
        let invalid = run_development_proof(
            Box::new(invalid_store.clone()),
            Box::new(NeverCancel),
            1_780_000_000,
            0,
        );
        assert_eq!(invalid.code, MowyCoreCode::InvalidInput);
        assert_eq!(invalid.receipt, None);
        assert!(!invalid_store.inner.root.exists());

        let success_store = TestStore::new("public-success");
        let success = run_development_proof(
            Box::new(success_store.clone()),
            Box::new(NeverCancel),
            1_780_000_000,
            65_537,
        );
        assert_eq!(success.code, MowyCoreCode::Success);
        let receipt = success.receipt.ok_or(MowyCoreError::Storage)?;
        assert_eq!(receipt.plaintext_length, 65_537);
        assert_eq!(receipt.proof_id.len(), 32);
        assert_eq!(receipt.ciphertext_sha256.len(), 64);
        assert_eq!(receipt.archive_sha256.len(), 64);
        success_store.cleanup()
    }
}
