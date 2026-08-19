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
    CanonicalUuid, KeyBundleError, KeyValidityWindow, PublishedKeyRepository, sign_current_bundle,
};
use crate::key_material::{
    CompanionState, InitializationState, KeyMaterialError, ProtectedKeyState, ProtectedKeyStore,
    ROOT_KEY_MATERIAL_BYTES, RootKeyMaterial, classify_initialization, initialize,
};
use crate::operation_repository::{OperationRepository, OperationRepositoryError, ReceiverCommit};
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
    }

    impl NativeProtectedKeyStore for TestStore {
        fn protected_data_available(&self) -> NativeBridgeResponse {
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
