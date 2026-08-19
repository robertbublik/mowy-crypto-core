//! Receiver ordering across sealed state, plaintext temp, and archive files.

use std::path::PathBuf;

use crate::archive::{ArchiveDescriptor, ArchiveError, ArchiveKey};
use crate::attachment_envelope::CancellationCheck;
use crate::key_bundle::CanonicalUuid;
use crate::operation_repository::{OperationRepository, OperationRepositoryError, ReceiverState};
use crate::private_files::{PrivateFileError, PrivateFileStore, VerifiedPlaintextState};
use crate::sealed_manifest::OpenedManifest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiverLifecycleError {
    InvalidInput,
    Unavailable,
    Conflict,
    Storage,
    Io,
    Authentication,
    Cryptography,
    Cancelled,
}

pub(crate) struct AvailableArchive {
    pub(crate) path: PathBuf,
    pub(crate) descriptor: ArchiveDescriptor,
}

pub(crate) trait AvailabilityCheck {
    fn is_available(&mut self) -> bool;
}

pub(crate) fn complete_or_recover<C: CancellationCheck, A: AvailabilityCheck>(
    repository: &mut OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    opened: OpenedManifest,
    archive_key: &ArchiveKey,
    availability: &mut A,
    cancellation: &mut C,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    require_available(availability)?;
    repository
        .require_exact_receiver(operation_id, &opened)
        .map_err(map_repository_error)?;
    let state = repository
        .receiver_state(operation_id)
        .map_err(map_repository_error)?
        .ok_or(ReceiverLifecycleError::Unavailable)?;
    match state {
        ReceiverState::WaitingForCiphertext => complete_waiting(
            repository,
            files,
            operation_id,
            &opened,
            archive_key,
            availability,
            cancellation,
        ),
        ReceiverState::VerifiedTemp => recover_verified_temp(
            repository,
            files,
            operation_id,
            &opened,
            archive_key,
            availability,
            cancellation,
        ),
        ReceiverState::Available => finish_available(repository, files, operation_id, availability),
        ReceiverState::UnavailableResend => {
            let asset_id = opened
                .manifest()
                .asset_id()
                .map_err(|_| ReceiverLifecycleError::InvalidInput)?;
            files
                .cleanup_available_transport(asset_id)
                .map_err(map_file_error)?;
            files
                .remove_archive_orphans(asset_id)
                .map_err(map_file_error)?;
            Err(ReceiverLifecycleError::Unavailable)
        }
    }
}

pub(crate) fn recover_available(
    repository: &OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    availability: &mut impl AvailabilityCheck,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    require_available(availability)?;
    if repository
        .receiver_state(operation_id)
        .map_err(map_repository_error)?
        != Some(ReceiverState::Available)
    {
        return Err(ReceiverLifecycleError::Conflict);
    }
    finish_available(repository, files, operation_id, availability)
}

fn complete_waiting<C: CancellationCheck, A: AvailabilityCheck>(
    repository: &mut OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    opened: &OpenedManifest,
    archive_key: &ArchiveKey,
    availability: &mut A,
    cancellation: &mut C,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    let manifest = opened.manifest();
    let asset_id = manifest
        .asset_id()
        .map_err(|_| ReceiverLifecycleError::InvalidInput)?;
    match files
        .verified_plaintext_state(asset_id)
        .map_err(map_file_error)?
    {
        VerifiedPlaintextState::Missing => {}
        VerifiedPlaintextState::Temp => files
            .remove_plaintext_orphan(asset_id)
            .map_err(map_file_error)?,
        VerifiedPlaintextState::Final | VerifiedPlaintextState::Conflict => {
            return Err(ReceiverLifecycleError::Unavailable);
        }
    }
    files
        .remove_archive_orphans(asset_id)
        .map_err(map_file_error)?;
    files
        .decrypt_to_unverified_temp(asset_id, manifest, cancellation)
        .map_err(map_file_error)?;
    if let Err(error) = require_available(availability) {
        let _ = files.remove_plaintext_orphan(asset_id);
        return Err(error);
    }
    if let Err(error) = repository.mark_verified_temp(operation_id) {
        let _ = files.remove_plaintext_orphan(asset_id);
        return Err(map_repository_error(error));
    }
    if let Err(error) = require_available(availability) {
        let _ = files.remove_plaintext_orphan(asset_id);
        return Err(error);
    }
    files
        .promote_verified_plaintext(asset_id)
        .map_err(map_file_error)?;
    finish_verified_plaintext(
        repository,
        files,
        operation_id,
        manifest
            .conversation_id()
            .map_err(|_| ReceiverLifecycleError::InvalidInput)?,
        asset_id,
        archive_key,
        availability,
        cancellation,
    )
}

fn recover_verified_temp<C: CancellationCheck, A: AvailabilityCheck>(
    repository: &mut OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    opened: &OpenedManifest,
    archive_key: &ArchiveKey,
    availability: &mut A,
    cancellation: &mut C,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    let manifest = opened.manifest();
    let asset_id = manifest
        .asset_id()
        .map_err(|_| ReceiverLifecycleError::InvalidInput)?;
    match files
        .verified_plaintext_state(asset_id)
        .map_err(map_file_error)?
    {
        VerifiedPlaintextState::Temp => {
            if let Err(error) = require_available(availability) {
                let _ = files.remove_unavailable_plaintext(asset_id);
                let _ = files.remove_archive_orphans(asset_id);
                return Err(error);
            }
            files
                .remove_archive_orphans(asset_id)
                .map_err(map_file_error)?;
            files
                .promote_verified_plaintext(asset_id)
                .map_err(map_file_error)?;
            finish_verified_plaintext(
                repository,
                files,
                operation_id,
                manifest
                    .conversation_id()
                    .map_err(|_| ReceiverLifecycleError::InvalidInput)?,
                asset_id,
                archive_key,
                availability,
                cancellation,
            )
        }
        VerifiedPlaintextState::Final | VerifiedPlaintextState::Conflict => {
            files
                .remove_unavailable_plaintext(asset_id)
                .map_err(map_file_error)?;
            files
                .remove_archive_orphans(asset_id)
                .map_err(map_file_error)?;
            repository
                .reset_verified_temp_to_waiting(operation_id)
                .map_err(map_repository_error)?;
            complete_waiting(
                repository,
                files,
                operation_id,
                opened,
                archive_key,
                availability,
                cancellation,
            )
        }
        VerifiedPlaintextState::Missing => Err(ReceiverLifecycleError::Unavailable),
    }
}

#[allow(clippy::too_many_arguments, reason = "one fixed receiver transition")]
fn finish_verified_plaintext<C: CancellationCheck, A: AvailabilityCheck>(
    repository: &mut OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    archive_key: &ArchiveKey,
    availability: &mut A,
    cancellation: &mut C,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    if let Err(error) = require_available(availability) {
        let _ = files.remove_unavailable_plaintext(asset_id);
        let _ = files.remove_archive_orphans(asset_id);
        return Err(error);
    }
    let archived = files
        .create_verified_archive(conversation_id, asset_id, archive_key, cancellation)
        .map_err(map_file_error)?;
    if let Err(error) = require_available(availability) {
        let _ = files.remove_unavailable_plaintext(asset_id);
        let _ = files.remove_archive_orphans(asset_id);
        return Err(error);
    }
    repository
        .commit_available(operation_id, &archived.verified)
        .map_err(map_repository_error)?;
    files
        .cleanup_available_transport(asset_id)
        .map_err(map_file_error)?;
    require_available(availability)?;
    if files
        .verified_plaintext_state(asset_id)
        .map_err(map_file_error)?
        != VerifiedPlaintextState::Missing
    {
        return Err(ReceiverLifecycleError::Unavailable);
    }
    Ok(AvailableArchive {
        path: archived.path,
        descriptor: *archived.verified.descriptor(),
    })
}

fn finish_available(
    repository: &OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
    availability: &mut impl AvailabilityCheck,
) -> Result<AvailableArchive, ReceiverLifecycleError> {
    require_available(availability)?;
    let available = repository
        .load_available(operation_id)
        .map_err(map_repository_error)?
        .ok_or(ReceiverLifecycleError::Unavailable)?;
    let asset_id = available.descriptor.asset_id();
    let archive_path = files.archive_path(asset_id);
    if archive_path.file_name().and_then(|name| name.to_str())
        != Some(available.archive_name.as_str())
    {
        return Err(ReceiverLifecycleError::Unavailable);
    }
    files
        .cleanup_available_transport(asset_id)
        .map_err(map_file_error)?;
    files.open_archive_file(asset_id).map_err(map_file_error)?;
    require_available(availability)?;
    Ok(AvailableArchive {
        path: archive_path,
        descriptor: available.descriptor,
    })
}

fn require_available(
    availability: &mut impl AvailabilityCheck,
) -> Result<(), ReceiverLifecycleError> {
    if availability.is_available() {
        Ok(())
    } else {
        Err(ReceiverLifecycleError::Unavailable)
    }
}

pub(crate) fn expire_waiting_and_cleanup(
    repository: &mut OperationRepository,
    files: &mut PrivateFileStore,
    now: u64,
) -> Result<u64, ReceiverLifecycleError> {
    let expired = repository
        .expire_waiting(now)
        .map_err(map_repository_error)?;
    for operation in &expired {
        files
            .cleanup_available_transport(operation.asset_id)
            .map_err(map_file_error)?;
        files
            .remove_archive_orphans(operation.asset_id)
            .map_err(map_file_error)?;
    }
    u64::try_from(expired.len()).map_err(|_| ReceiverLifecycleError::Storage)
}

pub(crate) fn retry_unavailable_cleanup(
    repository: &OperationRepository,
    files: &mut PrivateFileStore,
    operation_id: CanonicalUuid,
) -> Result<(), ReceiverLifecycleError> {
    let asset_id = repository
        .unavailable_asset(operation_id)
        .map_err(map_repository_error)?
        .ok_or(ReceiverLifecycleError::Conflict)?;
    files
        .cleanup_available_transport(asset_id)
        .map_err(map_file_error)?;
    files
        .remove_archive_orphans(asset_id)
        .map_err(map_file_error)
}

fn map_repository_error(error: OperationRepositoryError) -> ReceiverLifecycleError {
    match error {
        OperationRepositoryError::InvalidInput => ReceiverLifecycleError::InvalidInput,
        OperationRepositoryError::Conflict => ReceiverLifecycleError::Conflict,
        OperationRepositoryError::Storage => ReceiverLifecycleError::Storage,
    }
}

fn map_file_error(error: PrivateFileError) -> ReceiverLifecycleError {
    match error {
        PrivateFileError::InvalidInput | PrivateFileError::UnsafePath => {
            ReceiverLifecycleError::InvalidInput
        }
        PrivateFileError::Conflict => ReceiverLifecycleError::Conflict,
        PrivateFileError::Io => ReceiverLifecycleError::Io,
        PrivateFileError::Cryptography => ReceiverLifecycleError::Cryptography,
        PrivateFileError::Authentication => ReceiverLifecycleError::Authentication,
        PrivateFileError::Cancelled => ReceiverLifecycleError::Cancelled,
    }
}

fn map_archive_error(error: ArchiveError) -> ReceiverLifecycleError {
    match error {
        ArchiveError::InvalidInput => ReceiverLifecycleError::InvalidInput,
        ArchiveError::Authentication => ReceiverLifecycleError::Authentication,
        ArchiveError::Io => ReceiverLifecycleError::Io,
        ArchiveError::Cryptography => ReceiverLifecycleError::Cryptography,
        ArchiveError::Cancelled => ReceiverLifecycleError::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::archive::{ArchiveKey, open_archive};
    use crate::attachment_envelope::NeverCancelled;
    use crate::key_material::generate;
    use crate::operation_repository::ReceiverCommit;
    use crate::private_files::PrivateFileStore;
    use crate::sealed_manifest::{SEALED_BYTES, SealedManifest};

    struct AlwaysAvailable;

    impl AvailabilityCheck for AlwaysAvailable {
        fn is_available(&mut self) -> bool {
            true
        }
    }

    struct LockAfter {
        remaining_available_checks: u8,
    }

    impl AvailabilityCheck for LockAfter {
        fn is_available(&mut self) -> bool {
            if self.remaining_available_checks == 0 {
                false
            } else {
                self.remaining_available_checks -= 1;
                true
            }
        }
    }

    fn uuid(value: u8) -> Result<CanonicalUuid, ReceiverLifecycleError> {
        CanonicalUuid::from_network_bytes([value; 16])
            .map_err(|_| ReceiverLifecycleError::InvalidInput)
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mowy-p2-receiver-lifecycle-{label}-{}",
            std::process::id()
        ))
    }

    fn create_store(label: &str) -> Result<(PathBuf, PrivateFileStore), ReceiverLifecycleError> {
        let root = test_root(label);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).map_err(|_| ReceiverLifecycleError::Io)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ReceiverLifecycleError::Io)?;
        for name in [
            "source",
            "ciphertext",
            "receive-temp",
            "verified",
            "archive",
        ] {
            let path = root.join(name);
            std::fs::create_dir(&path).map_err(|_| ReceiverLifecycleError::Io)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ReceiverLifecycleError::Io)?;
        }
        let store = PrivateFileStore::open(&root).map_err(map_file_error)?;
        Ok((root, store))
    }

    struct Fixture {
        root: PathBuf,
        files: PrivateFileStore,
        repository: OperationRepository,
        operation_id: CanonicalUuid,
        opened: OpenedManifest,
        archive_key: ArchiveKey,
        expected: Vec<u8>,
    }

    fn fixture(label: &str) -> Result<Fixture, ReceiverLifecycleError> {
        let (root, mut files) = create_store(label)?;
        let conversation_id = uuid(1)?;
        let asset_id = uuid(2)?;
        let expected: Vec<u8> = (0..70_000).map(|index| (index % 251) as u8).collect();
        let source_path = files.source_path(asset_id);
        let mut source = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(source_path)
            .map_err(|_| ReceiverLifecycleError::Io)?;
        source
            .write_all(&expected)
            .map_err(|_| ReceiverLifecycleError::Io)?;
        source.sync_all().map_err(|_| ReceiverLifecycleError::Io)?;
        drop(source);
        let encrypted = files
            .encrypt_asset(conversation_id, asset_id, &mut NeverCancelled)
            .map_err(map_file_error)?;
        let sealed = SealedManifest::parse(uuid(4)?, &[0x90; SEALED_BYTES])
            .map_err(|_| ReceiverLifecycleError::InvalidInput)?;
        let opened = OpenedManifest::from_fixture(uuid(3)?, encrypted.encrypted.manifest, sealed);
        let operation_id = uuid(7)?;
        let mut repository = OperationRepository::in_memory().map_err(map_repository_error)?;
        assert_eq!(
            repository
                .commit_received_manifest(operation_id, &opened, 100)
                .map_err(map_repository_error)?,
            ReceiverCommit::Created
        );
        let (root_keys, _) = generate().map_err(|_| ReceiverLifecycleError::Cryptography)?;
        let archive_key = ArchiveKey::from_root(&root_keys).map_err(map_archive_error)?;
        Ok(Fixture {
            root,
            files,
            repository,
            operation_id,
            opened,
            archive_key,
            expected,
        })
    }

    fn assert_archive(mut fixture: Fixture) -> Result<(), ReceiverLifecycleError> {
        let mut availability = AlwaysAvailable;
        let available = complete_or_recover(
            &mut fixture.repository,
            &mut fixture.files,
            fixture.operation_id,
            fixture.opened,
            &fixture.archive_key,
            &mut availability,
            &mut NeverCancelled,
        )?;
        inspect_available(
            &fixture.root,
            &mut fixture.files,
            &fixture.repository,
            fixture.operation_id,
            &fixture.archive_key,
            &fixture.expected,
            &available,
        )
    }

    fn inspect_available(
        root: &Path,
        files: &mut PrivateFileStore,
        repository: &OperationRepository,
        operation_id: CanonicalUuid,
        archive_key: &ArchiveKey,
        expected: &[u8],
        available: &AvailableArchive,
    ) -> Result<(), ReceiverLifecycleError> {
        assert_eq!(
            repository
                .receiver_state(operation_id)
                .map_err(map_repository_error)?,
            Some(ReceiverState::Available)
        );
        assert!(available.path.is_file());
        assert!(!files.ciphertext_path(uuid(2)?).exists());
        assert_eq!(
            files
                .verified_plaintext_state(uuid(2)?)
                .map_err(map_file_error)?,
            VerifiedPlaintextState::Missing
        );
        let mut archive = files.open_archive_file(uuid(2)?).map_err(map_file_error)?;
        let mut plaintext = Vec::new();
        open_archive(
            &mut archive,
            &mut plaintext,
            &available.descriptor,
            archive_key,
            &mut NeverCancelled,
        )
        .map_err(map_archive_error)?;
        assert_eq!(plaintext, expected);
        std::fs::remove_dir_all(root).map_err(|_| ReceiverLifecycleError::Io)
    }

    #[test]
    fn completes_archive_before_erasure_and_returns_only_available()
    -> Result<(), ReceiverLifecycleError> {
        assert_archive(fixture("complete")?)
    }

    #[test]
    fn recovers_crashes_at_each_plaintext_and_archive_transition()
    -> Result<(), ReceiverLifecycleError> {
        let mut after_decrypt = fixture("after-decrypt")?;
        after_decrypt
            .files
            .decrypt_to_unverified_temp(
                uuid(2)?,
                after_decrypt.opened.manifest(),
                &mut NeverCancelled,
            )
            .map_err(map_file_error)?;
        assert_archive(after_decrypt)?;

        let mut after_mark = fixture("after-mark")?;
        after_mark
            .files
            .decrypt_to_unverified_temp(uuid(2)?, after_mark.opened.manifest(), &mut NeverCancelled)
            .map_err(map_file_error)?;
        after_mark
            .repository
            .mark_verified_temp(after_mark.operation_id)
            .map_err(map_repository_error)?;
        assert_archive(after_mark)?;

        let mut after_promote = fixture("after-promote")?;
        after_promote
            .files
            .decrypt_to_unverified_temp(
                uuid(2)?,
                after_promote.opened.manifest(),
                &mut NeverCancelled,
            )
            .map_err(map_file_error)?;
        after_promote
            .repository
            .mark_verified_temp(after_promote.operation_id)
            .map_err(map_repository_error)?;
        after_promote
            .files
            .promote_verified_plaintext(uuid(2)?)
            .map_err(map_file_error)?;
        assert_archive(after_promote)?;

        let mut after_archive = fixture("after-archive")?;
        after_archive
            .files
            .decrypt_to_unverified_temp(
                uuid(2)?,
                after_archive.opened.manifest(),
                &mut NeverCancelled,
            )
            .map_err(map_file_error)?;
        after_archive
            .repository
            .mark_verified_temp(after_archive.operation_id)
            .map_err(map_repository_error)?;
        after_archive
            .files
            .promote_verified_plaintext(uuid(2)?)
            .map_err(map_file_error)?;
        after_archive
            .files
            .create_verified_archive(
                uuid(1)?,
                uuid(2)?,
                &after_archive.archive_key,
                &mut NeverCancelled,
            )
            .map_err(map_file_error)?;
        assert_archive(after_archive)
    }

    #[test]
    fn available_relaunch_cleans_transport_before_returning_archive()
    -> Result<(), ReceiverLifecycleError> {
        let mut fixture = fixture("after-available")?;
        fixture
            .files
            .decrypt_to_unverified_temp(uuid(2)?, fixture.opened.manifest(), &mut NeverCancelled)
            .map_err(map_file_error)?;
        fixture
            .repository
            .mark_verified_temp(fixture.operation_id)
            .map_err(map_repository_error)?;
        fixture
            .files
            .promote_verified_plaintext(uuid(2)?)
            .map_err(map_file_error)?;
        let archived = fixture
            .files
            .create_verified_archive(
                uuid(1)?,
                uuid(2)?,
                &fixture.archive_key,
                &mut NeverCancelled,
            )
            .map_err(map_file_error)?;
        fixture
            .repository
            .commit_available(fixture.operation_id, &archived.verified)
            .map_err(map_repository_error)?;
        drop(fixture.opened);
        let mut availability = AlwaysAvailable;
        let available = recover_available(
            &fixture.repository,
            &mut fixture.files,
            fixture.operation_id,
            &mut availability,
        )?;
        inspect_available(
            &fixture.root,
            &mut fixture.files,
            &fixture.repository,
            fixture.operation_id,
            &fixture.archive_key,
            &fixture.expected,
            &available,
        )
    }

    #[test]
    fn missing_verified_temp_fails_closed_without_returning_a_path()
    -> Result<(), ReceiverLifecycleError> {
        let mut fixture = fixture("missing-verified-temp")?;
        fixture
            .repository
            .mark_verified_temp(fixture.operation_id)
            .map_err(map_repository_error)?;
        let mut availability = AlwaysAvailable;
        assert_eq!(
            complete_or_recover(
                &mut fixture.repository,
                &mut fixture.files,
                fixture.operation_id,
                fixture.opened,
                &fixture.archive_key,
                &mut availability,
                &mut NeverCancelled,
            )
            .err(),
            Some(ReceiverLifecycleError::Unavailable)
        );
        assert!(!fixture.files.archive_path(uuid(2)?).exists());
        std::fs::remove_dir_all(&fixture.root).map_err(|_| ReceiverLifecycleError::Io)
    }

    #[test]
    fn relock_before_plaintext_promotion_cleans_and_returns_unavailable()
    -> Result<(), ReceiverLifecycleError> {
        let mut fixture = fixture("relock-before-promotion")?;
        let mut availability = LockAfter {
            remaining_available_checks: 2,
        };
        assert_eq!(
            complete_or_recover(
                &mut fixture.repository,
                &mut fixture.files,
                fixture.operation_id,
                fixture.opened,
                &fixture.archive_key,
                &mut availability,
                &mut NeverCancelled,
            )
            .err(),
            Some(ReceiverLifecycleError::Unavailable)
        );
        assert_eq!(
            fixture
                .repository
                .receiver_state(fixture.operation_id)
                .map_err(map_repository_error)?,
            Some(ReceiverState::VerifiedTemp)
        );
        assert_eq!(
            fixture
                .files
                .verified_plaintext_state(uuid(2)?)
                .map_err(map_file_error)?,
            VerifiedPlaintextState::Missing
        );
        assert!(!fixture.files.archive_path(uuid(2)?).exists());
        std::fs::remove_dir_all(&fixture.root).map_err(|_| ReceiverLifecycleError::Io)
    }

    #[test]
    fn expiry_erases_state_and_local_transport() -> Result<(), ReceiverLifecycleError> {
        let mut fixture = fixture("expiry")?;
        assert_eq!(
            expire_waiting_and_cleanup(&mut fixture.repository, &mut fixture.files, 86_500)?,
            1
        );
        assert_eq!(
            fixture
                .repository
                .receiver_state(fixture.operation_id)
                .map_err(map_repository_error)?,
            Some(ReceiverState::UnavailableResend)
        );
        assert!(!fixture.files.ciphertext_path(uuid(2)?).exists());
        retry_unavailable_cleanup(
            &fixture.repository,
            &mut fixture.files,
            fixture.operation_id,
        )?;
        assert_eq!(
            retry_unavailable_cleanup(&fixture.repository, &mut fixture.files, uuid(8)?).err(),
            Some(ReceiverLifecycleError::Conflict)
        );
        assert_eq!(
            {
                let mut availability = AlwaysAvailable;
                complete_or_recover(
                    &mut fixture.repository,
                    &mut fixture.files,
                    fixture.operation_id,
                    fixture.opened,
                    &fixture.archive_key,
                    &mut availability,
                    &mut NeverCancelled,
                )
                .err()
            },
            Some(ReceiverLifecycleError::Unavailable)
        );
        std::fs::remove_dir_all(&fixture.root).map_err(|_| ReceiverLifecycleError::Io)
    }
}
