//! Package-owned, same-volume file lifecycle for attachment envelope operations.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::attachment_envelope::{
    AttachmentEnvelopeError, CancellationCheck, EncryptedAttachment, EnvelopeHeader,
    decrypt_stream, encrypt_stream,
};
use crate::attachment_manifest::AttachmentManifest;
use crate::key_bundle::CanonicalUuid;

static FILE_OPERATION_LOCK: Mutex<()> = Mutex::new(());

const SOURCE_DIRECTORY: &str = "source";
const CIPHERTEXT_DIRECTORY: &str = "ciphertext";
const RECEIVE_TEMP_DIRECTORY: &str = "receive-temp";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateFileError {
    InvalidInput,
    UnsafePath,
    Conflict,
    Io,
    Cryptography,
    Authentication,
    Cancelled,
}

pub(crate) struct PrivateFileStore {
    source_directory: PathBuf,
    ciphertext_directory: PathBuf,
    receive_temp_directory: PathBuf,
}

pub(crate) struct FileEncryptedAttachment {
    pub(crate) ciphertext_path: PathBuf,
    pub(crate) encrypted: EncryptedAttachment,
}

pub(crate) struct VerifiedPlaintextTemp {
    pub(crate) path: PathBuf,
    pub(crate) header: EnvelopeHeader,
}

impl PrivateFileStore {
    /// Opens only a pre-created package root and its three fixed namespaces.
    /// Platform code owns backup exclusion and iOS file-protection attributes.
    pub(crate) fn open(root: &Path) -> Result<Self, PrivateFileError> {
        let root = validate_directory(root, None)?;
        let source_directory = validate_directory(&root.join(SOURCE_DIRECTORY), Some(&root))?;
        let ciphertext_directory =
            validate_directory(&root.join(CIPHERTEXT_DIRECTORY), Some(&root))?;
        let receive_temp_directory =
            validate_directory(&root.join(RECEIVE_TEMP_DIRECTORY), Some(&root))?;
        Ok(Self {
            source_directory,
            ciphertext_directory,
            receive_temp_directory,
        })
    }

    pub(crate) fn source_path(&self, asset_id: CanonicalUuid) -> PathBuf {
        self.source_directory
            .join(format!("{}.source", uuid_hex(asset_id)))
    }

    pub(crate) fn ciphertext_path(&self, asset_id: CanonicalUuid) -> PathBuf {
        self.ciphertext_directory
            .join(format!("{}.mowy", uuid_hex(asset_id)))
    }

    fn ciphertext_temp_path(&self, asset_id: CanonicalUuid) -> PathBuf {
        self.ciphertext_directory
            .join(format!("{}.ciphertext.partial", uuid_hex(asset_id)))
    }

    pub(crate) fn receive_temp_path(&self, asset_id: CanonicalUuid) -> PathBuf {
        self.receive_temp_directory
            .join(format!("{}.plaintext.partial", uuid_hex(asset_id)))
    }

    pub(crate) fn encrypt_asset<C: CancellationCheck>(
        &mut self,
        conversation_id: CanonicalUuid,
        asset_id: CanonicalUuid,
        cancellation: &mut C,
    ) -> Result<FileEncryptedAttachment, PrivateFileError> {
        let _guard = FILE_OPERATION_LOCK
            .lock()
            .map_err(|_| PrivateFileError::Io)?;
        let source_path = self.source_path(asset_id);
        let final_path = self.ciphertext_path(asset_id);
        let temp_path = self.ciphertext_temp_path(asset_id);
        let mut source = open_regular_file(&source_path, &self.source_directory)?;
        let plaintext_length = source.metadata().map_err(|_| PrivateFileError::Io)?.len();
        reject_existing(&final_path)?;
        reject_existing(&temp_path)?;
        let mut temp = create_private_file(&temp_path)?;

        let encrypted = match encrypt_stream(
            &mut source,
            &mut temp,
            plaintext_length,
            conversation_id,
            asset_id,
            cancellation,
        ) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                drop(temp);
                remove_exact_if_file(&temp_path);
                return Err(map_envelope_error(error));
            }
        };
        if cancellation.is_cancelled() {
            drop(temp);
            remove_exact_if_file(&temp_path);
            return Err(PrivateFileError::Cancelled);
        }
        if temp.sync_all().is_err() {
            drop(temp);
            remove_exact_if_file(&temp_path);
            return Err(PrivateFileError::Io);
        }
        drop(temp);
        if let Err(error) = reject_existing(&final_path) {
            remove_exact_if_file(&temp_path);
            return Err(error);
        }
        if std::fs::rename(&temp_path, &final_path).is_err() {
            remove_exact_if_file(&temp_path);
            return Err(PrivateFileError::Io);
        }
        if sync_directory(&self.ciphertext_directory).is_err()
            || validate_regular_file(&final_path, &self.ciphertext_directory).is_err()
        {
            remove_exact_if_file(&final_path);
            let _ = sync_directory(&self.ciphertext_directory);
            return Err(PrivateFileError::Io);
        }
        Ok(FileEncryptedAttachment {
            ciphertext_path: final_path,
            encrypted,
        })
    }

    pub(crate) fn decrypt_to_unverified_temp<C: CancellationCheck>(
        &mut self,
        asset_id: CanonicalUuid,
        manifest: &AttachmentManifest,
        cancellation: &mut C,
    ) -> Result<VerifiedPlaintextTemp, PrivateFileError> {
        let _guard = FILE_OPERATION_LOCK
            .lock()
            .map_err(|_| PrivateFileError::Io)?;
        let ciphertext_path = self.ciphertext_path(asset_id);
        let temp_path = self.receive_temp_path(asset_id);
        let mut ciphertext = open_regular_file(&ciphertext_path, &self.ciphertext_directory)?;
        reject_existing(&temp_path)?;
        let mut temp = create_private_file(&temp_path)?;
        let header = match decrypt_stream(&mut ciphertext, &mut temp, manifest, cancellation) {
            Ok(header) => header,
            Err(error) => {
                drop(temp);
                remove_exact_if_file(&temp_path);
                return Err(map_envelope_error(error));
            }
        };
        if cancellation.is_cancelled() {
            drop(temp);
            remove_exact_if_file(&temp_path);
            return Err(PrivateFileError::Cancelled);
        }
        if temp.sync_all().is_err() {
            drop(temp);
            remove_exact_if_file(&temp_path);
            return Err(PrivateFileError::Io);
        }
        drop(temp);
        if sync_directory(&self.receive_temp_directory).is_err()
            || validate_regular_file(&temp_path, &self.receive_temp_directory).is_err()
        {
            remove_exact_if_file(&temp_path);
            let _ = sync_directory(&self.receive_temp_directory);
            return Err(PrivateFileError::Io);
        }
        Ok(VerifiedPlaintextTemp {
            path: temp_path,
            header,
        })
    }

    pub(crate) fn remove_encrypting_orphans(
        &mut self,
        asset_id: CanonicalUuid,
    ) -> Result<(), PrivateFileError> {
        let _guard = FILE_OPERATION_LOCK
            .lock()
            .map_err(|_| PrivateFileError::Io)?;
        remove_named_file_if_present(
            &self.ciphertext_temp_path(asset_id),
            &self.ciphertext_directory,
        )?;
        remove_named_file_if_present(&self.ciphertext_path(asset_id), &self.ciphertext_directory)
    }

    pub(crate) fn remove_plaintext_orphan(
        &mut self,
        asset_id: CanonicalUuid,
    ) -> Result<(), PrivateFileError> {
        let _guard = FILE_OPERATION_LOCK
            .lock()
            .map_err(|_| PrivateFileError::Io)?;
        remove_named_file_if_present(
            &self.receive_temp_path(asset_id),
            &self.receive_temp_directory,
        )
    }
}

fn validate_directory(path: &Path, parent: Option<&Path>) -> Result<PathBuf, PrivateFileError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| PrivateFileError::UnsafePath)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PrivateFileError::UnsafePath);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| PrivateFileError::UnsafePath)?;
    if let Some(expected_parent) = parent
        && canonical.parent() != Some(expected_parent)
    {
        return Err(PrivateFileError::UnsafePath);
    }
    Ok(canonical)
}

fn open_regular_file(path: &Path, parent: &Path) -> Result<File, PrivateFileError> {
    let before = regular_file_metadata(path, parent)?;
    let file = File::open(path).map_err(|_| PrivateFileError::Io)?;
    let after = file.metadata().map_err(|_| PrivateFileError::Io)?;
    if !after.file_type().is_file()
        || after.permissions().mode() & 0o077 != 0
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(PrivateFileError::UnsafePath);
    }
    Ok(file)
}

fn validate_regular_file(path: &Path, parent: &Path) -> Result<(), PrivateFileError> {
    regular_file_metadata(path, parent).map(|_| ())
}

fn regular_file_metadata(
    path: &Path,
    parent: &Path,
) -> Result<std::fs::Metadata, PrivateFileError> {
    if path.parent() != Some(parent) {
        return Err(PrivateFileError::UnsafePath);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| PrivateFileError::UnsafePath)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(PrivateFileError::UnsafePath);
    }
    Ok(metadata)
}

fn create_private_file(path: &Path) -> Result<File, PrivateFileError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PrivateFileError::Conflict
            } else {
                PrivateFileError::Io
            }
        })
}

fn reject_existing(path: &Path) -> Result<(), PrivateFileError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(PrivateFileError::Conflict),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivateFileError::Io),
    }
}

fn remove_named_file_if_present(path: &Path, parent: &Path) -> Result<(), PrivateFileError> {
    if path.parent() != Some(parent) {
        return Err(PrivateFileError::UnsafePath);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            std::fs::remove_file(path).map_err(|_| PrivateFileError::Io)?;
            sync_directory(parent)
        }
        Ok(_) => Err(PrivateFileError::UnsafePath),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivateFileError::Io),
    }
}

fn remove_exact_if_file(path: &Path) {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
    {
        let _ = std::fs::remove_file(path);
    }
}

fn sync_directory(path: &Path) -> Result<(), PrivateFileError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PrivateFileError::Io)
}

fn uuid_hex(uuid: CanonicalUuid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in uuid.as_network_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn map_envelope_error(error: AttachmentEnvelopeError) -> PrivateFileError {
    match error {
        AttachmentEnvelopeError::InvalidInput => PrivateFileError::InvalidInput,
        AttachmentEnvelopeError::Authentication => PrivateFileError::Authentication,
        AttachmentEnvelopeError::Io => PrivateFileError::Io,
        AttachmentEnvelopeError::Cryptography => PrivateFileError::Cryptography,
        AttachmentEnvelopeError::Cancelled => PrivateFileError::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::attachment_envelope::{HEADER_BYTES, NeverCancelled};

    fn uuid(value: u8) -> Result<CanonicalUuid, PrivateFileError> {
        CanonicalUuid::from_network_bytes([value; 16]).map_err(|_| PrivateFileError::InvalidInput)
    }

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mowy-p2-private-files-{label}-{}",
            std::process::id()
        ))
    }

    fn create_store(label: &str) -> Result<(PathBuf, PrivateFileStore), PrivateFileError> {
        let root = test_root(label);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).map_err(|_| PrivateFileError::Io)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| PrivateFileError::Io)?;
        for name in [
            SOURCE_DIRECTORY,
            CIPHERTEXT_DIRECTORY,
            RECEIVE_TEMP_DIRECTORY,
        ] {
            let path = root.join(name);
            std::fs::create_dir(&path).map_err(|_| PrivateFileError::Io)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| PrivateFileError::Io)?;
        }
        let store = PrivateFileStore::open(&root)?;
        Ok((root, store))
    }

    fn cleanup(root: &Path) -> Result<(), PrivateFileError> {
        std::fs::remove_dir_all(root).map_err(|_| PrivateFileError::Io)
    }

    #[test]
    fn atomically_encrypts_and_decrypts_only_fixed_paths() -> Result<(), PrivateFileError> {
        let (root, mut store) = create_store("round-trip")?;
        let asset_id = uuid(2)?;
        let source_path = store.source_path(asset_id);
        let mut source = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_path)
            .map_err(|_| PrivateFileError::Io)?;
        let expected: Vec<u8> = (0..70_000).map(|index| (index % 251) as u8).collect();
        source
            .write_all(&expected)
            .map_err(|_| PrivateFileError::Io)?;
        source.sync_all().map_err(|_| PrivateFileError::Io)?;
        drop(source);

        let encrypted = store.encrypt_asset(uuid(1)?, asset_id, &mut NeverCancelled)?;
        assert_eq!(encrypted.ciphertext_path, store.ciphertext_path(asset_id));
        assert!(encrypted.ciphertext_path.is_file());
        assert!(!store.ciphertext_temp_path(asset_id).exists());
        assert_eq!(
            std::fs::metadata(&encrypted.ciphertext_path)
                .map_err(|_| PrivateFileError::Io)?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let verified = store.decrypt_to_unverified_temp(
            asset_id,
            &encrypted.encrypted.manifest,
            &mut NeverCancelled,
        )?;
        assert_eq!(verified.path, store.receive_temp_path(asset_id));
        assert_eq!(
            std::fs::read(&verified.path).map_err(|_| PrivateFileError::Io)?,
            expected
        );
        assert_eq!(
            verified
                .header
                .plaintext_length()
                .map_err(map_envelope_error)?,
            70_000
        );
        cleanup(&root)
    }

    #[test]
    fn rejects_link_source_and_existing_destination() -> Result<(), PrivateFileError> {
        use std::os::unix::fs::symlink;

        let (root, mut store) = create_store("links")?;
        let asset_id = uuid(2)?;
        let outside = root.join("outside");
        std::fs::write(&outside, b"fixture").map_err(|_| PrivateFileError::Io)?;
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| PrivateFileError::Io)?;
        symlink(&outside, store.source_path(asset_id)).map_err(|_| PrivateFileError::Io)?;
        assert_eq!(
            store
                .encrypt_asset(uuid(1)?, asset_id, &mut NeverCancelled)
                .err(),
            Some(PrivateFileError::UnsafePath)
        );
        std::fs::remove_file(store.source_path(asset_id)).map_err(|_| PrivateFileError::Io)?;
        std::fs::write(store.source_path(asset_id), b"fixture")
            .map_err(|_| PrivateFileError::Io)?;
        std::fs::set_permissions(
            store.source_path(asset_id),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| PrivateFileError::Io)?;
        std::fs::write(store.ciphertext_path(asset_id), b"existing")
            .map_err(|_| PrivateFileError::Io)?;
        assert_eq!(
            store
                .encrypt_asset(uuid(1)?, asset_id, &mut NeverCancelled)
                .err(),
            Some(PrivateFileError::Conflict)
        );
        assert_eq!(
            std::fs::read(store.ciphertext_path(asset_id)).map_err(|_| PrivateFileError::Io)?,
            b"existing"
        );
        cleanup(&root)
    }

    #[test]
    fn cancellation_and_auth_failure_remove_only_partial_output() -> Result<(), PrivateFileError> {
        let (root, mut store) = create_store("cleanup")?;
        let asset_id = uuid(2)?;
        std::fs::write(store.source_path(asset_id), b"fixture")
            .map_err(|_| PrivateFileError::Io)?;
        std::fs::set_permissions(
            store.source_path(asset_id),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| PrivateFileError::Io)?;

        struct Cancel;
        impl CancellationCheck for Cancel {
            fn is_cancelled(&mut self) -> bool {
                true
            }
        }
        assert_eq!(
            store.encrypt_asset(uuid(1)?, asset_id, &mut Cancel).err(),
            Some(PrivateFileError::Cancelled)
        );
        assert!(!store.ciphertext_temp_path(asset_id).exists());
        assert!(!store.ciphertext_path(asset_id).exists());

        std::fs::write(store.source_path(asset_id), vec![0x41; 70_000])
            .map_err(|_| PrivateFileError::Io)?;
        struct CancelAfterFirstRecord {
            checks: u8,
        }
        impl CancellationCheck for CancelAfterFirstRecord {
            fn is_cancelled(&mut self) -> bool {
                self.checks = self.checks.saturating_add(1);
                self.checks == 3
            }
        }
        assert_eq!(
            store
                .encrypt_asset(
                    uuid(1)?,
                    asset_id,
                    &mut CancelAfterFirstRecord { checks: 0 },
                )
                .err(),
            Some(PrivateFileError::Cancelled)
        );
        assert!(!store.ciphertext_temp_path(asset_id).exists());
        assert!(!store.ciphertext_path(asset_id).exists());

        let encrypted = store.encrypt_asset(uuid(1)?, asset_id, &mut NeverCancelled)?;
        let mut corrupt =
            std::fs::read(&encrypted.ciphertext_path).map_err(|_| PrivateFileError::Io)?;
        corrupt[HEADER_BYTES + 1] ^= 1;
        std::fs::write(&encrypted.ciphertext_path, corrupt).map_err(|_| PrivateFileError::Io)?;
        assert_eq!(
            store
                .decrypt_to_unverified_temp(
                    asset_id,
                    &encrypted.encrypted.manifest,
                    &mut NeverCancelled,
                )
                .err(),
            Some(PrivateFileError::Authentication)
        );
        assert!(!store.receive_temp_path(asset_id).exists());
        cleanup(&root)
    }

    #[test]
    fn destination_race_preserves_conflict_and_removes_partial_ciphertext()
    -> Result<(), PrivateFileError> {
        let (root, mut store) = create_store("destination-race")?;
        let asset_id = uuid(2)?;
        std::fs::write(store.source_path(asset_id), b"fixture")
            .map_err(|_| PrivateFileError::Io)?;
        std::fs::set_permissions(
            store.source_path(asset_id),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| PrivateFileError::Io)?;

        struct CreateConflict {
            checks: u8,
            path: PathBuf,
        }
        impl CancellationCheck for CreateConflict {
            fn is_cancelled(&mut self) -> bool {
                self.checks = self.checks.saturating_add(1);
                if self.checks == 3
                    && let Ok(mut file) = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&self.path)
                {
                    let _ = file.write_all(b"racing destination");
                    let _ = file.sync_all();
                }
                false
            }
        }
        let final_path = store.ciphertext_path(asset_id);
        let mut race = CreateConflict {
            checks: 0,
            path: final_path.clone(),
        };
        assert_eq!(
            store.encrypt_asset(uuid(1)?, asset_id, &mut race).err(),
            Some(PrivateFileError::Conflict)
        );
        assert!(!store.ciphertext_temp_path(asset_id).exists());
        assert_eq!(
            std::fs::read(final_path).map_err(|_| PrivateFileError::Io)?,
            b"racing destination"
        );
        cleanup(&root)
    }

    #[test]
    fn removes_only_named_regular_orphans_and_rejects_linked_namespace()
    -> Result<(), PrivateFileError> {
        use std::os::unix::fs::symlink;

        let (root, mut store) = create_store("orphans")?;
        let asset_id = uuid(2)?;
        std::fs::write(store.ciphertext_temp_path(asset_id), b"partial orphan")
            .map_err(|_| PrivateFileError::Io)?;
        std::fs::write(store.ciphertext_path(asset_id), b"renamed orphan")
            .map_err(|_| PrivateFileError::Io)?;
        std::fs::write(store.receive_temp_path(asset_id), b"orphan")
            .map_err(|_| PrivateFileError::Io)?;
        store.remove_encrypting_orphans(asset_id)?;
        store.remove_plaintext_orphan(asset_id)?;
        assert!(!store.ciphertext_temp_path(asset_id).exists());
        assert!(!store.ciphertext_path(asset_id).exists());
        assert!(!store.receive_temp_path(asset_id).exists());

        let linked_root = test_root("linked-root");
        let _ = std::fs::remove_file(&linked_root);
        symlink(&root, &linked_root).map_err(|_| PrivateFileError::Io)?;
        assert!(matches!(
            PrivateFileStore::open(&linked_root),
            Err(PrivateFileError::UnsafePath)
        ));
        std::fs::remove_file(&linked_root).map_err(|_| PrivateFileError::Io)?;
        cleanup(&root)
    }
}
