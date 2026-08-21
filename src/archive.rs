//! Device-local archive re-encryption under the protected archive key.

use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};

use libsodium_rs::utils;
use zeroize::Zeroizing;

use crate::attachment_envelope::{
    AttachmentEnvelopeError, CancellationCheck, EnvelopeBinding, EnvelopeHeader,
    decrypt_stream_with_key, encrypt_stream_with_key,
};
use crate::attachment_manifest::{ATTACHMENT_KEY_BYTES, DIGEST_BYTES};
use crate::key_bundle::CanonicalUuid;
use crate::key_material::RootKeyMaterial;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveError {
    InvalidInput,
    Authentication,
    Io,
    Cryptography,
    Cancelled,
}

pub(crate) struct ArchiveKey(Zeroizing<[u8; ATTACHMENT_KEY_BYTES]>);

impl ArchiveKey {
    pub(crate) fn from_root(root: &RootKeyMaterial) -> Result<Self, ArchiveError> {
        let mut key = Zeroizing::new([0_u8; ATTACHMENT_KEY_BYTES]);
        if root.archive_secret().len() != ATTACHMENT_KEY_BYTES {
            return Err(ArchiveError::InvalidInput);
        }
        key.copy_from_slice(root.archive_secret());
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(crate) fn from_fixture(bytes: [u8; ATTACHMENT_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; ATTACHMENT_KEY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveDescriptor {
    binding: EnvelopeBinding,
}

impl ArchiveDescriptor {
    pub(crate) fn new(
        conversation_id: CanonicalUuid,
        asset_id: CanonicalUuid,
        plaintext_length: u64,
        ciphertext_length: u64,
        ciphertext_digest: [u8; DIGEST_BYTES],
    ) -> Result<Self, ArchiveError> {
        let binding = EnvelopeBinding::new(
            conversation_id,
            asset_id,
            plaintext_length,
            ciphertext_length,
            ciphertext_digest,
        )
        .map_err(map_envelope_error)?;
        Ok(Self { binding })
    }

    pub(crate) fn conversation_id(&self) -> CanonicalUuid {
        self.binding.conversation_id
    }

    pub(crate) fn asset_id(&self) -> CanonicalUuid {
        self.binding.asset_id
    }

    pub(crate) fn plaintext_length(&self) -> u64 {
        self.binding.plaintext_length
    }

    pub(crate) fn ciphertext_length(&self) -> u64 {
        self.binding.ciphertext_length
    }

    pub(crate) fn ciphertext_digest(&self) -> [u8; DIGEST_BYTES] {
        self.binding.ciphertext_digest
    }
}

pub(crate) struct VerifiedArchive {
    header: EnvelopeHeader,
    descriptor: ArchiveDescriptor,
}

impl VerifiedArchive {
    pub(crate) fn descriptor(&self) -> &ArchiveDescriptor {
        &self.descriptor
    }
}

/// Writes an archive and immediately opens it against the original plaintext.
pub(crate) fn create_and_verify_archive<R, F, C>(
    plaintext: &mut R,
    archive: &mut F,
    plaintext_length: u64,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    archive_key: &ArchiveKey,
    cancellation: &mut C,
) -> Result<VerifiedArchive, ArchiveError>
where
    R: Read + Seek,
    F: Read + Write + Seek,
    C: CancellationCheck,
{
    let encrypted = encrypt_stream_with_key(
        plaintext,
        archive,
        plaintext_length,
        conversation_id,
        asset_id,
        archive_key.as_bytes(),
        cancellation,
    )
    .map_err(map_envelope_error)?;
    archive.flush().map_err(|_| ArchiveError::Io)?;
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| ArchiveError::Io)?;
    plaintext
        .seek(SeekFrom::Start(0))
        .map_err(|_| ArchiveError::Io)?;
    let mut comparator = ExactPlaintextComparator { plaintext };
    decrypt_stream_with_key(
        archive,
        &mut comparator,
        &encrypted.binding,
        archive_key.as_bytes(),
        cancellation,
    )
    .map_err(map_envelope_error)?;
    comparator.require_eof()?;
    Ok(VerifiedArchive {
        header: encrypted.header,
        descriptor: ArchiveDescriptor {
            binding: encrypted.binding,
        },
    })
}

pub(crate) fn open_archive<R, W, C>(
    archive: &mut R,
    output: &mut W,
    descriptor: &ArchiveDescriptor,
    archive_key: &ArchiveKey,
    cancellation: &mut C,
) -> Result<EnvelopeHeader, ArchiveError>
where
    R: Read + Seek,
    W: Write,
    C: CancellationCheck,
{
    decrypt_stream_with_key(
        archive,
        output,
        &descriptor.binding,
        archive_key.as_bytes(),
        cancellation,
    )
    .map_err(map_envelope_error)
}

struct ExactPlaintextComparator<'a, R> {
    plaintext: &'a mut R,
}

impl<R: Read> ExactPlaintextComparator<'_, R> {
    fn require_eof(&mut self) -> Result<(), ArchiveError> {
        let mut trailing = [0_u8; 1];
        match self.plaintext.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) => Err(ArchiveError::Authentication),
            Err(_) => Err(ArchiveError::Io),
        }
    }
}

impl<R: Read> Write for ExactPlaintextComparator<'_, R> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let mut expected = Zeroizing::new(vec![0_u8; input.len()]);
        self.plaintext
            .read_exact(expected.as_mut())
            .map_err(|error| {
                if error.kind() == ErrorKind::UnexpectedEof {
                    Error::new(ErrorKind::InvalidData, "archive verification")
                } else {
                    error
                }
            })?;
        if !utils::memcmp(expected.as_ref(), input) {
            return Err(Error::new(ErrorKind::InvalidData, "archive verification"));
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn map_envelope_error(error: AttachmentEnvelopeError) -> ArchiveError {
    match error {
        AttachmentEnvelopeError::InvalidInput => ArchiveError::InvalidInput,
        AttachmentEnvelopeError::Authentication => ArchiveError::Authentication,
        AttachmentEnvelopeError::Io => ArchiveError::Io,
        AttachmentEnvelopeError::Cryptography => ArchiveError::Cryptography,
        AttachmentEnvelopeError::Cancelled => ArchiveError::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::attachment_envelope::NeverCancelled;

    fn uuid(value: u8) -> Result<CanonicalUuid, ArchiveError> {
        CanonicalUuid::from_network_bytes([value; 16]).map_err(|_| ArchiveError::InvalidInput)
    }

    fn plaintext(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn creates_verifies_and_opens_archive_with_fresh_headers() -> Result<(), ArchiveError> {
        let expected = plaintext(65_537);
        let key = ArchiveKey::from_fixture([0x31; ATTACHMENT_KEY_BYTES]);
        let mut first_source = Cursor::new(expected.clone());
        let mut first_archive = Cursor::new(Vec::new());
        let first = create_and_verify_archive(
            &mut first_source,
            &mut first_archive,
            expected.len() as u64,
            uuid(1)?,
            uuid(2)?,
            &key,
            &mut NeverCancelled,
        )?;
        let mut second_source = Cursor::new(expected.clone());
        let mut second_archive = Cursor::new(Vec::new());
        let second = create_and_verify_archive(
            &mut second_source,
            &mut second_archive,
            expected.len() as u64,
            uuid(1)?,
            uuid(2)?,
            &key,
            &mut NeverCancelled,
        )?;
        assert_ne!(first.header, second.header);
        assert_ne!(first_archive.get_ref(), second_archive.get_ref());

        first_archive.set_position(0);
        let mut opened = Vec::new();
        open_archive(
            &mut first_archive,
            &mut opened,
            &first.descriptor,
            &key,
            &mut NeverCancelled,
        )?;
        assert_eq!(opened, expected);
        Ok(())
    }

    #[test]
    fn rejects_wrong_key_identifier_and_ciphertext() -> Result<(), ArchiveError> {
        let expected = plaintext(64);
        let key = ArchiveKey::from_fixture([0x31; ATTACHMENT_KEY_BYTES]);
        let mut source = Cursor::new(expected);
        let mut archive = Cursor::new(Vec::new());
        let verified = create_and_verify_archive(
            &mut source,
            &mut archive,
            64,
            uuid(1)?,
            uuid(2)?,
            &key,
            &mut NeverCancelled,
        )?;
        archive.set_position(0);
        assert_eq!(
            open_archive(
                &mut archive,
                &mut Vec::new(),
                &verified.descriptor,
                &ArchiveKey::from_fixture([0x32; ATTACHMENT_KEY_BYTES]),
                &mut NeverCancelled,
            )
            .err(),
            Some(ArchiveError::Authentication)
        );

        archive.set_position(0);
        let wrong_id = ArchiveDescriptor::new(
            uuid(1)?,
            uuid(3)?,
            verified.descriptor.plaintext_length(),
            verified.descriptor.ciphertext_length(),
            verified.descriptor.ciphertext_digest(),
        )?;
        assert_eq!(
            open_archive(
                &mut archive,
                &mut Vec::new(),
                &wrong_id,
                &key,
                &mut NeverCancelled,
            )
            .err(),
            Some(ArchiveError::Authentication)
        );

        archive.get_mut()[60] ^= 1;
        archive.set_position(0);
        assert_eq!(
            open_archive(
                &mut archive,
                &mut Vec::new(),
                &verified.descriptor,
                &key,
                &mut NeverCancelled,
            )
            .err(),
            Some(ArchiveError::Authentication)
        );
        Ok(())
    }

    #[test]
    fn verification_detects_plaintext_change_between_passes() -> Result<(), ArchiveError> {
        struct ChangingSource {
            inner: Cursor<Vec<u8>>,
            change_on_rewind: bool,
        }
        impl Read for ChangingSource {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.inner.read(output)
            }
        }
        impl Seek for ChangingSource {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                if self.change_on_rewind && position == SeekFrom::Start(0) {
                    self.inner.get_mut()[0] ^= 1;
                    self.change_on_rewind = false;
                }
                self.inner.seek(position)
            }
        }
        let mut source = ChangingSource {
            inner: Cursor::new(plaintext(64)),
            change_on_rewind: true,
        };
        assert_eq!(
            create_and_verify_archive(
                &mut source,
                &mut Cursor::new(Vec::new()),
                64,
                uuid(1)?,
                uuid(2)?,
                &ArchiveKey::from_fixture([0x31; ATTACHMENT_KEY_BYTES]),
                &mut NeverCancelled,
            )
            .err(),
            Some(ArchiveError::Io)
        );
        Ok(())
    }
}
