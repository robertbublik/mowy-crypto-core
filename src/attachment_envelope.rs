//! Bounded streaming implementation of Mowy attachment envelope v1.

use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use libsodium_rs::{crypto_hash::sha256, crypto_secretstream::xchacha20poly1305, crypto_verify};
use zeroize::Zeroizing;

use crate::attachment_manifest::{
    AttachmentKey, AttachmentManifest, AttachmentManifestError, CHUNK_BYTES, ENVELOPE_HEADER_BYTES,
    RECORD_OVERHEAD_BYTES, canonical_ciphertext_length, chunk_count, format_chunk_count,
};
use crate::key_bundle::CanonicalUuid;

pub(crate) const HEADER_BYTES: usize = ENVELOPE_HEADER_BYTES as usize;
const STREAM_HEADER_BYTES: usize = xchacha20poly1305::HEADERBYTES;
const RECORD_CIPHERTEXT_BYTES: usize = CHUNK_BYTES as usize + RECORD_OVERHEAD_BYTES as usize;
const AAD_BYTES: usize = 115;
const MAGIC: &[u8; 8] = b"MOWYAUD\0";
const AAD_DOMAIN: &[u8; 19] = b"mowy-attachment-v1\0";
const VERSION: u16 = 1;
const ALGORITHM: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentEnvelopeError {
    InvalidInput,
    Authentication,
    Io,
    Cryptography,
    Cancelled,
}

pub(crate) trait CancellationCheck {
    fn is_cancelled(&mut self) -> bool;
}

pub(crate) struct NeverCancelled;

impl CancellationCheck for NeverCancelled {
    fn is_cancelled(&mut self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnvelopeHeader([u8; HEADER_BYTES]);

impl EnvelopeHeader {
    fn new(
        plaintext_length: u64,
        stream_header: [u8; STREAM_HEADER_BYTES],
    ) -> Result<Self, AttachmentEnvelopeError> {
        let count = format_chunk_count(plaintext_length).map_err(map_manifest_error)?;
        let mut bytes = [0_u8; HEADER_BYTES];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&ALGORITHM.to_be_bytes());
        bytes[12..16].copy_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&plaintext_length.to_be_bytes());
        bytes[24..28].copy_from_slice(&count.to_be_bytes());
        bytes[32..56].copy_from_slice(&stream_header);
        Ok(Self(bytes))
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, AttachmentEnvelopeError> {
        if bytes.len() != HEADER_BYTES {
            return Err(AttachmentEnvelopeError::InvalidInput);
        }
        let exact: [u8; HEADER_BYTES] = bytes
            .try_into()
            .map_err(|_| AttachmentEnvelopeError::InvalidInput)?;
        let header = Self(exact);
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; HEADER_BYTES] {
        &self.0
    }

    pub(crate) fn plaintext_length(&self) -> Result<u64, AttachmentEnvelopeError> {
        Ok(u64::from_be_bytes(exact_field(&self.0[16..24])?))
    }

    pub(crate) fn record_count(&self) -> Result<u32, AttachmentEnvelopeError> {
        Ok(u32::from_be_bytes(exact_field(&self.0[24..28])?))
    }

    fn stream_header(&self) -> Result<[u8; STREAM_HEADER_BYTES], AttachmentEnvelopeError> {
        exact_field(&self.0[32..56])
    }

    fn validate(&self) -> Result<(), AttachmentEnvelopeError> {
        if &self.0[0..8] != MAGIC
            || u16::from_be_bytes(exact_field(&self.0[8..10])?) != VERSION
            || u16::from_be_bytes(exact_field(&self.0[10..12])?) != ALGORITHM
            || u32::from_be_bytes(exact_field(&self.0[12..16])?) != CHUNK_BYTES as u32
            || self.0[28..32] != [0; 4]
        {
            return Err(AttachmentEnvelopeError::InvalidInput);
        }
        let length = self.plaintext_length()?;
        let expected_count = format_chunk_count(length).map_err(map_manifest_error)?;
        if self.record_count()? != expected_count {
            return Err(AttachmentEnvelopeError::InvalidInput);
        }
        Ok(())
    }
}

pub(crate) struct EncryptedAttachment {
    pub(crate) header: EnvelopeHeader,
    pub(crate) manifest: AttachmentManifest,
}

pub(crate) fn encrypt_stream<R, W, C>(
    source: &mut R,
    output: &mut W,
    plaintext_length: u64,
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    cancellation: &mut C,
) -> Result<EncryptedAttachment, AttachmentEnvelopeError>
where
    R: Read,
    W: Write,
    C: CancellationCheck,
{
    if cancellation.is_cancelled() {
        return Err(AttachmentEnvelopeError::Cancelled);
    }
    let count = chunk_count(plaintext_length).map_err(map_manifest_error)?;
    let attachment_key = AttachmentKey::generate().map_err(map_manifest_error)?;
    let key = xchacha20poly1305::Key::from_bytes(attachment_key.as_bytes())
        .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
    let (mut push, stream_header) = xchacha20poly1305::PushState::init_push(&key)
        .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
    let header = EnvelopeHeader::new(plaintext_length, stream_header)?;
    let mut digest = sha256::State::new();
    write_output(output, header.as_bytes())?;
    digest.update(header.as_bytes());

    let mut plaintext = Zeroizing::new([0_u8; CHUNK_BYTES as usize]);
    for index in 0..count {
        if cancellation.is_cancelled() {
            return Err(AttachmentEnvelopeError::Cancelled);
        }
        let expected = record_plaintext_length(plaintext_length, count, index)?;
        read_exact_input(source, &mut plaintext[..expected])?;
        let aad = record_aad(conversation_id, asset_id, header, index, count);
        let tag = if index + 1 == count {
            xchacha20poly1305::TAG_FINAL
        } else {
            xchacha20poly1305::TAG_MESSAGE
        };
        let ciphertext = push
            .push(&plaintext[..expected], Some(&aad), tag)
            .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
        plaintext[..expected].fill(0);
        if ciphertext.len() != expected + RECORD_OVERHEAD_BYTES as usize {
            return Err(AttachmentEnvelopeError::Cryptography);
        }
        if cancellation.is_cancelled() {
            return Err(AttachmentEnvelopeError::Cancelled);
        }
        write_output(output, &ciphertext)?;
        digest.update(&ciphertext);
    }
    require_eof(source)?;
    output.flush().map_err(|_| AttachmentEnvelopeError::Io)?;
    let ciphertext_digest = digest.finalize();
    let ciphertext_length =
        canonical_ciphertext_length(plaintext_length).map_err(map_manifest_error)?;
    let manifest = AttachmentManifest::new(
        conversation_id,
        asset_id,
        plaintext_length,
        ciphertext_length,
        ciphertext_digest,
        attachment_key,
    )
    .map_err(map_manifest_error)?;
    Ok(EncryptedAttachment { header, manifest })
}

pub(crate) fn decrypt_stream<R, W, C>(
    ciphertext: &mut R,
    output: &mut W,
    manifest: &AttachmentManifest,
    cancellation: &mut C,
) -> Result<EnvelopeHeader, AttachmentEnvelopeError>
where
    R: Read + Seek,
    W: Write,
    C: CancellationCheck,
{
    let verified_header = verify_ciphertext(ciphertext, manifest, cancellation)?;
    ciphertext
        .seek(SeekFrom::Start(0))
        .map_err(|_| AttachmentEnvelopeError::Io)?;
    if cancellation.is_cancelled() {
        return Err(AttachmentEnvelopeError::Cancelled);
    }

    let mut raw_header = [0_u8; HEADER_BYTES];
    read_exact_input(ciphertext, &mut raw_header)?;
    let header = EnvelopeHeader::parse(&raw_header)?;
    if !libsodium_rs::utils::memcmp(header.as_bytes(), verified_header.as_bytes()) {
        return Err(AttachmentEnvelopeError::InvalidInput);
    }
    let key =
        xchacha20poly1305::Key::from_bytes(manifest.attachment_key().map_err(map_manifest_error)?)
            .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
    let stream_header = header.stream_header()?;
    let mut pull = xchacha20poly1305::PullState::init_pull(&stream_header, &key)
        .map_err(|_| AttachmentEnvelopeError::Authentication)?;
    let conversation_id = manifest.conversation_id().map_err(map_manifest_error)?;
    let asset_id = manifest.asset_id().map_err(map_manifest_error)?;
    let plaintext_length = header.plaintext_length()?;
    let count = header.record_count()?;
    let mut record = vec![0_u8; RECORD_CIPHERTEXT_BYTES];

    for index in 0..count {
        if cancellation.is_cancelled() {
            return Err(AttachmentEnvelopeError::Cancelled);
        }
        let expected_plaintext = record_plaintext_length(plaintext_length, count, index)?;
        let expected_ciphertext = expected_plaintext + RECORD_OVERHEAD_BYTES as usize;
        read_exact_input(ciphertext, &mut record[..expected_ciphertext])?;
        let aad = record_aad(conversation_id, asset_id, header, index, count);
        let (plaintext, tag) = pull
            .pull(&record[..expected_ciphertext], Some(&aad))
            .map_err(|_| AttachmentEnvelopeError::Authentication)?;
        let plaintext = Zeroizing::new(plaintext);
        let expected_tag = if index + 1 == count {
            xchacha20poly1305::TAG_FINAL
        } else {
            xchacha20poly1305::TAG_MESSAGE
        };
        if plaintext.len() != expected_plaintext || tag != expected_tag {
            return Err(AttachmentEnvelopeError::Authentication);
        }
        if cancellation.is_cancelled() {
            return Err(AttachmentEnvelopeError::Cancelled);
        }
        write_output(output, plaintext.as_ref())?;
    }
    require_eof(ciphertext)?;
    output.flush().map_err(|_| AttachmentEnvelopeError::Io)?;
    Ok(header)
}

fn verify_ciphertext<R, C>(
    ciphertext: &mut R,
    manifest: &AttachmentManifest,
    cancellation: &mut C,
) -> Result<EnvelopeHeader, AttachmentEnvelopeError>
where
    R: Read,
    C: CancellationCheck,
{
    let expected_length = manifest.ciphertext_length().map_err(map_manifest_error)?;
    let mut raw_header = [0_u8; HEADER_BYTES];
    read_exact_input(ciphertext, &mut raw_header)?;
    let header = EnvelopeHeader::parse(&raw_header)?;
    if header.plaintext_length()? != manifest.plaintext_length().map_err(map_manifest_error)?
        || canonical_ciphertext_length(header.plaintext_length()?).map_err(map_manifest_error)?
            != expected_length
    {
        return Err(AttachmentEnvelopeError::InvalidInput);
    }

    let mut digest = sha256::State::new();
    digest.update(&raw_header);
    let mut remaining = expected_length
        .checked_sub(HEADER_BYTES as u64)
        .ok_or(AttachmentEnvelopeError::InvalidInput)?;
    let mut buffer = [0_u8; CHUNK_BYTES as usize];
    while remaining != 0 {
        if cancellation.is_cancelled() {
            return Err(AttachmentEnvelopeError::Cancelled);
        }
        let length = usize::try_from(remaining.min(CHUNK_BYTES))
            .map_err(|_| AttachmentEnvelopeError::InvalidInput)?;
        read_exact_input(ciphertext, &mut buffer[..length])?;
        digest.update(&buffer[..length]);
        remaining -= length as u64;
    }
    require_eof(ciphertext)?;
    let actual_digest = digest.finalize();
    let expected_digest = manifest.ciphertext_digest().map_err(map_manifest_error)?;
    if !crypto_verify::verify_32(&actual_digest, &expected_digest) {
        return Err(AttachmentEnvelopeError::Authentication);
    }
    Ok(header)
}

fn record_plaintext_length(
    plaintext_length: u64,
    count: u32,
    index: u32,
) -> Result<usize, AttachmentEnvelopeError> {
    if count == 0 || index >= count {
        return Err(AttachmentEnvelopeError::InvalidInput);
    }
    if index + 1 != count {
        return Ok(CHUNK_BYTES as usize);
    }
    let preceding = u64::from(count - 1)
        .checked_mul(CHUNK_BYTES)
        .ok_or(AttachmentEnvelopeError::InvalidInput)?;
    let final_length = plaintext_length
        .checked_sub(preceding)
        .ok_or(AttachmentEnvelopeError::InvalidInput)?;
    if final_length == 0 || final_length > CHUNK_BYTES {
        return Err(AttachmentEnvelopeError::InvalidInput);
    }
    usize::try_from(final_length).map_err(|_| AttachmentEnvelopeError::InvalidInput)
}

fn record_aad(
    conversation_id: CanonicalUuid,
    asset_id: CanonicalUuid,
    header: EnvelopeHeader,
    index: u32,
    count: u32,
) -> [u8; AAD_BYTES] {
    let mut aad = [0_u8; AAD_BYTES];
    aad[0..19].copy_from_slice(AAD_DOMAIN);
    aad[19..35].copy_from_slice(conversation_id.as_network_bytes());
    aad[35..51].copy_from_slice(asset_id.as_network_bytes());
    aad[51..107].copy_from_slice(header.as_bytes());
    aad[107..111].copy_from_slice(&index.to_be_bytes());
    aad[111..115].copy_from_slice(&count.to_be_bytes());
    aad
}

fn read_exact_input<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<(), AttachmentEnvelopeError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            AttachmentEnvelopeError::InvalidInput
        } else {
            AttachmentEnvelopeError::Io
        }
    })
}

fn require_eof<R: Read>(reader: &mut R) -> Result<(), AttachmentEnvelopeError> {
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(AttachmentEnvelopeError::InvalidInput),
        Err(_) => Err(AttachmentEnvelopeError::Io),
    }
}

fn write_output<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), AttachmentEnvelopeError> {
    writer
        .write_all(bytes)
        .map_err(|_| AttachmentEnvelopeError::Io)
}

fn exact_field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AttachmentEnvelopeError> {
    bytes
        .try_into()
        .map_err(|_| AttachmentEnvelopeError::InvalidInput)
}

fn map_manifest_error(error: AttachmentManifestError) -> AttachmentEnvelopeError {
    match error {
        AttachmentManifestError::InvalidInput => AttachmentEnvelopeError::InvalidInput,
        AttachmentManifestError::Cryptography => AttachmentEnvelopeError::Cryptography,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Error, Result as IoResult};

    use proptest::prelude::*;

    use super::*;
    use crate::attachment_manifest::{ATTACHMENT_KEY_BYTES, DIGEST_BYTES, MANIFEST_BYTES};

    fn uuid(value: u8) -> Result<CanonicalUuid, AttachmentEnvelopeError> {
        CanonicalUuid::from_network_bytes([value; 16])
            .map_err(|_| AttachmentEnvelopeError::InvalidInput)
    }

    fn plaintext(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn opens_the_exact_public_vector() -> Result<(), AttachmentEnvelopeError> {
        let vector = include_str!("../vectors/attachment-envelope-v1.txt");
        let header_bytes = decode_hex::<56>(vector_value(vector, "header")?)?;
        let header = EnvelopeHeader::parse(&header_bytes)?;
        let aad = decode_hex::<115>(vector_value(vector, "record_0_aad")?)?;
        let fixture_plaintext = decode_hex::<33>(vector_value(vector, "plaintext")?)?;
        let record = decode_hex::<50>(vector_value(vector, "record_0")?)?;
        let envelope = decode_hex::<106>(vector_value(vector, "envelope")?)?;
        let digest = decode_hex::<32>(vector_value(vector, "ciphertext_digest")?)?;
        let attachment_key =
            decode_hex::<ATTACHMENT_KEY_BYTES>(vector_value(vector, "fixture_attachment_key")?)?;

        assert_eq!(header.plaintext_length()?, 33);
        assert_eq!(header.record_count()?, 1);
        assert_eq!(record_aad(uuid(4)?, uuid(5)?, header, 0, 1), aad);
        assert_eq!(&envelope[..HEADER_BYTES], &header_bytes);
        assert_eq!(&envelope[HEADER_BYTES..], &record);
        assert_eq!(sha256::hash(&envelope), digest);

        let manifest = AttachmentManifest::new(
            uuid(4)?,
            uuid(5)?,
            33,
            106,
            digest,
            AttachmentKey::from_fixture(attachment_key),
        )
        .map_err(map_manifest_error)?;
        assert_eq!(decrypt_bytes(&envelope, &manifest)?, fixture_plaintext);
        Ok(())
    }

    fn vector_value<'a>(vector: &'a str, name: &str) -> Result<&'a str, AttachmentEnvelopeError> {
        for line in vector.lines() {
            if let Some((field, value)) = line.split_once('=')
                && field == name
            {
                return Ok(value);
            }
        }
        Err(AttachmentEnvelopeError::InvalidInput)
    }

    fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], AttachmentEnvelopeError> {
        if value.len() != N * 2 {
            return Err(AttachmentEnvelopeError::InvalidInput);
        }
        let encoded = value.as_bytes();
        let mut output = [0_u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            let high = hex_nibble(encoded[index * 2])?;
            let low = hex_nibble(encoded[index * 2 + 1])?;
            *byte = (high << 4) | low;
        }
        Ok(output)
    }

    fn hex_nibble(value: u8) -> Result<u8, AttachmentEnvelopeError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(AttachmentEnvelopeError::InvalidInput),
        }
    }

    fn encrypt_bytes(
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, EncryptedAttachment), AttachmentEnvelopeError> {
        let mut source = Cursor::new(plaintext);
        let mut ciphertext = Vec::new();
        let mut cancellation = NeverCancelled;
        let encrypted = encrypt_stream(
            &mut source,
            &mut ciphertext,
            plaintext.len() as u64,
            uuid(1)?,
            uuid(2)?,
            &mut cancellation,
        )?;
        Ok((ciphertext, encrypted))
    }

    fn decrypt_bytes(
        ciphertext: &[u8],
        manifest: &AttachmentManifest,
    ) -> Result<Vec<u8>, AttachmentEnvelopeError> {
        let mut source = Cursor::new(ciphertext);
        let mut plaintext = Vec::new();
        let mut cancellation = NeverCancelled;
        decrypt_stream(&mut source, &mut plaintext, manifest, &mut cancellation)?;
        Ok(plaintext)
    }

    #[test]
    fn round_trips_boundaries_with_fresh_keys_and_headers() -> Result<(), AttachmentEnvelopeError> {
        for length in [1, CHUNK_BYTES as usize, CHUNK_BYTES as usize + 1] {
            let input = plaintext(length);
            let (first_bytes, first) = encrypt_bytes(&input)?;
            let (second_bytes, second) = encrypt_bytes(&input)?;
            assert_eq!(
                first_bytes.len() as u64,
                canonical_ciphertext_length(length as u64).map_err(map_manifest_error)?
            );
            assert_ne!(first.header, second.header);
            assert_ne!(first_bytes, second_bytes);
            assert!(!crypto_verify::verify_32(
                first
                    .manifest
                    .attachment_key()
                    .map_err(map_manifest_error)?,
                second
                    .manifest
                    .attachment_key()
                    .map_err(map_manifest_error)?,
            ));
            assert_eq!(decrypt_bytes(&first_bytes, &first.manifest)?, input);
        }
        Ok(())
    }

    #[test]
    fn rejects_tamper_truncation_trailing_reorder_and_duplicate()
    -> Result<(), AttachmentEnvelopeError> {
        let input = plaintext((CHUNK_BYTES * 2) as usize);
        let (ciphertext, encrypted) = encrypt_bytes(&input)?;

        let mut tampered = ciphertext.clone();
        tampered[HEADER_BYTES + 5] ^= 1;
        assert_eq!(
            decrypt_bytes(&tampered, &encrypted.manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );

        assert_eq!(
            decrypt_bytes(&ciphertext[..ciphertext.len() - 1], &encrypted.manifest).err(),
            Some(AttachmentEnvelopeError::InvalidInput)
        );
        let mut trailing = ciphertext.clone();
        trailing.push(0);
        assert_eq!(
            decrypt_bytes(&trailing, &encrypted.manifest).err(),
            Some(AttachmentEnvelopeError::InvalidInput)
        );

        let record_length = CHUNK_BYTES as usize + RECORD_OVERHEAD_BYTES as usize;
        let mut reordered = ciphertext.clone();
        let records = &mut reordered[HEADER_BYTES..];
        let (first, second) = records.split_at_mut(record_length);
        first.swap_with_slice(second);
        assert_eq!(
            decrypt_bytes(&reordered, &encrypted.manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );

        let mut duplicated = ciphertext.clone();
        let first_record = ciphertext[HEADER_BYTES..HEADER_BYTES + record_length].to_vec();
        duplicated[HEADER_BYTES + record_length..].copy_from_slice(&first_record);
        assert_eq!(
            decrypt_bytes(&duplicated, &encrypted.manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );
        Ok(())
    }

    #[test]
    fn rejects_tamper_in_every_record_position() -> Result<(), AttachmentEnvelopeError> {
        let input = plaintext((CHUNK_BYTES * 2 + 1) as usize);
        let (ciphertext, encrypted) = encrypt_bytes(&input)?;
        let full_record = CHUNK_BYTES as usize + RECORD_OVERHEAD_BYTES as usize;
        for offset in [
            HEADER_BYTES + 1,
            HEADER_BYTES + full_record + 1,
            HEADER_BYTES + full_record * 2 + 1,
        ] {
            let mut tampered = ciphertext.clone();
            tampered[offset] ^= 1;
            assert_eq!(
                decrypt_bytes(&tampered, &encrypted.manifest).err(),
                Some(AttachmentEnvelopeError::Authentication)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_wrong_key_and_identifier_aad() -> Result<(), AttachmentEnvelopeError> {
        let input = plaintext(64);
        let (ciphertext, encrypted) = encrypt_bytes(&input)?;
        let wrong_key_manifest = AttachmentManifest::new(
            uuid(1)?,
            uuid(2)?,
            input.len() as u64,
            ciphertext.len() as u64,
            encrypted
                .manifest
                .ciphertext_digest()
                .map_err(map_manifest_error)?,
            AttachmentKey::from_fixture([0x55; ATTACHMENT_KEY_BYTES]),
        )
        .map_err(map_manifest_error)?;
        assert_eq!(
            decrypt_bytes(&ciphertext, &wrong_key_manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );

        let wrong_id_manifest = AttachmentManifest::new(
            uuid(9)?,
            uuid(2)?,
            input.len() as u64,
            ciphertext.len() as u64,
            encrypted
                .manifest
                .ciphertext_digest()
                .map_err(map_manifest_error)?,
            AttachmentKey::from_fixture(
                *encrypted
                    .manifest
                    .attachment_key()
                    .map_err(map_manifest_error)?,
            ),
        )
        .map_err(map_manifest_error)?;
        assert_eq!(
            decrypt_bytes(&ciphertext, &wrong_id_manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );
        Ok(())
    }

    #[test]
    fn rejects_every_authenticated_nonfinal_last_tag() -> Result<(), AttachmentEnvelopeError> {
        let plaintext = [0x42_u8];
        for tag in [
            xchacha20poly1305::TAG_MESSAGE,
            xchacha20poly1305::TAG_PUSH,
            xchacha20poly1305::TAG_REKEY,
        ] {
            let attachment_key = AttachmentKey::from_fixture([0x33; ATTACHMENT_KEY_BYTES]);
            let key = xchacha20poly1305::Key::from_bytes(attachment_key.as_bytes())
                .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
            let (mut push, stream_header) = xchacha20poly1305::PushState::init_push(&key)
                .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
            let header = EnvelopeHeader::new(1, stream_header)?;
            let aad = record_aad(uuid(1)?, uuid(2)?, header, 0, 1);
            let record = push
                .push(&plaintext, Some(&aad), tag)
                .map_err(|_| AttachmentEnvelopeError::Cryptography)?;
            let mut ciphertext = header.as_bytes().to_vec();
            ciphertext.extend_from_slice(&record);
            let manifest = AttachmentManifest::new(
                uuid(1)?,
                uuid(2)?,
                1,
                ciphertext.len() as u64,
                sha256::hash(&ciphertext),
                attachment_key,
            )
            .map_err(map_manifest_error)?;
            assert_eq!(
                decrypt_bytes(&ciphertext, &manifest).err(),
                Some(AttachmentEnvelopeError::Authentication)
            );
        }
        Ok(())
    }

    struct FailingWriter {
        accepted: usize,
        limit: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> IoResult<usize> {
            if self.accepted >= self.limit {
                return Err(Error::new(ErrorKind::StorageFull, "fixture full"));
            }
            let count = bytes.len().min(self.limit - self.accepted);
            self.accepted += count;
            Ok(count)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn reports_short_source_disk_full_and_cancellation_without_success()
    -> Result<(), AttachmentEnvelopeError> {
        let input = plaintext(100);
        let mut short_source = Cursor::new(&input[..99]);
        let mut output = Vec::new();
        let mut cancellation = NeverCancelled;
        assert_eq!(
            encrypt_stream(
                &mut short_source,
                &mut output,
                100,
                uuid(1)?,
                uuid(2)?,
                &mut cancellation,
            )
            .err(),
            Some(AttachmentEnvelopeError::InvalidInput)
        );

        let mut source = Cursor::new(&input);
        let mut full = FailingWriter {
            accepted: 0,
            limit: HEADER_BYTES + 3,
        };
        assert_eq!(
            encrypt_stream(
                &mut source,
                &mut full,
                input.len() as u64,
                uuid(1)?,
                uuid(2)?,
                &mut cancellation,
            )
            .err(),
            Some(AttachmentEnvelopeError::Io)
        );

        struct CancelNow;
        impl CancellationCheck for CancelNow {
            fn is_cancelled(&mut self) -> bool {
                true
            }
        }
        let mut source = Cursor::new(&input);
        let mut output = Vec::new();
        assert_eq!(
            encrypt_stream(
                &mut source,
                &mut output,
                input.len() as u64,
                uuid(1)?,
                uuid(2)?,
                &mut CancelNow,
            )
            .err(),
            Some(AttachmentEnvelopeError::Cancelled)
        );
        assert!(output.is_empty());
        Ok(())
    }

    struct ChoppyReader {
        inner: Cursor<Vec<u8>>,
        maximum: usize,
    }

    impl Read for ChoppyReader {
        fn read(&mut self, output: &mut [u8]) -> IoResult<usize> {
            let length = output.len().min(self.maximum);
            self.inner.read(&mut output[..length])
        }
    }

    impl Seek for ChoppyReader {
        fn seek(&mut self, position: SeekFrom) -> IoResult<u64> {
            self.inner.seek(position)
        }
    }

    struct ChoppyWriter {
        bytes: Vec<u8>,
        maximum: usize,
    }

    impl Write for ChoppyWriter {
        fn write(&mut self, input: &[u8]) -> IoResult<usize> {
            let length = input.len().min(self.maximum);
            self.bytes.extend_from_slice(&input[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn handles_short_successful_reads_and_writes() -> Result<(), AttachmentEnvelopeError> {
        let input = plaintext(CHUNK_BYTES as usize + 1);
        let mut source = ChoppyReader {
            inner: Cursor::new(input.clone()),
            maximum: 7,
        };
        let mut encrypted_output = ChoppyWriter {
            bytes: Vec::new(),
            maximum: 11,
        };
        let mut cancellation = NeverCancelled;
        let encrypted = encrypt_stream(
            &mut source,
            &mut encrypted_output,
            input.len() as u64,
            uuid(1)?,
            uuid(2)?,
            &mut cancellation,
        )?;
        let mut ciphertext = ChoppyReader {
            inner: Cursor::new(encrypted_output.bytes),
            maximum: 13,
        };
        let mut plaintext_output = ChoppyWriter {
            bytes: Vec::new(),
            maximum: 5,
        };
        decrypt_stream(
            &mut ciphertext,
            &mut plaintext_output,
            &encrypted.manifest,
            &mut cancellation,
        )?;
        assert_eq!(plaintext_output.bytes, input);
        Ok(())
    }

    struct PatternReader {
        position: u64,
        length: u64,
    }

    impl Read for PatternReader {
        fn read(&mut self, output: &mut [u8]) -> IoResult<usize> {
            let remaining = self.length.saturating_sub(self.position);
            let count = usize::try_from(remaining.min(output.len() as u64))
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "fixture length"))?;
            for (offset, byte) in output[..count].iter_mut().enumerate() {
                *byte = ((self.position + offset as u64) % 251) as u8;
            }
            self.position += count as u64;
            Ok(count)
        }
    }

    struct PatternVerifier {
        position: u64,
    }

    impl Write for PatternVerifier {
        fn write(&mut self, input: &[u8]) -> IoResult<usize> {
            for (offset, byte) in input.iter().enumerate() {
                if *byte != ((self.position + offset as u64) % 251) as u8 {
                    return Err(Error::new(ErrorKind::InvalidData, "fixture mismatch"));
                }
            }
            self.position += input.len() as u64;
            Ok(input.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn streams_exact_maximum_fixture_with_bounded_buffers() -> Result<(), AttachmentEnvelopeError> {
        let length = crate::attachment_manifest::MAX_P2_PLAINTEXT_BYTES;
        let mut source = PatternReader {
            position: 0,
            length,
        };
        let mut ciphertext = Vec::with_capacity(26_221_256);
        let mut cancellation = NeverCancelled;
        let encrypted = encrypt_stream(
            &mut source,
            &mut ciphertext,
            length,
            uuid(1)?,
            uuid(2)?,
            &mut cancellation,
        )?;
        assert_eq!(ciphertext.len(), 26_221_256);

        let mut ciphertext_reader = Cursor::new(&ciphertext);
        let mut verifier = PatternVerifier { position: 0 };
        decrypt_stream(
            &mut ciphertext_reader,
            &mut verifier,
            &encrypted.manifest,
            &mut cancellation,
        )?;
        assert_eq!(verifier.position, length);
        Ok(())
    }

    #[test]
    fn header_rejects_every_field_class() -> Result<(), AttachmentEnvelopeError> {
        let (ciphertext, encrypted) = encrypt_bytes(&plaintext(1))?;
        for offset in [0, 8, 10, 12, 16, 24, 28, 31] {
            let mut bytes = *encrypted.header.as_bytes();
            bytes[offset] ^= 1;
            assert_eq!(
                EnvelopeHeader::parse(&bytes).err(),
                Some(AttachmentEnvelopeError::InvalidInput)
            );
        }
        assert_eq!(
            EnvelopeHeader::parse(&encrypted.header.as_bytes()[..55]).err(),
            Some(AttachmentEnvelopeError::InvalidInput)
        );

        let above_policy = EnvelopeHeader::new(
            crate::attachment_manifest::MAX_P2_PLAINTEXT_BYTES + 1,
            [0_u8; STREAM_HEADER_BYTES],
        )?;
        assert_eq!(
            EnvelopeHeader::parse(above_policy.as_bytes())?.record_count()?,
            401
        );

        let mut changed_stream_header = ciphertext;
        changed_stream_header[32] ^= 1;
        let rebound_manifest = AttachmentManifest::new(
            uuid(1)?,
            uuid(2)?,
            1,
            changed_stream_header.len() as u64,
            sha256::hash(&changed_stream_header),
            AttachmentKey::from_fixture(
                *encrypted
                    .manifest
                    .attachment_key()
                    .map_err(map_manifest_error)?,
            ),
        )
        .map_err(map_manifest_error)?;
        assert_eq!(
            decrypt_bytes(&changed_stream_header, &rebound_manifest).err(),
            Some(AttachmentEnvelopeError::Authentication)
        );
        Ok(())
    }

    #[test]
    fn manifest_layout_constant_remains_exact() {
        assert_eq!(MANIFEST_BYTES, 128);
        assert_eq!(DIGEST_BYTES, 32);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_headers_never_panic(bytes in any::<[u8; HEADER_BYTES]>()) {
            let _ = EnvelopeHeader::parse(&bytes);
        }

        #[test]
        fn boundary_lengths_have_exact_geometry(length in 1_u64..=crate::attachment_manifest::MAX_P2_PLAINTEXT_BYTES) {
            let count = chunk_count(length);
            let ciphertext = canonical_ciphertext_length(length);
            prop_assert!(count.is_ok());
            prop_assert!(ciphertext.is_ok());
            if let (Ok(count), Ok(ciphertext)) = (count, ciphertext) {
                prop_assert_eq!(
                    ciphertext,
                    HEADER_BYTES as u64 + length + u64::from(count) * RECORD_OVERHEAD_BYTES
                );
            }
        }
    }
}
