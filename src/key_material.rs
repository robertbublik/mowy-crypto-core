//! Generates the three device secrets and coordinates their protected storage.
//!
//! Rust owns entropy and zeroization. Swift and Kotlin implement the storage
//! trait inside the native core; JavaScript never implements or observes it.

use libsodium_rs::{crypto_box, crypto_secretstream, crypto_sign, ensure_init, random, utils};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const ROOT_KEY_MATERIAL_BYTES: usize = 96;
const KEY_BYTES: usize = 32;

/// Coarse failures intentionally carry no platform, path, or key detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyMaterialError {
    Unavailable,
    CorruptState,
    Conflict,
    Storage,
    Cryptography,
}

/// Describes whether the protected root-key item exists as one complete item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedKeyState {
    Absent,
    Present,
    Partial,
}

/// Non-secret companion artifacts used to detect reinstall and partial state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompanionState {
    pub(crate) installation_marker_exists: bool,
    pub(crate) database_exists: bool,
}

/// Initialization never repairs a partial combination or replaces missing keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitializationState {
    Empty,
    Ready,
    Unavailable,
}

/// The only values allowed to leave key initialization are public keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DevicePublicKeys {
    pub(crate) identity: [u8; KEY_BYTES],
    pub(crate) key_agreement: [u8; KEY_BYTES],
}

/// Exact private root layout: Ed25519 seed, X25519 secret, archive key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct RootKeyMaterial([u8; ROOT_KEY_MATERIAL_BYTES]);

impl RootKeyMaterial {
    fn zeroed() -> Self {
        Self([0; ROOT_KEY_MATERIAL_BYTES])
    }

    /// This view is consumed only by the native protected-storage adapter.
    pub(crate) fn expose_for_protected_storage(&self) -> &[u8; ROOT_KEY_MATERIAL_BYTES] {
        &self.0
    }

    pub(crate) fn identity_seed(&self) -> &[u8] {
        &self.0[..KEY_BYTES]
    }

    pub(crate) fn agreement_secret(&self) -> &[u8] {
        &self.0[KEY_BYTES..KEY_BYTES * 2]
    }
}

/// Platform implementations must enforce lock checks around every operation.
pub(crate) trait ProtectedKeyStore {
    fn protected_data_available(&self) -> Result<bool, KeyMaterialError>;
    fn state(&self) -> Result<ProtectedKeyState, KeyMaterialError>;
    fn store_new(&mut self, material: &RootKeyMaterial) -> Result<(), KeyMaterialError>;
    fn load(&self) -> Result<RootKeyMaterial, KeyMaterialError>;
}

/// Classifies all cross-resource combinations without attempting automatic repair.
pub(crate) fn classify_initialization(
    protected_keys: ProtectedKeyState,
    companions: CompanionState,
) -> InitializationState {
    match (
        protected_keys,
        companions.installation_marker_exists,
        companions.database_exists,
    ) {
        (ProtectedKeyState::Absent, false, false) => InitializationState::Empty,
        (ProtectedKeyState::Present, true, true) => InitializationState::Ready,
        _ => InitializationState::Unavailable,
    }
}

/// Creates the root item only from a completely absent installation state.
pub(crate) fn initialize<S: ProtectedKeyStore>(
    store: &mut S,
    companions: CompanionState,
) -> Result<DevicePublicKeys, KeyMaterialError> {
    if !store.protected_data_available()? {
        return Err(KeyMaterialError::Unavailable);
    }

    match classify_initialization(store.state()?, companions) {
        InitializationState::Empty => initialize_empty(store),
        InitializationState::Ready => load_public_keys(store),
        InitializationState::Unavailable => Err(KeyMaterialError::CorruptState),
    }
}

fn initialize_empty<S: ProtectedKeyStore>(
    store: &mut S,
) -> Result<DevicePublicKeys, KeyMaterialError> {
    let (material, public_keys) = generate()?;
    store.store_new(&material)?;

    if !store.protected_data_available()? {
        return Err(KeyMaterialError::Unavailable);
    }

    let persisted = store.load()?;
    if !utils::memcmp(
        material.expose_for_protected_storage(),
        persisted.expose_for_protected_storage(),
    ) {
        return Err(KeyMaterialError::CorruptState);
    }

    Ok(public_keys)
}

fn load_public_keys<S: ProtectedKeyStore>(store: &S) -> Result<DevicePublicKeys, KeyMaterialError> {
    let material = store.load()?;
    if !store.protected_data_available()? {
        return Err(KeyMaterialError::Unavailable);
    }
    derive_public_keys(&material)
}

pub(crate) fn generate() -> Result<(RootKeyMaterial, DevicePublicKeys), KeyMaterialError> {
    ensure_init().map_err(|_| KeyMaterialError::Cryptography)?;

    let mut identity_seed = Zeroizing::new([0_u8; KEY_BYTES]);
    random::fill_bytes(identity_seed.as_mut());
    let identity = crypto_sign::KeyPair::from_seed(identity_seed.as_ref())
        .map_err(|_| KeyMaterialError::Cryptography)?;

    let mut agreement_seed = Zeroizing::new([0_u8; KEY_BYTES]);
    random::fill_bytes(agreement_seed.as_mut());
    let agreement = crypto_box::KeyPair::from_seed(agreement_seed.as_ref())
        .map_err(|_| KeyMaterialError::Cryptography)?;

    let archive = crypto_secretstream::Key::generate();
    let mut material = RootKeyMaterial::zeroed();
    material.0[..KEY_BYTES].copy_from_slice(identity_seed.as_ref());
    material.0[KEY_BYTES..KEY_BYTES * 2].copy_from_slice(agreement.secret_key.as_bytes());
    material.0[KEY_BYTES * 2..].copy_from_slice(archive.as_bytes());

    let public_keys = DevicePublicKeys {
        identity: *identity.public_key.as_bytes(),
        key_agreement: *agreement.public_key.as_bytes(),
    };

    Ok((material, public_keys))
}

fn derive_public_keys(material: &RootKeyMaterial) -> Result<DevicePublicKeys, KeyMaterialError> {
    let identity = crypto_sign::KeyPair::from_seed(material.identity_seed())
        .map_err(|_| KeyMaterialError::CorruptState)?;
    let agreement = crypto_box::SecretKey::from_bytes(material.agreement_secret())
        .map_err(|_| KeyMaterialError::CorruptState)?;
    let agreement_public =
        libsodium_rs::crypto_scalarmult::curve25519::scalarmult_base(agreement.as_bytes())
            .map_err(|_| KeyMaterialError::CorruptState)?;

    Ok(DevicePublicKeys {
        identity: *identity.public_key.as_bytes(),
        key_agreement: agreement_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryStore {
        available: bool,
        state: ProtectedKeyState,
        material: Option<Zeroizing<[u8; ROOT_KEY_MATERIAL_BYTES]>>,
        corrupt_load: bool,
        fail_store: bool,
    }

    impl MemoryStore {
        fn empty() -> Self {
            Self {
                available: true,
                state: ProtectedKeyState::Absent,
                material: None,
                corrupt_load: false,
                fail_store: false,
            }
        }
    }

    impl ProtectedKeyStore for MemoryStore {
        fn protected_data_available(&self) -> Result<bool, KeyMaterialError> {
            Ok(self.available)
        }

        fn state(&self) -> Result<ProtectedKeyState, KeyMaterialError> {
            Ok(self.state)
        }

        fn store_new(&mut self, material: &RootKeyMaterial) -> Result<(), KeyMaterialError> {
            if self.fail_store {
                return Err(KeyMaterialError::Storage);
            }
            if self.state != ProtectedKeyState::Absent {
                return Err(KeyMaterialError::Conflict);
            }
            let mut stored = Zeroizing::new([0; ROOT_KEY_MATERIAL_BYTES]);
            stored.copy_from_slice(material.expose_for_protected_storage());
            self.material = Some(stored);
            self.state = ProtectedKeyState::Present;
            Ok(())
        }

        fn load(&self) -> Result<RootKeyMaterial, KeyMaterialError> {
            let mut material = RootKeyMaterial::zeroed();
            material.0.copy_from_slice(
                self.material
                    .as_ref()
                    .ok_or(KeyMaterialError::Unavailable)?
                    .as_ref(),
            );
            if self.corrupt_load {
                material.0[0] ^= 1;
            }
            Ok(material)
        }
    }

    const EMPTY_COMPANIONS: CompanionState = CompanionState {
        installation_marker_exists: false,
        database_exists: false,
    };

    const READY_COMPANIONS: CompanionState = CompanionState {
        installation_marker_exists: true,
        database_exists: true,
    };

    #[test]
    fn classifies_only_complete_installation_states() {
        assert_eq!(
            classify_initialization(ProtectedKeyState::Absent, EMPTY_COMPANIONS),
            InitializationState::Empty
        );
        assert_eq!(
            classify_initialization(ProtectedKeyState::Present, READY_COMPANIONS),
            InitializationState::Ready
        );
        assert_eq!(
            classify_initialization(ProtectedKeyState::Partial, READY_COMPANIONS),
            InitializationState::Unavailable
        );
        assert_eq!(
            classify_initialization(ProtectedKeyState::Present, EMPTY_COMPANIONS),
            InitializationState::Unavailable
        );
    }

    #[test]
    fn generates_distinct_root_material_and_public_keys() -> Result<(), KeyMaterialError> {
        let mut first = MemoryStore::empty();
        let mut second = MemoryStore::empty();

        let first_public = initialize(&mut first, EMPTY_COMPANIONS)?;
        let second_public = initialize(&mut second, EMPTY_COMPANIONS)?;
        let first_material = first.material.as_ref().ok_or(KeyMaterialError::Storage)?;
        let second_material = second.material.as_ref().ok_or(KeyMaterialError::Storage)?;

        assert_ne!(first_public, second_public);
        assert!(!utils::memcmp(&first_material[..], &second_material[..]));
        Ok(())
    }

    #[test]
    fn ready_initialization_is_idempotent() -> Result<(), KeyMaterialError> {
        let mut store = MemoryStore::empty();
        let created = initialize(&mut store, EMPTY_COMPANIONS)?;
        let loaded = initialize(&mut store, READY_COMPANIONS)?;

        assert_eq!(created, loaded);
        Ok(())
    }

    #[test]
    fn rejects_partial_state_without_replacement() {
        let mut store = MemoryStore::empty();
        store.state = ProtectedKeyState::Partial;

        assert_eq!(
            initialize(&mut store, EMPTY_COMPANIONS),
            Err(KeyMaterialError::CorruptState)
        );
        assert!(store.material.is_none());
    }

    #[test]
    fn rejects_unavailable_protected_data_before_creation() {
        let mut store = MemoryStore::empty();
        store.available = false;

        assert_eq!(
            initialize(&mut store, EMPTY_COMPANIONS),
            Err(KeyMaterialError::Unavailable)
        );
        assert!(store.material.is_none());
    }

    #[test]
    fn rejects_corrupt_round_trip() {
        let mut store = MemoryStore::empty();
        store.corrupt_load = true;

        assert_eq!(
            initialize(&mut store, EMPTY_COMPANIONS),
            Err(KeyMaterialError::CorruptState)
        );
    }

    #[test]
    fn maps_storage_failure_without_revealing_material() {
        let mut store = MemoryStore::empty();
        store.fail_store = true;

        assert_eq!(
            initialize(&mut store, EMPTY_COMPANIONS),
            Err(KeyMaterialError::Storage)
        );
        assert!(store.material.is_none());
    }
}
