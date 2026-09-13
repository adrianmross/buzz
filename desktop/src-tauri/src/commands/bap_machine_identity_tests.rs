use std::cell::RefCell;
use std::collections::HashMap;

use nostr::{Keys, ToBech32};

use super::{
    machine_identity_create, machine_identity_pubkey, MachineKeyStore, MACHINE_IDENTITY_KEY_NAME,
};

/// In-memory [`MachineKeyStore`]; `fail_store` drives the keyring-write
/// failure arm.
struct FakeStore {
    slot: RefCell<HashMap<String, String>>,
    fail_store: bool,
}

impl FakeStore {
    fn empty() -> Self {
        Self {
            slot: RefCell::new(HashMap::new()),
            fail_store: false,
        }
    }
}

impl MachineKeyStore for FakeStore {
    fn load(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self.slot.borrow().get(name).cloned())
    }
    fn store(&self, name: &str, value: &str) -> Result<(), String> {
        if self.fail_store {
            return Err("keyring unavailable".to_string());
        }
        self.slot
            .borrow_mut()
            .insert(name.to_string(), value.to_string());
        Ok(())
    }
}

#[test]
fn get_is_none_before_create() {
    let store = FakeStore::empty();
    assert_eq!(machine_identity_pubkey(&store).unwrap(), None);
}

#[test]
fn create_then_get_round_trips_and_only_the_secret_is_stored() {
    let store = FakeStore::empty();
    let pubkey = machine_identity_create(&store).unwrap();
    assert_eq!(pubkey.len(), 64);
    assert_eq!(
        machine_identity_pubkey(&store).unwrap(),
        Some(pubkey.clone())
    );

    // The keyring holds an nsec whose pubkey is what the command returned —
    // and the command output never carries the secret.
    let stored = store.load(MACHINE_IDENTITY_KEY_NAME).unwrap().unwrap();
    assert!(stored.starts_with("nsec1"));
    assert_eq!(Keys::parse(&stored).unwrap().public_key().to_hex(), pubkey);
    assert_ne!(stored, pubkey);
}

#[test]
fn create_is_idempotent() {
    let store = FakeStore::empty();
    let first = machine_identity_create(&store).unwrap();
    let second = machine_identity_create(&store).unwrap();
    assert_eq!(first, second);
}

#[test]
fn create_propagates_keyring_write_failure() {
    let store = FakeStore {
        slot: RefCell::new(HashMap::new()),
        fail_store: true,
    };
    assert!(machine_identity_create(&store).is_err());
    assert_eq!(machine_identity_pubkey(&store).unwrap(), None);
}

#[test]
fn get_rejects_a_corrupt_stored_secret() {
    let store = FakeStore::empty();
    store
        .store(MACHINE_IDENTITY_KEY_NAME, "not-an-nsec")
        .unwrap();
    assert!(machine_identity_pubkey(&store).is_err());
}

#[test]
fn get_reads_an_externally_seeded_key() {
    let keys = Keys::generate();
    let store = FakeStore::empty();
    store
        .store(
            MACHINE_IDENTITY_KEY_NAME,
            &keys.secret_key().to_bech32().unwrap(),
        )
        .unwrap();
    assert_eq!(
        machine_identity_pubkey(&store).unwrap(),
        Some(keys.public_key().to_hex())
    );
}
