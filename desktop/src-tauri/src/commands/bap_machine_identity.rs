//! BAP machine identity: a second, machine-scoped Schnorr keypair distinct
//! from the human identity. The secret lives only in the OS keyring blob
//! (same [`crate::secret_store::SecretStore`] as the human nsec) and never
//! crosses the IPC boundary — commands return the x-only pubkey hex only.

use nostr::{Keys, ToBech32};

/// Keyring key name for the machine identity nsec.
pub(crate) const MACHINE_IDENTITY_KEY_NAME: &str = "bap-machine-identity";

/// The two keyring operations the machine identity needs. Abstracted so the
/// create/get logic is unit-testable against an in-memory fake.
pub(crate) trait MachineKeyStore {
    fn load(&self, name: &str) -> Result<Option<String>, String>;
    fn store(&self, name: &str, value: &str) -> Result<(), String>;
}

impl MachineKeyStore for crate::secret_store::SecretStore {
    fn load(&self, name: &str) -> Result<Option<String>, String> {
        crate::secret_store::SecretStore::load(self, name)
    }
    fn store(&self, name: &str, value: &str) -> Result<(), String> {
        crate::secret_store::SecretStore::store(self, name, value)
    }
}

/// Pubkey hex of the stored machine identity, or `None` when none exists.
pub(crate) fn machine_identity_pubkey(
    store: &impl MachineKeyStore,
) -> Result<Option<String>, String> {
    match store.load(MACHINE_IDENTITY_KEY_NAME)? {
        Some(nsec) => {
            let keys = Keys::parse(nsec.trim())
                .map_err(|error| format!("stored machine identity is invalid: {error}"))?;
            Ok(Some(keys.public_key().to_hex()))
        }
        None => Ok(None),
    }
}

/// Return the existing machine identity pubkey, generating and storing a new
/// keypair when none exists. Idempotent: a second call never rotates the key.
pub(crate) fn machine_identity_create(store: &impl MachineKeyStore) -> Result<String, String> {
    if let Some(existing) = machine_identity_pubkey(store)? {
        return Ok(existing);
    }
    let keys = Keys::generate();
    let nsec = keys
        .secret_key()
        .to_bech32()
        .map_err(|error| format!("encode machine identity: {error}"))?;
    store.store(MACHINE_IDENTITY_KEY_NAME, &nsec)?;
    Ok(keys.public_key().to_hex())
}

fn shared_store() -> &'static crate::secret_store::SecretStore {
    crate::secret_store::SecretStore::shared(crate::app_state::keyring_service())
}

/// Pubkey hex of this machine's BAP identity, or `null` when not yet created.
#[tauri::command]
pub fn bap_machine_identity_get() -> Result<Option<String>, String> {
    // ponytail: keyring only, no 0o600 file fallback — the human identity's
    // file fallback (`app_state::load_file_or_generate`) can be reused if a
    // keyring-less build ever needs a machine identity.
    machine_identity_pubkey(shared_store())
}

/// Create (or return the existing) machine identity; the secret stays in Rust.
#[tauri::command]
pub fn bap_machine_identity_create() -> Result<String, String> {
    machine_identity_create(shared_store())
}

#[cfg(test)]
#[path = "bap_machine_identity_tests.rs"]
mod bap_machine_identity_tests;
