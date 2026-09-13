//! Native DBAP authenticator (macOS): a P-256 key in the Secure Enclave gated
//! by Touch ID (device password as fallback), used by the app itself as the
//! WebAuthn-shaped authenticator the BAP relying party verifies.
//!
//! The RP (bap-core `dbap.ts` / `webauthn-register.ts`) accepts attestation
//! format `none` and ES256 assertions, so the app produces exactly what a
//! platform passkey would: rpIdHash = sha256(rp_id), flags UP|UV(|AT),
//! signCount 0 (as Apple's platform authenticator reports), zero AAGUID,
//! COSE EC2 P-256 key, clientDataJSON `{type, challenge, origin, crossOrigin}`
//! and an ES256 DER signature over authenticatorData || sha256(clientDataJSON).
//!
//! Everything above the Secure Enclave call is pure and unit-tested here; the
//! interop vector those tests can emit is checked against bap-core's own
//! verifiers in `src/features/bap/lib/nativeAuthenticator.test.mjs`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct DbapAuthenticatorStatus {
    pub available: bool,
    pub enrolled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What `POST /register` on the RP expects (plus the id/key for the caller).
#[derive(Debug, Clone, Serialize)]
pub struct DbapRegistration {
    pub attestation_object: String,
    pub client_data_json: String,
    pub credential_id: String,
    pub cose_key: String,
}

/// The `proof.webauthn` block of a DBAP proof, minus `rp_id` (the caller has it).
#[derive(Debug, Clone, Serialize)]
pub struct DbapAssertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// CBOR head for `major` with argument `n` (RFC 8949, shortest form).
fn cbor_head(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => vec![m | 25, (n >> 8) as u8, n as u8],
        _ => vec![
            m | 26,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ],
    }
}

fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, b.len());
    out.extend_from_slice(b);
    out
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut out = cbor_head(3, s.len());
    out.extend_from_slice(s.as_bytes());
    out
}

/// COSE_Key EC2 P-256 ES256 for an uncompressed SEC1 point; byte-identical to
/// bap-core `pointToCoseP256`: `{1:2, 3:-7, -1:1, -2:x, -3:y}`.
pub(crate) fn cose_p256_key(point: &[u8]) -> Result<Vec<u8>, String> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err("public key must be an uncompressed SEC1 P-256 point".into());
    }
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    out.extend(cbor_bytes(&point[1..33]));
    out.push(0x22);
    out.extend(cbor_bytes(&point[33..65]));
    Ok(out)
}

/// Credential id: sha256 of the public point (32 bytes, within WebAuthn's
/// 16..=64), the same derivation as bap-core's software authenticator, so
/// nothing but the key itself needs persisting.
pub(crate) fn credential_id_for(point: &[u8]) -> [u8; 32] {
    sha256(point)
}

/// `clientDataJSON` as a browser serialises it (field order matters for
/// nothing but fidelity; the RP parses it as JSON).
pub(crate) fn client_data_json(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::json!({
        "type": kind,
        "challenge": b64url(challenge.as_bytes()),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

/// WebAuthn authenticator data: rpIdHash || flags || signCount(0) [|| attested
/// credential data: zero AAGUID || idLen || id || COSE key].
pub(crate) fn authenticator_data(
    rp_id: &str,
    flags: u8,
    attested: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = sha256(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&[0, 0, 0, 0]);
    if let Some((credential_id, cose_key)) = attested {
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    out
}

/// `{fmt: "none", attStmt: {}, authData: <bytes>}` — key order as bap-core encodes it.
pub(crate) fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(5, 3);
    out.extend(cbor_text("fmt"));
    out.extend(cbor_text("none"));
    out.extend(cbor_text("attStmt"));
    out.extend(cbor_head(5, 0));
    out.extend(cbor_text("authData"));
    out.extend(cbor_bytes(auth_data));
    out
}

/// Registration response for `point`, shaped like `navigator.credentials.create()`.
pub(crate) fn build_registration(
    point: &[u8],
    rp_id: &str,
    origin: &str,
    challenge: &str,
) -> Result<DbapRegistration, String> {
    let cose = cose_p256_key(point)?;
    let credential_id = credential_id_for(point);
    let auth_data = authenticator_data(
        rp_id,
        FLAG_UP | FLAG_UV | FLAG_AT,
        Some((&credential_id, &cose)),
    );
    Ok(DbapRegistration {
        attestation_object: b64url(&attestation_object(&auth_data)),
        client_data_json: b64url(&client_data_json("webauthn.create", challenge, origin)),
        credential_id: b64url(&credential_id),
        cose_key: b64url(&cose),
    })
}

/// Assertion over `challenge`; `sign` is ES256 (DER) over the message bytes
/// `authenticatorData || sha256(clientDataJSON)` — hashing is the signer's.
pub(crate) fn build_assertion(
    point: &[u8],
    rp_id: &str,
    origin: &str,
    challenge: &str,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<DbapAssertion, String> {
    let cdj = client_data_json("webauthn.get", challenge, origin);
    let auth_data = authenticator_data(rp_id, FLAG_UP | FLAG_UV, None);
    let mut message = auth_data.clone();
    message.extend_from_slice(&sha256(&cdj));
    let signature = sign(&message)?;
    Ok(DbapAssertion {
        credential_id: b64url(&credential_id_for(point)),
        authenticator_data: b64url(&auth_data),
        client_data_json: b64url(&cdj),
        signature: b64url(&signature),
    })
}

#[cfg(target_os = "macos")]
mod macos {
    //! The Secure Enclave / LocalAuthentication half. `unsafe` is confined to
    //! the objc2 LAContext calls (the crate marks every method unsafe) and one
    //! toll-free bridge of that context into the keychain query, mirroring
    //! `macos_notifications.rs`.
    use core_foundation::base::{CFType, TCFType};
    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{
        ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
    };
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework_sys::access_control::{
        kSecAccessControlBiometryCurrentSet, kSecAccessControlDevicePasscode, kSecAccessControlOr,
        kSecAccessControlPrivateKeyUsage,
    };

    use super::{
        build_assertion, build_registration, credential_id_for, DbapAssertion,
        DbapAuthenticatorStatus, DbapRegistration,
    };

    /// `kSecAttrLabel` of the one DBAP key this app keeps; re-enrolling replaces it.
    const KEY_LABEL: &str = "buzz-desktop.bap.dbap-credential";
    const PROMPT: &str = "Approve BAP request";
    const ERR_SEC_MISSING_ENTITLEMENT: i64 = -34018;
    const ERR_SEC_USER_CANCELED: i64 = -128;

    fn describe(prefix: &str, error: &core_foundation::error::CFError) -> String {
        match error.code() as i64 {
            ERR_SEC_MISSING_ENTITLEMENT => format!(
                "{prefix}: Secure Enclave keys need a code-signed build with the keychain entitlement (dev builds are unsigned)"
            ),
            ERR_SEC_USER_CANCELED => format!("{prefix}: cancelled"),
            code => format!("{prefix}: {} ({code})", error.description()),
        }
    }

    fn biometry_check() -> Result<(), String> {
        // SAFETY: LAContext is a plain Foundation object; `new` and
        // `canEvaluatePolicy_error` take no raw pointers and are documented
        // as callable from any thread.
        unsafe {
            LAContext::new()
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .map_err(|error| error.localizedDescription().to_string())
        }
    }

    /// An LAContext carrying the Touch ID prompt text, bridged for
    /// `kSecUseAuthenticationContext`. The `Retained` keeps it alive.
    fn prompt_context() -> (Retained<LAContext>, CFType) {
        // SAFETY: same as `biometry_check`; `setLocalizedReason` copies the
        // string. The bridge is a retain (get rule) of a live NSObject, which
        // `SecItemCopyMatching` accepts under kSecUseAuthenticationContext.
        unsafe {
            let ctx = LAContext::new();
            ctx.setLocalizedReason(&NSString::from_str(PROMPT));
            let cf = CFType::wrap_under_get_rule(Retained::as_ptr(&ctx).cast());
            (ctx, cf)
        }
    }

    fn search(auth: Option<CFType>) -> ItemSearchOptions {
        let mut opts = ItemSearchOptions::new();
        opts.class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(KEY_LABEL)
            .ignore_legacy_keychains()
            .load_refs(true)
            .local_authentication_context(auth);
        opts
    }

    fn find_key(auth: Option<CFType>) -> Result<Option<SecKey>, String> {
        let results = match search(auth).search() {
            Ok(results) => results,
            Err(error) if error.code() == -25300 => return Ok(None), // errSecItemNotFound
            Err(error) => return Err(format!("keychain search: {error}")),
        };
        Ok(results.into_iter().find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        }))
    }

    fn public_point(key: &SecKey) -> Result<Vec<u8>, String> {
        key.public_key()
            .and_then(|public| public.external_representation())
            .map(|data| data.to_vec())
            .ok_or_else(|| "could not export the credential public key".to_string())
    }

    pub fn status() -> DbapAuthenticatorStatus {
        let (available, reason) = match biometry_check() {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(reason)),
        };
        let credential_id = find_key(None)
            .ok()
            .flatten()
            .and_then(|key| public_point(&key).ok())
            .map(|point| super::b64url(&credential_id_for(&point)));
        DbapAuthenticatorStatus {
            available,
            enrolled: credential_id.is_some(),
            credential_id,
            reason,
        }
    }

    pub fn enroll(rp_id: &str, origin: &str, challenge: &str) -> Result<DbapRegistration, String> {
        biometry_check()?;
        if find_key(None)?.is_some() {
            search(None)
                .delete()
                .map_err(|error| format!("could not replace the previous credential: {error}"))?;
        }
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage
                | kSecAccessControlBiometryCurrentSet
                | kSecAccessControlOr
                | kSecAccessControlDevicePasscode,
        )
        .map_err(|error| format!("access control: {error}"))?;
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(KEY_LABEL)
            .set_access_control(access);
        let key = SecKey::new(&opts).map_err(|error| describe("Secure Enclave key", &error))?;
        build_registration(&public_point(&key)?, rp_id, origin, challenge)
    }

    pub fn assert(rp_id: &str, origin: &str, challenge: &str) -> Result<DbapAssertion, String> {
        let (_ctx, auth) = prompt_context();
        let key = find_key(Some(auth))?.ok_or("no Touch ID credential enrolled on this Mac")?;
        let point = public_point(&key)?;
        build_assertion(&point, rp_id, origin, challenge, |message| {
            key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
                .map_err(|error| describe("Touch ID", &error))
        })
    }
}

#[cfg(not(target_os = "macos"))]
mod macos {
    use super::{DbapAssertion, DbapAuthenticatorStatus, DbapRegistration};
    const UNAVAILABLE: &str = "the native DBAP authenticator is macOS-only";

    pub fn status() -> DbapAuthenticatorStatus {
        DbapAuthenticatorStatus {
            available: false,
            enrolled: false,
            credential_id: None,
            reason: Some(UNAVAILABLE.into()),
        }
    }
    pub fn enroll(_: &str, _: &str, _: &str) -> Result<DbapRegistration, String> {
        Err(UNAVAILABLE.into())
    }
    pub fn assert(_: &str, _: &str, _: &str) -> Result<DbapAssertion, String> {
        Err(UNAVAILABLE.into())
    }
}

/// Secure Enclave + biometry availability and whether a credential is enrolled.
#[tauri::command]
pub async fn dbap_authenticator_status() -> Result<DbapAuthenticatorStatus, String> {
    tauri::async_runtime::spawn_blocking(macos::status)
        .await
        .map_err(|error| format!("spawn_blocking failed: {error}"))
}

/// Create (or replace) the Secure Enclave credential and return the
/// registration the RP's `POST /register` expects.
#[tauri::command]
pub async fn dbap_authenticator_enroll(
    rp_id: String,
    origin: String,
    challenge: String,
) -> Result<DbapRegistration, String> {
    tauri::async_runtime::spawn_blocking(move || macos::enroll(&rp_id, &origin, &challenge))
        .await
        .map_err(|error| format!("spawn_blocking failed: {error}"))?
}

/// The RP endpoints the desktop may call; anything else is refused so this
/// command cannot be used as a general proxy.
const RP_PATHS: [&str; 4] = ["/register/challenge", "/register", "/challenge", "/verify"];

/// Validate `<rp_base><path>`: https, or http only to loopback (dev RP).
pub(crate) fn rp_endpoint(rp_base: &str, path: &str) -> Result<url::Url, String> {
    if !RP_PATHS.contains(&path) {
        return Err(format!("{path} is not a BAP relying-party endpoint"));
    }
    let url = url::Url::parse(&format!("{}{path}", rp_base.trim_end_matches('/')))
        .map_err(|error| format!("relying party URL: {error}"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        scheme => Err(format!("relying party must be https (got {scheme}://)")),
    }
}

/// `POST <rp_base><path>` with a JSON body, from Rust because the RP only
/// answers CORS for its own origin (the hosted wallet page). Returns the
/// JSON body for any status — the RP reports refusals as `{error}` / `{ok:false}`.
#[tauri::command]
pub async fn dbap_rp_post(
    rp_base: String,
    path: String,
    body: serde_json::Value,
    state: tauri::State<'_, crate::app_state::AppState>,
) -> Result<serde_json::Value, String> {
    let url = rp_endpoint(&rp_base, &path)?;
    let response = state
        .http_client
        .post(url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| format!("relying party unreachable: {error}"))?;
    let status = response.status();
    response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| format!("relying party returned {status} without JSON: {error}"))
}

/// Touch ID prompt, then an ES256 assertion over `challenge` for `rp_id`.
#[tauri::command]
pub async fn dbap_authenticator_assert(
    rp_id: String,
    origin: String,
    challenge: String,
) -> Result<DbapAssertion, String> {
    tauri::async_runtime::spawn_blocking(move || macos::assert(&rp_id, &origin, &challenge))
        .await
        .map_err(|error| format!("spawn_blocking failed: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING,
    };

    const RP: &str = "approve.localhost";
    const ORIGIN: &str = "https://approve.localhost";

    fn unb64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    #[test]
    fn cbor_heads_use_the_shortest_form() {
        assert_eq!(cbor_head(2, 5), vec![0x45]);
        assert_eq!(cbor_head(2, 32), vec![0x58, 32]);
        assert_eq!(cbor_head(2, 300), vec![0x59, 1, 44]);
        assert_eq!(cbor_head(5, 0), vec![0xa0]);
    }

    #[test]
    fn cose_key_matches_bap_core_layout() {
        let mut point = vec![0x04];
        point.extend([0xaa; 32]);
        point.extend([0xbb; 32]);
        let cose = cose_p256_key(&point).unwrap();
        assert_eq!(cose.len(), 77);
        assert_eq!(
            &cose[..8],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]
        );
        assert_eq!(&cose[8..10], &[0x58, 0x20]);
        assert_eq!(&cose[10..42], &[0xaa; 32]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..], &[0xbb; 32]);
        assert!(cose_p256_key(&point[1..]).is_err());
    }

    #[test]
    fn registration_carries_attested_credential_data_with_uv_and_at() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let reg = build_registration(point, RP, ORIGIN, "dbap:enroll:abc").unwrap();
        let ao = unb64(&reg.attestation_object);
        // a3 63 "fmt" 64 "none" 67 "attStmt" a0 68 "authData" 58/59 …
        assert_eq!(&ao[..2], &[0xa3, 0x63]);
        assert_eq!(&ao[2..5], b"fmt");
        assert_eq!(&ao[6..10], b"none");
        let auth_start = 1 + 4 + 5 + 8 + 1 + 9;
        // 37 + 16 + 2 + 32 + 77 = 164 bytes: a one-byte CBOR length.
        assert_eq!(&ao[auth_start..auth_start + 2], &[0x58, 164]);
        let len = 164;
        let auth_data = &ao[auth_start + 2..];
        assert_eq!(auth_data.len(), len, "no trailing bytes after authData");
        assert_eq!(&auth_data[..32], &sha256(RP.as_bytes()));
        assert_eq!(auth_data[32], FLAG_UP | FLAG_UV | FLAG_AT);
        assert_eq!(&auth_data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth_data[37..53], &[0u8; 16], "zero AAGUID");
        assert_eq!(&auth_data[53..55], &[0, 32]);
        assert_eq!(&auth_data[55..87], &unb64(&reg.credential_id)[..]);
        assert_eq!(&auth_data[87..], &unb64(&reg.cose_key)[..]);
        let cdj: serde_json::Value = serde_json::from_slice(&unb64(&reg.client_data_json)).unwrap();
        assert_eq!(cdj["type"], "webauthn.create");
        assert_eq!(cdj["origin"], ORIGIN);
        assert_eq!(cdj["crossOrigin"], false);
        assert_eq!(
            unb64(cdj["challenge"].as_str().unwrap()),
            b"dbap:enroll:abc"
        );
    }

    #[test]
    fn assertion_signs_auth_data_and_client_data_hash_as_es256_der() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let rng = SystemRandom::new();
        let assertion = build_assertion(&point, RP, ORIGIN, "dbap:v1:xyz", |message| {
            Ok(pair.sign(&rng, message).unwrap().as_ref().to_vec())
        })
        .unwrap();
        let auth_data = unb64(&assertion.authenticator_data);
        assert_eq!(auth_data.len(), 37);
        assert_eq!(auth_data[32], FLAG_UP | FLAG_UV);
        let cdj = unb64(&assertion.client_data_json);
        let mut message = auth_data.clone();
        message.extend_from_slice(&sha256(&cdj));
        // The RP verifies ES256 over exactly this message (dbap.ts verifyAssertion).
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(&message, &unb64(&assertion.signature))
            .expect("signature verifies over authData || sha256(clientDataJSON)");
        assert_eq!(assertion.credential_id, b64url(&credential_id_for(&point)));
        let cdj: serde_json::Value = serde_json::from_slice(&cdj).unwrap();
        assert_eq!(cdj["type"], "webauthn.get");
    }

    /// Emits a registration + assertion for bap-core's verifiers when
    /// `BAP_DBAP_VECTOR_OUT` names a file; the committed copy lives at
    /// `src/features/bap/lib/nativeAuthenticator.vector.json` and is checked
    /// by `nativeAuthenticator.test.mjs` with `verifyRegistration`/`verifyProof`.
    #[test]
    fn interop_vector_for_bap_core() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let rng = SystemRandom::new();
        let enroll_challenge = "dbap:enroll:Zm9vYmFyYmF6cXV4MTIzNA";
        // `challengeFor(commitment)` = "dbap:v1:" + b64url(sha256(JCS(commitment)));
        // the JCS form is a literal so the node side can `JSON.parse` it back
        // into the commitment and run bap-core's `verifyProof` end to end.
        let commitment_jcs = concat!(
            r#"{"audience_did":"did:key:zQ3shS9i8ufXsDMmNUWAzJDryVeJeQjh2cQNVA6Sc3r9W8wnv","#,
            r#""command":"/git/merge","dbap_version":"1.0","expires":1900,"grant_type":"ucan-delegation","#,
            r#""issuer_did":"did:key:zQ3shSjz9ynfhPyXRUxz6uQDZHUzwPK5V3UTc5gvJc4xZ2cE5","#,
            r#""nonce":"AAAAAAAAAAAAAAAAAAAAAA","not_before":1000,"#,
            r#""policy":[["==",".action_digest","sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"]],"#,
            r#""request_ref":"req-1","resource":"nostr:git/naddr1/refs/heads/main"}"#
        );
        let assert_challenge = format!("dbap:v1:{}", b64url(&sha256(commitment_jcs.as_bytes())));
        let registration = build_registration(&point, RP, ORIGIN, enroll_challenge).unwrap();
        let assertion = build_assertion(&point, RP, ORIGIN, &assert_challenge, |message| {
            Ok(pair.sign(&rng, message).unwrap().as_ref().to_vec())
        })
        .unwrap();
        let vector = serde_json::json!({
            "rp_id": RP,
            "origin": ORIGIN,
            "enroll_challenge": enroll_challenge,
            "commitment_jcs": commitment_jcs,
            "assert_challenge": assert_challenge,
            "registration": registration,
            "assertion": assertion,
        });
        if let Ok(path) = std::env::var("BAP_DBAP_VECTOR_OUT") {
            std::fs::write(path, serde_json::to_string_pretty(&vector).unwrap()).unwrap();
        }
        assert_eq!(
            vector["registration"]["credential_id"],
            vector["assertion"]["credential_id"]
        );
    }

    #[test]
    fn rp_endpoint_allows_only_rp_paths_over_https_or_loopback_http() {
        assert_eq!(
            rp_endpoint("https://approve.example/", "/verify")
                .unwrap()
                .as_str(),
            "https://approve.example/verify"
        );
        assert!(rp_endpoint("http://127.0.0.1:8790", "/challenge").is_ok());
        assert!(rp_endpoint("http://approve.example", "/challenge").is_err());
        assert!(rp_endpoint("https://approve.example", "/admin").is_err());
        assert!(rp_endpoint("not a url", "/verify").is_err());
    }
}
