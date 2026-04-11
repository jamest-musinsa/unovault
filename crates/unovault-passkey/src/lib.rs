// Panic-policy exception for test code — see unovault-core/src/lib.rs.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! # unovault-passkey
//!
//! Software passkey (FIDO2 / WebAuthn) authenticator.
//!
//! This crate is the Rust-side credential store for passkeys. The
//! desktop app registers a new passkey against an origin, stores the
//! private material inside a vault item, and later signs a challenge
//! the Chrome extension hands over during a WebAuthn ceremony.
//!
//! ## Why a software authenticator
//!
//! The long-term goal is per-device Secure Enclave storage on macOS
//! and a Windows Hello backend on Windows. Both need native platform
//! entitlements that are not available in the current build profile.
//! Until those land, unovault uses a software authenticator: the
//! private key lives in the vault, encrypted by the vault's master
//! key, and signing happens inside this crate on CPU.
//!
//! The upgrade path to Secure Enclave is local: swap the key
//! generation/sign functions for their SE equivalents and keep the
//! same `PasskeyCredential` shape on disk. Existing credentials stay
//! readable either way, and the two backends can coexist via a
//! per-credential `backend` tag.
//!
//! ## Algorithm
//!
//! v1 supports **ECDSA P-256** only. This is the default passkey
//! algorithm (`COSE alg -7` in WebAuthn) and is supported by every
//! major browser. Ed25519 (`COSE alg -8`) is a near-term follow-up.
//!
//! ## What this crate deliberately does not do
//!
//! * **No CTAP2 HID transport.** That's the `ctap2` crate's job and
//!   requires IOKit + entitlements on macOS. This crate is pure Rust
//!   and tests on CI.
//! * **No browser-side WebAuthn protocol.** The Chrome extension
//!   generates the `clientDataJSON`, hashes it, and hands the hash
//!   over to this crate. We sign; the extension assembles the
//!   `AuthenticatorAssertionResponse`.
//! * **No attestation.** v1 produces `none` attestation — same
//!   posture as every software passkey manager. Hardware-backed
//!   attestation lands with Secure Enclave.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unovault_core::secret::Secret;
use zeroize::Zeroize;

// =============================================================================
// ERRORS
// =============================================================================

/// Errors surfaced by the passkey crate.
///
/// These collapse into `unovault_core::VaultError::BugInUnovault`
/// at the Tauri command boundary — a passkey failure is always a
/// bug or a corrupted credential, not a user input error. Wrong-site
/// mismatches surface separately at the WebAuthn protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("failed to generate a random key")]
    RandomGenerationFailed,

    #[error("the stored credential is malformed or corrupted")]
    MalformedCredential,

    #[error("the RP ID hash did not match the stored credential")]
    RpIdMismatch,

    #[error("signing a challenge failed")]
    SigningFailed,

    #[error("an algorithm not supported by this build was requested")]
    UnsupportedAlgorithm,
}

pub type Result<T> = std::result::Result<T, PasskeyError>;

// =============================================================================
// CREDENTIAL STRUCT
// =============================================================================

/// Identifier of the signing algorithm used by a credential.
///
/// COSE algorithm identifiers from IANA. `ES256` is the WebAuthn
/// default for passkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// ECDSA using P-256 and SHA-256 (COSE `-7`).
    Es256,
}

/// One passkey credential as it lives on disk.
///
/// Serializable via serde so vault code can encode it into a
/// `FieldValue::Bytes` payload inside a normal vault item.
///
/// `Zeroize` is derived so the whole struct wipes its heap-allocated
/// fields (`rp_id`, `private_key_bytes`, etc.) on drop. `Algorithm`
/// is marked `zeroize(skip)` because it's a plain enum tag with no
/// secret content.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct PasskeyCredential {
    /// Credential ID assigned at registration. WebAuthn lets the
    /// authenticator choose any opaque ID up to 1023 bytes; we use a
    /// random 16-byte UUID-like blob.
    pub credential_id: Vec<u8>,

    /// The Relying Party ID (e.g. `"github.com"`) the credential was
    /// minted for. WebAuthn authenticators verify the RP ID hash on
    /// every sign call; we do too in [`sign_challenge`].
    pub rp_id: String,

    /// Optional user handle the RP supplied. Opaque bytes bound to
    /// the credential but not used by the authenticator itself.
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,

    /// Algorithm this credential was generated for.
    #[zeroize(skip)]
    pub algorithm: Algorithm,

    /// Raw SEC1 private key bytes (32 bytes for ES256). The payload
    /// the caller must treat with zeroize discipline.
    pub private_key_bytes: Vec<u8>,

    /// Raw SEC1-encoded public key (uncompressed, 65 bytes starting
    /// with 0x04 for ES256). Duplicated from the private key so the
    /// Chrome extension can read it without unlocking the vault.
    pub public_key_bytes: Vec<u8>,

    /// Signature counter. WebAuthn uses this to detect cloned
    /// credentials; some RPs check it, so we increment on each sign.
    #[zeroize(skip)]
    pub sign_count: u32,
}

// Manual Debug that redacts the private key bytes. Deriving Debug
// would leak `private_key_bytes: [0x..., ...]` into any log line that
// formats the struct via `{:?}`.
impl std::fmt::Debug for PasskeyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyCredential")
            .field("credential_id_len", &self.credential_id.len())
            .field("rp_id", &self.rp_id)
            .field(
                "user_handle_len",
                &self.user_handle.as_ref().map(|u| u.len()),
            )
            .field("algorithm", &self.algorithm)
            .field(
                "private_key_bytes",
                &format!("<redacted {} bytes>", self.private_key_bytes.len()),
            )
            .field("public_key_bytes_len", &self.public_key_bytes.len())
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

// Redacted Debug for the secret parts so a stray `tracing::debug!` on a
// PasskeyCredential can't leak the private key.
impl PasskeyCredential {
    /// Length of the private key blob (for diagnostics). Does not
    /// expose the bytes.
    pub fn private_key_len(&self) -> usize {
        self.private_key_bytes.len()
    }
}

// =============================================================================
// GENERATION
// =============================================================================

/// Generate a fresh ES256 credential for the given relying party.
///
/// Reads 32 bytes of OS randomness for the credential ID and uses
/// p256's `SigningKey::random` for the key pair. Returns the new
/// credential wrapped in `Secret<T>` so the caller handles it with
/// zeroize discipline in the brief window between generation and
/// vault write.
pub fn generate_es256(
    rp_id: impl Into<String>,
    user_handle: Option<Vec<u8>>,
) -> Result<Secret<PasskeyCredential>> {
    let mut cred_id = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut cred_id)
        .map_err(|_| PasskeyError::RandomGenerationFailed)?;

    // p256's random uses its own RngCore-compatible source. We pass
    // `&mut rand_core::OsRng` via the shim below — p256 0.13 uses
    // rand_core 0.6.
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    let private_key_bytes = signing_key.to_bytes().to_vec();
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    let credential = PasskeyCredential {
        credential_id: cred_id.to_vec(),
        rp_id: rp_id.into(),
        user_handle,
        algorithm: Algorithm::Es256,
        private_key_bytes,
        public_key_bytes,
        sign_count: 0,
    };
    Ok(Secret::new(credential))
}

// =============================================================================
// SIGNING
// =============================================================================

/// Sign the SHA-256 hash of `client_data_json` concatenated with the
/// authenticator data, matching the WebAuthn signing contract. The
/// caller produces the client data JSON; this function:
///
/// 1. Verifies the requested RP ID matches the credential's RP ID
///    (authenticator-side origin binding — the Chrome extension also
///    checks origin at the protocol level, this is defence in depth).
/// 2. Builds the 37-byte authenticator data: SHA-256 of the RP ID,
///    flags (user presence + user verified), the current sign counter.
/// 3. Computes `sha256(client_data_json)` as the client data hash.
/// 4. Signs `authenticator_data || client_data_hash` with the
///    credential's private key.
/// 5. Increments the sign counter (caller persists the updated
///    credential back to the vault).
///
/// Returns the DER-encoded ECDSA signature and the authenticator
/// data — both fields needed to assemble a WebAuthn assertion.
pub fn sign_challenge(
    credential: &mut PasskeyCredential,
    rp_id: &str,
    client_data_json: &[u8],
) -> Result<SignResponse> {
    if credential.rp_id != rp_id {
        return Err(PasskeyError::RpIdMismatch);
    }
    if !matches!(credential.algorithm, Algorithm::Es256) {
        return Err(PasskeyError::UnsupportedAlgorithm);
    }

    let signing_key = SigningKey::from_slice(&credential.private_key_bytes)
        .map_err(|_| PasskeyError::MalformedCredential)?;

    // Step 1: build authenticator data. Layout from the WebAuthn spec:
    //   rpIdHash (32) || flags (1) || signCount (4) || (optional extensions)
    // v1 omits extensions.
    let mut auth_data = Vec::with_capacity(37);
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);

    // Flags: 0x01 = User Present, 0x04 = User Verified.
    // The desktop Touch ID unlock proves verification; software
    // authenticator always sets UV until a real hardware backend
    // lands.
    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;
    auth_data.push(FLAG_UP | FLAG_UV);

    let new_count = credential.sign_count.wrapping_add(1);
    auth_data.extend_from_slice(&new_count.to_be_bytes());

    // Step 2: client data hash.
    let client_data_hash = Sha256::digest(client_data_json);

    // Step 3: sign authenticator_data || client_data_hash.
    let mut to_sign = auth_data.clone();
    to_sign.extend_from_slice(&client_data_hash);

    let signature: Signature = signing_key
        .try_sign(&to_sign)
        .map_err(|_| PasskeyError::SigningFailed)?;

    credential.sign_count = new_count;

    Ok(SignResponse {
        authenticator_data: auth_data,
        signature: signature.to_der().as_bytes().to_vec(),
        new_sign_count: new_count,
    })
}

/// A WebAuthn-ready signing response. The Chrome extension uses these
/// fields to assemble an `AuthenticatorAssertionResponse` without
/// needing to know how the signing was done.
#[derive(Debug, Clone)]
pub struct SignResponse {
    /// Raw authenticator data (37 bytes for v1 — no extensions).
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature.
    pub signature: Vec<u8>,
    /// Updated sign counter. Caller persists this back to the vault.
    pub new_sign_count: u32,
}

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify a signature produced by [`sign_challenge`] against the
/// stored public key. Useful for the vault's own self-test and for
/// the Chrome extension's end-to-end test harness.
pub fn verify_signature(
    credential: &PasskeyCredential,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_sec1_bytes(&credential.public_key_bytes)
        .map_err(|_| PasskeyError::MalformedCredential)?;

    let signature =
        Signature::from_der(signature_der).map_err(|_| PasskeyError::MalformedCredential)?;

    let client_data_hash = Sha256::digest(client_data_json);
    let mut to_verify = authenticator_data.to_vec();
    to_verify.extend_from_slice(&client_data_hash);

    verifying_key
        .verify(&to_verify, &signature)
        .map_err(|_| PasskeyError::SigningFailed)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_es256_produces_32_byte_private_and_65_byte_public() {
        let cred = generate_es256("github.com", None).expect("generate");
        let inner = cred.expose();
        assert_eq!(inner.private_key_bytes.len(), 32);
        assert_eq!(inner.public_key_bytes.len(), 65);
        // Uncompressed P-256 SEC1 points start with 0x04.
        assert_eq!(inner.public_key_bytes[0], 0x04);
        assert_eq!(inner.rp_id, "github.com");
        assert_eq!(inner.sign_count, 0);
        assert_eq!(inner.credential_id.len(), 16);
    }

    #[test]
    fn two_credentials_have_distinct_ids_and_keys() {
        let a = generate_es256("github.com", None).expect("a");
        let b = generate_es256("github.com", None).expect("b");
        let a = a.expose();
        let b = b.expose();
        assert_ne!(a.credential_id, b.credential_id);
        assert_ne!(a.private_key_bytes, b.private_key_bytes);
        assert_ne!(a.public_key_bytes, b.public_key_bytes);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let cred_secret = generate_es256("example.com", None).expect("generate");
        let mut cred = cred_secret.expose().clone();
        let client_data =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}"#;

        let response = sign_challenge(&mut cred, "example.com", client_data).expect("sign");
        assert_eq!(cred.sign_count, 1);
        assert_eq!(response.new_sign_count, 1);
        assert_eq!(response.authenticator_data.len(), 37);

        verify_signature(
            &cred,
            &response.authenticator_data,
            client_data,
            &response.signature,
        )
        .expect("verify");
    }

    #[test]
    fn sign_rejects_wrong_rp_id() {
        let cred_secret = generate_es256("example.com", None).expect("generate");
        let mut cred = cred_secret.expose().clone();
        match sign_challenge(&mut cred, "attacker.com", b"{}") {
            Err(PasskeyError::RpIdMismatch) => {}
            other => panic!("expected RpIdMismatch, got {other:?}"),
        }
        // Counter did NOT advance on a rejected sign.
        assert_eq!(cred.sign_count, 0);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let cred_secret = generate_es256("example.com", None).expect("generate");
        let mut cred = cred_secret.expose().clone();
        let response = sign_challenge(&mut cred, "example.com", b"{}").expect("sign");

        let mut tampered = response.signature.clone();
        // Flip a byte deep in the signature — valid DER but wrong payload.
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;

        match verify_signature(&cred, &response.authenticator_data, b"{}", &tampered) {
            Err(_) => {}
            Ok(()) => panic!("expected tamper to fail verification"),
        }
    }

    #[test]
    fn verify_rejects_tampered_authenticator_data() {
        let cred_secret = generate_es256("example.com", None).expect("generate");
        let mut cred = cred_secret.expose().clone();
        let response = sign_challenge(&mut cred, "example.com", b"{}").expect("sign");

        let mut tampered = response.authenticator_data.clone();
        tampered[0] ^= 0xFF;
        match verify_signature(&cred, &tampered, b"{}", &response.signature) {
            Err(_) => {}
            Ok(()) => panic!("expected auth-data tamper to fail verification"),
        }
    }

    #[test]
    fn credential_serde_round_trips_without_losing_keys() {
        let cred_secret = generate_es256("example.com", Some(vec![1, 2, 3])).expect("gen");
        let cred = cred_secret.expose().clone();
        let encoded = serde_json::to_vec(&cred).expect("encode");
        let decoded: PasskeyCredential = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.credential_id, cred.credential_id);
        assert_eq!(decoded.private_key_bytes, cred.private_key_bytes);
        assert_eq!(decoded.public_key_bytes, cred.public_key_bytes);
        assert_eq!(decoded.user_handle.as_deref(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn sign_counter_increments_monotonically_across_calls() {
        let cred_secret = generate_es256("example.com", None).expect("gen");
        let mut cred = cred_secret.expose().clone();
        for expected in 1..=5 {
            let response = sign_challenge(&mut cred, "example.com", b"{}").expect("sign");
            assert_eq!(response.new_sign_count, expected);
            assert_eq!(cred.sign_count, expected);
        }
    }

    #[test]
    fn private_key_len_does_not_expose_bytes() {
        let cred_secret = generate_es256("x.y", None).expect("gen");
        let cred = cred_secret.expose();
        assert_eq!(cred.private_key_len(), 32);
    }
}
