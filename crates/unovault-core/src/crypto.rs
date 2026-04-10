//! Crypto primitives for the unovault vault engine.
//!
//! All three cryptographic choices here were locked in by the design doc
//! after the spec reviews; this module is the implementation, not the
//! decision point. Any change to parameters or algorithms requires a
//! format-version bump and a migration path.
//!
//! ## Primitives
//!
//! | Purpose                    | Algorithm                        |
//! |----------------------------|----------------------------------|
//! | Master key derivation      | argon2id                         |
//! | Sub-key derivation         | HKDF-SHA256                      |
//! | Chunk payload encryption   | XChaCha20-Poly1305 (AEAD)        |
//! | Manifest integrity         | HMAC-SHA256                      |
//! | Constant-time comparison   | `subtle` crate                   |
//! | OS randomness              | `OsRng` (platform CSPRNG)        |
//!
//! ## Key hierarchy
//!
//! ```text
//!           master password
//!                 │
//!         argon2id + salt
//!                 │
//!                 ▼
//!         master key (32 bytes)
//!                 │
//!           HKDF-SHA256
//!          ┌──────┴──────┐
//!          ▼             ▼
//!   encryption key   mac key
//!    (32 bytes)      (32 bytes)
//! ```
//!
//! The master key itself never touches the chunk encryption or manifest
//! integrity directly. It only exists to seed HKDF. This gives us domain
//! separation: a bug in the MAC derivation cannot silently also weaken the
//! encryption key, and vice versa.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{BugInUnovaultError, Secret, UserActionableError, VaultError};

/// Length of the argon2id salt stored in the manifest.
pub const SALT_LEN: usize = 16;

/// Length of the XChaCha20 nonce per chunk. 24 bytes is the "X" part —
/// extended nonce space means we can generate nonces randomly without
/// worrying about collision probability.
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag appended to every chunk
/// ciphertext.
pub const TAG_LEN: usize = 16;

/// Length of every symmetric key in the system: master, encryption, MAC.
pub const KEY_LEN: usize = 32;

/// Length of the HMAC-SHA256 output used for manifest integrity.
pub const MAC_LEN: usize = 32;

/// argon2id tuning parameters. V1 targets ~500ms on a modern M-series Mac
/// and ~1-1.5s on an M1 Air. The threat model in the design doc justifies
/// these numbers.
///
/// `KdfParams` is `Serialize`/`Deserialize` so it can live in `manifest.json`
/// alongside the salt — older vaults created with different parameters will
/// still decrypt correctly because the parameters travel with the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes. 262144 = 256 MiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// Recommended parameters for format version 1.
    pub const V1: Self = Self {
        m_cost_kib: 262_144,
        t_cost: 3,
        p_cost: 4,
    };

    /// Cheaper parameters used only in tests so the suite finishes in
    /// seconds, not minutes. Never use these in production.
    #[cfg(test)]
    pub const TEST_ONLY: Self = Self {
        m_cost_kib: 8, // 8 KiB — crypto is fine, just fast
        t_cost: 1,
        p_cost: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::V1
    }
}

/// Bundle of derived symmetric keys used by the vault.
///
/// `DerivedKeys` is itself `Zeroize` so it can be wrapped in `Secret<T>`.
/// The wrapper `Secret` adds the redacted `Debug` impl and the zeroize-on-
/// drop semantics; this struct just provides the raw key bytes.
#[derive(Default, Zeroize)]
pub struct DerivedKeys {
    /// Used for XChaCha20-Poly1305 chunk encryption.
    pub encryption: [u8; KEY_LEN],
    /// Used for HMAC-SHA256 manifest integrity.
    pub mac: [u8; KEY_LEN],
}

/// Generate a random salt for argon2id. Salts are not secret but must be
/// unique per vault — each new vault gets a fresh salt at creation time
/// and the salt is stored in plaintext in the manifest.
///
/// An `OsRng` failure is classified as a bug, not a platform-policy issue,
/// because the OS CSPRNG is expected to always succeed on supported
/// platforms. A real failure here means something is deeply wrong with the
/// host — the user should see a "please file a bug report" dialog, not
/// "Keychain was denied."
pub fn generate_salt() -> Result<[u8; SALT_LEN], VaultError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.try_fill_bytes(&mut salt).map_err(|_| {
        BugInUnovaultError::InvariantViolation("OS RNG failed during salt generation")
    })?;
    Ok(salt)
}

/// Generate a random nonce for one chunk. XChaCha20's 24-byte nonce space
/// makes random generation safe; collision probability is negligible even
/// after 2^40 encryptions.
pub fn generate_nonce() -> Result<[u8; NONCE_LEN], VaultError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| {
        BugInUnovaultError::InvariantViolation("OS RNG failed during nonce generation")
    })?;
    Ok(nonce)
}

/// Derive a 32-byte master key from a password + salt using argon2id.
///
/// The caller supplies a borrowed `Secret<String>` to make exposure at the
/// call site visible in a grep. The returned master key is also wrapped in
/// `Secret` so it zeroizes on drop.
pub fn derive_master_key(
    password: &Secret<String>,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Secret<[u8; KEY_LEN]>, VaultError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| BugInUnovaultError::InvariantViolation("argon2 params rejected"))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.expose().as_bytes(), salt, &mut output)
        .map_err(|_| BugInUnovaultError::InvariantViolation("argon2 hash_password_into failed"))?;

    Ok(Secret::new(output))
}

/// Derive the (encryption, mac) sub-key pair from the master key via HKDF.
///
/// The master key is already a uniformly-random 32-byte value (argon2id
/// output), so we skip HKDF-Extract and feed it directly to HKDF-Expand via
/// [`Hkdf::from_prk`]. Using `new(None, ...)` would still be sound because
/// Extract is a no-op on a uniform input, but `from_prk` documents the
/// invariant at the type level and stops future refactors from accidentally
/// feeding a non-uniform seed through the Extract step with an all-zero
/// salt.
///
/// Two separate `expand` calls with distinct `info` strings give domain-
/// separated encryption and MAC keys. HKDF guarantees they are
/// cryptographically independent as long as the `info` strings differ.
/// Adding a third sub-key in the future means another expand call with its
/// own distinct info.
pub fn derive_sub_keys(master: &Secret<[u8; KEY_LEN]>) -> Result<Secret<DerivedKeys>, VaultError> {
    let hkdf = Hkdf::<Sha256>::from_prk(master.expose()).map_err(|_| {
        BugInUnovaultError::InvariantViolation("hkdf from_prk: master key wrong length")
    })?;

    let mut derived = DerivedKeys::default();
    hkdf.expand(b"unovault-v1/enc", &mut derived.encryption)
        .map_err(|_| BugInUnovaultError::InvariantViolation("hkdf expand enc key"))?;
    hkdf.expand(b"unovault-v1/mac", &mut derived.mac)
        .map_err(|_| BugInUnovaultError::InvariantViolation("hkdf expand mac key"))?;

    Ok(Secret::new(derived))
}

/// Encrypt a chunk payload.
///
/// Output layout: `[nonce (24 bytes)] [ciphertext] [tag (16 bytes)]`.
/// The tag is inline at the end of the ciphertext via the AEAD construction;
/// the nonce is prepended so decryption is a single pass over the input.
pub fn encrypt_chunk(keys: &Secret<DerivedKeys>, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(keys.expose().encryption.as_ref().into());
    let nonce_bytes = generate_nonce()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| BugInUnovaultError::InvariantViolation("AEAD encrypt failed"))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a chunk payload produced by [`encrypt_chunk`].
///
/// Any failure — too short, tampered nonce, bad tag, wrong key — surfaces
/// as [`UserActionableError::CorruptedChunk`] because the most likely cause
/// is a damaged file, not a bug in the caller.
pub fn decrypt_chunk(keys: &Secret<DerivedKeys>, input: &[u8]) -> Result<Vec<u8>, VaultError> {
    if input.len() < NONCE_LEN + TAG_LEN {
        return Err(UserActionableError::CorruptedChunk.into());
    }

    let (nonce_bytes, ciphertext) = input.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(keys.expose().encryption.as_ref().into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| UserActionableError::CorruptedChunk.into())
}

/// Compute HMAC-SHA256 over arbitrary bytes using the manifest MAC key.
pub fn compute_mac(keys: &Secret<DerivedKeys>, body: &[u8]) -> Result<[u8; MAC_LEN], VaultError> {
    type HmacSha256 = Hmac<Sha256>;

    // Fully qualify because both `hmac::Mac` and `chacha20poly1305::KeyInit`
    // define a `new_from_slice` method and both are in scope in this module.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.expose().mac)
        .map_err(|_| BugInUnovaultError::InvariantViolation("hmac key length"))?;
    mac.update(body);

    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Verify an HMAC-SHA256 tag in constant time.
///
/// Uses [`subtle::ConstantTimeEq`] rather than byte-wise `==` so a timing
/// oracle can't differentiate "MAC differs at byte 1" from "MAC differs at
/// byte 31." This is paranoia for a local vault file, but it costs nothing
/// and sets the bar for future crypto additions.
pub fn verify_mac(
    keys: &Secret<DerivedKeys>,
    body: &[u8],
    expected: &[u8; MAC_LEN],
) -> Result<(), VaultError> {
    let computed = compute_mac(keys, body)?;
    if computed.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(UserActionableError::CorruptedManifest.into())
    }
}

/// Encode a MAC tag as unpadded base64 (URL-safe alphabet) for JSON storage
/// in the manifest.
pub fn mac_to_base64(mac: &[u8; MAC_LEN]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac)
}

/// Decode a base64 MAC tag from the manifest.
pub fn mac_from_base64(s: &str) -> Result<[u8; MAC_LEN], VaultError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| UserActionableError::CorruptedManifest)?;
    if bytes.len() != MAC_LEN {
        return Err(UserActionableError::CorruptedManifest.into());
    }
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encode a salt as unpadded URL-safe base64 for JSON storage.
pub fn salt_to_base64(salt: &[u8; SALT_LEN]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt)
}

/// Decode a salt from unpadded URL-safe base64.
pub fn salt_from_base64(s: &str) -> Result<[u8; SALT_LEN], VaultError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| UserActionableError::CorruptedManifest)?;
    if bytes.len() != SALT_LEN {
        return Err(UserActionableError::CorruptedManifest.into());
    }
    let mut out = [0u8; SALT_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a derived-key pair from a known password. All crypto tests use
    /// cheap argon2id params via `KdfParams::TEST_ONLY` so the suite finishes
    /// in milliseconds.
    fn derive_test_keys(password: &str) -> Secret<DerivedKeys> {
        let salt = [0u8; SALT_LEN];
        let pw = Secret::new(String::from(password));
        let master = derive_master_key(&pw, &salt, &KdfParams::TEST_ONLY)
            .expect("derive_master_key should not fail on valid input");
        derive_sub_keys(&master).expect("derive_sub_keys should not fail on valid input")
    }

    #[test]
    fn master_key_is_deterministic_for_same_password_and_salt() {
        let pw = Secret::new(String::from("hunter2"));
        let salt = [1u8; SALT_LEN];
        let a = derive_master_key(&pw, &salt, &KdfParams::TEST_ONLY).expect("first");
        let b = derive_master_key(&pw, &salt, &KdfParams::TEST_ONLY).expect("second");
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn different_passwords_yield_different_master_keys() {
        let salt = [1u8; SALT_LEN];
        let a = derive_master_key(
            &Secret::new(String::from("hunter2")),
            &salt,
            &KdfParams::TEST_ONLY,
        )
        .expect("a");
        let b = derive_master_key(
            &Secret::new(String::from("hunter3")),
            &salt,
            &KdfParams::TEST_ONLY,
        )
        .expect("b");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn different_salts_yield_different_master_keys() {
        let pw = Secret::new(String::from("hunter2"));
        let a = derive_master_key(&pw, &[1u8; SALT_LEN], &KdfParams::TEST_ONLY).expect("a");
        let b = derive_master_key(&pw, &[2u8; SALT_LEN], &KdfParams::TEST_ONLY).expect("b");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn sub_keys_are_distinct_from_each_other() {
        let keys = derive_test_keys("hunter2");
        assert_ne!(keys.expose().encryption, keys.expose().mac);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_preserves_plaintext() {
        let keys = derive_test_keys("hunter2");
        let plaintext = b"correct horse battery staple";
        let ciphertext = encrypt_chunk(&keys, plaintext).expect("encrypt");
        let recovered = decrypt_chunk(&keys, &ciphertext).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_output_contains_nonce_ciphertext_and_tag() {
        let keys = derive_test_keys("hunter2");
        let plaintext = b"x";
        let ciphertext = encrypt_chunk(&keys, plaintext).expect("encrypt");
        // 24 nonce + 1 plaintext byte + 16 tag
        assert_eq!(ciphertext.len(), NONCE_LEN + 1 + TAG_LEN);
    }

    #[test]
    fn encrypting_the_same_plaintext_twice_produces_different_outputs() {
        // Because nonces are randomly generated each call.
        let keys = derive_test_keys("hunter2");
        let plaintext = b"same input";
        let a = encrypt_chunk(&keys, plaintext).expect("a");
        let b = encrypt_chunk(&keys, plaintext).expect("b");
        assert_ne!(a, b, "nonce reuse would make these identical");
    }

    #[test]
    fn plaintext_bytes_do_not_appear_in_ciphertext() {
        let keys = derive_test_keys("hunter2");
        // Use a distinctive plaintext so substring search is meaningful.
        let plaintext = b"BANANA_SMOOTHIE_RECIPE_v42";
        let ciphertext = encrypt_chunk(&keys, plaintext).expect("encrypt");
        // Skip the first NONCE_LEN bytes — nonces are random and could
        // theoretically coincide with our input by chance.
        let body = &ciphertext[NONCE_LEN..];
        for window in body.windows(plaintext.len()) {
            assert_ne!(window, plaintext, "plaintext leaked into ciphertext");
        }
    }

    #[test]
    fn tampered_ciphertext_fails_with_corrupted_chunk() {
        let keys = derive_test_keys("hunter2");
        let plaintext = b"hello";
        let mut ciphertext = encrypt_chunk(&keys, plaintext).expect("encrypt");
        // Flip one byte of the ciphertext body (after the nonce).
        ciphertext[NONCE_LEN + 1] ^= 0x55;
        match decrypt_chunk(&keys, &ciphertext) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk, got {other:?}"),
        }
    }

    #[test]
    fn tampered_tag_fails_with_corrupted_chunk() {
        let keys = derive_test_keys("hunter2");
        let plaintext = b"hello";
        let mut ciphertext = encrypt_chunk(&keys, plaintext).expect("encrypt");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        match decrypt_chunk(&keys, &ciphertext) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails_with_corrupted_chunk() {
        let keys_a = derive_test_keys("hunter2");
        let keys_b = derive_test_keys("hunter3");
        let ciphertext = encrypt_chunk(&keys_a, b"hello").expect("encrypt");
        match decrypt_chunk(&keys_b, &ciphertext) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk under wrong key, got {other:?}"),
        }
    }

    #[test]
    fn truncated_ciphertext_fails_cleanly() {
        let keys = derive_test_keys("hunter2");
        let ciphertext = encrypt_chunk(&keys, b"hello").expect("encrypt");
        let truncated = &ciphertext[..NONCE_LEN + TAG_LEN - 1];
        match decrypt_chunk(&keys, truncated) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedChunk)) => {}
            other => panic!("expected CorruptedChunk on truncated input, got {other:?}"),
        }
    }

    #[test]
    fn mac_roundtrip_verifies_unchanged_body() {
        let keys = derive_test_keys("hunter2");
        let body = b"manifest-json-body-bytes";
        let tag = compute_mac(&keys, body).expect("compute_mac");
        verify_mac(&keys, body, &tag).expect("verify_mac should accept unchanged body");
    }

    #[test]
    fn mac_rejects_tampered_body() {
        let keys = derive_test_keys("hunter2");
        let body = b"manifest-json-body-bytes";
        let tag = compute_mac(&keys, body).expect("compute_mac");
        let tampered = b"manifest-json-body-byteX";
        match verify_mac(&keys, tampered, &tag) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedManifest)) => {}
            other => panic!("expected CorruptedManifest, got {other:?}"),
        }
    }

    #[test]
    fn mac_rejects_wrong_key() {
        let keys_a = derive_test_keys("hunter2");
        let keys_b = derive_test_keys("hunter3");
        let body = b"manifest-body";
        let tag = compute_mac(&keys_a, body).expect("compute");
        match verify_mac(&keys_b, body, &tag) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedManifest)) => {}
            other => panic!("expected CorruptedManifest, got {other:?}"),
        }
    }

    #[test]
    fn base64_roundtrip_for_mac() {
        let mac = [0xABu8; MAC_LEN];
        let encoded = mac_to_base64(&mac);
        let decoded = mac_from_base64(&encoded).expect("decode");
        assert_eq!(decoded, mac);
    }

    #[test]
    fn base64_roundtrip_for_salt() {
        let salt = [0xCDu8; SALT_LEN];
        let encoded = salt_to_base64(&salt);
        let decoded = salt_from_base64(&encoded).expect("decode");
        assert_eq!(decoded, salt);
    }

    #[test]
    fn base64_decode_rejects_wrong_length_for_mac() {
        let short = mac_to_base64(&[0u8; MAC_LEN])[..20].to_string();
        match mac_from_base64(&short) {
            Err(VaultError::UserActionable(UserActionableError::CorruptedManifest)) => {}
            other => panic!("expected CorruptedManifest, got {other:?}"),
        }
    }

    #[test]
    fn generate_salt_is_not_all_zero() {
        // Probabilistic: an all-zero salt is astronomically unlikely. If this
        // test ever fails, the OS RNG is broken and nothing else matters.
        let salt = generate_salt().expect("generate_salt");
        assert_ne!(salt, [0u8; SALT_LEN]);
    }

    #[test]
    fn generate_salt_differs_between_calls() {
        let a = generate_salt().expect("a");
        let b = generate_salt().expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn generate_nonce_is_not_all_zero() {
        let nonce = generate_nonce().expect("generate_nonce");
        assert_ne!(nonce, [0u8; NONCE_LEN]);
    }

    // Property tests — three invariants:
    //
    // 1. Encrypt then decrypt is an identity function across arbitrary
    //    input sizes including empty and 4 KiB. Failing this means vault
    //    data is corrupted on round-trip.
    //
    // 2. The plaintext byte sequence never appears contiguously in the
    //    ciphertext body (skipping the NONCE_LEN prefix because a random
    //    nonce could theoretically coincide with a 24-byte substring of
    //    the input by chance).
    //
    // 3. `decrypt_chunk` never panics on adversarial input — this is the
    //    panic-policy proof for the decrypt path. Must return an error,
    //    not crash.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn proptest_encrypt_decrypt_roundtrip(
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..=4096)
        ) {
            let keys = derive_test_keys("hunter2");
            let ciphertext = encrypt_chunk(&keys, &plaintext).expect("encrypt");
            let recovered = decrypt_chunk(&keys, &ciphertext).expect("decrypt");
            proptest::prop_assert_eq!(recovered, plaintext);
        }

        #[test]
        fn proptest_no_plaintext_in_ciphertext(
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 16..=1024)
        ) {
            let keys = derive_test_keys("hunter2");
            let ciphertext = encrypt_chunk(&keys, &plaintext).expect("encrypt");
            let body = &ciphertext[NONCE_LEN..];
            for window in body.windows(plaintext.len()) {
                proptest::prop_assert_ne!(window, plaintext.as_slice());
            }
        }

        #[test]
        fn proptest_decrypt_rejects_garbage_without_panic(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=2048)
        ) {
            let keys = derive_test_keys("hunter2");
            let _ = decrypt_chunk(&keys, &bytes); // must not panic
        }
    }
}
