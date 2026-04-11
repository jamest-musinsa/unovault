//! BIP39 24-word recovery phrase handling.
//!
//! The recovery phrase is the only way to unlock a vault if the user
//! forgets their master password. It is generated once at vault
//! creation, shown to the user immediately, and **never** stored on
//! disk. The vault stores a copy of the master key wrapped under a
//! KEK derived from the phrase via argon2id; see
//! [`crate::format::VaultManifest`] for the on-disk shape.
//!
//! # Why BIP39
//!
//! BIP39 is an existing, well-specified wordlist with error-detection
//! via the mnemonic checksum. The 24-word variant encodes 256 bits of
//! entropy, matching the 256-bit master key length. Users are more
//! likely to copy a 24-word phrase correctly than a long random hex
//! string, and the checksum catches most single-word typos at unlock
//! time.
//!
//! # Zeroization discipline
//!
//! The phrase is wrapped in [`Secret<String>`] so a dropped
//! [`RecoveryPhrase`] wipes its plaintext. The underlying `bip39`
//! crate zeroizes its own internal buffer when the `zeroize` feature
//! is on, which is what we enable in the workspace manifest.
//!
//! # What this module does not do
//!
//! * Does not persist the phrase anywhere. The caller is responsible
//!   for showing it to the user once. A second call to
//!   [`RecoveryPhrase::generate`] always produces a fresh phrase.
//! * Does not validate against passphrase extensions. BIP39 optionally
//!   lets users add an arbitrary passphrase to derive a different seed;
//!   v1 uses the bare mnemonic without the optional passphrase so users
//!   only have one secret to remember.

use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::secret::Secret;
use crate::{BugInUnovaultError, UserActionableError, VaultError};

/// A BIP39 24-word mnemonic suitable for recovering a vault master key.
///
/// The phrase is `Secret<String>` internally so it zeroizes on drop.
/// The `Display` impl is deliberately absent — call sites must go
/// through [`RecoveryPhrase::as_secret_string`] to reach the plaintext,
/// which keeps exposure grep-friendly.
#[derive(Debug)]
pub struct RecoveryPhrase {
    inner: Secret<String>,
}

impl RecoveryPhrase {
    /// Generate a fresh 24-word phrase from 256 bits of OS entropy.
    ///
    /// Returns [`BugInUnovaultError::InvariantViolation`] if the OS
    /// RNG or the bip39 constructor refuses — neither should ever
    /// fire on a healthy platform, and categorising as a bug makes
    /// the failure obvious in diagnostics.
    pub fn generate() -> Result<Self, VaultError> {
        // 24 words = 256 bits of entropy. The bip39 crate's
        // `from_entropy_in` takes exactly 32 bytes for a 24-word
        // mnemonic; we read those bytes from the platform CSPRNG
        // directly so the entropy source is the same `OsRng` the rest
        // of the vault uses.
        let mut entropy = [0u8; 32];
        OsRng.try_fill_bytes(&mut entropy).map_err(|_| {
            BugInUnovaultError::InvariantViolation(
                "OS RNG failed during recovery phrase generation",
            )
        })?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).map_err(|_| {
            BugInUnovaultError::InvariantViolation("bip39 from_entropy_in rejected 32 bytes")
        })?;
        // Wipe the local entropy buffer as soon as the mnemonic is
        // built. `Mnemonic` keeps its own internal copy of the entropy
        // (zeroized on drop because the `zeroize` feature is enabled
        // on the workspace `bip39` dependency), so the only extra
        // exposure is this stack buffer.
        use zeroize::Zeroize;
        entropy.zeroize();
        Ok(Self {
            inner: Secret::new(mnemonic.to_string()),
        })
    }

    /// Parse a phrase the user typed back in. Whitespace is normalised
    /// so "one  two  three" and "one two three\n" both parse. Returns
    /// [`UserActionableError::InvalidRecoveryPhrase`] on any of the
    /// failure modes bip39 can report: wrong word count, out-of-wordlist
    /// word, bad checksum.
    pub fn parse(input: &str) -> Result<Self, VaultError> {
        let normalised = input.split_whitespace().collect::<Vec<_>>().join(" ");
        // bip39::parse_in_normalized verifies the checksum; a typo in
        // any single word is caught here.
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalised)
            .map_err(|_| UserActionableError::InvalidRecoveryPhrase)?;
        if mnemonic.word_count() != 24 {
            return Err(UserActionableError::InvalidRecoveryPhrase.into());
        }
        Ok(Self {
            inner: Secret::new(normalised),
        })
    }

    /// Borrow the phrase as a `Secret<String>` for feeding into the
    /// argon2id KEK derivation.
    pub fn as_secret_string(&self) -> &Secret<String> {
        &self.inner
    }

    /// Borrow the raw plaintext bytes — used by the UI to display the
    /// phrase once after generation. Reviewers should treat every call
    /// site as a conscious decision: the phrase is the highest-value
    /// secret in the whole system and should leave this function only
    /// to reach the user's screen.
    pub fn expose(&self) -> &str {
        self.inner.expose()
    }

    /// Word count. Always 24 for phrases produced by this module;
    /// exposed for sanity checks in tests and the UI.
    pub fn word_count(&self) -> usize {
        self.inner.expose().split_whitespace().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() {
        let phrase = RecoveryPhrase::generate().expect("generate");
        assert_eq!(phrase.word_count(), 24);
    }

    #[test]
    fn generate_produces_unique_phrases() {
        let a = RecoveryPhrase::generate().expect("a");
        let b = RecoveryPhrase::generate().expect("b");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn parse_accepts_a_generated_phrase_round_trip() {
        let original = RecoveryPhrase::generate().expect("generate");
        let parsed = RecoveryPhrase::parse(original.expose()).expect("parse");
        assert_eq!(parsed.expose(), original.expose());
    }

    #[test]
    fn parse_rejects_wrong_word_count() {
        // 12 words is a valid BIP39 phrase length but not what this
        // module produces. Reject for v1 so "I pasted my 1Password
        // emergency kit by mistake" fails loudly.
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        match RecoveryPhrase::parse(twelve) {
            Err(VaultError::UserActionable(UserActionableError::InvalidRecoveryPhrase)) => {}
            other => panic!("expected InvalidRecoveryPhrase, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_typo() {
        let mut phrase = RecoveryPhrase::generate()
            .expect("generate")
            .expose()
            .to_string();
        // Swap the last word for a deliberate non-wordlist token.
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.pop();
        words.push("zzzzzzzz");
        phrase = words.join(" ");
        match RecoveryPhrase::parse(&phrase) {
            Err(VaultError::UserActionable(UserActionableError::InvalidRecoveryPhrase)) => {}
            other => panic!("expected InvalidRecoveryPhrase, got {other:?}"),
        }
    }

    #[test]
    fn parse_tolerates_whitespace_differences() {
        let original = RecoveryPhrase::generate().expect("generate");
        let noisy = format!("  {}\n\t", original.expose().replace(' ', "   "));
        let parsed = RecoveryPhrase::parse(&noisy).expect("parse");
        assert_eq!(parsed.word_count(), 24);
    }

    #[test]
    fn debug_does_not_leak_phrase_plaintext() {
        let phrase = RecoveryPhrase::generate().expect("generate");
        let debug = format!("{phrase:?}");
        // The phrase words should not appear in the debug string —
        // Secret<String>'s Debug redacts.
        let first_word = phrase
            .expose()
            .split_whitespace()
            .next()
            .expect("has words");
        assert!(
            !debug.contains(first_word),
            "RecoveryPhrase Debug leaked plaintext: {debug}"
        );
    }
}
