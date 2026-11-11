//! End-to-end encryption for DMs. Everything secret lives only in this
//! process: the server sees public keys, a locked key backup, and ciphertext.
//!
//! ```text
//! password ─Argon2id─▶ master ─┬─HKDF "auth"─▶ auth key ─▶ server (login only)
//!                              └─HKDF "wrap"─▶ wrap key ─▶ locks the private key backup
//!
//! my private key + your public key ─X25519─▶ shared secret ─HKDF─▶ DM key
//! DM key + random nonce ─XChaCha20-Poly1305─▶ ciphertext (bound to channel/message/author)
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;

/// A 32-byte key that is overwritten with zeros when dropped, so it doesn't
/// linger in freed memory.
type SecretKey = Zeroizing<[u8; 32]>;

// ---------- Password-derived keys ----------

/// Argon2id cost settings. The server holds each user's encrypted key backup,
/// so whoever runs the server can try password guesses offline, as fast as
/// their hardware allows. These numbers set the price of *every* guess.
///
/// `Argon2::default()` (19 MiB, 2 passes) is tuned for servers doing thousands
/// of logins a second. We run it once per login on the user's own machine, so
/// we can afford far more: 256 MiB of memory makes each guess expensive even on
/// GPUs (they have lots of cores but little memory per core).
///
/// The settings are hard-coded in the client, never sent by the server, so a
/// malicious server can't talk a client into weaker ones. To change them
/// later: bump `KDF_VERSION` (which changes every key) and add a way for
/// existing accounts to migrate.
const KDF_VERSION: &str = "v2";
const ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 1;

/// Minimum score from zxcvbn's 0-4 scale. 3 = "safely unguessable: moderate
/// protection from offline slow-hash scenario", which is exactly our threat.
const MIN_PASSWORD_SCORE: u8 = 3;
const MIN_PASSWORD_CHARS: usize = 10;

pub struct PasswordKeys {
    /// Sent to the server as proof of the password (hex). Can't be reversed
    /// into the wrap key. Wiped from memory when dropped.
    pub auth_key: Zeroizing<String>,
    /// Never leaves this machine.
    wrap_key: SecretKey,
}

/// Slow on purpose (Argon2id): every password guess an attacker makes costs
/// the same work. Call from a background thread.
pub fn derive_password_keys(username: &str, password: &str) -> Result<PasswordKeys, String> {
    // The salt makes identical passwords produce different keys for different
    // users. It must be known before login, so it's derived from the username.
    let salt = format!("oxide-{KDF_VERSION}:{}", normalize(username));
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32))
        .map_err(|e| format!("bad Argon2 settings: {e}"))?;
    let mut master: SecretKey = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut master[..])
        .map_err(|e| format!("key derivation failed: {e}"))?;

    // HKDF with different "info" labels gives independent keys: knowing one
    // tells you nothing about the other.
    let hk = Hkdf::<Sha256>::new(None, &master[..]);
    let mut auth: SecretKey = Zeroizing::new([0u8; 32]);
    let mut wrap_key: SecretKey = Zeroizing::new([0u8; 32]);
    hk.expand(format!("oxide auth {KDF_VERSION}").as_bytes(), &mut auth[..])
        .expect("32 bytes is a valid HKDF length");
    hk.expand(format!("oxide key-wrap {KDF_VERSION}").as_bytes(), &mut wrap_key[..])
        .expect("32 bytes is a valid HKDF length");

    Ok(PasswordKeys { auth_key: Zeroizing::new(to_hex(&auth[..])), wrap_key })
}

/// Returns why a new password is too weak, or `None` if it's acceptable.
///
/// Length alone is a poor rule: "Password123!" is 12 characters but is among
/// the first things a cracker tries. zxcvbn estimates how many guesses a smart
/// attacker (dictionaries, common patterns, keyboard walks, your username...)
/// would need.
pub fn password_problem(username: &str, password: &str) -> Option<String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Some(format!("password must be at least {MIN_PASSWORD_CHARS} characters"));
    }
    let estimate = zxcvbn::zxcvbn(password, &[username]);
    if u8::from(estimate.score()) >= MIN_PASSWORD_SCORE {
        return None;
    }
    // zxcvbn explains *why* when it can ("This is a top-100 common password").
    let hint = estimate
        .feedback()
        .and_then(|f| f.warning().map(|w| w.to_string()).or_else(|| f.suggestions().first().map(|s| s.to_string())))
        .unwrap_or_else(|| "Add more words or characters.".into());
    Some(format!(
        "password is too easy to guess. {hint} Tip: a few random words, like \
         \"tulip orbit canyon velvet\", is strong and easy to remember."
    ))
}

// ---------- Identity key pair ----------

/// A user's long-term X25519 key pair.
pub struct Identity {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Encrypts the private key with the wrap key so it can be stored on the
    /// server. Format: nonce || ciphertext.
    pub fn wrap(&self, keys: &PasswordKeys, username: &str) -> Vec<u8> {
        let secret_bytes = Zeroizing::new(self.secret.to_bytes());
        let (nonce, ciphertext) = seal(&keys.wrap_key, &secret_bytes[..], backup_aad(username).as_bytes());
        [nonce.as_slice(), &ciphertext].concat()
    }

    /// Unlocks a key backup. Fails if the password is wrong or the server
    /// tampered with the backup or the public key.
    pub fn unwrap(blob: &[u8], keys: &PasswordKeys, username: &str, expected_public: &[u8]) -> Result<Self, String> {
        if blob.len() < NONCE_LEN {
            return Err("key backup is corrupt".into());
        }
        let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
        let plain = Zeroizing::new(open(&keys.wrap_key, nonce, ciphertext, backup_aad(username).as_bytes())?);
        let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| "key backup is corrupt")?;

        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        // If the server handed out a *different* public key for us, people
        // would be encrypting to a key we don't own. Refuse to continue.
        if public.as_slice() != expected_public {
            return Err("the server's copy of your public key doesn't match your private key".into());
        }
        Ok(Self { secret, public })
    }

    /// Derives the key for one DM conversation. Both people compute the same
    /// key: X25519(my_secret, their_public) == X25519(their_secret, my_public).
    pub fn conversation_key(&self, their_public: &[u8], channel_id: Uuid) -> Result<ConversationKey, String> {
        let their: [u8; 32] = their_public.try_into().map_err(|_| "invalid public key length")?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(their));
        // Rejects malicious "low-order" public keys that would force the
        // shared secret to a known value.
        if !shared.was_contributory() {
            return Err("invalid public key".into());
        }
        // Salting with the channel id gives each conversation its own key.
        let hk = Hkdf::<Sha256>::new(Some(channel_id.as_bytes()), shared.as_bytes());
        let mut key: SecretKey = Zeroizing::new([0u8; 32]);
        hk.expand(b"oxide dm v1", &mut key[..]).expect("32 bytes is a valid HKDF length");
        Ok(ConversationKey(key))
    }
}

// ---------- Per-conversation encryption ----------

pub struct ConversationKey(SecretKey);

impl ConversationKey {
    /// Returns (nonce, ciphertext).
    pub fn encrypt(&self, channel_id: Uuid, message_id: Uuid, author_id: Uuid, text: &str) -> (Vec<u8>, Vec<u8>) {
        let padded = pad(text.as_bytes());
        let (nonce, ciphertext) = seal(&self.0, &padded, &message_aad(channel_id, message_id, author_id));
        (nonce.to_vec(), ciphertext)
    }

    pub fn decrypt(
        &self,
        channel_id: Uuid,
        message_id: Uuid,
        author_id: Uuid,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<String, String> {
        let padded = open(&self.0, nonce, ciphertext, &message_aad(channel_id, message_id, author_id))?;
        String::from_utf8(unpad(padded)?).map_err(|_| "decrypted message is not valid text".into())
    }
}

// ---------- Padding ----------

/// Encryption hides *what* you said but not *how much*: ciphertext is exactly
/// as long as the plaintext (plus a 16-byte tag). "ok" vs. a long paragraph
/// would be obvious to the server. Rounding every message up to a multiple of
/// this size means the server only learns a rough size bucket.
/// Must match `PAD_BLOCK` in the server's chat.rs.
pub const PAD_BLOCK: usize = 256;

/// ISO/IEC 7816-4 padding: append one 0x80 byte, then zeros up to the block
/// size. The 0x80 marks where the real text ends, so it can be removed
/// unambiguously even if the text itself ends in zero bytes.
fn pad(text: &[u8]) -> Zeroizing<Vec<u8>> {
    let padded_len = (text.len() + 1).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
    out.extend_from_slice(text);
    out.push(0x80);
    out.resize(padded_len, 0);
    out
}

fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>, String> {
    // Walk back over the zeros; the first non-zero byte must be the 0x80 marker.
    match padded.iter().rposition(|&b| b != 0) {
        Some(end) if padded[end] == 0x80 => {
            padded.truncate(end);
            Ok(padded)
        }
        _ => Err("message padding is invalid".into()),
    }
}

// ---------- Safety numbers ----------

/// A number both people in a DM can compare (in person, by phone...). It's
/// computed from both public keys, so if the server swapped in a fake key,
/// the two screens would show different numbers.
pub fn safety_number(key_a: &[u8], key_b: &[u8]) -> String {
    // Sort so both sides hash the keys in the same order.
    let (lo, hi) = if key_a <= key_b { (key_a, key_b) } else { (key_b, key_a) };
    let digest = Sha256::new()
        .chain_update(b"oxide safety-number v1")
        .chain_update(lo)
        .chain_update(hi)
        .finalize();
    digest[..30]
        .chunks(5)
        .map(|chunk| {
            let n = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------- Primitives ----------

/// XChaCha20-Poly1305 with a fresh random 24-byte nonce. 24 bytes is large
/// enough that random nonces will never realistically repeat.
fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("encryption with a valid key cannot fail");
    (nonce, ciphertext)
}

/// Fails if *anything* differs: key, nonce, ciphertext, or associated data.
fn open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != NONCE_LEN {
        return Err("invalid nonce".into());
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes");
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| "decryption failed (wrong key or tampered data)".into())
}

/// "Associated data" is authenticated but not encrypted. Binding these ids
/// means the server can't move a ciphertext into another chat, re-send it as
/// a new message, or claim someone else wrote it: decryption would fail.
fn message_aad(channel_id: Uuid, message_id: Uuid, author_id: Uuid) -> Vec<u8> {
    // v2: plaintext is now padded (see `pad`).
    [b"oxide dm-msg v2".as_slice(), channel_id.as_bytes(), message_id.as_bytes(), author_id.as_bytes()].concat()
}

fn backup_aad(username: &str) -> String {
    format!("oxide key-backup v1:{}", normalize(username))
}

/// Usernames are case-insensitive, so keys must be too.
fn normalize(username: &str) -> String {
    username.trim().to_lowercase()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- Tests (run with `cargo test -p client`) ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_keys_are_deterministic_and_independent() {
        let a = derive_password_keys("Alice", "correct horse").unwrap();
        let b = derive_password_keys("alice", "correct horse").unwrap();
        let wrong = derive_password_keys("alice", "wrong horse").unwrap();
        let other_user = derive_password_keys("bob", "correct horse").unwrap();

        assert_eq!(a.auth_key, b.auth_key, "usernames are case-insensitive");
        assert_ne!(a.auth_key, wrong.auth_key);
        assert_ne!(a.auth_key, other_user.auth_key, "salt differs per user");
        assert_ne!(*a.auth_key, to_hex(&a.wrap_key[..]), "auth and wrap keys must differ");
    }

    #[test]
    fn padding_hides_length_and_round_trips() {
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let (channel, author) = (Uuid::new_v4(), Uuid::new_v4());
        let key = alice.conversation_key(&bob.public, channel).unwrap();

        let short = key.encrypt(channel, Uuid::new_v4(), author, "ok").1;
        let long = key.encrypt(channel, Uuid::new_v4(), author, &"a".repeat(200)).1;
        assert_eq!(short.len(), long.len(), "both fit in one block, so the server can't tell them apart");
        assert_eq!(short.len(), PAD_BLOCK + 16);

        // Edge cases: empty, exactly one block, text ending in a zero byte.
        for text in ["", &"x".repeat(PAD_BLOCK), "ends with nul\0"] {
            let id = Uuid::new_v4();
            let (nonce, ct) = key.encrypt(channel, id, author, text);
            assert_eq!((ct.len() - 16) % PAD_BLOCK, 0);
            assert_eq!(key.decrypt(channel, id, author, &nonce, &ct).unwrap(), text);
        }
        assert!(unpad(vec![0u8; PAD_BLOCK]).is_err(), "no 0x80 marker -> rejected");
    }

    #[test]
    fn weak_passwords_are_rejected() {
        for weak in ["short", "password123", "Password123!", "aliceAlice123", "qwertyuiop"] {
            assert!(password_problem("alice", weak).is_some(), "{weak:?} should be rejected");
        }
        assert!(password_problem("alice", "tulip orbit canyon velvet").is_none());
    }

    #[test]
    fn key_backup_round_trips_and_rejects_wrong_password() {
        let keys = derive_password_keys("alice", "correct horse").unwrap();
        let id = Identity::generate();
        let blob = id.wrap(&keys, "alice");

        let restored = Identity::unwrap(&blob, &keys, "ALICE", &id.public).unwrap();
        assert_eq!(restored.public, id.public);

        let wrong = derive_password_keys("alice", "wrong horse").unwrap();
        assert!(Identity::unwrap(&blob, &wrong, "alice", &id.public).is_err());

        // Server substitutes a different public key -> refused.
        let impostor = Identity::generate();
        assert!(Identity::unwrap(&blob, &keys, "alice", &impostor.public).is_err());
    }

    #[test]
    fn both_sides_derive_the_same_conversation_key() {
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let (channel, msg, author) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        let alice_key = alice.conversation_key(&bob.public, channel).unwrap();
        let bob_key = bob.conversation_key(&alice.public, channel).unwrap();

        let (nonce, ct) = alice_key.encrypt(channel, msg, author, "hi bob 👋");
        assert_eq!(bob_key.decrypt(channel, msg, author, &nonce, &ct).unwrap(), "hi bob 👋");
        assert!(!ct.windows(6).any(|w| w == b"hi bob"), "ciphertext must not contain plaintext");
    }

    #[test]
    fn outsiders_and_tampering_are_detected() {
        let (alice, bob, eve) = (Identity::generate(), Identity::generate(), Identity::generate());
        let (channel, msg, author) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let key = alice.conversation_key(&bob.public, channel).unwrap();
        let (nonce, ct) = key.encrypt(channel, msg, author, "secret");

        // Eve (or the server) with her own key can't read it.
        let eve_key = eve.conversation_key(&alice.public, channel).unwrap();
        assert!(eve_key.decrypt(channel, msg, author, &nonce, &ct).is_err());

        // Flipping a single bit is detected.
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(key.decrypt(channel, msg, author, &nonce, &tampered).is_err());

        // Relabeling the author, message id, or channel is detected.
        assert!(key.decrypt(channel, msg, Uuid::new_v4(), &nonce, &ct).is_err());
        assert!(key.decrypt(channel, Uuid::new_v4(), author, &nonce, &ct).is_err());
        assert!(key.decrypt(Uuid::new_v4(), msg, author, &nonce, &ct).is_err());
    }

    #[test]
    fn rejects_low_order_public_key() {
        let alice = Identity::generate();
        assert!(alice.conversation_key(&[0u8; 32], Uuid::new_v4()).is_err());
    }

    #[test]
    fn safety_number_is_symmetric() {
        let (a, b, c) = (Identity::generate(), Identity::generate(), Identity::generate());
        assert_eq!(safety_number(&a.public, &b.public), safety_number(&b.public, &a.public));
        assert_ne!(safety_number(&a.public, &b.public), safety_number(&a.public, &c.public));
        assert_eq!(safety_number(&a.public, &b.public).len(), 6 * 5 + 5); // 6 groups + spaces
    }
}
