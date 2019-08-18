//! # Shielded Memory
//!
//! A crate drawing inspiration and parts of the documentation from OpenBSD's /
//! OpenSSH's
//! [commit](https://github.com/openbsd/src/commit/707316f931b35ef67f1390b2a00386bdd0863568).
//!
//! This crate implements a Shielded Memory providing protection at rest for
//! secrets kept in memory against speculation and memory sidechannel attacks
//! like Spectre, Meltdown, Rowhammer and Rambleed. The contents of the memory
//! are encrypted when [`Shielded`](struct.Shielded.html) is constructed, then
//! decrypted on demand and encrypted again after memory is no longer needed.
//!
//! The memory protection is achieved by generating a 16kB secure random prekey
//! which is then hashed with SHA512 to construct an encryption key for
//! ChaCha20-Poly1305 cipher. This cipher is then used to encrypt the contents
//! of memory in-place.
//!
//! Attackers must recover the entire prekey with high accuracy before they can
//! attempt to decrypt the shielded memory, but the current generation of
//! attacks have bit error rates that, when applied cumulatively to the entire
//! prekey, make this unlikely.

#![forbid(
    anonymous_parameters,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    warnings
)]

use ring::aead::{self, BoundKey, OpeningKey, SealingKey, UnboundKey};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use aead::CHACHA20_POLY1305 as SHIELD_CIPHER;
use digest::SHA512 as SHIELD_PREKEY_HASH;
const SHIELD_PREKEY_LEN: usize = 16 * 1024;

// Used for allocations to mark allocated but not populated memory regions
const MAGIC_BYTE: u8 = 0xDF;

struct PreKey(Vec<u8>);
struct Key(Vec<u8>);
struct Nonce(Vec<u8>);

/// A construct holding a piece of memory encrypted.
pub struct Shielded {
    prekey: PreKey,
    nonce: Nonce,
    memory: Vec<u8>,
}

impl Shielded {
    /// Construct a new `Shielded` memory.
    pub fn new(buf: Vec<u8>) -> Self {
        let buf_len = buf.len();
        let mut shielded = Self {
            prekey: PreKey(vec![MAGIC_BYTE; SHIELD_PREKEY_LEN]),
            nonce: Nonce(vec![MAGIC_BYTE; SHIELD_CIPHER.nonce_len()]),
            memory: buf,
        };

        shielded.shield(None);

        // Encryption tag is added to the memory so it should be longer than
        // buf.
        debug_assert!(shielded.memory.len() > buf_len);

        shielded
    }

    fn shield(&mut self, payload_len: Option<usize>) {
        let rng = ring::rand::SystemRandom::new();
        let prekey = new_prekey(&rng);
        let nonce_bytes = new_nonce(&rng);
        let key = new_key(&prekey);
        let unbound_key = UnboundKey::new(&SHIELD_CIPHER, &key.0).expect("new UnboundKey");
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes.0).expect("new Nonce");
        let nonce_sequence = OneNonceSequence::new(nonce);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        // Add prekey into additionally authenticated data. This authenticates
        // the prekey, but doesn't encrypt it. If the authentication check fails
        // on decryption, something has modified the prekey kept in memory.
        let aad = aead::Aad::from(&prekey.0);

        if let Some(len) = payload_len {
            // Encryption tag is added to self.memory so it appears longer than
            // what the real content is.
            self.memory.truncate(len);
        }

        sealing_key
            .seal_in_place_append_tag(aad, &mut self.memory)
            .expect("seal in place");
        self.prekey = prekey;
        self.nonce = nonce_bytes;

        debug_assert_eq!(self.prekey.0.len(), SHIELD_PREKEY_LEN);
        debug_assert_eq!(self.nonce.0.len(), SHIELD_CIPHER.nonce_len());
    }

    /// Decrypt the Shielded content in-place.
    pub fn unshield(&mut self) -> UnShielded<'_> {
        let key = new_key(&self.prekey);
        let unbound_key = UnboundKey::new(&SHIELD_CIPHER, &key.0).expect("new UnboundKey");
        let nonce = aead::Nonce::try_assume_unique_for_key(&self.nonce.0).expect("new Nonce");
        let nonce_sequence = OneNonceSequence::new(nonce);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        let aad = aead::Aad::from(&self.prekey.0);

        let plaintext = opening_key
            .open_in_place(aad, &mut self.memory)
            .expect("open in place");

        UnShielded {
            plaintext_len: plaintext.len(),
            shielded: self,
        }
    }
}

impl From<Vec<u8>> for Shielded {
    fn from(buf: Vec<u8>) -> Self {
        Shielded::new(buf)
    }
}

impl Drop for Shielded {
    fn drop(&mut self) {
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut self.memory).expect("rng fill memory in drop");
    }
}

/// UnShielded memory containing decrypted contents of what previously was
/// encrypted. After `UnShielded` goes out of scope or is dropped, the
/// `Shielded` is reinitialized with new cryptographic keys and the contents are
/// crypted again.
pub struct UnShielded<'a> {
    // After decryption this `Shielded.memory[..plaintext_len]` contains the
    // unecrypted content.
    shielded: &'a mut Shielded,
    plaintext_len: usize,
}

impl<'a> AsRef<[u8]> for UnShielded<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.shielded.memory[..self.plaintext_len]
    }
}

impl<'a> AsMut<[u8]> for UnShielded<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.shielded.memory[..self.plaintext_len].as_mut()
    }
}

impl<'a> Drop for UnShielded<'a> {
    fn drop(&mut self) {
        self.shielded.shield(Some(self.plaintext_len));
    }
}

fn new_prekey(rng: &SystemRandom) -> PreKey {
    let mut k = vec![MAGIC_BYTE; SHIELD_PREKEY_LEN];
    rng.fill(&mut k).expect("rng fill prekey");
    PreKey(k)
}

fn new_nonce(rng: &SystemRandom) -> Nonce {
    let mut n = vec![MAGIC_BYTE; SHIELD_CIPHER.nonce_len()];
    rng.fill(&mut n).expect("rng fill");
    Nonce(n)
}

fn new_key(prekey: &PreKey) -> Key {
    let d = digest::digest(&SHIELD_PREKEY_HASH, &prekey.0);
    let k = d.as_ref()[0..SHIELD_CIPHER.key_len()].to_owned();
    Key(k)
}

// This struct and following impls' are borrowed from Ring's tests.
struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
