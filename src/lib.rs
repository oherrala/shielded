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

use ring::aead::{self, Nonce, OpeningKey, SealingKey};
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use aead::CHACHA20_POLY1305 as SHIELD_CIPHER;
use digest::SHA512 as SHIELD_PREKEY_HASH;
static SHIELD_PREKEY_LEN: usize = 16 * 1024;

/// A construct holding a piece of memory encrypted.
pub struct Shielded {
    prekey: Vec<u8>,
    nonce: Vec<u8>,
    memory: Vec<u8>,
}

impl Shielded {
    /// Construct a new `Shielded` memory.
    pub fn new(mut buf: Vec<u8>) -> Self {
        // Extend the vector to contain enough space for cipher's tag.
        buf.extend(vec![0xDF; SHIELD_CIPHER.tag_len()]);
        buf.shrink_to_fit();

        let mut shielded = Self {
            prekey: Vec::new(),
            nonce: Vec::new(),
            memory: buf,
        };

        shielded.shield();
        shielded
    }

    fn shield(&mut self) {
        let rng = ring::rand::SystemRandom::new();
        let prekey = new_prekey(&rng);
        let nonce_bytes = new_nonce(&rng);
        let key = prekey_to_key(&prekey);
        let sealing_key = SealingKey::new(&SHIELD_CIPHER, &key).expect("new SealingKey");
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).expect("new Nonce");
        let tag_len = SHIELD_CIPHER.tag_len();

        // Add prekey into additionally authenticated data. This authenticates
        // the prekey, but doesn't encrypt it. If the authentication check fails
        // on decryption, something has modified the prekey kept in memory.
        let aad = aead::Aad::from(&prekey);

        let _out_len = aead::seal_in_place(&sealing_key, nonce, aad, &mut self.memory, tag_len)
            .expect("seal in place");
        self.prekey = prekey;
        self.nonce = nonce_bytes;

        debug_assert_eq!(self.prekey.len(), SHIELD_PREKEY_LEN);
        debug_assert_eq!(self.nonce.len(), SHIELD_CIPHER.nonce_len());
    }

    /// Decrypt the Shielded content in-place.
    pub fn unshield(&mut self) -> UnShielded<'_> {
        let key = prekey_to_key(&self.prekey);
        let opening_key = OpeningKey::new(&SHIELD_CIPHER, &key).expect("new OpeningKey");
        let nonce = Nonce::try_assume_unique_for_key(&self.nonce).expect("new Nonce");
        let aad = aead::Aad::from(&self.prekey);

        let plaintext = aead::open_in_place(&opening_key, nonce, aad, 0, &mut self.memory)
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

/// UnShielded memory containing decrypted contents of what previously was
/// encrypted. After `UnShielded` goes out of scope or is dropped, the `Shielded` is
/// reinitialized with new cryptographic keys and the contents are crypted
/// again.
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

impl<'a> Drop for UnShielded<'a> {
    fn drop(&mut self) {
        self.shielded.shield();
    }
}

fn new_prekey(rng: &SystemRandom) -> Vec<u8> {
    let mut k = vec![0xDF; SHIELD_PREKEY_LEN];
    rng.fill(&mut k).expect("rng fill prekey");
    k
}

fn new_nonce(rng: &SystemRandom) -> Vec<u8> {
    let mut n = vec![0xDF; SHIELD_CIPHER.nonce_len()];
    rng.fill(&mut n).expect("rng fill");
    n
}

fn prekey_to_key(prekey: &[u8]) -> Vec<u8> {
    let d = digest::digest(&SHIELD_PREKEY_HASH, &prekey);
    d.as_ref()[0..SHIELD_CIPHER.key_len()].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    #[test]
    fn test_shielded_unshield() {
        let buf = vec![0xAA; 5 * 1789 /* Yep, strange numbers */];

        let original = buf.clone();
        let mut shielded = Shielded::new(buf);

        let unshielded = shielded.unshield();
        assert_eq!(original, unshielded.as_ref());
    }

    quickcheck! {
        fn prop_shield_unshield(xs: Vec<u8>) -> bool {
            let original = xs.clone();
            let mut shielded = Shielded::new(xs);
            let unshielded = shielded.unshield();
            original == unshielded.as_ref()
        }
    }
}
