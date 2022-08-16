// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Ed25519 keys.

use super::error::DecodingError;
use core::fmt;
use ed25519_compact as ed25519;
use rand::RngCore;
use zeroize::Zeroize;

/// An Ed25519 keypair.
#[derive(Clone)]
pub struct Keypair(ed25519::KeyPair);

impl Keypair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Keypair {
        Keypair(ed25519::KeyPair::generate())
    }

    /// Encode the keypair into a byte array by concatenating the bytes
    /// of the secret scalar and the compressed public point,
    /// an informal standard for encoding Ed25519 keypairs.
    pub fn encode(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[0..32].copy_from_slice(&*self.0.sk);
        bytes[32..64].copy_from_slice(&*self.0.pk);

        bytes
    }

    /// Decode a keypair from the [binary format](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5)
    /// produced by [`Keypair::encode`], zeroing the input on success.
    ///
    /// Note that this binary format is the same as `ed25519_dalek`'s and `ed25519_zebra`'s.
    pub fn decode(kp: &mut [u8]) -> Result<Keypair, DecodingError> {
        ed25519::KeyPair::from_slice(kp)
            .map(|k| {
                kp.zeroize();
                Keypair(k)
            })
            .map_err(|e| DecodingError::new("Ed25519 keypair").source(e))
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0
            .sk
            .sign(msg, Some(ed25519::Noise::generate()))
            .as_ref()
            .to_vec()
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.pk)
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> SecretKey {
        SecretKey(self.0.sk)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.0.pk)
            .finish()
    }
}

/// Demote an Ed25519 keypair to a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        SecretKey(kp.0.sk)
    }
}

/// Promote an Ed25519 secret key into a keypair.
// impl From<SecretKey> for Keypair {
//     fn from(sk: SecretKey) -> Keypair {
//         let secret: ed25519::SecretKey = (&sk.0).into();
//         let pk = ed25519::PublicKey::from(&secret);
//         Keypair(ed25519::KeyPair {
//             sk: sk.0,
//             pk,
//         })
//     }
// }

/// An Ed25519 public key.
#[derive(PartialEq, Eq, Clone)]
pub struct PublicKey(ed25519::PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(compressed): ")?;
        for byte in *self.0 {
            write!(f, "{:x}", byte)?;
        }
        Ok(())
    }
}

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        ed25519::Signature::from_slice(sig)
            .and_then(|s| self.0.verify(msg, &s))
            .is_ok()
    }

    /// Encode the public key into a byte array in compressed form, i.e.
    /// where one coordinate is represented by a single bit.
    pub fn encode(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.0.as_ref());

        bytes
    }

    /// Decode a public key from a byte array as produced by `encode`.
    pub fn decode(k: &[u8]) -> Result<PublicKey, DecodingError> {
        ed25519::PublicKey::from_slice(k)
            .map_err(|e| DecodingError::new("Ed25519 public key").source(e))
            .map(PublicKey)
    }
}

/// An Ed25519 secret key.
#[derive(Clone)]
pub struct SecretKey(ed25519::SecretKey);

/// View the bytes of the secret key.
impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    /// Generate a new Ed25519 secret key.
    pub fn generate() -> SecretKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SecretKey(
            ed25519::SecretKey::from_slice(&bytes).expect(
                "this returns `Err` only if the length is wrong; the length is correct; qed",
            ),
        )
    }

    /// Create an Ed25519 secret key from a byte slice, zeroing the input on success.
    /// If the bytes do not constitute a valid Ed25519 secret key, an error is
    /// returned.
    pub fn from_bytes(mut sk_bytes: impl AsMut<[u8]>) -> Result<SecretKey, DecodingError> {
        let sk_bytes = sk_bytes.as_mut();
        let secret = ed25519::SecretKey::from_slice(&*sk_bytes)
            .map_err(|e| DecodingError::new("Ed25519 secret key").source(e))?;
        sk_bytes.zeroize();
        Ok(SecretKey(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    fn eq_keypairs(kp1: &Keypair, kp2: &Keypair) -> bool {
        kp1.public() == kp2.public() && kp1.0.secret.as_bytes() == kp2.0.secret.as_bytes()
    }

    #[test]
    fn ed25519_keypair_encode_decode() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let mut kp1_enc = kp1.encode();
            let kp2 = Keypair::decode(&mut kp1_enc).unwrap();
            eq_keypairs(&kp1, &kp2) && kp1_enc.iter().all(|b| *b == 0)
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn ed25519_keypair_from_secret() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let mut sk = kp1.0.secret.to_bytes();
            let kp2 = Keypair::from(SecretKey::from_bytes(&mut sk).unwrap());
            eq_keypairs(&kp1, &kp2) && sk == [0u8; 32]
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn ed25519_signature() {
        let kp = Keypair::generate();
        let pk = kp.public();

        let msg = "hello world".as_bytes();
        let sig = kp.sign(msg);
        assert!(pk.verify(msg, &sig));

        let mut invalid_sig = sig.clone();
        invalid_sig[3..6].copy_from_slice(&[10, 23, 42]);
        assert!(!pk.verify(msg, &invalid_sig));

        let invalid_msg = "h3ll0 w0rld".as_bytes();
        assert!(!pk.verify(invalid_msg, &sig));
    }
}
