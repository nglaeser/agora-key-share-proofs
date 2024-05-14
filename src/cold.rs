use blsful::inner_types::*;
use rand::{RngCore, CryptoRng};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use zeroize::DefaultIsZeroes;
use crate::client::VerificationKey;
use crate::encrypt::*;
use crate::Universal;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct DecryptionKeys(pub [DecryptionKey; 3]);

impl DefaultIsZeroes for DecryptionKeys {}

impl DecryptionKeys {
    /// Generate new random decryption keys
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        DecryptionKeys([
            DecryptionKey::random(&mut rng),
            DecryptionKey::random(&mut rng),
            DecryptionKey::random(&mut rng),
        ])
    }

    pub fn sign(&self, verification_key: VerificationKey, message: &[u8]) -> ColdSignature {
        let components = [
            verification_key.0 * self.0[0].0,
            verification_key.0 * self.0[1].0,
            verification_key.0 * self.0[2].0,
        ];
        let sk = Universal::hash_g2(&components);
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        ColdSignature(pt * sk)
    }
}

impl From<&DecryptionKeys> for EncryptionKeys {
    fn from(value: &DecryptionKeys) -> Self {
        EncryptionKeys([
            EncryptionKey::from(&value.0[0]),
            EncryptionKey::from(&value.0[1]),
            EncryptionKey::from(&value.0[2]),
        ])
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct EncryptionKeys(pub [EncryptionKey; 3]);

impl EncryptionKeys {
    /// Encrypt a message
    pub fn encrypt(&self, m: Scalar, mut rng: impl RngCore + CryptoRng) -> Ciphertext {
        let r = Scalar::random(&mut rng);
        let c1 = G1Projective::GENERATOR * r;
        let c2 = m + Universal::hash_g2(&[self.0[0].0 * r, self.0[1].0, self.0[2].0]);
        Ciphertext { c1, c2 }
    }

    /// Encrypted share is of the form x_i + Universal::hash_g2(&[ek_1 ^ x, ek_2 ^ x, ek_3 ^ x])
    pub fn sign(&self, encrypted_share: Scalar, message: &[u8]) -> HotSignature {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        HotSignature(pt * encrypted_share)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct Signature(pub G1Projective);

impl Signature {
    /// Reconstruct a signature from a list of signatures without checking
    /// whether the signatures are valid
    pub fn reconstruct_unchecked(signatures: &[(HotSignature, ColdSignature)]) -> Self {
        Signature(signatures.iter().fold(G1Projective::IDENTITY, |acc, &(hot, cold)| {
            acc + (hot.0 - cold.0)
        }))
    }

    pub fn verify(&self, verification_key: VerificationKey, message: &[u8]) -> Choice {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        multi_miller_loop(&[
            (&pt.to_affine(), &G2Prepared::from(verification_key.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(-G2Projective::GENERATOR.to_affine())),
        ]).final_exponentiation().is_identity()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct ColdSignature(pub G1Projective);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct HotSignature(pub G1Projective);
