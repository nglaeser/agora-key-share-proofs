use blsful::inner_types::*;
use rand::{RngCore, CryptoRng};
use serde::{Deserialize, Serialize};
use subtle::Choice;
use zeroize::DefaultIsZeroes;
use crate::client::VerificationKey;
use crate::encrypt::*;
use crate::{KeyShareProofError, KeyShareProofResult, Universal};


/// The decryption keys for the cold storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct DecryptionKeys(pub [DecryptionKey; 2]);

impl DefaultIsZeroes for DecryptionKeys {}

impl DecryptionKeys {
    /// Generate new random decryption keys
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        DecryptionKeys([
            DecryptionKey::random(&mut rng),
            DecryptionKey::random(&mut rng),
        ])
    }

    /// Sign the message using the cold keys
    pub fn sign(&self, verification_key: VerificationKey, message: &[u8]) -> ColdSignature {
        let components = [
            verification_key.0 * self.0[0].0,
            verification_key.0 * self.0[1].0,
        ];
        let sk = Universal::hash_g2(&components);
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        ColdSignature(pt * sk)
    }

    /// Create a cold storage proof
    pub fn prove(&self) -> ColdStorageProof {
        let r1 = Scalar::random(&mut rand::rngs::OsRng);
        let r2 = Scalar::random(&mut rand::rngs::OsRng);
        let a1 = G2Projective::GENERATOR * r1;
        let a2 = G2Projective::GENERATOR * r2;
        let mut bytes = [0u8; 192 + 8];
        bytes[..96].copy_from_slice(a1.to_compressed().as_ref());
        bytes[96..192].copy_from_slice(a2.to_compressed().as_ref());
        bytes[192..].copy_from_slice(&1000u64.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let z1 = r1 + c * self.0[0].0;
        let z2 = r2 + c * self.0[1].0;
        ColdStorageProof { a1, a2, z1, z2 }
    }
}

impl From<&DecryptionKeys> for EncryptionKeys {
    fn from(value: &DecryptionKeys) -> Self {
        EncryptionKeys([
            EncryptionKey::from(&value.0[0]),
            EncryptionKey::from(&value.0[1]),
        ])
    }
}

/// The encryption keys for the hot storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct EncryptionKeys(pub [EncryptionKey; 2]);

impl EncryptionKeys {
    /// Encrypted share is of the form x_i + Universal::hash_g2(&[ek_1 ^ x, ek_2 ^ x, ek_3 ^ x])
    pub fn sign(&self, encrypted_share: Scalar, message: &[u8]) -> HotSignature {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        HotSignature(pt * encrypted_share)
    }
}

/// The signature for the wallet
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

    /// Verify the signature
    pub fn verify(&self, verification_key: VerificationKey, message: &[u8]) -> Choice {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(message, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_");
        multi_miller_loop(&[
            (&pt.to_affine(), &G2Prepared::from(verification_key.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(-G2Projective::GENERATOR.to_affine())),
        ]).final_exponentiation().is_identity()
    }
}

/// A cold storage signature
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct ColdSignature(pub G1Projective);

/// A hot storage signature
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct HotSignature(pub G1Projective);

/// The proof for the cold storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct ColdStorageProof {
    /// The first commitment
    pub a1: G2Projective,
    /// The second commitment
    pub a2: G2Projective,
    /// The first proof
    pub z1: Scalar,
    /// The second proof
    pub z2: Scalar,
}

impl ColdStorageProof {
    /// Verify the cold storage proof
    pub fn verify(&self, encryption_keys: &EncryptionKeys) -> KeyShareProofResult<()> {
        let mut bytes = [0u8; 192 + 8];
        bytes[..96].copy_from_slice(self.a1.to_compressed().as_ref());
        bytes[96..192].copy_from_slice(self.a2.to_compressed().as_ref());
        bytes[192..].copy_from_slice(&1000u64.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let lhs = G2Projective::GENERATOR * self.z1 + self.a1 * c;
        let rhs = encryption_keys.0[0].0 * self.z1 + encryption_keys.0[1].0 * self.z2;
        let result = lhs - rhs;
        if result.is_identity().into() {
            Ok(())
        } else {
            Err(KeyShareProofError::General("invalid cold storage proof".to_string()))
        }
    }
}

/// The payload for the client registration when submitting new encrypted shares
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Default)]
pub struct ClientRegisterPayload {
    /// The encrypted share
    pub encrypted_share: Scalar,
    /// The verification share
    pub verification_share: G2Projective,
    /// The KZG commitment to the polynomial
    pub commitment: G1Projective,
    /// The opening proof
    pub proof: G1Projective,
}