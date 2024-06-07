use crate::KeyShareProofError;
use blsful::inner_types::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter, LowerHex, UpperHex},
    str::FromStr,
};
use zeroize::DefaultIsZeroes;

/// The decryption key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecryptionKey(pub Scalar);

impl DefaultIsZeroes for DecryptionKey {}

impl From<&DecryptionKey> for Vec<u8> {
    fn from(d: &DecryptionKey) -> Vec<u8> {
        d.0.to_be_bytes().to_vec()
    }
}

impl From<DecryptionKey> for Vec<u8> {
    fn from(d: DecryptionKey) -> Vec<u8> {
        Self::from(&d)
    }
}

impl From<&DecryptionKey> for [u8; 32] {
    fn from(d: &DecryptionKey) -> [u8; 32] {
        d.0.to_be_bytes()
    }
}

impl From<DecryptionKey> for [u8; 32] {
    fn from(d: DecryptionKey) -> [u8; 32] {
        Self::from(&d)
    }
}

impl TryFrom<&[u8]> for DecryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| KeyShareProofError::General("Invalid bytes length".to_string()))?;
        let s = Option::<Scalar>::from(Scalar::from_be_bytes(&bytes))
            .ok_or(KeyShareProofError::General("Invalid bytes".to_string()))?;
        Ok(Self(s))
    }
}

impl TryFrom<Vec<u8>> for DecryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&Vec<u8>> for DecryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<Box<[u8]>> for DecryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl Display for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_be_bytes()))
    }
}

impl LowerHex for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl UpperHex for DecryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0.to_be_bytes()))
    }
}

impl FromStr for DecryptionKey {
    type Err = KeyShareProofError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|_| KeyShareProofError::General("Invalid hex string".to_string()))?;
        Self::try_from(bytes)
    }
}

impl DecryptionKey {
    /// Generate a random decryption key
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        DecryptionKey(Scalar::random(&mut rng))
    }

    /// Get the encryption key associated with this decryption key
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey(G2Projective::GENERATOR * self.0)
    }
}

/// The encryption key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EncryptionKey(pub G2Projective);

impl From<&DecryptionKey> for EncryptionKey {
    fn from(d: &DecryptionKey) -> EncryptionKey {
        EncryptionKey(G2Projective::GENERATOR * d.0)
    }
}

impl From<DecryptionKey> for EncryptionKey {
    fn from(d: DecryptionKey) -> EncryptionKey {
        EncryptionKey::from(&d)
    }
}

impl From<&EncryptionKey> for Vec<u8> {
    fn from(d: &EncryptionKey) -> Vec<u8> {
        d.0.to_compressed().to_vec()
    }
}

impl From<EncryptionKey> for Vec<u8> {
    fn from(d: EncryptionKey) -> Vec<u8> {
        Self::from(&d)
    }
}

impl From<&EncryptionKey> for [u8; 96] {
    fn from(d: &EncryptionKey) -> [u8; 96] {
        d.0.to_compressed()
    }
}

impl From<EncryptionKey> for [u8; 96] {
    fn from(d: EncryptionKey) -> [u8; 96] {
        Self::from(&d)
    }
}

impl TryFrom<&[u8]> for EncryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes
            .try_into()
            .map_err(|_| KeyShareProofError::General("Invalid bytes length".to_string()))?;
        let s = Option::<G2Projective>::from(G2Projective::from_compressed(&bytes))
            .ok_or(KeyShareProofError::General("Invalid bytes".to_string()))?;
        Ok(Self(s))
    }
}

impl TryFrom<Vec<u8>> for EncryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&Vec<u8>> for EncryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<Box<[u8]>> for EncryptionKey {
    type Error = KeyShareProofError;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl Display for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_compressed()))
    }
}

impl LowerHex for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl UpperHex for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0.to_compressed()))
    }
}

impl FromStr for EncryptionKey {
    type Err = KeyShareProofError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|_| KeyShareProofError::General("Invalid hex string".to_string()))?;
        Self::try_from(bytes)
    }
}

impl EncryptionKey {}
