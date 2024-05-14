use blsful::inner_types::{Field, G2Projective, Scalar};
use itertools::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;
use crate::{KeyShareProofError, KeyShareProofResult};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct VerificationKey(pub G2Projective);

impl From<&SigningKey> for VerificationKey {
    fn from(s: &SigningKey) -> Self {
        VerificationKey(G2Projective::GENERATOR * s.0)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKey(pub Scalar);

impl DefaultIsZeroes for SigningKey {}

impl SigningKey {
    pub fn create_shares(&self, threshold: usize, num_shares: usize, mut rng: impl RngCore + CryptoRng) -> KeyShareProofResult<(Vec<SigningKeyShare>, SigningKeyPolynomial)> {
        if threshold > num_shares {
            return Err(KeyShareProofError::General("Threshold cannot be greater than the number of shares".to_string()));
        }
        if threshold < 2 {
            return Err(KeyShareProofError::General("Threshold must be at least 2".to_string()));
        }
        let mut shares = vec![SigningKeyShare::default(); num_shares];
        let polynomial = SigningKeyPolynomial::generate(self.0, threshold - 1, &mut rng);
        for (i, share) in shares.iter_mut().enumerate() {
            let sc = polynomial.evaluate(Scalar::from((i + 1) as u64));
            share.0 = ((i + 1) as u16, sc);
        }

        Ok((shares, polynomial))
    }

    pub fn from_shares(shares: &[SigningKeyShare]) -> KeyShareProofResult<Self> {
        if shares.len() < 2 {
            return Err(KeyShareProofError::General("At least 2 shares are required".to_string()));
        }
        if !shares.iter().map(|s| s.0.0).all_unique() {
            return Err(KeyShareProofError::General("Shares must have unique indices".to_string()));
        }
        let shares = shares.iter().map(|s| (Scalar::from(s.0.0 as u64), s.0.1)).collect_vec();
        let identifiers = shares.iter().map(|&s| s.0).collect_vec();
        let key = shares.iter().map(|&(i, s)| lagrange(i, identifiers.as_slice()) * s).sum();

        Ok(Self(key))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKeyShare(pub (u16, Scalar));


#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKeyPolynomial(pub Vec<Scalar>);

impl SigningKeyPolynomial {
    pub fn generate(zero: Scalar, size: usize, mut rng: impl RngCore + CryptoRng) -> Self {
        let mut coefficients = vec![Scalar::ZERO; size];
        coefficients[0] = zero;
        for c in &mut coefficients[1..] {
            *c = Scalar::random(&mut rng);
        }
        SigningKeyPolynomial(coefficients)
    }

    pub fn evaluate(&self, x: Scalar) -> Scalar {
        self.0.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
    }
}

fn lagrange(id: Scalar, others: &[Scalar]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in others {
        if id == j {
            continue;
        }
        num *= j;
        den *= j - id;
    }
    num * den.invert().expect("denominator is zero")
}
