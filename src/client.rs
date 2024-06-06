use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use blsful::inner_types::{Field, G2Projective, Scalar};
use itertools::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;
use crate::{ClientRegisterPayload, DensePolyPrimeField, EncryptionKeys, KeyShareProofError, KeyShareProofResult, KZG10CommonReferenceParams};

/// The verification key for the client
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct VerificationKey(pub G2Projective);

impl From<&SigningKey> for VerificationKey {
    fn from(s: &SigningKey) -> Self {
        VerificationKey(G2Projective::GENERATOR * s.0)
    }
}

/// The signing key for the client that they want to protect
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKey(pub Scalar);

impl DefaultIsZeroes for SigningKey {}

impl SigningKey {
    /// Create secret shares
    pub fn create_shares(&self, threshold: usize, num_shares: usize, mut rng: impl RngCore + CryptoRng) -> KeyShareProofResult<(Vec<SigningKeyShare>, DensePolyPrimeField<Scalar>)> {
        if threshold > num_shares {
            return Err(KeyShareProofError::General("Threshold cannot be greater than the number of shares".to_string()));
        }
        if threshold < 2 {
            return Err(KeyShareProofError::General("Threshold must be at least 2".to_string()));
        }
        let mut shares = vec![SigningKeyShare::default(); num_shares];
        let mut polynomial = DensePolyPrimeField::random(threshold, &mut rng);
        polynomial.0[0] = self.0;
        for (i, share) in shares.iter_mut().enumerate() {
            let sc = polynomial.evaluate(&Scalar::from((i + 1) as u64));
            share.id = (i + 1) as u16;
            share.threshold = threshold as u16;
            share.share = sc;
        }

        Ok((shares, polynomial))
    }

    /// Reconstruct the signing key from the shares
    pub fn from_shares(shares: &[SigningKeyShare]) -> KeyShareProofResult<Self> {
        if shares.len() < 2 {
            return Err(KeyShareProofError::General("At least 2 shares are required".to_string()));
        }
        if shares.len() < shares[0].threshold as usize {
            return Err(KeyShareProofError::General("Not enough shares to reconstruct the key".to_string()));
        }
        if !shares.iter().map(|s| s.id).all_unique() {
            return Err(KeyShareProofError::General("Shares must have unique indices".to_string()));
        }
        if shares.iter().any(|s| s.id == 0) {
            return Err(KeyShareProofError::General("Shares must have indices greater than 0".to_string()));
        }
        let shares = shares.iter().map(|s| (Scalar::from(s.id as u64), s.share)).collect_vec();
        let identifiers = shares.iter().map(|&s| s.0).collect_vec();
        let key = shares.iter().map(|&(i, s)| lagrange(i, identifiers.as_slice()) * s).sum();

        Ok(Self(key))
    }

    /// Generate encrypted shares for hot storage wallets
    pub fn generate_register_payloads<W: AsRef<EncryptionKeys>>(
        &self,
        threshold: usize,
        crs: &KZG10CommonReferenceParams,
        mut rng: impl RngCore + CryptoRng,
        hot_wallet_encryption_keys: W,
    ) -> KeyShareProofResult<Vec<ClientRegisterPayload>>
    {
        let encryption_keys = hot_wallet_encryption_keys.as_ref();
        let (shares, poly) = self.create_shares(threshold, encryption_keys.0.len(), &mut rng)?;
        let mut register_payloads = vec![ClientRegisterPayload::default(); shares.len()];

        let domain_size = threshold.next_power_of_two();
        let domain = GeneralEvaluationDomain::<Scalar>::new(domain_size).expect("Failed to create domain");
        let aux_domain = GeneralEvaluationDomain::<Scalar>::new(domain_size * 2).expect("Failed to create aux_domain");

        let t_evals = aux_domain.fft(&crs.powers_of_g);
        let d_evals = aux_domain.fft(&poly.0);

        let dt_evals = t_evals
            .iter()
            .zip(d_evals.iter())
            .map(|(t, d)| t * d)
            .collect::<Vec<_>>();

        let dt_poly = aux_domain.ifft(&dt_evals);
        let result = domain.fft(&dt_poly[domain_size..]);

        Ok(register_payloads)
    }
}

/// A share of the signing key
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKeyShare {
    pub(crate) id: u16,
    pub(crate) share: Scalar,
    pub(crate) threshold: u16,
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
