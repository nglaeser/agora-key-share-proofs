use crate::{DensePolyPrimeField, KeyShareProofError, KeyShareProofResult};
use blsful::inner_types::group::prime::PrimeCurveAffine;
use blsful::inner_types::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Common Reference String for a Universal Setup
pub struct KZG10CommonReferenceParams {
    /// The powers of tau in the G1 group
    pub powers_of_g: Vec<G1Projective>,
    /// The powers of tau in the G2 group
    pub powers_of_h: [G2Projective; 2],
}

impl KZG10CommonReferenceParams {
    /// Generate a common reference string for the KZG10 scheme
    pub fn setup(max_degree: NonZeroUsize, rng: impl RngCore + CryptoRng) -> Self {
        let max_degree = max_degree.get();
        let tau = Scalar::random(rng);

        let mut powers_of_g = Vec::with_capacity(max_degree);

        let mut powers_of_tau = Vec::with_capacity(max_degree);
        powers_of_tau.push(Scalar::ONE);
        powers_of_tau.push(tau);

        powers_of_g.push(G1Projective::GENERATOR);
        powers_of_g.push(G1Projective::GENERATOR * tau);

        let powers_of_h = [G2Projective::GENERATOR, G2Projective::GENERATOR * tau];

        for i in 2..max_degree {
            let power_beta = powers_of_tau[i - 1] * tau;
            powers_of_tau.push(power_beta);
            powers_of_g.push(G1Projective::GENERATOR * power_beta);
        }

        Self {
            powers_of_g,
            powers_of_h,
        }
    }

    /// Commit to a polynomial in the G1 group
    pub fn commit_g1(&self, polynomial: &DensePolyPrimeField<Scalar>) -> G1Projective {
        if polynomial.0.len() > self.powers_of_g.len() {
            panic!("Polynomial degree is too high for the CRS");
        }
        // Allow for smaller polynomials
        G1Projective::sum_of_products(&self.powers_of_g[..polynomial.0.len()], &polynomial.0)
    }

    /// Open a polynomial in the G1 group
    pub fn open(&self, fx: &DensePolyPrimeField<Scalar>, challenge: Scalar) -> G1Projective {
        // f(x)
        let eval = fx.evaluate(&challenge);
        // f(i)
        let eval_poly = DensePolyPrimeField(vec![eval]);
        // f(x) - f(i)
        let num = fx - &eval_poly;
        // x - i
        let den = DensePolyPrimeField(vec![-challenge, Scalar::ONE]);
        // (f(x) - f(i)) / (x - i)
        let (quo, _) = num.poly_mod(&den);
        // π = Com(crs, q_i(x))
        self.commit_g1(&quo)
    }

    /// Confirm y = f(i)
    pub fn verify(
        &self,
        commitment: &G1Projective,
        i: Scalar,
        y: Scalar,
        proof: &G1Projective,
    ) -> KeyShareProofResult<()> {
        // g1^Y
        let comm = G1Projective::GENERATOR * y;
        // com_f / g1^Y
        let lhs = commitment - comm;

        // g2^𝜏 / g2^i
        let rhs = self.powers_of_h[1] - G2Projective::GENERATOR * i;

        // e(com_f / g1^Y, -g2) . e(π, g2^𝜏 / g2^i) == 1
        let res = multi_miller_loop(&[
            (&lhs.to_affine(), &G2Prepared::from(-G2Affine::generator())),
            (&proof.to_affine(), &G2Prepared::from(rhs.to_affine())),
        ])
        .final_exponentiation()
        .is_identity();

        if bool::from(res) {
            Ok(())
        } else {
            Err(KeyShareProofError::General("invalid proof".to_string()))
        }
    }
}

#[test]
fn test_kzg10() {
    use rand::SeedableRng;

    let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
    let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(10).unwrap(), &mut rng);
    let poly = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
    let commitment = crs.commit_g1(&poly);
    let i = Scalar::random(&mut rng);
    let proof = crs.open(&poly, i);
    let y = poly.evaluate(&i);
    assert!(crs.verify(&commitment, i, y, &proof).is_ok());
}
