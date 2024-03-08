use crate::hash::consts::UniversalHashIter;
use blsful::inner_types::*;
use subtle::{Choice, ConditionallySelectable};

mod consts;

/// The universal hash function
#[derive(Debug, Copy, Clone)]
pub struct Universal;

impl Universal {
    /// Hashes the input into a scalar
    pub fn hash(input: &[G1Projective; 3]) -> Scalar {
        let mut output = Scalar::ZERO;
        let mut iter = UniversalHashIter::default();
        for p in input {
            for b in p.to_compressed() {
                for j in (0..8).rev() {
                    let (zero, one) = iter.next().expect("not enough parameters");
                    let bit = (b >> j) & 1;
                    output += Scalar::conditional_select(&zero, &one, Choice::from(bit));
                }
            }
        }
        output
    }
}

#[test]
fn test_universal_hash() {
    let input = [
        G1Projective::generator(),
        G1Projective::generator(),
        G1Projective::generator(),
    ];
    let output = Universal::hash(&input);
    assert_eq!(
        output,
        Scalar::from_be_hex("50916b48d7e1eab86c271dbedfad5b38b476c0ca71d7db63541d673bdb81de07")
            .unwrap()
    );
}
