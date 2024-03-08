use blsful::inner_types::*;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sha2::digest::Reset;

/// The total number of compressed bytes in a G1 point times 3
pub const TOTAL_POINT_BYTES: usize = 48 * 3;
/// The total number of bits to operate over in the hash function
pub const TOTAL_HASH_PARAMETER_BITS: usize = TOTAL_POINT_BYTES * 8;
/// The prime number 113910913923300788319699387848674650656041243163866388656000063249848353322899
/// which is also a cunningham chain of the first kind with a length of 5
pub const PARAMETER_SEED_RNG: [u8; 32] = [
    0x93, 0x77, 0x32, 0xf5, 0xd6, 0x96, 0x63, 0x49, 0x58, 0xb2, 0xbb, 0x7d, 0x91, 0x9c, 0x40, 0xd7,
    0x45, 0x8d, 0xe5, 0xdb, 0xb1, 0xe5, 0x3a, 0xf6, 0x15, 0xa1, 0x1d, 0x8c, 0xe1, 0x4a, 0xd7, 0xfb,
];

#[derive(Debug, Clone)]
pub struct UniversalHashIter {
    rng: ChaChaRng,
    index: usize,
}

impl Default for UniversalHashIter {
    fn default() -> Self {
        UniversalHashIter {
            rng: ChaChaRng::from_seed(PARAMETER_SEED_RNG),
            index: 0,
        }
    }
}

impl Reset for UniversalHashIter {
    fn reset(&mut self) {
        self.rng = ChaChaRng::from_seed(PARAMETER_SEED_RNG);
        self.index = 0;
    }
}

impl Iterator for UniversalHashIter {
    type Item = (Scalar, Scalar);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < TOTAL_HASH_PARAMETER_BITS {
            let zero = Scalar::random(&mut self.rng);
            let one = Scalar::random(&mut self.rng);
            self.index += 1;
            Some((zero, one))
        } else {
            None
        }
    }
}

// TOO SLOW, left for reference purposes
// pub fn parameters() -> ([Scalar; TOTAL_HASH_PARAMETER_BITS], [Scalar; TOTAL_HASH_PARAMETER_BITS]) {
//     let mut rng = ChaChaRng::from_seed(PARAMETER_SEED_RNG);
//     let mut zeros = [Scalar::ZERO; TOTAL_HASH_PARAMETER_BITS];
//     let mut ones = [Scalar::ZERO; TOTAL_HASH_PARAMETER_BITS];
//     for i in 0..TOTAL_HASH_PARAMETER_BITS {
//         zeros[i] = Scalar::random(&mut rng);
//         ones[i] = Scalar::random(&mut rng);
//     }
//     (zeros, ones)
// }
