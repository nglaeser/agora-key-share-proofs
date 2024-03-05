/*
    Copyright Hyperledger. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use super::*;
use blsful::inner_types::PrimeField;
use rand::{Rng, RngCore};
use serde::{de::Error as E, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// A sparse polynomial over a prime field.
#[derive(Clone, PartialEq, Eq)]
pub struct SparsePolyPrimeField<F: PrimeField>(
    /// The coefficients and the powers of the polynomial
    pub BTreeMap<usize, F>,
);

unsafe impl<F: PrimeField> Send for SparsePolyPrimeField<F> {}

unsafe impl<F: PrimeField> Sync for SparsePolyPrimeField<F> {}

impl<F: PrimeField> Default for SparsePolyPrimeField<F> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<F: PrimeField> Debug for SparsePolyPrimeField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "SparsePolyPrimeField({:?})", self.0)
    }
}

impl<F: PrimeField> Display for SparsePolyPrimeField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let vals = self
            .0
            .iter()
            .map(|(power, c)| {
                let repr = c.to_repr();
                let len = repr.as_ref().len();
                let c = hex::encode(repr.as_ref());
                if *power == 0 {
                    let mut builder = "0x".to_string();
                    while builder.len() < len - 1 {
                        builder.push('0');
                    }
                    builder.push('1');
                    builder
                } else if *power == 1 {
                    format!("0x{}", c)
                } else {
                    format!("0x{}{}", c, to_super_script_digits(power + 1))
                }
            })
            .collect::<Vec<_>>()
            .join(" + ");
        write!(f, "{}", vals)
    }
}

impl<F: PrimeField> Add<&SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn add(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        output += rhs;
        output
    }
}

impl<F: PrimeField> Add<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn add(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        &self + rhs
    }
}

impl<F: PrimeField> Add<SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn add(self, rhs: SparsePolyPrimeField<F>) -> Self::Output {
        self + &rhs
    }
}

impl<F: PrimeField> Add for SparsePolyPrimeField<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<F: PrimeField> AddAssign<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: &SparsePolyPrimeField<F>) {
        for (exp, coeff) in &rhs.0 {
            match self.0.entry(*exp) {
                Entry::Occupied(e) => {
                    let new_coeff = e.remove() + coeff;
                    if new_coeff != F::ZERO {
                        self.0.insert(*exp, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if *coeff != F::ZERO {
                        e.insert(*coeff);
                    }
                }
            }
        }
    }
}

impl<F: PrimeField> AddAssign<SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: SparsePolyPrimeField<F>) {
        *self += &rhs;
    }
}

impl<F: PrimeField> Add<&DensePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn add(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        output += rhs;
        output
    }
}

impl<F: PrimeField> Add<DensePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn add(self, rhs: DensePolyPrimeField<F>) -> Self::Output {
        self + &rhs
    }
}

impl<F: PrimeField> Add<&DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    type Output = Self;

    fn add(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        &self + rhs
    }
}

impl<F: PrimeField> Add<DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    type Output = Self;

    fn add(self, rhs: DensePolyPrimeField<F>) -> Self::Output {
        &self + &rhs
    }
}

impl<F: PrimeField> AddAssign<&DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: &DensePolyPrimeField<F>) {
        *self += Self::from(rhs);
    }
}

impl<F: PrimeField> AddAssign<DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: DensePolyPrimeField<F>) {
        *self += &rhs;
    }
}

impl<F: PrimeField> Sub<&SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn sub(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        output -= rhs;
        output
    }
}

impl<F: PrimeField> Sub<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn sub(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        &self - rhs
    }
}

impl<F: PrimeField> Sub<SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn sub(self, rhs: SparsePolyPrimeField<F>) -> Self::Output {
        self - &rhs
    }
}

impl<F: PrimeField> Sub for SparsePolyPrimeField<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl<F: PrimeField> SubAssign<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn sub_assign(&mut self, rhs: &SparsePolyPrimeField<F>) {
        for (exp, coeff) in &rhs.0 {
            match self.0.entry(*exp) {
                Entry::Occupied(e) => {
                    let new_coeff = e.remove() - coeff;
                    if new_coeff != F::ZERO {
                        self.0.insert(*exp, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if *coeff != F::ZERO {
                        e.insert(-*coeff);
                    }
                }
            }
        }
    }
}

impl<F: PrimeField> SubAssign<SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn sub_assign(&mut self, rhs: SparsePolyPrimeField<F>) {
        *self -= &rhs;
    }
}

impl<F: PrimeField> Neg for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn neg(self) -> Self::Output {
        let mut output = self.clone();
        for (_, c) in output.0.iter_mut() {
            *c = -(*c);
        }
        output
    }
}

impl<F: PrimeField> Neg for SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<F: PrimeField> Mul<&SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn mul(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        output *= rhs;
        output
    }
}

impl<F: PrimeField> Mul<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn mul(self, rhs: &SparsePolyPrimeField<F>) -> Self::Output {
        &self * rhs
    }
}

impl<F: PrimeField> Mul<SparsePolyPrimeField<F>> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn mul(self, rhs: SparsePolyPrimeField<F>) -> Self::Output {
        self * &rhs
    }
}

impl<F: PrimeField> Mul for SparsePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<F: PrimeField> MulAssign<&SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: &SparsePolyPrimeField<F>) {
        let mut result = SparsePolyPrimeField::default();

        for (exp1, coeff1) in &self.0 {
            for (exp2, coeff2) in &rhs.0 {
                let new_exp = exp1 + exp2;
                let mut new_coeff = *coeff1 * *coeff2;
                if new_coeff != F::ZERO {
                    match result.0.entry(new_exp) {
                        Entry::Occupied(e) => {
                            new_coeff += e.remove();
                            if new_coeff != F::ZERO {
                                result.0.insert(new_exp, new_coeff);
                            }
                        }
                        Entry::Vacant(e) => {
                            if new_coeff != F::ZERO {
                                e.insert(new_coeff);
                            }
                        }
                    }
                }
            }
        }

        *self = result
    }
}

impl<F: PrimeField> MulAssign<SparsePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: SparsePolyPrimeField<F>) {
        *self *= &rhs;
    }
}

impl<F: PrimeField> Mul<&F> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;
    fn mul(self, rhs: &F) -> Self::Output {
        self * *rhs
    }
}

impl<F: PrimeField> Mul<F> for &SparsePolyPrimeField<F> {
    type Output = SparsePolyPrimeField<F>;

    fn mul(self, rhs: F) -> Self::Output {
        let mut output = self.clone();
        output *= rhs;
        output
    }
}

impl<F: PrimeField> Mul<&F> for SparsePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        &self * *rhs
    }
}

impl<F: PrimeField> Mul<F> for SparsePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        &self * rhs
    }
}

impl<F: PrimeField> MulAssign<&F> for SparsePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: &F) {
        *self *= *rhs;
    }
}

impl<F: PrimeField> MulAssign<F> for SparsePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.0.iter_mut().for_each(|(_, coeff)| *coeff *= rhs);
    }
}

impl<F: PrimeField> Serialize for SparsePolyPrimeField<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            self.0
                .iter()
                .map(|(power, c)| (power.to_string(), hex::encode(c.to_repr().as_ref())))
                .collect::<Vec<_>>()
                .serialize(s)
        } else {
            let repr = F::Repr::default();
            let len = repr.as_ref().len();
            let mut rows = Vec::with_capacity(self.0.len());
            for (power, c) in &self.0 {
                let mut bytes = Vec::with_capacity(len + 8);
                let p = *power as u64;
                bytes.extend_from_slice(c.to_repr().as_ref());
                bytes.extend_from_slice(&p.to_be_bytes());
                rows.push(bytes);
            }
            rows.serialize(s)
        }
    }
}

impl<'de, F: PrimeField> Deserialize<'de> for SparsePolyPrimeField<F> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let v: Vec<(String, String)> = Vec::deserialize(d)?;
            let mut result = SparsePolyPrimeField::default();
            for (power, c) in &v {
                let repr_bytes = hex::decode(c).map_err(E::custom)?;
                let mut repr = F::Repr::default();
                repr.as_mut().copy_from_slice(&repr_bytes);
                let c = Option::<F>::from(F::from_repr(repr))
                    .ok_or(E::custom("invalid bytes for element"))?;
                let power = power.parse().map_err(E::custom)?;
                result.0.insert(power, c);
            }
            Ok(result)
        } else {
            let v: Vec<Vec<u8>> = Vec::deserialize(d)?;
            let mut result = SparsePolyPrimeField::default();
            for bytes in &v {
                let mut repr = F::Repr::default();
                let len = repr.as_ref().len();
                if bytes.len() < len + 8 {
                    return Err(E::custom("Invalid byte length"));
                }
                repr.as_mut().copy_from_slice(&bytes[..len]);
                let c = Option::<F>::from(F::from_repr(repr))
                    .ok_or(E::custom("Invalid field bytes"))?;
                let power = u64::from_be_bytes([
                    bytes[len],
                    bytes[len + 1],
                    bytes[len + 2],
                    bytes[len + 3],
                    bytes[len + 4],
                    bytes[len + 5],
                    bytes[len + 6],
                    bytes[len + 7],
                ]) as usize;
                result.0.insert(power, c);
            }
            Ok(result)
        }
    }
}

impl<F: PrimeField> FromIterator<(usize, F)> for SparsePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = (usize, F)>>(iter: T) -> Self {
        let mut inner = BTreeMap::new();
        for (power, coeff) in iter {
            match inner.entry(power) {
                Entry::Occupied(e) => {
                    let new_coeff = coeff + e.remove();
                    if new_coeff != F::ZERO {
                        inner.insert(power, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if coeff != F::ZERO {
                        e.insert(coeff);
                    }
                }
            }
        }
        Self(inner)
    }
}

impl<'a, F: PrimeField> FromIterator<(&'a usize, F)> for SparsePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = (&'a usize, F)>>(iter: T) -> Self {
        let mut inner = BTreeMap::new();
        for (power, coeff) in iter {
            match inner.entry(*power) {
                Entry::Occupied(e) => {
                    let new_coeff = coeff + e.remove();
                    if new_coeff != F::ZERO {
                        inner.insert(*power, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if coeff != F::ZERO {
                        e.insert(coeff);
                    }
                }
            }
        }
        Self(inner)
    }
}

impl<'a, F: PrimeField> FromIterator<(usize, &'a F)> for SparsePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = (usize, &'a F)>>(iter: T) -> Self {
        let mut inner = BTreeMap::new();
        for (power, coeff) in iter {
            match inner.entry(power) {
                Entry::Occupied(e) => {
                    let new_coeff = *coeff + e.remove();
                    if new_coeff != F::ZERO {
                        inner.insert(power, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if *coeff != F::ZERO {
                        e.insert(*coeff);
                    }
                }
            }
        }
        Self(inner)
    }
}

impl<'a, F: PrimeField> FromIterator<(&'a usize, &'a F)> for SparsePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = (&'a usize, &'a F)>>(iter: T) -> Self {
        let mut inner = BTreeMap::new();
        for (power, coeff) in iter {
            match inner.entry(*power) {
                Entry::Occupied(e) => {
                    let new_coeff = *coeff + e.remove();
                    if new_coeff != F::ZERO {
                        inner.insert(*power, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if *coeff != F::ZERO {
                        e.insert(*coeff);
                    }
                }
            }
        }
        Self(inner)
    }
}

impl<'a, F: PrimeField> FromIterator<&'a (usize, F)> for SparsePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = &'a (usize, F)>>(iter: T) -> Self {
        let mut inner = BTreeMap::new();
        for (power, coeff) in iter {
            match inner.entry(*power) {
                Entry::Occupied(e) => {
                    let new_coeff = *coeff + e.remove();
                    if new_coeff != F::ZERO {
                        inner.insert(*power, new_coeff);
                    }
                }
                Entry::Vacant(e) => {
                    if *coeff != F::ZERO {
                        e.insert(*coeff);
                    }
                }
            }
        }
        Self(inner)
    }
}

impl<F: PrimeField> From<&DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn from(value: &DensePolyPrimeField<F>) -> Self {
        Self::from_iter(value.0.iter().enumerate())
    }
}

impl<F: PrimeField> From<DensePolyPrimeField<F>> for SparsePolyPrimeField<F> {
    fn from(value: DensePolyPrimeField<F>) -> Self {
        Self::from(&value)
    }
}

impl<F: PrimeField> From<&[(usize, F)]> for SparsePolyPrimeField<F> {
    fn from(value: &[(usize, F)]) -> Self {
        SparsePolyPrimeField::from_iter(value)
    }
}

impl<F: PrimeField> From<Vec<(usize, F)>> for SparsePolyPrimeField<F> {
    fn from(value: Vec<(usize, F)>) -> Self {
        Self::from(value.as_slice())
    }
}

impl<F: PrimeField> From<&Vec<(usize, F)>> for SparsePolyPrimeField<F> {
    fn from(value: &Vec<(usize, F)>) -> Self {
        Self::from(value.as_slice())
    }
}

impl<F: PrimeField> From<SparsePolyPrimeField<F>> for Vec<u8> {
    fn from(value: SparsePolyPrimeField<F>) -> Self {
        Self::from(&value)
    }
}

impl<F: PrimeField> From<&SparsePolyPrimeField<F>> for Vec<u8> {
    fn from(value: &SparsePolyPrimeField<F>) -> Self {
        serde_bare::to_vec(value).expect("to serialize to bytes")
    }
}

impl<F: PrimeField> TryFrom<Vec<u8>> for SparsePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<F: PrimeField> TryFrom<&Vec<u8>> for SparsePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<F: PrimeField> TryFrom<&[u8]> for SparsePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let s = serde_bare::from_slice(value).map_err(|_e| "invalid bytes")?;
        Ok(s)
    }
}

impl<F: PrimeField> TryFrom<Box<[u8]>> for SparsePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl<F: PrimeField> SparsePolyPrimeField<F> {
    /// The zero polynomial
    pub const ZERO: Self = Self(BTreeMap::new());

    /// Check if the polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// Create a polynomial with a value of 1
    pub fn one() -> Self {
        let mut map = BTreeMap::new();
        map.insert(0, F::ONE);
        Self(map)
    }

    /// Return the degree of the polynomial
    pub fn degree(&self) -> usize {
        if let Some((power, _)) = self.0.last_key_value() {
            *power
        } else {
            0
        }
    }

    /// Is this polynomial a cyclotomic polynomial
    pub fn is_cyclotomic(&self) -> bool {
        let m_one = -F::ONE;
        for coeff in self.0.values() {
            if (!(coeff.ct_eq(&m_one) | coeff.ct_eq(&F::ZERO))).into() {
                return false;
            }
        }
        true
    }

    /// Generate a random sparse polynomial where the length is defined by the `num_terms`
    /// and the powers are randomly less than `max_power`
    pub fn random(num_terms: usize, max_power: usize, mut rng: impl RngCore) -> Self {
        let mut coeffs = BTreeMap::new();
        while coeffs.len() < num_terms {
            let power = rng.gen::<usize>() % max_power;
            let s = F::random(&mut rng);
            coeffs.entry(power).and_modify(|c| *c += s).or_insert(s);
        }
        Self(coeffs)
    }

    /// Compute the dot product of the two polynomials
    pub fn dot_product(&self, other: &Self) -> F {
        self.0
            .iter()
            .map(|(power, c)| other.0.get(power).map(|c2| *c * *c2).unwrap_or(F::ZERO))
            .sum()
    }

    /// Evaluate the polynomial for a given value
    pub fn evaluate(&self, x: &F) -> F {
        self.0.iter().fold(F::ZERO, move |acc, (power, c)| {
            acc + *c * x.pow([*power as u64])
        })
    }

    /// Compute the polynomial division and return the quotient and remainder
    pub fn poly_mod(&self, m: &Self) -> (Self, Self) {
        // Ensure divisor is not zero
        assert!(!m.0.is_empty());

        let self_degree = self.degree();
        let m_degree = m.degree();
        if self_degree < m_degree {
            return (Self::ZERO, self.clone());
        }

        let mut quotient = SparsePolyPrimeField(BTreeMap::new());
        let mut remainder = self.clone();

        // Loop until the remainder's degree is less than the divisor's degree
        let lead_term_div = m.0.last_key_value().expect("should be at least one entry");
        let largest_coeff_inv = lead_term_div
            .1
            .invert()
            .expect("lead term should not be zero");
        while !remainder.0.is_empty() && remainder.degree() >= m_degree {
            // Calculate the leading term of the remainder and divisor
            let lead_term_rem = remainder
                .0
                .last_key_value()
                .expect("remainder should have at least one entry");

            // Calculate the exponent and coefficient for the division
            let exp_diff = lead_term_rem.0 - lead_term_div.0;
            let coeff_div = *lead_term_rem.1 * largest_coeff_inv;

            if coeff_div == F::ZERO {
                continue;
            }

            // Add the term to the quotient
            quotient.0.insert(exp_diff, coeff_div);

            // Subtract the term (divisor * coeff_div * x^exp_diff) from the remainder
            let term_to_subtract =
                m.0.iter()
                    .map(|(exp, coeff)| (*exp + exp_diff, *coeff * coeff_div))
                    .collect::<BTreeMap<_, _>>();
            remainder -= SparsePolyPrimeField(term_to_subtract);
        }

        (quotient, remainder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsful::inner_types::Scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn add() {
        let mut rng = ChaChaRng::from_seed([4u8; 32]);
        let a = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        let b = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        assert!(a.degree() < 100);
        assert!(b.degree() < 100);
        let c = &a + &b;
        assert_eq!(c.0.len(), 8);
    }

    #[test]
    fn sub() {
        let mut rng = ChaChaRng::from_seed([4u8; 32]);
        let a = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        let b = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        assert!(a.degree() < 100);
        assert!(b.degree() < 100);
        let c = &a - &b;
        assert_eq!(c.0.len(), 8);
    }

    #[test]
    fn mul() {
        let mut rng = ChaChaRng::from_seed([8u8; 32]);
        let a = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        let b = SparsePolyPrimeField::<Scalar>::random(4, 100, &mut rng);
        let c = &a * &b;
        println!("{}", c);
    }

    #[test]
    fn poly_mod() {
        // x^4 - 2x^2 - 4
        let mut dividend = SparsePolyPrimeField::default();
        dividend.0.insert(3, Scalar::ONE);
        dividend.0.insert(2, -Scalar::from(2u32));
        dividend.0.insert(0, -Scalar::from(4u32));

        // x - 3
        let mut divisor = SparsePolyPrimeField::default();
        divisor.0.insert(1, Scalar::ONE);
        divisor.0.insert(0, -Scalar::from(3u32));

        let (quotient, remainder) = dividend.poly_mod(&divisor);

        assert_eq!(quotient.0.len(), 3);
        assert_eq!(quotient.0.get(&2), Some(Scalar::ONE).as_ref());
        assert_eq!(quotient.0.get(&1), Some(Scalar::ONE).as_ref());
        assert_eq!(quotient.0.get(&0), Some(Scalar::from(3u32)).as_ref());
        assert_eq!(remainder.0.len(), 1);
        assert_eq!(remainder.0.get(&0), Some(Scalar::from(5u32)).as_ref());

        let mut res = quotient * divisor;
        res += remainder;
        assert_eq!(res, dividend);

        let mut rng = ChaChaRng::from_seed([9u8; 32]);

        let a = SparsePolyPrimeField::<Scalar>::random(4, 20, &mut rng);
        let b = SparsePolyPrimeField::<Scalar>::random(2, 10, &mut rng);

        let (div, rem) = a.poly_mod(&b);
        let div_b = &div * &b;
        let div_b_pr = &div_b + &rem;
        assert_eq!(a, div_b_pr);

        let (div, rem) = b.poly_mod(&a);
        assert_eq!(div, SparsePolyPrimeField::default());
        assert_eq!(rem, b);
    }

    #[test]
    fn poly_mod_cyclotomic() {
        let mut rng = ChaChaRng::from_seed([9u8; 32]);
        let a = SparsePolyPrimeField::<Scalar>::random(10, 100, &mut rng);
        let mut b = SparsePolyPrimeField::default();
        b.0.insert(a.degree() / 2, Scalar::ONE);
        b.0.insert(0, -Scalar::ONE);

        let (div, rem) = a.poly_mod(&b);
        let div_b = &div * &b;
        let div_b_pr = &div_b + &rem;
        assert_eq!(a, div_b_pr);
    }

    #[test]
    fn dot_product() {
        let a = SparsePolyPrimeField(maplit::btreemap! {
            1 => Scalar::from(2u32),
            2 => Scalar::from(3u32),
            3 => Scalar::from(4u32),
            6 => Scalar::from(10u32),
        });
        let b = SparsePolyPrimeField(maplit::btreemap! {
            1 => Scalar::from(2u32),
            3 => Scalar::from(3u32),
            4 => Scalar::from(4u32),
            5 => Scalar::from(10u32),
        });
        let c = a.dot_product(&b);
        let expected =
            Scalar::from(2u32) * Scalar::from(2u32) + Scalar::from(3u32) * Scalar::from(4u32);
        assert_eq!(c, expected);
    }
}
