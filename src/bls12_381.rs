/*
Wrapper around bls12_381 types for trait implementations
*/

use bls12_381;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct G1Affine(bls12_381::G1Affine);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct G1Projective(bls12_381::G1Projective);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Scalar(bls12_381::Scalar);

impl From<bls12_381::G1Affine> for G1Affine {
    fn from(x: bls12_381::G1Affine) -> G1Affine {
        G1Affine(x)
    }
}

impl From<bls12_381::G1Projective> for G1Affine {
    fn from(x: bls12_381::G1Projective) -> G1Affine {
        bls12_381::G1Affine::from(x).into()
    }
}

impl From<G1Projective> for G1Affine {
    fn from(x: G1Projective) -> G1Affine {
        G1Affine::from(x.0)
    }
}

impl From<bls12_381::G1Projective> for G1Projective {
    fn from(x: bls12_381::G1Projective) -> G1Projective {
        G1Projective(x)
    }
}

impl From<bls12_381::Scalar> for Scalar {
    fn from(x: bls12_381::Scalar) -> Scalar {
        Scalar(x)
    }
}

impl From<u64> for Scalar {
    fn from(x: u64) -> Scalar {
        bls12_381::Scalar::from(x).into()
    }
}

impl From<u32> for Scalar {
    fn from(x: u32) -> Scalar {
        u64::from(x).into()
    }
}

impl std::ops::Add for G1Affine {
    type Output = G1Affine;

    fn add(self, rhs: G1Affine) -> G1Affine {
        let lhs = bls12_381::G1Projective::from(self.0);
        G1Affine::from(lhs + rhs.0)
    }
}

impl std::ops::AddAssign for G1Affine {
    fn add_assign(&mut self, rhs: G1Affine) {
        *self = *self + rhs
    }
}

impl std::ops::Add for G1Projective {
    type Output = G1Projective;

    fn add(self, rhs: G1Projective) -> G1Projective {
        G1Projective(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for G1Projective {
    fn add_assign(&mut self, rhs: G1Projective) {
        *self = *self + rhs
    }
}

impl std::ops::Add for Scalar {
    type Output = Scalar;

    fn add(self, rhs: Scalar) -> Scalar {
        Scalar(self.0 + rhs.0)
    }
}

impl std::ops::AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        *self = *self + rhs
    }
}

impl std::iter::Sum for G1Projective {
    fn sum<I: Iterator<Item = G1Projective>>(iter: I) -> Self {
        iter.fold(G1Projective::zero(), std::ops::Add::add)
    }
}

impl std::iter::Sum for Scalar {
    fn sum<I: Iterator<Item = Scalar>>(iter: I) -> Self {
        iter.fold(Scalar::zero(), std::ops::Add::add)
    }
}

impl std::ops::Mul<Scalar> for G1Affine {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> G1Projective {
        (self.0 * rhs.0).into()
    }
}

impl std::ops::Mul<Scalar> for G1Projective {
    type Output = G1Projective;

    fn mul(self, rhs: Scalar) -> G1Projective {
        (self.0 * rhs.0).into()
    }
}

impl std::ops::Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Scalar {
        (self.0 * rhs.0).into()
    }
}

impl std::ops::MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = *self * rhs
    }
}

impl std::ops::Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        (-self.0).into()
    }
}

impl std::ops::Sub for Scalar {
    type Output = Scalar;

    fn sub(self, rhs: Scalar) -> Scalar {
        (self.0 - rhs.0).into()
    }
}

impl G1Projective {
    pub fn zero() -> G1Projective {
        bls12_381::G1Projective::identity().into()
    }

    fn is_zero(&self) -> bool {
        bool::from(self.0.is_identity())
    }

    pub fn one() -> G1Projective {
        bls12_381::G1Projective::generator().into()
    }
}

impl num_traits::identities::Zero for G1Projective {
    fn zero() -> G1Projective {
        G1Projective::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl Scalar {
    pub fn zero() -> Scalar {
        bls12_381::Scalar::zero().into()
    }

    fn is_zero(&self) -> bool {
        *self == Scalar::zero()
    }

    pub fn one() -> Scalar {
        bls12_381::Scalar::one().into()
    }

    pub fn random<R: rand::Rng + Sized>(mut rng: R) -> Scalar {
        <bls12_381::Scalar as ff::Field>::random(&mut rng).into()
    }

    pub fn pow(&self, i: &[u64; 4]) -> Scalar {
        self.0.pow(i).into()
    }

    pub fn invert(&self) -> Scalar {
        self.0.invert().unwrap().into()
    }
}

impl num_traits::identities::Zero for Scalar {
    fn zero() -> Scalar {
        Scalar::zero()
    }

    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}
