use crate::poly;
use bls12_381::Scalar;

/// From dusk_bls12-381
pub fn domain(num_coeffs: usize) -> Option<(Scalar, u32, u64)> {
    let size = num_coeffs.next_power_of_two() as u64;
    let log_size_of_group = size.trailing_zeros();
    const TWO_ADACITY: u32 = 32;

    if log_size_of_group >= TWO_ADACITY {
        return None;
    }

    // Compute the generator for the multiplicative subgroup.
    // It should be 2^(log_size_of_group) root of unity.

    let mut group_gen = <Scalar as ff::PrimeField>::root_of_unity();
    for _ in log_size_of_group..TWO_ADACITY {
        group_gen = group_gen.square();
    }
    Some((group_gen, log_size_of_group, size))
}

/// From dusk_bls12-381
pub fn fft(a: &mut [Scalar], omega: Scalar, log_n: u32) {
    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m = omega.pow(&[(n / (2 * m)) as u64, 0, 0, 0]);

        let mut k = 0;
        while k < n {
            let mut w = Scalar::one();
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= &w;
                let mut tmp = a[(k + j) as usize];
                tmp -= &t;
                a[(k + j + m) as usize] = tmp;
                a[(k + j) as usize] += &t;
                w *= w_m;
            }
            k += 2 * m;
        }
        m *= 2;
    }
}

// From dusk_bls12-381
#[inline]
pub fn bitreverse(mut n: u32, l: u32) -> u32 {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

pub fn multi_evaluate(
    a: &poly::Share,
    domain: (Scalar, u32, u64),
) -> Vec<Scalar> {
    use std::convert::TryInto;
    let mut shares = Vec::with_capacity(domain.2.try_into().unwrap());
    shares.extend(a.iter());
    shares.resize_with(domain.2.try_into().unwrap(), Default::default);
    fft(&mut shares, domain.0, domain.1);
    shares
}
