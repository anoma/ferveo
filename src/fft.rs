use ark_bls12_381::Fr;
use ark_ff::{Field, One};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

type Scalar = Fr;

/// From dusk_bls12-381
// group_gen, log_size_of_group, size
pub fn domain(degree: usize) -> Radix2EvaluationDomain<Fr> {
    Radix2EvaluationDomain::new(degree).unwrap()
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
