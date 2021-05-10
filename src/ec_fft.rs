use ark_ec::PairingEngine;
use ark_ff::{Field, One};

pub fn ec_fft<E: PairingEngine>(
    a: &mut [E::G1Projective],
    omega: E::Fr,
    two_adicity: u32,
) {
    let n = a.len();
    assert_eq!(n, 1 << two_adicity);

    // swapping in place (from Storer's book)
    for k in 0..n {
        let rk = bitreverse(k as u32, two_adicity) as usize;
        if k < rk {
            a.swap(k, rk);
        }
    }

    let mut m = 1;
    for _ in 0..two_adicity {
        // w_m is 2^s-th root of unity now
        let w_m = omega.pow(&[(n / (2 * m)) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = E::Fr::one();
            for j in 0..m {
                let mut t = a[(k + m) + j];
                t *= w;
                a[(k + m) + j] = a[k + j];
                a[(k + m) + j] -= t;
                a[k + j] += t;
                w *= w_m;
            }
            k += 2 * m;
        }
        m *= 2;
    }
}

#[inline]
pub(crate) fn bitreverse(mut n: u32, l: u32) -> u32 {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}
