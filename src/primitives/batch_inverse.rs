use crate::*;
use ark_ff::PrimeField;

///
/// TODO: have None unwraps return None
pub fn batch_inverse<F: PrimeField>(a: &[F]) -> Option<Vec<F>> {
    let n = a.len();
    // a_n, a_n*a_{n-1}, ..., a_n*...*a_1
    let mut accumulator = Vec::with_capacity(n);
    // a_2*...*a_n, a_1*a_3*...*a_n, ..., a_1*...*a_{n-1}
    let mut missing_one = Vec::with_capacity(n);

    let mut a_iter = a.iter().rev();
    accumulator.push(*a_iter.next().unwrap());
    for x in a_iter {
        accumulator.push(*x * *accumulator.last().unwrap());
    }

    let mut accumulator_iter = accumulator.iter().rev();
    // running_total = (a_1 * ... * a_n)^{-1}
    let mut running_total = accumulator_iter.next().unwrap().inverse().unwrap();

    for (a_i, A_i) in a.iter().zip(accumulator_iter) {
        // running_total = (a_1 * ... * a_{i-1}) * (a_1 * ... * a_n)^{-1}
        // A_i = a_{i+1} * ... * a_n
        missing_one.push(running_total * A_i);
        running_total *= a_i;
    }
    missing_one.push(running_total);
    Some(missing_one)
}

#[test]
fn test_batch_inverse() {
    use ark_std::UniformRand;
    let rng = &mut ark_std::test_rng();
    let a = (0..100)
        .map(|_| ark_bls12_381::Fr::rand(rng))
        .collect::<Vec<_>>();

    let b = batch_inverse(&a).unwrap();
    for (i, j) in a.iter().zip(b.iter()) {
        assert_eq!(i.inverse().unwrap(), *j);
    }
}
