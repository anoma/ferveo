/*
Hacky implementation of hash-to-curve using miracl_core.
*/


#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]

fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

fn hash_to_field_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp::FP; 2] {
    use miracl_core::bls12381::big::BIG;
    use miracl_core::bls12381::dbig::DBIG;
    use miracl_core::bls12381::fp::FP;
    use miracl_core::bls12381::rom;
    use miracl_core::hmac;

    let mut u: [FP; 2] = [FP::new(), FP::new()];

    let q = BIG::new_ints(&rom::MODULUS);
    let k = q.nbits();
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    let m = r.nbits();
    let L = ceil(k + ceil(m, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, L * ctr, &dst, &msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..L {
            fd[j] = okm[i * L + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..L]);
        let w = FP::new_big(&dx.dmod(&q));
        u[i].copy(&w);
    }

    u
}

fn htp_bls12381_g1(mess: &str) -> bls12_381::G1Affine {
    use miracl_core::bls12381::ecp;
    use miracl_core::bls12381::ecp::ECP;
    use miracl_core::hmac;

    let m = mess.as_bytes();
    let dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".as_bytes();
    let u = hash_to_field_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, m, 2);
    let mut P = ECP::map2point(&u[0]);
    let P1 = ECP::map2point(&u[1]);
    P.add(&P1);
    P.cfp();
    P.affine();
    /* For arcane reasons, miracl_core uses an extra leading byte,
    which is always set to 0x02 for compressed representations,
    and set to 0x04 for uncompressed representations. */
    let mut uncompressed_bytes_with_lead = [0u8; 97];
    P.tobytes(&mut uncompressed_bytes_with_lead, false);
    let mut uncompressed_bytes = [0u8; 96];
    uncompressed_bytes.clone_from_slice(&uncompressed_bytes_with_lead[1..]);
    bls12_381::G1Affine::from_uncompressed(&uncompressed_bytes).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_zero_len_str() {
        let mut expected = [0u8; 48];
        let expected_str =  "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1";
        hex::decode_to_slice(expected_str, &mut expected)
            .expect("Failed to decode hex");
        let expected = bls12_381::G1Affine::from_compressed(&expected).unwrap();
        let res = htp_bls12381_g1(&"");
        assert!(res == expected)
    }
}
