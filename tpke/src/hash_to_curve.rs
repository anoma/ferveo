#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]

use ark_serialize::CanonicalDeserialize;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::dbig::DBIG;
use miracl_core::bls12381::ecp;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp::FP;
use miracl_core::bls12381::fp2::FP2;
use miracl_core::bls12381::rom;
use miracl_core::hmac;

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

fn hash_to_field2_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp2::FP2; 2] {
    let mut u: [FP2; 2] = [FP2::new(), FP2::new()];

    let q = BIG::new_ints(&rom::MODULUS);
    let k = q.nbits();
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    let m = r.nbits();
    let L = ceil(k + ceil(m, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, 2 * L * ctr, &dst, &msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..L {
            fd[j] = okm[2 * i * L + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..L]);
        let w1 = FP::new_big(&dx.dmod(&q));

        for j in 0..L {
            fd[j] = okm[(2 * i + 1) * L + j];
        }
        dx = DBIG::frombytes(&fd[0..L]);
        let w2 = FP::new_big(&dx.dmod(&q));
        u[i].copy(&FP2::new_fps(&w1, &w2));
    }
    u
}

pub fn htp_bls12381_g1(msg: &[u8]) -> ark_bls12_381::G1Affine {
    let dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".as_bytes();
    let u = hash_to_field_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 2);
    let mut P = ECP::map2point(&u[0]);
    let P1 = ECP::map2point(&u[1]);
    P.add(&P1);
    P.cfp();
    P.affine();
    /* For arcane reasons, miracl_core uses an extra leading byte,
    which is always set to either 0x02 or 0x03 for compressed representations,
    and set to 0x04 for uncompressed representations. */

    let mut compressed = [0u8; 49];
    P.tobytes(&mut compressed, true);

    let mut compressed_rev = [0u8; 48];
    compressed_rev.clone_from_slice(&compressed[1..]);
    compressed_rev[000..=047].reverse();

    ark_bls12_381::G1Affine::deserialize(&compressed_rev[..]).unwrap()
}

pub fn htp_bls12381_g2(msg: &[u8]) -> ark_bls12_381::G2Affine {
    let dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_".as_bytes();
    let u = hash_to_field2_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 2);
    let mut P = ECP2::map2point(&u[0]);
    let P1 = ECP2::map2point(&u[1]);
    P.add(&P1);
    P.cfp();
    P.affine();
    /* For arcane reasons, miracl_core uses an extra leading byte,
    which is always set to either 0x02 or 0x03 for compressed representations,
    and set to 0x04 for uncompressed representations.
    miracl_core uses little-endian encoding for Fp2,
    whereas bls12_381 uses big-endian. */

    let mut compressed = [0u8; 97];
    P.tobytes(&mut compressed, true);

    let mut compressed_rev = [0u8; 96];
    compressed_rev.clone_from_slice(&compressed[1..]);
    compressed_rev[000..=047].reverse();
    compressed_rev[048..=095].reverse();

    ark_bls12_381::G2Affine::deserialize(&compressed_rev[..]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash_to_g1(msg: &[u8], expected_hex_string: &str) {
        let mut expected_compressed = [0u8; 48];
        hex::decode_to_slice(expected_hex_string, &mut expected_compressed)
            .expect("Failed to decode hex");

        let mut expected_compressed_rev = expected_compressed.clone();
        expected_compressed_rev[0] &= (1 << 5) - 1;
        expected_compressed_rev.reverse();

        let expected = ark_bls12_381::G1Affine::deserialize(&expected_compressed_rev[..]).unwrap();

        let res = htp_bls12381_g1(msg);

        assert!(res == expected)
    }

    fn test_hash_to_g2(msg: &[u8], expected_hex_string: &str) {
        let mut expected_compressed = [0u8; 96];
        hex::decode_to_slice(expected_hex_string, &mut expected_compressed)
            .expect("Failed to decode hex");

        let mut expected_compressed_rev = expected_compressed.clone();
        expected_compressed_rev[0] &= (1 << 5) - 1;
        expected_compressed_rev.reverse();

        let expected = ark_bls12_381::G2Affine::deserialize(&expected_compressed_rev[..]).unwrap();

        let res = htp_bls12381_g2(msg);

        assert!(res == expected)
    }

    #[test]
    fn hash_nothing_g1() {
        let msg = b"";
        let expected_hex_string =
            "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1";
        test_hash_to_g1(msg, &expected_hex_string)
    }

    #[test]
    fn hash_abc_g1() {
        let msg = b"abc";
        let expected_hex_string =
            "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903";
        test_hash_to_g1(msg, &expected_hex_string)
    }

    #[test]
    fn hash_nothing_g2() {
        let msg = b"";
        let expected_hex_string =
            "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a";
        test_hash_to_g2(msg, &expected_hex_string)
    }

    #[test]
    fn hash_abc_g2() {
        let msg = b"abc";
        let expected_hex_string =
            "939cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6";
        test_hash_to_g2(msg, &expected_hex_string)
    }
}
