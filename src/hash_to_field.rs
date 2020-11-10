/*
Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

/*!
 This module implements hash_to_field and related hashing primitives
 for use with BLS signatures.
*/

use bls12_381::Scalar;
use digest::generic_array::{
    typenum::Unsigned, typenum::U48, ArrayLength, GenericArray,
};
use digest::{BlockInput, Digest, ExtendableOutput, Update};
use std::marker::PhantomData;

/// hash_to_field for type T using ExpandMsg variant X
pub fn hash_to_field<T, X>(msg: &[u8], dst: &[u8], count: usize) -> Vec<T>
where
    T: FromRO,
    X: ExpandMsg,
{
    let len_per_elm = <T as FromRO>::Length::to_usize();
    let len_in_bytes = count * len_per_elm;
    let pseudo_random_bytes = X::expand_message(msg, dst, len_in_bytes);

    let mut ret = Vec::<T>::with_capacity(count);
    for idx in 0..count {
        let bytes_to_convert =
            &pseudo_random_bytes[idx * len_per_elm..(idx + 1) * len_per_elm];
        let bytes_arr = GenericArray::<u8, <T as FromRO>::Length>::from_slice(
            bytes_to_convert,
        );
        ret.push(T::from_ro(bytes_arr));
    }

    ret
}

/// Generate a field element from a random string of bytes
pub trait FromRO {
    type Length: ArrayLength<u8>;

    fn from_ro(okm: &GenericArray<u8, <Self as FromRO>::Length>) -> Self;
}

/// BaseFromRO is a FromRO impl for a field with extension degree 1.
impl<T: BaseFromRO> FromRO for T {
    type Length = <Self as BaseFromRO>::BaseLength;

    fn from_ro(okm: &GenericArray<u8, <Self as FromRO>::Length>) -> Self {
        Self::from_okm(okm)
    }
}

/// Generate an element of a base field for a random string of bytes
/// (used by FromRO for extension fields).
pub trait BaseFromRO {
    type BaseLength: ArrayLength<u8>;

    fn from_okm(
        okm: &GenericArray<u8, <Self as BaseFromRO>::BaseLength>,
    ) -> Self;
}

/// Trait for types implementing expand_message interface for hash_to_field
pub trait ExpandMsg {
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8>;
}

/// Placeholder type for implementing expand_message_xof based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXof<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        HashT::default()
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize_boxed(len_in_bytes)
            .into()
    }
}

/// Placeholder type for implementing expand_message_xmd based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXmd<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
{
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        let b_in_bytes = <HashT as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        if ell > 255 {
            panic!("ell was too big in expand_message_xmd");
        }
        let b_0 = HashT::new()
            .chain(
                GenericArray::<u8, <HashT as BlockInput>::BlockSize>::default(),
            )
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0_u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize();

        let mut b_vals = Vec::<u8>::with_capacity(ell * b_in_bytes);
        // b_1
        b_vals.extend_from_slice(
            HashT::new()
                .chain(&b_0[..])
                .chain([1_u8])
                .chain(dst)
                .chain([dst.len() as u8])
                .finalize()
                .as_ref(),
        );

        for idx in 1..ell {
            // b_0 XOR b_(idx - 1)
            let mut tmp =
                GenericArray::<u8, <HashT as Digest>::OutputSize>::default();
            b_0.iter()
                .zip(&b_vals[(idx - 1) * b_in_bytes..idx * b_in_bytes])
                .enumerate()
                .for_each(|(jdx, (b0val, bi1val))| tmp[jdx] = b0val ^ bi1val);
            b_vals.extend_from_slice(
                HashT::new()
                    .chain(tmp)
                    .chain([(idx + 1) as u8])
                    .chain(dst)
                    .chain([dst.len() as u8])
                    .finalize()
                    .as_ref(),
            );
        }

        b_vals.truncate(len_in_bytes);
        b_vals
    }
}

impl BaseFromRO for Scalar {
    type BaseLength = U48;

    fn from_okm(okm: &GenericArray<u8, U48>) -> Scalar {
        const F_2_192: Scalar = Scalar::from_raw([
            0x5947_6ebc_41b4_528f_u64,
            0xc5a3_0cb2_43fc_c152_u64,
            0x2b34_e639_40cc_bd72_u64,
            0x1e17_9025_ca24_7088_u64,
        ]);

        // unwraps are safe here: we only use 24 bytes at a time, which is strictly less than p
        let mut le_bytes = [0_u8; 32];
        for (i, b) in okm[..24].iter().rev().enumerate() {
            le_bytes[i] = *b
        }

        let mut res = Scalar::from_bytes(&le_bytes).unwrap() * F_2_192;

        for (i, b) in okm[24..].iter().rev().enumerate() {
            le_bytes[i] = *b
        }
        res += Scalar::from_bytes(&le_bytes).unwrap();
        res
    }
}
