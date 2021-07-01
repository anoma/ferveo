# Cryptographic Primitives

## Curve

Ferveo's distributed key generator and threshold cryptographic schemes rely on the use of a **bilinear group** where the Gap Diffie-Hellman assumption holds. 

The default curve used is BLS12-381. Optionally, BLS12-377 may also be implemented, which would allow easier SNARK verification of the DKG or other cryptographic primitives, or BLS12-461 at a higher security level. For documentation purposes, an abstract bilinear group is assumed.

\\(\mathbb{G}_1\\) denotes the prime order subgroup of order \\(r\\) and \\(\mathbb{F}_r\\) is the scalar field of the curve with prime order \\(r\\). The pairing operation is \\(e(P,Q) : \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T\\). The generator of \\(\mathbb{G}_1\\) and \\(\mathbb{G}_2\\) are denoted \\(G_1\\) and \\(G_2\\) respectively.

Let \\(\omega\\) denote an \\(W\\)th root of unity in \\(\mathbb{F}_r\\).

## Fast subgroup checks

All subgroup checks of membership in the subgroup \\(\mathbb{G}_1\\) and \\(\mathbb{G}_2\\) are performed as described in https://eprint.iacr.org/2019/814.pdf for performance reasons.
## Hashing

Let \\(\operatorname{H}_{\mathbb{G}}: \{0,1\}^* \rightarrow \mathbb{G}\\) be the hash to curve function into the group \\(\mathbb{G}\\) as specified in RFC https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/

Let \\(\operatorname{H}_{\mathbb{F}}: \{0,1\}^* \rightarrow \mathbb{F}\\) be the hash to field function into the group \\(\mathbb{F}\\)

Let \\(\operatorname{H}_{\ell}: \{0,1\}^* \rightarrow \{0,1\}^\ell\\) be a hash function into \\(\ell\\) bits. The default hash function is BLAKE2b.

## Symmetric Cryptography

The authenticated encryption and decryption operations with key $k$, ciphertext $C$, and plaintext $M$ are denoted:

\\[C = \operatorname{encrypt}(k, M)\\]
\\[M = \operatorname{decrypt}(k, C)\\]

Symmetric key encryption and decryption are provided by the ChaCha20Poly1305 (RFC8439) cipher, implemented as the chacha20poly1305 crate.