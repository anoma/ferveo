# Threshold Signature Scheme
A Schnorr-like signature scheme based on Gap Diffie-Hellman in ROM.

## Setup

* Let \\(G\\) be a generator of \(\mathbb{G}_1\\) and let \\(H\\) be a generator of \\(\mathbb{G}_2\\)
* Let \\(Y = [x] G\\) be the public key and \\(Y_i = [x_i] G\\) be the public key of the \\(i\\)th share
* Let \\(Z = [x] H\\) be the private key, and \\(Z_i = [x_i] H\\) be the private key of the \\(i\\)th share

## Notation

* Let \\(H_\ell\\) denote hash to \\(\{0,1\}^{\ell}\\) for some integer \\(\ell\\)
* Let \\(H_\mathbb{F}\\) denote hash to scalar field \\(\mathbb{F}\\)
* Let \\(H_\mathbb{G}\\) denote hash to group \\(\mathbb{G}\\)


### To sign with group element as private key

Let \\(m\\) be the message to sign. 

1. Let \\(k\\) be a random scalar
3. Let \\(R = e([k] G, H)\\)
5. Let \\(c = H_\mathbb{F}(R || Y || m)\\)
6. Let \\(z = [k] H + [c] Z\\)
7. Let the signature be \\(\sigma = (R,z)\\)

Note that \\(z = [k+xc] H\\), but is computable without knowledge of \\(x\\).

### To verify

1. Let \\(\sigma = (R,z)\\) be the signature of \\(m\\)
2. Let \\(c = H_\mathbb{F}( R || Y || m)\\)
3. Let \\(R' = e( G, z)*e([c]Y, H)^{-1}\\)
4. If \\(R = R'\\) the signature is valid.

### Threshold Signature

The technique of [FROST](https://eprint.iacr.org/2020/852.pdf) can be applied here;
the individual commitments \\(R_i\\) are computed similar to FROST as:

\\(R_i = e(D + [\rho_i] E_i, H)\\)

and

\\(R = \prod R_i\\)

and the value \\(z = [d_i + e_i \rho_i]H + [\lambda_i s_i c] Z\\)

