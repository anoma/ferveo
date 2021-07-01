# Threshold Encryption Scheme

Based on [A Simple and Efficient Threshold Cryptosystem from the Gap Diffie-Hellman Group](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf)

## Overview

The threshold encryption scheme allows the encrypter to derive a **shared secret** \\(s\\) from the threshold public key \\(Y\\), such that sufficient threshold of validators holding private key shares \\(Z_i\\) associated with \\(Y\\) can also derive the shared secret. Both encrypter and decrypter can use the shared secret to derive a ChaCha20 symmetric key via HKDF.

### To encrypt

1. Let \\(r\\) be a random scalar
2. Let \\(s = e([r] Y, H)\\)
3. Let \\(U = [r] G\\)
4. Let \\(W = [r] H_{\mathbb{G}_2} (U || V)\\)
5. Let \\(k = HKDF\\)

The public key portion of the ciphertext is \\(U,W)\\) and the derived shared secret is \\(s\\).

### To Validate Ciphertext (for IND-CCA2 security)

Check that \\(e(U, H_{\mathbb{G}_2} (U || V))= e(G, W)\\) for ciphertext validity.

### To Decrypt

1. Check ciphertext validity.
2. Let \\(s = e(U, Z)\\)

### Threshold Decryption (simple method)

1. Check ciphertext validity.
2. Each decryption share is \\(C_i = e(U, Z_i)\\).
3. To combine decryption shares, s = \\(\prod C_i^{\lambda_i(0)}\\) where \\(\lambda_i(0)\\) is the lagrange coefficient over the appropriate size domain.
4. Plaintext $m = H_\ell(s) \oplus V$

### Threshold Decryption (fast method)

Thanks to Kobi Gurkan for this approach.

Each validator generates a random scalar \\(b\\) and blinds their private key shares \\([b] Z_{i, \omega_j})\\). The blinded private key shares are publicly distributed, either by gossip or by posting to the blockchain. 

1. Check ciphertext validity
2. The validator's decryption share is \\(D_i = [b^{-1}] U\\)

Note that to create a decryption share takes only one \\(\mathbb{G}_1\\) multiplication, and not one pairing as in the simple method.

To combine decryption shares, an aggregator computes for each decryption share \\(D_i = [b^{-1}] U\\):

\\[ S_i = e( [b^{-1}] U, \sum_{\omega_j \in \Omega_i} [\lambda_{\omega_j}(0)] D_i  ) \\]

<!--- The decryption shares can be made verifiable if each validator posts a blinded public key \\(P_i =  [b]A_{i,\omega_j} \\) for a single \\(\omega_j\\).

Then validity of a decryption share can be checked by \\(e(D_i, [b]Z_{i,\omega_j})= e(U, H) \\)-->

### Proof sketch

The non-threshold version of the scheme is IND-CCA2 secure. 

Suppose there is an adversary that wins the IND-CCA2 game. Then on input $(G, [a]G, [b]G, H)$, there exists an adversary that computes  $e(G,H)^{ab}$.



#### Rekeyability

The shared secret $s$ can be rekeyed with respect to the secret key $Z_1$ to a new secret key $\hat{Z} = [\alpha] Z_1 + Z_2$, as the new shared secret $\hat{s} = s^{\alpha} e(U, Z_2) = e(U, [\alpha] Z_2)e(U, Z_2) = e(U, [\alpha]Z_1 + Z_2)$.

The shared secret $s$ can be rekeyed with respect to the public key $Y_1$ to a new public key $\hat{Y} = [\alpha] Y_1 + Y_2$ as the new shared secret $\hat{s} = s^{\alpha} e([r] Y_2, H) = e([r\alpha] Y_1, H)e([r]Y_2, H) = e([r]([\alpha]Y_1 + Y_2), H)$.
 