# Complete Concrete Scheme

There are optimizations that can be done to increase decryption throughput when decrypting many transactions within a block. For completeness, the full concrete scheme is described here.

## Summary

The DKG and TPKE schemes support the following key operations:

* `DKG.KeyGen(tau, total_weight, {(s_i, ek_i)})`
* `DKG.Announce() -> (ek, dk)`
* `DKG.PartitionDomain() `
* `DKG.Share` 
* `TPKE.Blind(Z_i)` inputs a validators private key shares and outputs a 
* `TPKE.VerifyBlinding()`

And supports the following ciphertext operations:

* `TPKE.Encrypt(Y)` inputs a public threshold key \\(Y\\) and outputs a random ciphertext \\((U,W)\\) encrypted to that public key
* `TPKE.CiphertextValidity(U,W)` tests if $\\((U,W)\\) is a valid ciphertext
* `TPKE.CreateDecryptionShare()`
* `TPKE.VerifyDecryptionShares`
* `TPKE.BatchVerifyDecryptionShares`
* `TPKE.CombineDecryptionShares` combines decryption shares 
* `TPKE.VerifyCombination` verifies a combination for many 
* `TPKE.DeriveSymmetricKey`

## Lagrange Coefficients

Given a validator subset \\(\{i\}\\), the Lagrange coefficients \\(\lambda_{\omega}(0)\\) for the domain \\(\cup \Omega_i \\) can be computed efficiently using the Subproduct Domain technique.

Total cost: \\( O(p \log p) \\) 

## `TPKE.Encrypt(Y)`

`TPKE.Encrypt(Y)` creates a new, random ciphertext \\((U,W)\\) encrypted to the public key \\(Y\\), and a corresponding ephemeral shared secret \\(S\\) such that the private key associated with \\(Y\\) can efficiently compute \\(S\\) from the ciphertext \\((U,W)\\). 

The ephemeral shared secret \\(S\\) can be used to derive a shared symmetric encryption key.


1. Let \\(r\\) be a uniformly random scalar.
2. Let \\(S = e([r] Y, H)\\)
3. Let \\(U = [r] G\\)
4. Let \\(W = [r] H_{\mathbb{G}_2} (U)\\)

Then \\((U,W)\\) is the ciphertext and \\(S\\) is the ephemeral shared secret. 

## `TPKE.CiphertextValidity(U,W)`

To provide chosen ciphertext security, ciphertext validity must be checked for each ciphertext \\((U,W)\\) separately. The ciphertext can be checked by:

\\[e(U, H_{\mathbb{G}_2} (U)) = e(G, W)\\]

## `TPKE.VerifyDecryptionShares`

Given many valid ciphertexts \\((U_j,W_j)\\), on input potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\) from a single validator \\(i\\) with blinded public key \\(B_i\\), the validity of those shares can be checked by:

\\[ e(\sum_j \alpha_j D_i, \sum_j \alpha_j^{-1} P_i) = e(U, H) \\]

Total cost: 2 pairings per validator, plus 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_2\\) multiply per ciphertext.

## `TPKE.BatchVerifyDecryptionShares`

Given many valid ciphertexts \\((U_j,W_j)\\), on input 2/3 weight of potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\), corresponding to validator set \\(\{i\}\\) with blinded public keys \\(B_i\\), the validity of those shares can be checked:

\\[ e(\sum_{i,j} \alpha_{i,j} D_i, \sum_{i,j} \alpha_{i,j}^{-1} P_i) = e(U, H) \\]

Total cost: 2 pairings, plus 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_2\\) multiply per ciphertext.

## `TPKE.CombineDecryptionShares()`

For a given ciphertext \\((U_j,W_j)\\), on input 2/3 weight of valid decryption shares \\(\{D_{i,j}\}\\) as checked by ``TPKE.VerifyDecryptionShares`, corresponding to validator set \\(\{i\}\\).

Then a partial combined share \\(S_{i,j}\\) for that transaction can be computed with one pairing:

\\[ S_{i,j} = e( D_{i,j}, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] [b] Z_{i,\omega_j}  ) \\]

and combined to get the final combined share \\(S_j = \prod_i S_{i,j}\\).

Total cost: 1 pairing and 1 \\(\mathbb{G}_T\\) multiply per validator 

## `TPKE.VerifyCombination`

Verifying \\(S_j\\) for many transactions with the same decrypting validator set can be done faster than generating each \\(S_j\\) separately. For each ciphertext \\((U_j, W_j)\\) with valid decryption shares \\( D_{i,j}\\), combined shares \\(\{S_j\}\\) and random scalars \\(\alpha_j\\), for each validator \\(i\\), an aggregated decryption share: 

\\[\hat{D}_i = \sum_j \alpha_j D_{i,j} \\]

can be used to compute an aggregated partial combined share \\(\hat{S}_i \\):

\\[ \hat{S}_i = e( \hat{D}_i, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] [b] Z_{i,\omega_j}  ) \\]

and combined to get an aggregated final combined share \\( \hat{S} = \prod_i \hat{S}_i\\) which can be checked against the computed \\(\{S_j\}\\) by: 

\\[ \hat{S} = \sum_j \alpha_j S_j \\]

Total cost: 1 pairing and 1 \\(\mathbb{G}_T\\) multiply per validator, plus 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_T\\) multiply per ciphertext.
