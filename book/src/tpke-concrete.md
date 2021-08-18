# Complete Concrete Scheme

There are optimizations that can be done to increase decryption throughput when decrypting many transactions within a block. For completeness, the full concrete scheme is described here.

## Summary

The DKG and TPKE schemes support the following key operations:

* `DKG.GenerateEpochKeypair() -> (ek, dk)`
* `DKG.PartitionDomain() `
* `DKG.GeneratePVSS(tau, total_weight, {(s_i, ek_i)})`
* `DKG.VerifyPVSS`
* `DKG.AggregatePVSS`

And supports the following ciphertext operations:

* `TPKE.Encrypt(Y)` inputs a public threshold key \\(Y\\) and outputs a random ciphertext \\((U,W)\\) encrypted to that public key
* `TPKE.Blind`
* `TPKE.CiphertextValidity(U,W)` tests if $\\((U,W)\\) is a valid ciphertext
* `TPKE.CreateDecryptionShare(dk_j, U_i,W_i) -> D_{i,j}`
* `TPKE.VerifyDecryptionShares`
* `TPKE.BatchVerifyDecryptionShares`
* `TPKE.CombineDecryptionShares` combines decryption shares 
* `TPKE.VerifyCombination` verifies a combination for many 
* `TPKE.DeriveSymmetricKey`

## `DKG.GenerateEpochKeypair() -> (ek, dk)`

Choose a uniformly random scalar \\(dk \in \mathbb{F}_r \\) and compute \\( ek = [dk] H \\)

## `DKG.PartitionDomain() -> {(Omega_i, ek_i)}`

## `DKG.GeneratePVSS(tau, total_weight, {(Omega_i, ek_i)}) -> `

2. Choose a uniformly random polynomial \\(f(x) = \sum^p_i a_i x^i \\) of degree \\(t\\).
3. Let \\(F_0, \ldots, F_p \leftarrow = [a_0] G, \ldots, [a_t] G \\)
5. For each validator \\(i\\), for each \\(\omega_j \in \Omega_i\\), encrypt the evaluation \\( \hat{Y}_{i, \omega_j} \leftarrow [f(\omega_j)] ek_i  \\)


## `DKG.VerifyPVSS`

## `DKG.AggregatePVSS`

4. 
4. Post the signed message \\(\tau, (F_0, \ldots, F_t), \hat{u}_2, (\hat{Y}_{i,\omega_j})\\) to the blockchain

## `DKG.VerifyAggregatedPVSS`

## Public verification

1. Check \\(e(F_0, \hat{u}_1)=  e(G_1, \hat{u_2})\\)
2. Compute by FFT \\(A_1, \ldots, A_W \leftarrow [f(\omega_0)]G_1, \ldots, [f(\omega_W)]G_1 \\)
3. Partition \\(A_1, \ldots, A_W\\) into \\(A_{i,\omega_j} \\) for validator \\(i\\)'s shares \\(\omega_j\\)
4. For each encrypted share \\(\hat{Y}_{i,\omega_i} \\), check \\(e(G_1, \hat{Y}_{i,\omega_j}) = e(A_{i,\omega_j}, ek_i) \\)

## Lagrange Coefficients

Given a validator subset \\(\{i\}\\), the Lagrange coefficients \\(\lambda_{\omega}(0)\\) for the domain \\(\cup \Omega_i \\) can be computed efficiently using the Subproduct Domain technique.

Total cost: \\( O(p \log p) \\) 

## `DKG.GenerateEpochKeypair() -> (ek, dk)`

The validator generates a random scalar \\(dk \in \mathbb{F}_r \\) and computes the public key \\( ek = [dk] H \\)

## `TPKE.Encrypt(Y, aad) -> (U,W)`

`TPKE.Encrypt(Y, aad)` creates a new, random ciphertext \\((U,W)\\) encrypted to the public key \\(Y\\), and a corresponding ephemeral shared secret \\(S\\) such that the private key associated with \\(Y\\) can efficiently compute \\(S\\) from the ciphertext \\((U,W)\\). Additional authenticated data `aad` may be attached to the ciphertext.

The ephemeral shared secret \\(S\\) can be used to derive a shared symmetric encryption key.

1. Let \\(r\\) be a uniformly random scalar.
2. Let \\(S = e([r] Y, H)\\)
3. Let \\(U = [r] G\\)
4. Let \\(W = [r] H_{\mathbb{G}_2} (U, aad)\\)

Then \\((U,W)\\) is the ciphertext and \\(S\\) is the ephemeral shared secret. 

## `TPKE.CiphertextValidity(U,W) -> bool`

To provide chosen ciphertext security, ciphertext validity must be checked for each ciphertext \\((U,W)\\) separately. The ciphertext can be checked by:

\\[e(U, H_{\mathbb{G}_2} (U)) = e(G, W)\\]

Total cost:
* 1 \\(\mathbb{G}_1\\) and 1 \\(\mathbb{G}_2\\) deserialize per ciphertext
* 1 product of pairings
* 
## `TPKE.BatchCiphertextValidity( {U,W} ) -> bool`

Once a block proposer has verified ciphertext validity, the entire block can be optimistically verified:

\\[\prod_j e(\alpha_j U_j, H_{\mathbb{G}_2} (U_j)) = e(G, \sum_j \alpha_j W_j) \\]

Total cost:
* 1 \\(\mathbb{G}_1\\) and 1 \\(\mathbb{G}_2\\) deserialize per ciphertext
* 1 product of pairings

## `TPKE.CreateDecryptionShare(dk_i, U_j) -> D_{i,j}`

\\[D_{i,j} = [dk_i^{-1}] U_j\\]

## `TPKE.VerifyDecryptionShares(ek_i, { U_j }, { D_{i,j} }) -> bool`

Given many valid ciphertexts \\((U_j,W_j)\\), on input potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\) from a single validator \\(i\\) with epoch public key \\(ek_i\\), the validity of those shares can be checked by:

\\[D_{i,j} = [dk_i^{-1}] U_j\\]

\\[ e(\sum_j [\alpha_j] D_{i,j}, ek_i) = e(\sum_j [\alpha_j] U_j, H) \\]

Total cost:
* 1 \\(\mathbb{G}_1\\) deserialize per validator per ciphertext
* 2 pairings per validator
* 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_2\\) multiply per ciphertext.

## `TPKE.BatchVerifyDecryptionShares({ek_i}, { U_j }, { D_{i,j} }) -> bool`

Given many valid ciphertexts \\((U_j,W_j)\\), on input 2/3 weight of potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\), corresponding to validator set \\(\{i\}\\) with epoch public keys \\(ek_i\\), the validity of those shares can be checked:

\\[ \prod_i e(\sum_{j} [\alpha_{i,j}] D_{i,j}, ek_i) = e([\sum_{i,j} \alpha_{i,j}] U_j, H) \\]

Total cost:
* 1 G1 deserialize per validator
* V+1 pairings
* 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_2\\) multiply, per ciphertext.

## `TPKE.AggregateDecryptionShares( {U_j}, {D_{i,j}} ) -> {\hat{D}_i} `

Given many valid ciphertexts \\((U_j,W_j)\\), on input 2/3 weight of potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\) sharing the same validator set, if decryption shares are only needed to check the validity of the decryption process, the decryption shares of many ciphertexts can be aggregated into one decryption share set. 

For each ciphertext \\(j\\) compute the scalar coefficient:

\\[ \rho_j = H(U_1, \ldots, U_k, j) \\]

which can be used to compute the aggregated decryption share for validator \\(i\\):

\\[\hat{D}_i = \sum_j \rho_j D_{i,j} \\]


## `TPKE.VerifyAggregatedDecryptionShares({U_j}, {\hat{D}_i}) -> bool`
Given many valid ciphertexts \\((U_j,W_j)\\) and an aggregated decryption share set for those ciphertexts, the validity of the aggregation can be checked by computing the publicly known coefficients:

\\[ \rho_j = H(U_1, \ldots, U_k, j) \\]

and checking the pairing equation:

\\[ \prod_i e(\sum_{j} [\rho_i] \hat{D}_{i}, P_i) = e([\sum_{i,j} \rho_i] U_j, H) \\]

## `TPKE.CombineDecryptionShares( {U_j}, {D_{i,j}) -> {S_j}`

For a given ciphertext \\((U_j,W_j)\\), on input 2/3 weight of valid decryption shares \\(\{D_{i,j}\}\\) as checked by ``TPKE.VerifyDecryptionShares`, corresponding to validator set \\(\{i\}\\).

Then a partial combined share \\(S_{i,j}\\) for that ciphertext can be computed with one pairing:

\\[ S_{i,j} = e( D_{i,j}, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] Z_{i,\omega_j}  ) \\]

and combined to get the final combined share \\(S_j = \prod_i S_{i,j}\\).

Total cost: 
* 1 pairing and 1 \\(\mathbb{G}_T\\) multiply per validator 

## `TPKE.VerifyAggregatedCombination`

Verifying \\(\prod_j S_j\\) for many ciphertexts with the same decrypting validator set can be done faster than generating each \\(S_j\\) separately. For ciphertexts \\((U_j, W_j)\\) with valid aggregated decryption shares \\( \hat{D}_{i}\\) (checked by `TPKE.VerifyAggregatedDecryptionShares`), combined shares \\(\{S_j\}\\) and random scalars \\(\rho_j\\), for each validator \\(i\\), an aggregated decryption share: 

\\[\hat{D}_i = \sum_j \rho_j D_{i,j} \\]

computed using unknown \\(D_{i,j}\\) but with the publicly known coefficients:

\\[ \rho_j = H(U_1, \ldots, U_k, j) \\]

can be used to compute an aggregated partial combined share \\(\hat{S}_i \\):

\\[ \hat{S}_i = e( \hat{D}_i, [\sum_{\omega_j \in \Omega_i} \lambda_{\omega_j}(0)] Z_{i,\omega_j}  ) \\]

and combined to get an aggregated final combined share \\( \hat{S} = \prod_i \hat{S}_i\\) which can be checked against the computed \\(\{S_j\}\\) by: 

\\[ \hat{S} = \sum_j \alpha_j S_j \\]

Total cost:
* 1 pairing and 1 \\(\mathbb{G}_T\\) multiply per validator
* 1 \\(\mathbb{G}_1\\) multiply and 1 \\(\mathbb{G}_T\\) multiply per ciphertext.
