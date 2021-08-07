# Decryption Share Aggregation

In order to provide guarantees that every valid transaction is executed in the order it appears in a finalized block, it is necessary that validators cannot censor valid transactions by pretending that the transaction was invalidly constructed. In the case of a valid transaction, the resulting symmetric key is sufficient to prove correct decryption; however, in
case of invalid transactions, the resulting symmetric key may not correctly decrypt the payload. Therefore, the decryption shares must be retained to allow verification that the decryption procedure was followed correctly and that all transactions not processed were actually invalid.

Since decryption shares are rather large in size, it is possible to consume a large amount of storage space by submitting many invalid transactions. This waste of storage space can be mitigated by use of decryption share aggregation, where many valid decryption shares for many transactions can be aggregated together into one set of decryption shares. The resulting shared secrets cannot be obtained directly from the aggregated decryption shares, but an aggregated shared secret can be obtained, and compared against stored shared secrets. Therefore, the storage cost of decryption shares across many invalid transactions is amortized and the incremental cost of an invalid transaction in a block is only the bytes of the shared secret (one \\(\mathbb{G}_T\\) element).

## To aggregate decryption shares from many transactions

Given many valid ciphertexts \\((U_j,W_j)\\), on input 2/3 weight of potential decryption shares for each ciphertext \\(\{D_{i,j}\}\\) sharing the same validator set, if decryption shares are only needed to check the validity of the decryption process, the decryption shares of many ciphertexts can be aggregated into one decryption share set. 

For each ciphertext \\(j\\) compute the scalar coefficient:

\\[ \rho_j = H(U_1, \ldots, U_k, j) \\]

which can be used to compute the aggregated decryption share for validator \\(i\\):

\\[\hat{D}_i = \sum_j \rho_j D_{i,j} \\]


## To verify the correctness of an aggregation against aggregated ciphertexts

Given many valid ciphertexts \\((U_j,W_j)\\) and an aggregated decryption share set for those ciphertexts, the validity of the aggregation can be checked by computing the publicly known coefficients:

\\[ \rho_j = H(U_1, \ldots, U_k, j) \\]

and checking the pairing equation:

\\[ \prod_i e(\sum_{j} [\rho_i] \hat{D}_{i}, P_i) = e([\sum_{i,j} \rho_i] U_j, H) \\]

## Proof sketch 

(TODO: turn into an actual proof)

The aggregation does not reduce security due to the Forking Lemma. Assume each validator provides an aggregated decryption share \\(D_i\\) that passes the aggregated check \\(e(D_i, P_i) = e( [a] U_1 + [b] U_2, H)\\) where \\(a,b\\) are from \\(H(U_1,U_2)\\). Assume an adversary can create a fake \\(D_i\\), then rewind the adversary and replay with new \\(a',b'\\) to get a new forgery \\(D_i'\\). Then \\([X,Y] = [[a,b],[a',b']]^{-1} * [D_i, D_i']\\) should satisfy \\(e(X, P_i) = e( U_1, H)\\) and \\(e(Y, P_i) = e(U_2, H)\\) so X,Y are valid decryption shares for each ciphertext. Therefore every adversary that passes the aggregated check passes the original check.