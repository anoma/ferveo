# Publicly Verifiable Secret Sharing

The PVSS scheme used is a modified Scrape PVSS. 

## Dealer's role

1. The dealer chooses a uniformly random polynomial \\(f(x) = \sum^t_i a_i x^i \\) of degree \\(t\\).
2. Let \\(F_0, \ldots, F_t \leftarrow [a_0] G_1, \ldots, [a_t] G_1 \\)
3. Let \\(\hat{u}_2 \rightarrow [a_0] \hat{u_1} \\)
4. For each validator \\(i\\), for each \\(\omega_j \in \Omega_i\\), encrypt the evaluation \\( \hat{Y}_{i, \omega_j} \leftarrow [f(\omega_j)] ek_i  \\)
4. Post the signed message \\(\tau, (F_0, \ldots, F_t), \hat{u}_2, (\hat{Y}_{i,\omega_j})) to the blockchain

## Public verification

1. Check \\(e(F_0, \hat{u}_1)=  e(G_1, \hat{u_2})\\)
2. Compute by FFT \\(A_1, \ldots, A_W \leftarrow [f(\omega_0)]G_1, \ldots, [f(\omega_W)]G_1 \\)
3. Partition \\(A_1, \ldots, A_W\\) into \\(A_{i,\omega_j} \\) for validator \\(i\\)'s shares \\(\omega_j\\)
4. For each encrypted share \\(\hat{Y}_{i,\omega_i} \\), check \\(e(G_1, \hat{Y}_{i,\omega_j}) = e(A_{i,\omega_j}, ek_i) \\)

## Public Aggregation

Multiple PVSS instances can be aggregated into one by a single validator, speeding up verification time. The aggregation and verification are similar to the Aggregatable DKG paper.