# Lagrange Interpolation

In the threshold decryption procedure, many \\(\mathbb_{G}_2 \\) points must be multiplied by Lagrange coefficients \\(\mathcal{L}^T_{i} (0)\\) before being summed, to interpolate the shared secret committed inside the \\(\mathbb_{G}_2\\) points, where \\(T\\) is the sufficiently large threshold subset of evaluation points.

To compute this value \\(\mathcal{L}^T_{i} (0)\\), note the equality:

\\[\mathcal{L}^T_{i} (0) = \frac{\prod_{j\in T} (-\omega_j)}{-\omega_i \lambda_i} \\]

where \\(\frac{1}{\lambda_i}\\) is the inverse Lagrange coefficient as computed using the Subproduct Domain technique.

## Caching of Lagrange Interpolation results

Since the block signer set may, in the worst case, change for every block, and may be as small as 2/3 of the total validator set, it is possible that the Lagrange coefficients are distinct for every new block. Therefore, the protocol must accommodate the computation load required to recompute the Lagrange coefficients, and all operations that are data-dependent on the coefficients, which is significant. 

However, in the expected case, validators are penalized for insufficient liveness and the block signer set should rarely deviate from block to block. Therefore it makes sense to aggressively cache the Lagrange coefficients of the longest live 2/3 subset of validators, and other data. In particular the `G2Prepared` form of the blinded private key shares multiplied by the Lagrange coefficients is quite expensive to compute and can be cached in case the block signer set does not change significantly, potentially saving a substantial amount of compute time.