# Lagrange Interpolation

In the threshold decryption procedure, many \\(\mathbb_{G}_2 \\) points must be multiplied by Lagrange coefficients \\(\mathcal{L}^T_{i} (0)\\) before being summed, to interpolate the shared secret committed inside the \\(\mathbb_{G}_2\\) points, where \\(T\\) is the sufficiently large threshold subset of evaluation points.

To compute this value \\(\mathcal{L}^T_{i} (0)\\), note the equality:

\\[\mathcal{L}^T_{i} (0) = \frac{\prod_{j\in T} (-\omega_j)}{-\omega_i \lambda_i} \\]

where \\(\frac{1}{\lambda_i}\\) is the inverse Lagrange coefficient as computed using the Subproduct Domain technique.