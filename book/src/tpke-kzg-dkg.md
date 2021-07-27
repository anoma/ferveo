# Threshold Encryption

## Curve specification

Let \\(P_1, P_2\\) be the generators of \\(G_1, G_2\\) respectively.

Let \\(H\\) be a hash function from \\(\{0,1\}^* \to G_2\\).

Let \\(G\\) be a PRF from \\(G_1 \to \{0,1\}^*\\)

In the protocol, \\(U\\) is on \\(G_1\\), pubkeys \\(Y\\) are on \\(G_1\\), and \\(W\\) is on \\(G_2\\).

## Encrypt

\\(Enc(m, AD):\\)

1. Let \\(r\\) be a random scalar
2. Let \((U = rP_1\\)
3. Let \\(V = G(rY) \oplus m\\)
4. Let \\(W = rH(U, V, AD)\))

The public key portion of the ciphertext is \(((U, W)\\) and \\(V\\) is the ciphertext.

## Calculate Decryption Share

\\(Dec(U, V, W, AD, x_i):\\)

1. Let \\(H = H(U,V, AD)\\)
2. Check that \\(e(P_1, W) = e(U, H)\\)

If the above check passes, the decryption share is \\(U_i = x_i U\\).

## Decryption share validation

\\(Verify\_Dec(C, AD, U_i, Y_i):\\)

1. Parse C as \\((U, V, W)\\)
2. Compute \\(H = H(U,V,AD)\\)
3. Check that \\(e(P_1, W) = e(U, H)\\)
4. If the above check passes, check \\(e(U_i, H) = e(Y_i, W)\\)

## Decryption share aggregation

Given \\(t\\) evaluations of \\((i, f(i + 1) P_1)\\), for a polynomial \\(f\\) of degree less than \\(t\\), we can compute \\(f(0) P_1\\) via lagrange interpolation.

Since we are given many evaluations of \\(U_i = f(i + 1) U = x_i r P_1\\), we can use lagrange interpolation to obtain \\(x r P_1 = rY\\). 

Then we get our decrypted message as \\(decrypt(G(rY), V)\\).
