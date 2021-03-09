# Ferveo crypto design

## Introduction

This document describes the cryptography used in Ferveo. Cryptoeconomics, incentives, slashing, etc., are described elsewhere.

## Goals

The cryptography in Ferveo allows fast distributed key generation, threshold signature, and threshold encryption operations in a trustless and asynchronous manner, where the relative weights of participants are determined by cryptoeconomics/staking values.

## Definitions

Each node $i \in [1,n]$ in Ferveo has an associated public key identity, and associated weight $w_i$. The total weight $\sum_i w_i = W$ can be determined with a performance tradeoff (higher total weight allows more identities, higher resolution of weights, but larger computation and communication complexity)

### System model

Among the $n$ nodes, at most total weight $t$ nodes are Byzantine (adversarial) and at most $f$ weight nodes are faulty (some or all communications fail). When faulty nodes crash and recover, at most $f$ weight nodes are faulty at a given moment of time. If proactive secret sharing/key refresh is used, then at most $t$ weight nodes are Byzantine during a key phase.

AVSS can only offer resiliance when $W \ge 3t + 2f + 1$, therefore $t<W/3$. The privacy threshold $p$ is the value such that subsets of nodes of weight at least $p+1$ can always recover the key or perform operations using the key, and subsets nodes of weight at most $p$ are unable to recover the key or perform operations using the key. It must be $p < W - t$. The default values $t = W/3 - 1$ and $p = 2W/3$ offer maximal sharing of the key.

### Curve

The curve used is BLS12-381. $\mathbb{G}_1$ denotes the prime order subgroup of order $r$ and $\mathbb{F}_r$ is the scalar field of BLS12-381 with prime order $r$. The pairing operation is $e(P,Q) : \mathbb{G}_1 \times \mathbb{G}_2$ \rightarrow \mathbb{G}_T$. The generator of $\mathbb{G}_1$ and $\mathbb{G}_2$ are denoted $G_1$ and $G_2$ respectively.

Let $\omega$ denote an $W$th root of unity in $\mathbb{F}_r$. 

#### Fast subgroup checks

All subgroup checks of membership in the subgroup $\mathbb{G}_1$ are performed as described in https://eprint.iacr.org/2019/814.pdf

### Symmetric Cryptography

The authenticated encryption and decryption operations with key $k$, ciphertext $C$, and plaintext $M$ are denoted:

$C = \operatorname{encrypt}(k, M)$
$M = \operatorname{decrypt}(k, C)$

Symmetric key encryption and decryption are provided by the ChaCha20Poly1305 (RFC8439) cipher, implemented as the chacha20poly1305 crate.

(TODO: Evaluate potential use of AES-NI in place of ChaCha20, primarily for CPUs with hardware implementation)

## Public Key identities

Every node $i$ in the network chooses $sk_i \in \mathbb{F}_r$ and derives $pk_i = [sk_i]G_1 \in \mathbb{G}_1$.

## Key agreement

Node $i$ can send asynchronous messages to node $j$ through a gossip protocol. The messages should be encrypted and authenticated via a symmetric cipher (e.g. ChaCha20) using an ephemeral key derived through key agreement.

1. Node $i$ chooses an ephemeral secret key $\alpha \in \mathbb{F}_r$
2. The ephemeral public key is $[\alpha]G_1$.
3. The ephemeral shared secret is $[sk_i] pk_j = [sk_i sk_j] G_1$.
4. The shared symmetric key is $\operatorname{BLAKE2b}([\alpha]G_1, [sk_i] pk_j)$

(TODO: Check this is accurate and complete)

## Initialization

Each DKG session begins by choosing a unique integer session id $\tau$. This can begin at 0 and then be incremented from the previous $\tau$. The total number of shares $W$, Byzantine threshold $t$, and privacy threshold $p$ should also be fixed (independent of $n$, the number of nodes).

## Staking phase

Nodes that want to participate in the DKG and receive key shares can stake value tied to the session id. Using the consensus layer, all nodes should agree on a canonical ordering of $(pk_i, w_i)$ where $pk_i$ is the public key of the $i$th node participating in the DKG and $w_i$ is number of shares belonging to node $i$. The value $i$ is the integer id of the node with public key $pk_i$. 

Let $\Psi_{\tau,i} = \{ k, k+1, \ldots, k+w_i} \}$ be a disjoint partition of $\{0,1, \ldots, W-1\}$, and $\Omega_{\tau,i} = \{ \omega^k \ mid k \in \Psi_{\tau,i} \}$.

## VSS

The Verifiable Secret Sharing scheme used is a modified version of the Haven HAVSS scheme (https://eprint.iacr.org/2021/118.pdf) with performance enhancements and weighted shares. All polynomial evaluations are at powers of $\omega$ to allow FFT based polynomial operations.

### KZG commitment scheme

There is a modified KZG commitment scheme from "Efficient polynomial commitment schemes for multiple points and polynomials" by Dan Boneh, Justin Drake, Ben Fisch, Ariel Gabizon, to allow multiple-point multi-polynomial opening proofs with only two $\mathbb{G}_1$ points.

Additional performance enhancements from https://github.com/khovratovich/Kate/blob/66aae66cd4e99db3182025c27f02e147dfa0c034/Kate_amortized.pdf, https://alinush.github.io/2020/03/12/towards-scalable-vss-and-dkg.html#authenticated-multipoint-evaluation-trees-amts.

(TODO: possibly compare/implement the Haven inner product commitment scheme as well)

### Vector commitment scheme

While it is possible to use the KZG commitment scheme (alternatively, inner product argument scheme) for the vector commitments, likely the best performant primitive will be Merkle tree commitments, as only one element opening is needed for each node.

### Dealer messages

1. The dealer $d$ chooses a uniformly random *recovery* polynomial $R$ of degree $p$.
2. For all $i \in [1,n]$, a uniformly random polynomial $S_i$ of degree $t$ such that $S_i(\alpha) = R(\alpha)$ for all $\alpha \in \Omega_i$.
3. Commit to $R$ to obtain $\hat{R}$
4. Commit to each $S_i$ to obtain $\hat{S}_i$.
5. For all $i \in [1,n]$: 
   -  use generalized KZG commitment to create an opening proof $\pi_i$ of all commitments $\{ \hat{S_j} \mid j \in [1,n] \}$ at all points $\alpha \in \Omega_i$. 
   - compute $\hat{T_i} = \hat{R} - \hat{S}_i$ where $T_i = R - S_i$
   -  Let $\hat{s}_i = \operatorname{BLAKE2b}(\langle \hat{S}_j \mid j \in \Psi_i)$
6.  Construct Merkle tree with $\hat{s}_i$ located at $i$th leaf and root $C$.

For each node $i$, the dealer sends to node $i$ the encrypted $(\tau, d, C, \hat{R}, \hat{S}, \langle S_j(\alpha) \mid \alpha \in \Omega_i, j \in [1,n] \rangle, \langle T_i(\omega^i) \mid i \in [1,n] \rangle$ which consists of:

* The round number $\tau$
* The dealer id $d$
* $C$, the root of the Merkle tree of commitments
* $\hat{R}$, the KZG commitment to the recovery polynomial
* $\hat{S} = \langle \hat{S}_1, \ldots \hat{S}_n \rangle$, the KZG commitments to the share polynomials
* $\langle S_j(\alpha) \mid \alpha \in \Omega_i, j \in [1,n] \rangle$, the share evaluations belonging to node $i$. 
* $ \langle T_i(\omega^i) \mid i \in [1,n] \rangle$, the diagonal evaluations (TODO: Aren't these all 0?)
* The opening proof $\pi_{i}$. 

If the Merkle tree is constructed in a consistent way, it may not be necessary to attach witnesses to $\hat{R}$ and $\hat{S}$.

The cost of each plaintext is $2$ integers, ?? $\mathbb{F}_r$ elements and $2$ $\mathbb{G}_1$ elements. (TODO)

#### Offline precompute

Most of the dealer's computation can be done offline/precomputed, potentially saving online computation time.

### Receiving dealer message

Node $i$ recieves, decrypts, and authenticates $(\tau, d, \hat{R}, \langle \hat{S}_1, \ldots \hat{S}_n \rangle, \langle s_{j,\alpha} \rangle, \langle t_j \rangle$ from dealer $d$.

1. For all $j \in [1,n]$: 
    - Check that commitments in $\hat{S}$ open to $\langle s_{j,\alpha} \rangle$
    - Compute $\hat{T}_j = \hat{R} - \hat{S}_j$ 
    - Check that $\hat{T}_j$ opens to $\langle t_j \rangle$ at $\omega^j$ ($=0$)
2. Check that $C$ is the correct Merkle tree root of $\hat{R}$ and $\hat{S}$

If these checks pass, then node $i$ can send to node $j$ the encrypted echo message $(\tau, d, C, \langle \hat{S}_k \mid k \in \Psi_j, \langle s_{j, \alpha} \mid \alpha \in \Omega_i \rangle, \operatorname{MerklePath}(C, \langle \langle \hat{S}_k \mid k \in \Psi_j \rangle) )$.

Note only one MerklePath is attached per echo message and the Merkle tree is $\log n$ depth.

### Receiving echo message

TODO: mostly as described in Haven paper

### Receiving ready message

TODO: mostly as described in Haven paper

If the check passes, then $pk_i$ signs $(\tau,d,C)$ to get signature $\sigma_{\tau,d,i}$ and gossips $??$ to the other nodes to signify "ready". (TODO)

### Ready signature aggregation

Once any helper network participant (not necessarily a node in the DKG) collects $W-t-f$ valid signatures of ready messages, BLS multi-signature aggregation is used to aggregate to one BLS signature $\Sigma_{\tau,d}$ of $(\tau,d,cm)$. Along with a bitarray identifying the $W-t-f$ signers, $\Sigma_{\tau,d}$ is posted to the consensus layer.

### VSS finalization

Once $\Sigma_{\tau,d}$ is posted, the VSS initiated by dealer $d$ in round $\tau$ with commitments $cm_{\tau,d}$ is considered succeeded. The remaining $t+f$ weight nodes can complete the VSS to obtain their shares gossiped from honest up nodes.

### Proof sketch

(TODO: sketch proof that changes to the VSS are OK) 

## DKG

The DKG will consist of some number of nodes dealing VSS instances until consensus is reached that enough VSS instances have completed to recover a distributed key. The final shares of the distributed key are equal to the pointwise sum of the shares of each VSS instance.

### Optimistic phase

The ideal scenario is that the fewest possible number of VSS instances are used, and everyone computationally prioritizes the same instances (so there are fewer VSS instances that consume computation time and are left unused)

Since we need at least dealer total weight $p+1$ of VSS instances to finish, the dealer identities can be sorted by their weight such that the $\ell$ highest weighted dealers sum to total weight at least $p+1$ and $\ell$ is minimized.

In the optimistic phase, if there are no faults that prevent these $\ell$ VSS instances from finishing, then these VSS instances are used in the DKG. This can be confirmed by $W-t-f$ weight signing a message indicating the optimistic phase succeeded along with the resulting public key. Since BLS signature aggregation can be used, this consumes $O(\log m)$ on-chain storage.


### Pessimistic phase

Assume the optimistic phase does not succeed before a timeout period expires. Then the DKG enters the pessimistic phase where an arbitrary set of VSS instances of total weight at least $t$ can be used for DKG. The nodes should go in order of decreasing weight of dealers to again minimize the total number of VSS instances that need to finish, and also to minimize the number of VSS instances a node spends computation on but remain unused.

In the pessimistic phase, the consensus layer must be used to achieve consensus on which VSS instances contribute to the distributed key. Since a VSS instance is determined uniquely by dealer identity $d$, DKG phase $\tau$, and the committed polynomials $cm_{\tau,d}$, the hash $\operatorname{BLAKE2b}(\tau, d, cm_{\tau,d})$ of those can be signed by $pk_i$ to indicate node $i$ is ready on that VSS instance. The aggregated signature along with a $\log n$ bitarray encoding identities of the signers can be posted on-chain, which should only cost $O(\log m)$ on-chain data per VSS instance, for total cost roughly $O(m \log m)$ of on-chain data. 

### Proof Sketch 

TODO: proof sketch of resiliance in the appropriate model

### Signature aggregation

TODO - standard BLS multi-signature aggregation with rogue-key attack protection

## Public key

Once the DKG process is complete, nodes compute their shares of the public key. Let $P$ be a fixed generator, then the public key is $Q = sP$ where $s$ is the shared key generated by the DKG.

## Hashing

Let $\operatorname{HTC}: \{0,1\}^* \rightarrow \mathbb{G}_1$ be the hash to curve function as specified in RFC https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/ 

TODO: details of exact instantiation chosen

## Threshold signature

TODO

## Randomness beacon

To produce $r_\lambda$, the randomness beacon at step $\lambda$, the nodes threshold sign the value $\operatorname{BLAKE2b}(\lambda \Vert r_{\lambda-1})$ to obtain signature $\sigma_\lambda$.

The randomness beacon $r_\lambda = \operatorname{BLAKE2b}(\sigma_\lambda)$ is unpredictable and unbiased under the cryptographic assumptions. 

## Threshold encryption

Messages should be encrypted with a symmetric cipher with authentication, for example ChaCha20.

Scheme based on "Simple and Efficient Threshold Cryptosystem from the Gap Diffie-Hellman Group" 

Let $k \in \{0,1\}^256$ be a symmetric key.
Let $r \in \mathbb{F}_q$ be uniformly random.
Let $V = \operatorname{BLAKE2b}(rQ) \oplus k$.
The ciphertext $C = (rP, V, r \operatorname{HTC}(\operatorname{repr}(rQ), V))$

## Threshold decryption

### Generation of decryption shares

Given a ciphertext $C = (U,V,W)$, check $e(P,W) = e(U, \operatorname{HTC}(U,V))$.

If so, if $S_i = \{k, k+1, \ldots, k+w_i\}$, then output $(i, [s_k]U, [s_{k+1}]U, \ldots, [s_{k+w_i}]U)$

(TODO: potential to aggregate decryption shares to a single curve point $[\sum s_j]U$ if known how many decryption shares are needed)

(TODO: potential to batch the pairing check for many different ciphertexts. Given the pairing is by far the most expensive part of decryption, amortizing the pairing check across many decryptions would be nice)

### Combination of decryption shares

Shares of the decrypted symmetric key $k$ can be verifiably recovered from $p+1$ shares.

TODO

## Miscellany

## Key refresh

It is possible to refresh a key (also called proactive secret sharing) to change all the issued key shares without changing the actual public key. 

The primary purpose is to limit vulnerability windows for key shares to leak or compromise. Instead of compromising sufficient key shares of the distributed key, an attacker must compromise those key shares within the refresh window. The secondary purpose may be to invalidate and/or issue new key shares of the same key to adjust for dynamic weights (e.g. change in stake) without changing the public key.

This is accomplished by running the DKG again, except the VSS instances all share the secret 0, and an opening of each $R$ polynomial at 0 is revealed. When the DKG succeeds the new shares of secret 0 are added to the old shares.

### Side channel vulnerability analysis and mitigations

TODO