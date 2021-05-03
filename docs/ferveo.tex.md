# Ferveo crypto design

## Introduction

This document describes the cryptography used in Ferveo. Cryptoeconomics, incentives, slashing, etc., are described elsewhere.

## Goals

The cryptography in Ferveo allows fast distributed key generation, threshold signature, and threshold encryption operations, with weighted participants, where the relative weights of participants are determined by cryptoeconomics/staking values. Because relative weighting requires many more shares of the distributed key than other distributed key protocols, primitives in Ferveo are highly optimized and run in nearly linear time. Ferveo runs on top of a synchronizing consensus layer such as Tendermint, though some messages may be gossiped peer-to-peer if synchrony is not required.

## Definitions

Each node $i \in [1,n]$ in Ferveo has an associated Ed25519 public key identity, and associated relative weight $w_i$. The total weight $\sum_i w_i = W$ can be determined with a performance tradeoff (higher total weight allows more identities, higher resolution of weights, but larger computation and communication complexity). For performance reasons, $W$ is ideally a power of two.

### System model

Among the $n$ nodes, at most total weight $t$ nodes are Byzantine (adversarial) and at most $f$ weight nodes are faulty (some or all communications fail). When faulty nodes crash and recover, at most $f$ weight nodes are faulty at a given moment of time. If proactive secret sharing/key refresh is used, then at most $t$ weight nodes are Byzantine during a key phase.

Synchronous VSS can achieve resiliance when $W \ge 2t+1$, implying $t < W/2$. The privacy threshold $p$ is the value such that subsets of nodes of weight at least $p+1$ can always recover the key or perform operations using the key, and subsets nodes of weight at most $p$ are unable to recover the key or perform operations using the key. It must be $p < W - t$. The default values $t = W/3 - 1$ and $p = 2W/3$ are designed to match the resiliance of Tendermint.

### Assumptions

Under the asynchronous model, node clocks are not synchronized and messages can be delayed for arbitrary periods of time.

In practice a weak synchrony assumption is needed to assure liveness.
Under weak synchrony, the time difference $delay(T)$ between the time a message was sent ($T$) and the time it is received doesn't grow indefinitely over time.

#### Tendermint
Tendermint works under the partially synchronous model.
In this model, there exist a point in time (GST - Global Stabilization Time) after which messages are delivered within a specific time bound.
The GST and time bound are not known in advance.
Tendermint tolerates a $t$-limited Byzantine adversary, with resilience  
$n \ge 3t+1$

#### Ferveo
Ferveo's model and resilience will be the most restrictive of the above:  
$n \ge 3t+1$ under the partially synchronous mode.

In addition, it is assumed that $2W/3$ weight nodes honestly follow the protocol (this excludes honest-but-curious behavior, such as engaging in out-of-band collusion outside of the protocol)

### Curve

The curve used is BLS12-381. $\mathbb{G}_1$ denotes the prime order subgroup of order $r$ and $\mathbb{F}_r$ is the scalar field of BLS12-381 with prime order $r$. The pairing operation is $e(P,Q) : \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$. The generator of $\mathbb{G}_1$ and $\mathbb{G}_2$ are denoted $G_1$ and $G_2$ respectively.

Optionally, BLS12-377 may also be implemented.

Let $\omega$ denote an $W$th root of unity in $\mathbb{F}_r$.

#### Hashing

Let $\operatorname{HTC}: \{0,1\}^* \rightarrow \mathbb{G}_1$ be the hash to curve function as specified in RFC https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/

#### Fast subgroup checks

All subgroup checks of membership in the subgroup $\mathbb{G}_1$ and $\mathbb{G}_2$ are performed as described in https://eprint.iacr.org/2019/814.pdf for performance reasons.

### Symmetric Cryptography

The authenticated encryption and decryption operations with key $k$, ciphertext $C$, and plaintext $M$ are denoted:

$C = \operatorname{encrypt}(k, M)$
$M = \operatorname{decrypt}(k, C)$

Symmetric key encryption and decryption are provided by the ChaCha20Poly1305 (RFC8439) cipher, implemented as the chacha20poly1305 crate.

(Future work: Evaluate potential use of AES-NI in place of ChaCha20, primarily for CPUs with hardware implementation)

## Public Key identities

Every node $i$ in the network chooses an Ed25519 keypair for signing and an x25519 keypair for ephemeral key exchange.

## Key agreement

Node $i$ can send asynchronous messages to node $j$ through either a gossip protocol or on-chain. The messages should be encrypted and authenticated via a symmetric cipher (e.g. ChaCha20) using an x25519 ephemeral key derived through standard key agreement.

1. Node $i$ chooses an ephemeral secret key $\alpha \in \mathbb{F}_r$
2. The ephemeral public key is $[\alpha] G$.
3. The ephemeral shared secret is $[sk_i] pk_j = [sk_i sk_j] G$.
4. (Optional) The shared symmetric key can be additionaly derived  $\operatorname{BLAKE2b}([\alpha]G, [sk_i] pk_j)$

## Initialization

Each DKG session begins by choosing a unique integer session id $\tau$. This can begin at 0 and then be incremented from the previous $\tau$. The total number of shares $W$, Byzantine threshold $t$, and privacy threshold $p$ should also be fixed (independent of $n$, the number of nodes).

## Staking phase

Nodes that want to participate in the DKG and receive key shares can stake value tied to the session id. Using the consensus layer, all nodes should agree on a canonical ordering of $(pk_i, w_i)$ where $pk_i$ is the public key of the $i$th node participating in the DKG and $w_i$ is number of shares belonging to node $i$. The value $i$ is the integer id of the node with public key $pk_i$.

Let $\Psi_{i} = \{ a, a+1, \ldots, a+w_i \}$ be a disjoint partition where $\cup_i \Psi_{i} =  \{0,1, \ldots, W-1\}$, and $\Omega_{i} = \{ \omega^k \ mid k \in \Psi_{i} \}$.

## VSS

The Verifiable Secret Sharing scheme used is a modified version of the ETHDKG scheme (https://eprint.iacr.org/2021/118.pdf) with performance enhancements and weighted shares. All polynomial evaluations are at powers of $\omega$ to allow FFT based polynomial operations.

### KZG commitment scheme

(TODO: if necessary) There is a modified KZG commitment scheme from "Efficient polynomial commitment schemes for multiple points and polynomials" by Dan Boneh, Justin Drake, Ben Fisch, Ariel Gabizon, to allow multiple-point multi-polynomial opening proofs with only two $\mathbb{G}_1$ points.

Additional performance enhancements from:
* https://github.com/khovratovich/Kate/blob/66aae66cd4e99db3182025c27f02e147dfa0c034/Kate_amortized.pdf
* https://alinush.github.io/2020/03/12/towards-scalable-vss-and-dkg.html#authenticated-multipoint-evaluation-trees-amts.

(TODO: possibly compare the inner product commitment scheme as well)

### Dealer messages

1. The dealer $d$ chooses a uniformly random polynomial $S$ of degree $p$.
2. KZG commit to $S$ to obtain $\hat{S}$
3. KZG commit to $S(0)$ to obtain $[S(0)] G_1$
4. Create an opening proof $\pi_0$ of commitment $\hat{S} - [S(0)] G_1$ opening to $0$ at $0$.
5. For all $i \in [1,n]$:
   - create an opening proof $\pi_i$ of commitment $\hat{S}$ at all points $\alpha \in \Omega_i$.
   - compute $\hat{T_i} = \hat{R} - \hat{S}_i$ where $T_i = R - S_i$

The dealer signs and posts $(\tau,d,\hat{S}, [S(0)] G_1, \pi_0)$ to the blockchain.

For each node $i$, the dealer encrypts (with MAC) to $pk_i$ the message $(\tau, d, \langle S(\alpha) \mid \alpha \in \Omega_i \rangle, \pi_i)$ which consists of:

* $\tau$, the round number
* $d$, the dealer id
* $\hat{S}$, the KZG commitment to the share polynomial
* $\langle S(\alpha) \mid \alpha \in \Omega_i\rangle$, the share evaluations belonging to node $i$.
* $\pi_{i}$, the opening proof of $\hat{S}$ at $\Omega_i$

For all $i \in [1,n]$ the dealer posts the $i$th message to the blockchain.

The cost of each plaintext is $2$ integers, ?? $\mathbb{F}_r$ elements and $2$ $\mathbb{G}_1$ elements. (TODO)

#### Offline precompute

Most of the dealer's computation can be done offline/precomputed, potentially saving online computation time.

### Receiving dealer message

Node $i$ recieves, decrypts, and authenticates $(\tau,d,\hat{S}, \pi_0)$ and $(\tau, d, \hat{S},  \langle s_{\alpha} \rangle, \pi)$ from dealer $d$ through the blockchain.

1. Check that commitment $\hat{S}$ and proof $\pi$ open to $\langle s_{\alpha} \rangle$
2. Check that commitment $\hat{S} - [S(0)] G_1$ and proof $\pi_0$ opens to $0$ at $0$.
3. If the decryption or opening check fails, then initiate pre-success or post-success dispute process
4. Else, the VSS has succeeded for node $i$. Sign and post the ready message $(\tau, d, \hat{S})$.

### Pre-success dispute

In the case where the dealer $d$ posts an invalid distribution of shares, a node can initiate the pre-dispute process as long as no DKG has finalized using that VSS. A node $i$ signs and posts a message $(\text{dispute}, \tau, d, k, \pi)$ where $k$ is the shared ephemeral secret key used to encrypt the message from $d$ to $i$ and $\pi$ is the NIZK proof that it is the ephemeral key. The remaining nodes adjucate the dispute in favor of the dealer or complainer. In case the dealer is found to be faulty, that dealer's VSS is terminated. Additionally, penalties and rewards may be allocated.

### VSS finalization

To ensure the DKG results in an unbiased key, a new base $H_1 = \operatorname{HTC}(\text{DKG session} \tau)$ is used for every generated public key.

Once sufficient weight of signatures are posted, the dealer $d$ posts the public share $[S(0)] H_1$ along with a NIZK proof that $[S(0)] G_1$ and $[S(0)] H_1$ share the same discrete log.

Once these are posted and verified, the VSS initiated by dealer $d$ in round $\tau$ with commitment $\hat{S}$ is considered succeeded.

The remaining slow $t+f$ weight nodes can complete the VSS from information on the blockchain. In case those shares are invalid, the slow nodes can initiate the post-success dispute procedure.

If the dealer fails to finalize its VSS session after a timeout period, then a new set of VSS instances of sufficient weight are initiated.

### Post-success finalization

A slow node may discover the dealer has distributed invalid shares after the relevant DKG has already been finalized, or alternatively been unable to post a dispute beforehand. The difficulty is that removing the troublesome VSS instance may change an actively used distributed key, but leaving the VSS instance in place reduces the resiliance of the network. Furthermore, the dispute process might publicly reveal valid shares of the VSS (for example, if a node receives some but not all valid shares from the dealer).

Penalties and rewards can still be allocated for disputes posted after the validity of the distributed key expires, but this process also must happen in a defined window of time between the expiry of the key and the release of staked value for the DKG session.

### Proof sketch

(TODO: sketch proof that changes to the VSS are OK)

## DKG

The DKG will consist of some number of nodes dealing VSS instances until consensus is reached that enough VSS instances have completed to recover a distributed key. The final shares of the distributed key are equal to the pointwise sum of the shares of each VSS instance.

### Optimistic phase

The ideal scenario is that the fewest possible number of VSS instances are used, and everyone computationally prioritizes the same instances (so there are fewer VSS instances that consume computation time and are left unused)

Since we need at least dealer total weight $p+1$ of VSS instances to finish, the dealer identities can be sorted by their weight such that the $\ell$ highest weighted dealers sum to total weight at least $p+1$ and $\ell$ is minimized.

In the optimistic phase, if there are no faults that prevent these $\ell$ VSS instances from being finalized, and no disputes against those dealers, then these VSS instances are used in the DKG. This can be confirmed by $W-t-f$ weight signing a message indicating the optimistic phase succeeded along with the resulting public key. Since BLS signature aggregation can be used, this consumes $O(\log m)$ on-chain storage.

### Pessimistic phase

Assume the optimistic phase does not succeed before a timeout period expires. Then the DKG enters the pessimistic phase where an arbitrary set of VSS instances of total weight at least $t$ can be used for DKG. The nodes should initiate additional VSS instances in order of decreasing weight of dealers to again minimize the total number of VSS instances that need to be dealt, and also to minimize the number of VSS instances a node spends computation to verify but remain unused. Every time a timeout period expires, more nodes should begin dealing VSS instances.

In the pessimistic phase, as soon as $W-t-f$ weight of VSS instances finalize (as determined by ready signatures with no disputes and dealer finalization), then the first sufficient subset of finalized VSS instances is used for the DKG, as determined by the order that the finalization messages are posted.

### Debiasing the final key

The approach of Neji et al can be used to debias the final key. The public key $[s] H_1$ is the sum of all finalization values $[S(0)] H_1$ for all successful VSS instances, and the shared secret key is sharewise sum of all VSS shares.  

### Proof Sketch

TODO: proof sketch of resiliance in the appropriate model

## Threshold signature

TODO

## Randomness beacon

To produce $r_\lambda$, the randomness beacon at step $\lambda$, the nodes threshold sign the value $\operatorname{BLAKE2b}(\lambda \Vert r_{\lambda-1})$ to obtain signature $\sigma_\lambda$.

The randomness beacon $r_\lambda = \operatorname{BLAKE2b}(\sigma_\lambda)$ is unpredictable and unbiased under the cryptographic assumptions.

## Threshold encryption
Scheme based on "Simple and Efficient Threshold Cryptosystem from the Gap Diffie-Hellman Group"

Let $m$ be the plaintext.
Denote ChaCha20 as $chacha20(msg, key)$.
Let $AD$ denote "additional data" for which we need authentication but not encryption.
Sample r as a random scalar from the scalar field.
Then set:
* $U = rG_1$
* $V = chacha20(m, BLAKE2b(rY))$
* $W = rHTC(U, V, AD)$  
The ciphertext $C = (U, V, W)$.

## Threshold decryption

### Generation of decryption shares

Given a ciphertext $C = (U,V,W)$, check $e(G_1, W) = e(U, HTC(U,V, AD))$.

If so, if $S_i = \{k, k+1, \ldots, k+w_i\}$, then output $(i, [s_k]U, [s_{k+1}]U, \ldots, [s_{k+w_i}]U)$

(TODO: potential to aggregate decryption shares to a single curve point $[\sum s_j]U$ if known how many decryption shares are needed)

(TODO: potential to batch the pairing check for many different ciphertexts. Given the pairing is by far the most expensive part of decryption, amortizing the pairing check across many decryptions would be nice)

### Combination of decryption shares

To obtain the plaintext we need to combine at least $t$ decryption shares $\{U_i\}_{i \in \Phi}$. Using lagrange intepolation we get
$rY = \sum_{i \in \Phi}{\lambda_{0,i}U_i}$
and then $m = chacha20(V, BLAKE2b(rY))$

## Dispute procedures

### VSS dealer dispute

Dispute in the VSS protocol is based on the ETHSKG method, https://eprint.iacr.org/2019/985.

Nodes are incentivized to perform the VSS protocol properly though penalties for VSS failure and rewards for reporting VSS failure.

In the case where a node serves as a VSS dealer and distributes encrypted VSS shares to the other nodes, the dealer node can be penalized if the encrypted shares are invalid. The dealer commits to a single polynomial, and every node has fixed evaluation points for its shares, so the recipient of the shares can verifiably reveal the shared secret used to encrypt the shares. In case of any inconsistency of the share encryption or the evaluations of the shares, the dealer can be penalized.

Therefore, dealers have incentive to ensure that the VSS shares distributed via Tendermint are well formed and decryptable according to the protocol, and that (for example) a partial distribution of shares is incentive-incompatible.

### Threshold decryption dispute

The goal of dispute in the threshold decryption process is to disincentivize early decryption of the ciphertexts. The threshold encryption/decryption scheme of BZ03 is not disputable in this way, because the encrypter of a ciphertext can also construct every participant's decryption share and so there is never cryptographically sound evidence of dishonest or out-of-protocol behavior by a participant.

There is an alternative threshold decryption scheme which is plausibly disputable in this way, however there are other problems with alternative disputable schemes: susceptibility to silent collusion via secure enclave, and also large ciphertexts.

## Miscellany

### Key refresh

It is possible to refresh a key (also called proactive secret sharing) to change all the issued key shares without changing the actual public key.

The primary purpose is to limit vulnerability windows for key shares to leak or compromise. Instead of compromising sufficient key shares of the distributed key, an attacker must compromise those key shares within the refresh window. The secondary purpose may be to invalidate and/or issue new key shares of the same key to adjust for dynamic weights (e.g. change in stake) without changing the public key.

This is accomplished by running the DKG again, except the VSS instances all share the secret 0, and an opening of each $R$ polynomial at 0 is revealed. When the DKG succeeds the new shares of secret 0 are added to the old shares.

### Secure enclave computations

The hardware-based security enclaves built into certain CPUs, such as Intel SGX, can both positively and negatively affect the security model.

Since the VSS, DKG, and threshold operations include storage and computation on secret data that should not be publicly revealed, a node may run these sensitive computations inside of a secure enclave as a layer of protection against attack by an external adversary. Since HSM support for VSS, DKG, and threshold operations is unlikely, use of a secure enclave may be useful.

Alternatively, secure enclaves can undermine the dispute process by facilitating silent collusion among adversarial or honest-but-curious participants. Since dispute procedures rely on incentivizing nodes (even adversarial or dishonest ones) to report dishonest behavior, a dispute process can only work if evidence of dishonest behavior is available; however, if collusion occurs entirely within a secure enclave or a cryptographic multiparty computation, then such evidence may not be revealed.

### Side channel vulnerability analysis and mitigations

TODO
