# Fast KZG DKG

The Verifiable Secret Sharing scheme using Fast KZG commitments is a modified version of the ETHDKG scheme (https://eprint.iacr.org/2021/118.pdf) and the DKG from (https://people.csail.mit.edu/devadas/pubs/scalable_thresh.pdf), with performance enhancements and weighted shares. All polynomial evaluations are at powers of \\(\omega\\) to allow FFT based polynomial operations.

### KZG commitment scheme

Batched fast KZG opening proofs contribute to scalability. Fast KZG openings are based off of the following:

* https://github.com/khovratovich/Kate/blob/66aae66cd4e99db3182025c27f02e147dfa0c034/Kate_amortized.pdf
* https://alinush.github.io/2020/03/12/towards-scalable-vss-and-dkg.html

The Feist and Khovratovich batch KZG opening allows for simultaneous fast computation of \\(2^n\\) opening proofs of a single polynomial at \\(2^n\\) roots of unity, which motivates the choice of evaluation points. 

Additionally, nearly linear time fast polynomial evaluation and fast polynomial interpolation algorithms allow the dealer to combine all openings belonging to a participant into a single \\(\mathbb{G}_1\\) element, and allow the recipient to fast verify the opening proof.

### Dealer messages

1. The dealer \\(d\\) chooses a uniformly random polynomial \\(S\\) of degree \\(p\\).
2. KZG commit to \\(S\\) to obtain \\(\hat{S}\\)
3. KZG commit to \\(S(0)\\) to obtain \\([S(0)] G_1\\)
4. Create an opening proof \\(\pi_0\\) of commitment \\(\hat{S} - [S(0)] G_1\\) opening to \\(0\\) at \\(0\\).
5. For all \\(i \in [1,n]\\):
   - create an opening proof \\(\pi_i\\) of commitment \\(\hat{S}\\) at all points \\(\alpha \in \Omega_i\\).
   - compute \\(\hat{T_i} = \hat{R} - \hat{S}_i\\) where \\(T_i = R - S_i\\)

The dealer signs and posts \\((\tau,d,\hat{S}, [S(0)] G_1, \pi_0)\\) to the blockchain.

For each node \\(i\\), the dealer encrypts (with MAC) to \\(pk_i\\) the message \\((\tau, d, \langle S(\alpha) \mid \alpha \in \Omega_i \rangle, \pi_i)\\) which consists of:

* \\(\tau\\), the round number
* \\(d\\), the dealer id
* \\(\hat{S}\\), the KZG commitment to the share polynomial
* \\(\langle S(\alpha) \mid \alpha \in \Omega_i\rangle\\), the share evaluations belonging to node \\(i\\).
* \\(\pi_{i}\\), the opening proof of \\(\hat{S}\\) at \\(\Omega_i\\)

For all \\(i \in [1,n]\\) the dealer posts the \\(i\\)th message to the blockchain.

The cost of each plaintext is \\(2\\) integers, ?? \\(\mathbb{F}_r\\) elements and \\(2\\) \\(\mathbb{G}_1\\) elements. (TODO)

#### Offline precompute

Much of the dealer's computation can be done offline/precomputed, potentially saving online computation time. The secret polynomial, commitment, and opening proofs can be speculatively computed, subject to maintaining secrecy of the secret data.

### Receiving dealer message

Node \\(i\\) recieves, decrypts, and authenticates \\((\tau,d,\hat{S}, \pi_0)\\) and \\((\tau, d, \hat{S},  \langle s_{\alpha} \rangle, \pi)\\) from dealer \\(d\\) through the blockchain.

1. Check that commitment \\(\hat{S}\\) and proof \\(\pi\\) open to \\(\langle s_{\alpha} \rangle\\)
2. Check that commitment \\(\hat{S} - [S(0)] G_1\\) and proof \\(\pi_0\\) opens to \\(0\\) at \\(0\\).
3. If the decryption or opening check fails, then initiate pre-success or post-success dispute process
4. Else, the VSS has succeeded for node \\(i\\). Sign and post the ready message \\((\tau, d, \hat{S})\\).

### Pre-success dispute

In the case where the dealer \\(d\\) posts an invalid distribution of shares, a node can initiate the pre-dispute process as long as no DKG has finalized using that VSS. A node \\(i\\) signs and posts a message \\((\text{dispute}, \tau, d, k, \pi)\\) where \\(k\\) is the shared ephemeral secret key used to encrypt the message from \\(d\\) to \\(i\\) and \\(\pi\\) is the NIZK proof that it is the ephemeral key. The remaining nodes adjucate the dispute in favor of the dealer or complainer. In case the dealer is found to be faulty, that dealer's VSS is terminated. Additionally, penalties and rewards may be allocated.

### VSS finalization

To ensure the DKG results in an unbiased key, a new debiasing base \\(H_1 = \operatorname{HTC}(\text{DKG session} \tau)\\) is used for every generated public key.

Once sufficient weight of signatures are posted, the dealer \\(d\\) posts the public share \\([S(0)] H_1\\) along with a NIZK proof that \\([S(0)] G_1\\) and \\([S(0)] H_1\\) share the same discrete log.

Once these are posted and verified, the VSS initiated by dealer \\(d\\) in round \\(\tau\\) with commitment \\(\hat{S}\\) is considered succeeded.

The remaining slow \\(t+f\\) weight nodes can complete the VSS from information on the blockchain. In case those shares are invalid, the slow nodes can initiate the post-success dispute procedure.

If the dealer fails to finalize its VSS session after a timeout period, then a new set of VSS instances of sufficient weight are initiated.

### Post-success finalization

A slow node may discover the dealer has distributed invalid shares after the relevant DKG has already been finalized, or alternatively been unable to post a dispute beforehand. The difficulty is that removing the troublesome VSS instance may change an actively used distributed key, but leaving the VSS instance in place reduces the resiliance of the network. Furthermore, the dispute process might publicly reveal valid shares of the VSS (for example, if a node receives some but not all valid shares from the dealer).

Penalties and rewards can still be allocated for disputes posted after the validity of the distributed key expires, but this process also must happen in a defined window of time between the expiry of the key and the release of staked value for the DKG session.

### Proof sketch

## DKG

The DKG will consist of some number of nodes dealing VSS instances until consensus is reached that enough VSS instances have completed to recover a distributed key. The final shares of the distributed key are equal to the pointwise sum of the shares of each VSS instance.

### Optimistic phase

The ideal scenario is that the fewest possible number of VSS instances are used, and everyone computationally prioritizes the same instances (so there are fewer VSS instances that consume computation time and are left unused)

Since we need at least dealer total weight \\(p+1\\) of VSS instances to finish, the dealer identities can be sorted by their weight such that the \\(\ell\\) highest weighted dealers sum to total weight at least \\(p+1\\) and \\(\ell\\) is minimized.

In the optimistic phase, if there are no faults that prevent these \\(\ell\\) VSS instances from being finalized, and no disputes against those dealers, then these VSS instances are used in the DKG. This can be confirmed by \\(W-t-f\\) weight signing a message indicating the optimistic phase succeeded along with the resulting public key. Since BLS signature aggregation can be used, this consumes \\(O(\log m)\\) on-chain storage.

### Pessimistic phase

Assume the optimistic phase does not succeed before a timeout period expires. Then the DKG enters the pessimistic phase where an arbitrary set of VSS instances of total weight at least \\(t\\) can be used for DKG. The nodes should initiate additional VSS instances in order of decreasing weight of dealers to again minimize the total number of VSS instances that need to be dealt, and also to minimize the number of VSS instances a node spends computation to verify but remain unused. Every time a timeout period expires, more nodes should begin dealing VSS instances.

In the pessimistic phase, as soon as \\(W-t-f\\) weight of VSS instances finalize (as determined by ready signatures with no disputes and dealer finalization), then the first sufficient subset of finalized VSS instances is used for the DKG, as determined by the order that the finalization messages are posted.

### Debiasing the final key

The approach of Neji et al can be used to debias the final key. The public key \\([s] H_1\\) is the sum of all finalization values \\([S(0)] H_1\\) for all successful VSS instances, and the shared secret key is sharewise sum of all VSS shares.  