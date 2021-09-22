# Publicly Verifiable Distributed Key Generation

Ferveo uses a Publicly Verifiable Distributed Key Generator

The **Aggregatable DKG** scheme of Kobi Gurkan, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, Gilad Stern, and Alin Tomescu uses a similar approach to obtain an \\( O(n \log n)\\) time *asynchronous* DKG. Here, Ferveo assumes an synchronous communication model instead.

The primary advantage of a Publicly Verifiable DKG is that no complaint or dispute round is necessary; every validator can check that the DKG succeeded correctly, even for validators that remain offline during the entire DKG. Such faulty validators can come online during any point during the epoch, and after syncing the missed blocks, becomes immediately able to recover its key shares. 

The primary disadvantage of a Publicly Verifiable DKG is that most schemes produce a private key shares consisting of **group elements** instead of scalar field elements, and thus are incompatible with many existing cryptographic primitives.  Ferveo works around this issue by using novel cryptographic primitives, still based on standard cryptographic assumptions, that are compatible with the private key shares generated

Some Publicly Verifiable DKG schemes, such as Groth21, produce field private key shares. Such a scheme may be evaluated for use in Ferveo at a later date.

## Parameters

In addition to the two independent generators \\(G \in \mathbb{G}_1\\) and \\(H \in \mathbb{G}_2\\), a third independent generator \\(\hat{u}_1 \in \mathbb{G}_2\\) is selected. 

## Epoch keys

Each validator \\(i\\) generates a **epoch keypair**: a private decryption key \\(dk_i \in \mathbb{F}_r\\), and a public encryption key \\(ek_i\in \mathbb{G}_2 \\). The encryption key is derived from the decryption key:

\\[ek_i = [dk_i] H \\]

Each validator is required to generate an epoch keypair at genesis, or upon joining the validator set. Each validator should generate and announce a new epoch public key once per epoch, but in the event that a validator does not announce a new epoch public key during an epoch, the last announced epoch public key should be used in the DKG. For this reason, each validator should persist their latest epoch private key on disk.

## Publicly Verifiable Secret Sharing

The validators should each generate exactly one PVSS instance as a dealer, and include that instance as a VoteExtension to a specially designated DKG block. The next block proposer is responsible for verifying and aggregating at least 2/3 by weight of PVSS instances, and including the aggregation in the next block.

For performance reasons, the aggregating validator may sort the PVSS instances by decreasing validator weight, and only include sufficient instances to reach the necessary 2/3 total weight. PVSS instances above the 2/3 weight threshold are ignored.

In case a dealer's PVSS instance does not verify as correct, that instance is discarded (and penalties may be imposed).

## Output

Once 2/3 by weight of correct PVSS instances have been aggregated into a single PVSS instance, the commitment to the constant term of the aggregated PVSS instance, \\(F_0\\), is the public key output \\(Y\\) from the PVDKG, and each validators aggregated private key shares \\(Z_{i,\omega_j} \\) are the private key shares associated with \\(Y\\)