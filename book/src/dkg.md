# Publicly Verifiable Distributed Key Generation

Ferveo uses a Publicly Verifiable Distributed Key Generator

The **Aggregatable DKG** scheme of Kobi Gurkan, Philipp Jovanovic, Mary Maller, Sarah Meiklejohn, Gilad Stern, and Alin Tomescu uses a similar approach to obtain an \\( O(n \log n)\\) time *asynchronous* DKG. Here, Ferveo assumes an synchronous communication model instead.

The primary advantage of a Publicly Verifiable DKG is that no complaint or dispute round is necessary; every validator can check that the DKG succeeded correctly, even for validators that remain offline during the entire DKG. Such faulty validators can come online during any point during the epoch, and after syncing the missed blocks, becomes immediately able to recover its key shares. 

The primary disadvantage of a Publicly Verifiable DKG is that most schemes produce a private key shares consisting of **group elements** instead of scalar field elements, and thus are incompatible with many existing cryptographic primitives.  Ferveo works around this issue by using novel cryptographic primitives, still based on standard cryptographic assumptions, that are compatible with the private key shares generated

Some Publicly Verifiable DKG schemes, such as Groth21, produce field private key shares. Such a scheme may be evaluated for use in Ferveo at a later date.

## Parameters

In addition to the two independent generators \\(G \in \mathbb{G}_1\\) and \\(H \in \mathbb{G}_2\\), a third independent generator \\(\hat{u}_1 \in \mathbb{G}_2\\) is selected. 

## Session keys

Each validator \\(i\\) generates a **session keypair** for the lifetime of the DKG: a decryption key \\(dk_i \in \mathbb{F}_r\\), and a signing key \\(sk_i\in \mathbb{F}_r \\). 

The signing key is used for a signature of knowledge in the DKG and is independent of the Ed25519 identity used for signing messages in the protocol.

The public session keypair consists of an **encryption key** \\(ek_i \in \mathbb{G}_2\\) and a verification key \\(sk_i \in \mathbb{G}_1\\):

\\[ek_i = [dk_i] H \\]
\\[vk_i = [sk_i] G \\]

## Publicly Verifiable Secret Sharing

The validators, in decreasing order of number of key shares, each act as a dealer for exactly one PVSS instance until at least 2/3 by weight of key shares have successfully posted a verified correct PVSS instance to the blockchain. In case a dealer's PVSS instance does not verify as correct, that instance is discarded (and penalties may be imposed) and additional validators act as dealers until the 2/3 threshold is reached.

## Output

Once 2/3 by weight of dealers have posted correct PVSS instances, all of the correct instances are aggregated into a single PVSS instance. The commitment to the constant term of the aggregated PVSS instance, \\(F_0\\), is the public key output \\(Y\\) from the PVDKG, and each validators aggregated private key shares \\(Z_{i,\omega_j} \\) are the private key shares associated with \\(Y\\)