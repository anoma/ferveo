# Secure enclave computation

The hardware-based security enclaves built into certain CPUs, such as Intel SGX, can both positively and negatively affect the security model.

Since the VSS, DKG, and threshold operations include storage and computation on secret data that should not be publicly revealed, a node may run these sensitive computations inside of a secure enclave as a layer of protection against attack by an external adversary. Since HSM support for VSS, DKG, and threshold operations is unlikely, use of a secure enclave may be useful.

Alternatively, secure enclaves can undermine the dispute process by facilitating silent collusion among adversarial or honest-but-curious participants. Since dispute procedures rely on incentivizing nodes (even adversarial or dishonest ones) to report dishonest behavior, a dispute process can only work if evidence of dishonest behavior is available; however, if collusion occurs entirely within a secure enclave or a cryptographic multiparty computation, then such evidence may not be revealed.

At this time, it does not appear practical to implement a DKG whose security model depends on the underlying security of a secure hardware enclave.