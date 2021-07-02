# System model and assumptions

The security model is intended to match the Tendermint security model. Among the validator set, safety and liveness is promised as long as less than 1/3 by weight are Byzantine (malicious, or otherwise not following the protocol) or faulty. When faulty validators crash and recover, they can resume the protocol, but liveness is only guaranteed if sufficient weight is honest and live. If proactive secret sharing is used to refresh a key during an epoch, then less than 1/3 weight nodes are Byzantine during a key phase.

Synchronous VSS can achieve resiliance with threshold \\(t\\) when \\(W \ge 2t+1\\), implying \\(t < W/2\\). The privacy threshold \\(p\\) is the value such that subsets of nodes of weight at least \\(p+1\\) can always recover the key or perform operations using the key, and subsets nodes of weight at most \\(p\\) are unable to recover the key or perform operations using the key. It must be \\(p < W - t\\). The default values \\(t = W/3 - 1\\) and \\(p = 2W/3\\) are designed to match the resiliance of Tendermint.

## Liveness guarantees

Ferveo depends on the liveness guarantees of the Tendermint protocol; if Tendermint fails to provide liveness, the DKG and threshold operations of Ferveo will also stop. Alternatively, whenever Tendermint can provide liveness, Ferveo's DKG and threshold operations will also be live. Therefore, any assumptions or improvements to Tendermint's liveness guarantees subsequently apply to Ferveo as well. Ferveo uses a Publicly Verifiable DKG specifically to match the liveness of the consensus layer.
