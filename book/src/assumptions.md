# System model and assumptions

The security model is intended to match the Tendermint security model. Among the validator set, safety and liveness is promised as long as less than 1/3 by weight are Byzantine (malicious) or faulty. When faulty validators crash and recover, they can resume the protocol, but liveness is only guaranteed if sufficient weight is honest and live. If proactive secret sharing is used to refresh a key during an epoch, then less than 1/3 weight nodes are Byzantine during a key phase.

Synchronous VSS can achieve resiliance with threshold \\(t\\) when \\(W \ge 2t+1\\), implying \\(t < W/2\\). The privacy threshold \\(p\\) is the value such that subsets of nodes of weight at least \\(p+1\\) can always recover the key or perform operations using the key, and subsets nodes of weight at most \\(p\\) are unable to recover the key or perform operations using the key. It must be \\(p < W - t\\). The default values \\(t = W/3 - 1\\) and \\(p = 2W/3\\) are designed to match the resiliance of Tendermint.

### Timing assumptions

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

In addition, the assumption that $2W/3$ weight of validators are not malicious means that they honestly follow the protocol. This excludes honest-but-curious behavior, such as engaging in out-of-band collusion outside of the protocol, which will be addressed later.