# Preliminaries

Ferveo is intended to integrate into an existing framework such as Tendermint, and so the validator set is the natural participant set for Ferveo. Therefore, Ferveo assumes that all \\(n\\) validators have an associated Ed25519 public key identity and have staked some amount of token for the current epoch. Ferveo derives from the staking amounts an associated relative weight $\\(w_i\\). The total weight \\(\sum_i w_i = W\\) is a fixed parameter of the system, determined by a performance tradeoff (higher total weight allows more identities, higher resolution of weights, but larger computation and communication complexity). For performance reasons, \\(W\\) is ideally a power of two.

## Lower bounds on \\(W\\)

In general, only performance concerns place a practical upper bound on how large \\(W\\) may be. The practical lower bound on \\(W\\) is determined by three factors:

- \\(W\\) must be large enough so that validators with lower staking amounts receive at least one key share. Otherwise, the network becomes more centeralized among validators with higher staking amount. Validators with at least 0.5% of the network stake should receive at least one key share.
- In order to ensure liveness of transaction decryption, ideally every subset of validators with network stake at least 2/3 should have at least 2/3 of key shares; that way an otherwise live network will not stop waiting for threshold decryption. However, because of rounding this is difficult to guarantee. Having a larger value of \\(W\\) with increased resolution of weights narrows the gap between the relative network stake of a validator subset and the relative key share of that subset.
- There should not be significant incentive for validators to strategically allocate stake among multiple identities to gain additional key shares through resolution or rounding, for example by creating many minimally staked validator identities. 