# Initialization

Each DKG session begins by choosing a unique integer session id \\(\tau\\). This can begin at 0 and then be incremented from the previous \\(\tau\\). When strongly integrated into Tendermint, the epoch number can be used as \\(tau\\), with the note that additional DKG sessions within an epoch (for example, to do key refresh) must use a unique \\(\tau\\).

# Share partitioning

In general the validator's staking weights will total much greater than \\(W\\), the number of shares issued in the DKG; therefore, the staking weights will have to be scaled and rounded.

The algorithm to assign relative weights achieves exactly the desired total weight. Initially, every participant weight is scaled and rounded down to the nearest integer. The amount of assigned weight is greater than the total desired weight minus the number of participants, so weight at most 1 can be added to each participant in order of staked weight, until the total desired weight is reached. After all total weight is assigned, each participant will have relative weight at most 1 away from their fractional scaled weight.

Using the consensus layer, all validators should agree on a canonical ordering of \\((pk_i, w_i)\\)$ where \\(pk_i\\) is the public key of the \\(i\\)th validator and \\(w_i\\) is number of shares belonging to node \\(i\\). The value \\(i\\) is the integer id of the node with public key \\(pk_i\\).

Let \\(\Psi_{i} = \{ a, a+1, \ldots, a+w_i \}$\\) be the disjoint partition described above such that \\(\cup_i \Psi_{i} =  \{0,1, \ldots, W-1\}\\), and \\(\Omega_{i} = \{ \omega^k \mid k \in \Psi_{i} \}\\). \\(\Psi_i\\) are the **share indexes** assigned to the \\(i\\)th validator and \\(\Omega_i\\) is the **share domain** of the \\(i\\)th validator.