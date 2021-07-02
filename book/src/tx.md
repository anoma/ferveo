# Encrypted Transactions

When Ferveo is integrated into Tendermint, the validators should run the DKG once per epoch and the generated public key \\(Y\\) broadcast to all nodes in the network.

Transactions sent to the mempool should be encrypted to this public key, and block proposers select encrypted transactions from the mempool and commit to them in to block proposals. Therefore, the execution and ordering of transactions is determined before they are decrypted and revealed.

An encrypted transaction consists of:

- The public key ciphertext \\(U, W\\) associated with this transaction
- The Chacha20 encrypted payload of the transaction, with symmetric key derived from \\(U, W\\)
- A BLAKE2b hash of the transaction payload
- Transaction fee payment details

The inclusion of fee payment outside of the payload ensures that the network is not saturated with invalid transactions.

## Block proposal

A block proposal, therefore, consists of some validator-selected encrypted transactions (likely ordered by fee) as well as all decryptions of transactions from the previous block. Availability of decryption shares for those transactions is guaranteed by new block finalization rules, and it is the block proposer's responsibility to combine the decryption shares to derive each transaction's symmetric key, and to compute the ChaCha20 decryption of each encrypted transaction's payload.

## Block finalization

In addition to the standard 2/3 weight requirements for block finalization, Ferveo adds an additional requirement: every validator signature on a block must include valid, signed decryption shares for every encrypted transaction committed to in that block. This guarantees liveness to the same extent: the network will not stop while waiting for decryption shares unless the network stops while waiting for signatures as well.

### Correctness of decryption shares

The validity of all decryption shares should be checked before accepting a block. Since penalties can be enforced on validators for sending bad decryption shares, optimistic verification can be done on the decryption shares.

## Privacy

Ferveo only provides privacy while pending **within the mempool**; once transactions are decrypted, all details of the payload become public. In addition, fee payment information reveals who the fee payer is (who may be a proxy).

## Invalid transactions

In the case where the transaction creator does not follow the protocol, for example by having an invalid payload, a payload that does not match the hash, or using a bad nonce \\(r\\), the network does not make any guarantees regarding privacy or execution order (or execution at all) of an invalid transaction.