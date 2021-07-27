# Encrypted Transactions

When Ferveo is integrated into Tendermint, the validators should run the DKG once per epoch and the generated public key \\(Y\\) broadcast to all nodes in the network.

Transactions sent to the mempool should be encrypted to this public key, and block proposers select encrypted transactions from the mempool and commit to them in to block proposals. Therefore, the execution and ordering of transactions is determined before they are decrypted and revealed.

An encrypted transaction consists of:

- The public key ciphertext \\(U, W\\) associated with this transaction
- The ChaCha20 encrypted payload of the transaction, with symmetric key derived from \\(U, W\\)
- A BLAKE2b hash of the transaction payload
- Transaction fee payment details

The inclusion of fee payment outside of the payload ensures that the network is not saturated with invalid transactions.

## Block proposal

A block proposal, therefore, consists of:

1.  Validator-selected encrypted transactions (likely ordered by fee)
2.  Combined decryption shares for all transactions in the previous block
3.  Decryptions of transactions from the previous block.   
 
Availability of decryption shares for those transactions is guaranteed by new block finalization rules, and it is the block proposer's responsibility to combine the decryption shares to derive each transaction's symmetric key, and to compute the ChaCha20 decryption of each encrypted transaction's payload.

Constructing a valid block proposal therefore executes 1 `TPKE.CombineDecryptionShares` operation per transaction per block signer in the previous block.

Verifying the validity of a block proposal therefore executes 1 `TPKE.VerifyCombination` operation per block signer in the previous block. 

## Block finalization

In addition to the standard 2/3 weight requirements for block finalization, Ferveo adds an additional requirement: every validator signature on a block must include valid, signed decryption shares corresponsing to that validator, for every encrypted transaction committed to in that block, totaling at least 2/3 weight of decryption shares. 

Signing a block proposal therefore executes 1 `TPKE.CiphertextValidity ` operation and 1 `TPKE.CreateDecryptionShare()` operation per transaction in that block proposal.

Verifying the block proposal executes 1 `TPKE.CiphertextValidity ` operation and 1 `TPKE.BatchVerifyDecryptionShares()` operation per transaction in that block proposal.

This guarantees liveness will be similar: the network will not stop while waiting for decryption shares unless the network stops while waiting for signatures as well.

## Invalid transactions

The primary issue in accepting the finality of a block is verification that the decryption of every transaction succeeded correctly. 

In the optimistic case, where all transactions are constructed exactly as required by the protocol, the block proposer can run `TPKE.CombineDecryptionShares()` to obtain the shared secret, and therefore the 256 bit symmetric key, for each transaction. Since all transactions are valid, this symmetric key successfully decrypts the transaction plaintext which matches the BLAKE2b hash. (Alternatively, a key-committing scheme could be used). Therefore, only one 32 byte symmetric key per transaction needs to be added to the block, to assist in block verification.

Problems arise when an invalid transaction, where either the symmetric key or BLAKE2b hash, does not match the transaction payload. The protocol must verify that the transaction is actually invalid and that no validator submitted invalid decryption shares or failed to combine shares according to protocol. Otherwise, a malicious validator would be able to deny execution of specific transactions upon discovering its contents. 

To avoid a high cost incurrec (and DoS attack vector) of many invalid transactions, all invalid transactions are handled in an aggregated way. The decryption shares of all invalid transactions are aggregated using `TPKE.AggregateDecryptionShares`; the aggregated decryption shares, along with the result of `TPKE.CombineDecryptionShares`
for each invalid transaction, is attached to the block instead of the 32 byte symmetric key. 

Therefore, full nodes can run the relatively inexpensive `TPKE.VerifyAggregatedCombination` to check the validity of the combined shares of each allegedly invalid transaction, and attempt symmetric decryption using each transaction's derived symmetric key. Upon the expected failure to decrypt an invalid transaction, that transaction is discarded instead of executed (consuming any fee) which mitigates the minor additional cost of invalidity verification. 


### Correctness of decryption shares

The validity of all decryption shares must be checked before accepting a block. 

In case `TPKE.BatchVerifyDecryptionShares` fails, indicating that some validator may have sent faulty decryption shares, a fallback protocol must be initiated to discover which validators sent valid decryption shares, by executing `TPKE.VerifyDecryptionShares` separately for each validator's decryption shares. 

This is significantly more expensive than `TPKE.BatchVerifyDecryptionShares`; however, since penalties can be enforced on validators for sending bad decryption shares, the optimistic verification `TPKE.BatchVerifyDecryptionShares` should succeed most of the time.

## Privacy

Ferveo only provides additional privacy while pending **within the mempool**; once transactions are decrypted, all details of the payload become public. In addition, fee payment information reveals who the fee payer is (who may be a proxy).

## Invalid transactions

In the case where the transaction creator does not follow the protocol, for example by having an invalid payload, a payload that does not match the hash, or using a bad nonce \\(r\\), the network does not make any guarantees regarding privacy or execution order (or execution at all) of an invalid transaction.