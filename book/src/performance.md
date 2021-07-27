Therefore the total work done per block, in the optimistic case, if there are T transactions and V validators, by role:

*  Block proposer:
   * ciphertext validity check: 2T pairings
   * combine decryption shares: T*V pairings plus T multiplies in G_t 

* Block signer: 

  * ciphertext validity check: T+1 pairings plus T multiplies in each G_1 and G_2
  * create decryption shares: T multiplies of G_1, T multiplies in G_t
  *  verify decryption shares: V+1pairings plus 2T multiplies in G_1
  *  verify combination: V pairings plus V+T multiplies in G_t

* Full node: 

  *  verify decryption shares: V+1 pairings plus 2T multiplies in G_1
  *  verify combination: V pairings plus V+T multiplies in G_t 

* Long term storage per block (this does assume ephemeral data is pruned):

  *  aggregated decryption shares (of invalid tx):  V elements of G_1 ( 48*V bytes)
  *  combined shares (of invalid tx): T elements of G_t (400*T bytes)