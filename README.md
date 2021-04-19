![ci-badge](https://github.com/heliaxdev/ferveo/actions/workflows/build.yaml/badge.svg)

# ferveo
An implementation of a DKG protocol for front-running protection on public blockchains.

## Questions
* Can we aggregate decryption shares?
  * Probably not but as soon as a transaction has been decrypted we don't need to gossip the decryption shares but can rather gossip the decrypted transaction.
* How to check if an encrypted transaction matches the decrypted transaction?
  * The encrypted transaction can include a hash commitment to the plain-text transaction that is verified.
* How to account for cost of storing and decrypting transactions?
  * Encrypted transactions need a fee payer that pays for that base cost.

## This branch
* We improve the verification with less final exponentiation in the
  pairing computation.
* We implement the multi-verification for the threshold signature, but
  the timings are not really significative: hashes to G2 is expensive
  and the pairing is not the most expensive part of the verification.
  
| verification of |               timing (in ms) |
|-----------------------------------|------------|
| a single signature | 4.49 |
| a (7-10)-threshold signature | 20.56 |
| twenty (rand-10)-threshold signatures | 348.79 |
| a 20-multi-signature | 331.13|
| a 10-aggregated signature| 4.96 |
| twenty 10-aggregated signatures | 95.44 |
| a 20-multi-aggregated signature | 56.37 |

**Next step:** look at aggregated signatures instead of signatures in
order to see if the multi-verification is useful.
