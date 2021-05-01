<h1 align="center">ferveo</h1>

![ci-badge](https://github.com/heliaxdev/ferveo/actions/workflows/build.yaml/badge.svg)

# ferveo
An implementation of a DKG protocol for front-running protection on public blockchains.


# Security Warning
This library is under development and has not been reviewed, audited, or prepared for production use.

## Build guide

Ferveo targets the `stable` toolchain of Rust. 

## Tests 

Ferveo will include a comprehensive library of tests.

## Questions
* Can we aggregate decryption shares?
  * Probably not but as soon as a transaction has been decrypted we don't need to gossip the decryption shares but can rather gossip the decrypted transaction.
* How to check if an encrypted transaction matches the decrypted transaction?
  * The encrypted transaction can include a hash commitment to the plain-text transaction that is verified.
* How to account for cost of storing and decrypting transactions?
  * Encrypted transactions need a fee payer that pays for that base cost.
