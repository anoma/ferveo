# Overview

## Goals

The cryptography in Ferveo should allow:
- Fast distributed key generation
- Fast threshold signature
- Fast threshold decryption 
  
with a set of weighted participants, where the relative weights of participants are determined by cryptoeconomics/staking values. Because relative weighting requires many more shares of the distributed key than other distributed key protocols, all primitives in Ferveo are highly optimized and run in nearly linear time. 

## Synchronization

Ferveo does not use an asynchronous DKG protocol. Instead, Ferveo runs on top of a synchronizing consensus layer such as Tendermint, though some messages may be gossiped peer-to-peer when synchrony is not required. The use of an underlying consensus layer allows better performance than using an asynchronous DKG because the DKG can use the **consensus** and **censorship resistance** features of the blockchain to save on computation and communication costs.
