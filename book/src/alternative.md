# Alternative Schemes

Several alternative DKG and threshold operation protocols are implemented in Ferveo for comparison and benchmarking purposes. The major alternative schemes are:

 - A Pedersen DKG using a Feldman VSS. A traditional DKG scheme, this can be implemented either over a bilinear group, or a non-pairing friendly elliptic curve such as Pallas. Performance is excellent, but communication complexity can be high, and liveness guarantees are complicated by the need for a complaint/dispute round to prevent malicious VSS instances.
 - A scalable DKG based on fast KZG commitments. KZG commitments can make VSS verification faster and communication complexity is smaller, at the cost of a slightly more complex protocol and the same complaint/dispute round is necessary.

For completeness, these DKG and VSS schemes are documented in this Appendix.
