# Key Refresh

It is possible to refresh a key (also called proactive secret sharing) to change all the issued key shares without changing the actual public key.

The primary purpose is to limit vulnerability windows for key shares to leak or compromise. Instead of compromising sufficient key shares of the distributed key, an attacker must compromise those key shares within the refresh window. The secondary purpose may be to invalidate and/or issue new key shares of the same key to adjust for dynamic weights (e.g. change in stake) without changing the public key.

This is accomplished by running the DKG again, except the VSS instances all share the secret 0, and an opening of each $R$ polynomial at 0 is revealed. When the DKG succeeds the new shares of secret 0 are added to the old shares.