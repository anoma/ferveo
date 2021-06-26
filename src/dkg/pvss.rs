encryption_key: G2Affine::prime_subgroup_generator()
.into_projective()
.mul(self.decryption_key.inverse().unwrap())
.into_affine(),
verification_key: G2Affine::prime_subgroup_generator()
.into_projective()
.mul(&self.signing_key.inverse().unwrap())
.into_affine(),