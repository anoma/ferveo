use rand::Rng;

// HybridVss parameters
#[derive(Copy, Clone)]
pub struct Params {
    pub d: u32, // dealer index
    pub f: u32, // failure threshold
    pub n: u32, // number of participants
    pub t: u32, // threshold
}

impl Params {
    // initialize with random values for `d`
    pub fn random_dealer<R: Rng>(f: u32, n: u32, t: u32, rng: &mut R) -> Self {
        let d = rng.gen_range(0, n);
        Params { d, f, n, t }
    }
}
