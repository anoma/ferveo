use rand::Rng;

// HybridVss parameters
#[derive(Clone)]
pub struct Params {
    pub d: u32,      // dealer index
    pub f: u32,      // failure threshold
    pub t: u32,      // threshold
    pub w: Vec<u32>, // weight of each participant
}

impl Params {
    pub fn new(d: u32, f: u32, t: u32, w: Vec<u32>) -> Self {
        Params { d, f, t, w }
    }

    // initialize with random values for `d`
    pub fn random_dealer<R: Rng>(
        f: u32,
        t: u32,
        w: Vec<u32>,
        rng: &mut R,
    ) -> Self {
        let d = rng.gen_range(0, w.len() as u32);
        Self::new(d, f, t, w)
    }

    // return the number of participants in the setup
    pub fn n(&self) -> u32 {
        self.w.len() as u32
    }

    pub fn total_weight(&self) -> u32 {
        self.w.iter().sum()
    }
}
