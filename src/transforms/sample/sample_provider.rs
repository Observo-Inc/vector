use rand::distributions::Uniform;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

// Create an enum that can hold either provider type
#[derive(Clone)]
pub(crate) enum SampleProviders {
    Default(ModuloSampleProvider),
    Random(RandomSampleProvider),
}

impl SampleProvider for SampleProviders {
    fn next_u64(&mut self) -> u64 {
        match self {
            SampleProviders::Default(provider) => provider.next_u64(),
            SampleProviders::Random(provider) => provider.next_u64(),
        }
    }
}
pub(crate) trait SampleProvider: Clone {
    fn next_u64(&mut self) -> u64;
}

#[derive(Clone)]
pub(crate) struct ModuloSampleProvider {
    rate: u64,
    counter: u64,
}

impl ModuloSampleProvider {
    pub fn new(rate: u64) -> Self {
        Self {
            rate,
            counter: 0,
        }
    }
}

impl SampleProvider for ModuloSampleProvider {
    fn next_u64(&mut self) -> u64 {
        let num = self.counter;
        self.counter = (self.counter + 1) % self.rate;
        num
    }
}

#[derive(Clone)]
pub(crate) struct RandomSampleProvider {
    rand_int: SmallRng,
    distribution: Uniform<u64>,
}

impl RandomSampleProvider {
    pub fn new(rate: u64) -> Self {
        Self {
            rand_int: SmallRng::seed_from_u64(0),
            distribution: Uniform::from(0..rate),
        }
    }
}

impl SampleProvider for RandomSampleProvider {
    fn next_u64(&mut self) -> u64 {
        self.rand_int.sample(&self.distribution)
    }
}