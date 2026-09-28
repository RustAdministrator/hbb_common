//! Fixed-seed randomized inputs for decoder robustness tests.
//!
//! Transport decoders parse data from remote peers and release builds abort
//! on panic, so every input must end in a value or an error. Seeds are fixed
//! so that a failure reproduces; a panic reports the seed, the iteration and
//! the input.

use rand::{rngs::StdRng, Rng, SeedableRng};
use std::panic::{self, AssertUnwindSafe};

const ITERATIONS: usize = 3_000;
const BOUNDARY_BYTES: [u8; 5] = [0x00, 0x01, 0x7f, 0x80, 0xff];

/// Feeds random byte strings of up to `max_len` bytes and mutations of every
/// valid sample to `decode`.
pub(crate) fn exercise_decoder(
    seed: u64,
    valid: &[Vec<u8>],
    max_len: usize,
    mut decode: impl FnMut(&[u8]),
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut run = |iteration: usize, input: Vec<u8>| {
        if let Err(panic) = panic::catch_unwind(AssertUnwindSafe(|| decode(&input))) {
            let hex: String = input.iter().map(|byte| format!("{:02x}", byte)).collect();
            eprintln!(
                "decoder panicked: seed={:#x} iteration={} input={}",
                seed, iteration, hex
            );
            panic::resume_unwind(panic);
        }
    };
    for iteration in 0..ITERATIONS {
        let len = rng.gen_range(0..=max_len);
        let input = (0..len).map(|_| rng.gen::<u8>()).collect();
        run(iteration, input);
    }
    for sample in valid {
        run(0, sample.clone());
        for iteration in 1..ITERATIONS {
            let input = mutate(&mut rng, sample);
            run(iteration, input);
        }
    }
}

/// One to four random edits: bit flips, random or boundary bytes, zeroed or
/// saturated 4-byte windows (length fields), truncation, extension and
/// duplicated slices.
fn mutate(rng: &mut StdRng, valid: &[u8]) -> Vec<u8> {
    let mut data = valid.to_vec();
    for _ in 0..rng.gen_range(1..=4) {
        let len = data.len();
        match rng.gen_range(0..7) {
            0 if len > 0 => {
                let index = rng.gen_range(0..len);
                data[index] ^= 1 << rng.gen_range(0..8);
            }
            1 if len > 0 => {
                let index = rng.gen_range(0..len);
                data[index] = rng.gen();
            }
            2 if len > 0 => {
                let index = rng.gen_range(0..len);
                data[index] = BOUNDARY_BYTES[rng.gen_range(0..BOUNDARY_BYTES.len())];
            }
            3 if len >= 4 => {
                let index = rng.gen_range(0..=len - 4);
                let value = if rng.gen::<bool>() { 0xff } else { 0x00 };
                data[index..index + 4].fill(value);
            }
            4 => data.truncate(rng.gen_range(0..=len)),
            5 => {
                let extra = rng.gen_range(1..=64);
                data.extend((0..extra).map(|_| rng.gen::<u8>()));
            }
            6 if len > 0 => {
                let start = rng.gen_range(0..len);
                let end = rng.gen_range(start..=len);
                let slice = data[start..end].to_vec();
                let at = rng.gen_range(0..=len);
                data.splice(at..at, slice);
            }
            _ => {}
        }
    }
    data
}
