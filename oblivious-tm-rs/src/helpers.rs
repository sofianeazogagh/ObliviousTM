use tfhe::core_crypto::prelude::*;
use tfhe::shortint::prelude::*;
use std::time::{Instant, Duration};

pub fn generate_accumulator<F>(
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        message_modulus: usize,
        delta: u64,
        f: F,
    ) -> GlweCiphertextOwned<u64>
        where
            F: Fn(u64) -> u64,
    {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = polynomial_size.0 / message_modulus;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..message_modulus {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator =
            allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext);

        accumulator
}

pub fn multi_run(function: fn()-> Duration, nbr_repet: u16, time: bool) {

    let mut total_duration = Duration::new(0, 0);
    for i in 1..nbr_repet+1 {

        // Get duration from the execution of the function. Function must return a Duration
        let duration = function();
        println!("---- Run #{} : {:?} --- ", i, duration);
        total_duration = total_duration + duration;
    }

    println!("---- Total {} runs {:?} --- ", nbr_repet, total_duration);

}

