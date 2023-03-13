use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use tfhe::core_crypto::fft_impl::c64;
use crate::unitest_baacc2d::*;

pub fn encrypt_instructions(
    glwe_key:&GlweSecretKeyOwned<u64>,
    message_modulus:u64,
    delta:u64,
    glwe_modular_std_dev:StandardDev,
    polynomial_size:PolynomialSize,
    mut encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    glwe_dimension:GlweDimension,
    instructions:Vec<Vec<u64>>)
    ->Vec<GlweCiphertext<Vec<u64>>>

{


    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in instructions.clone(){
        let accumulator_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f.clone(),);
        // Generate the accumulator for our multiplication by 2 using a simple closure
        let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
            &glwe_key,
            glwe_modular_std_dev,
            &mut encryption_generator,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            accumulator_u64);
        accumulators.push(accumulator);
    }
  return accumulators
}
