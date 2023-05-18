use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use tfhe::core_crypto::fft_impl::fft64::c64;
use crate::unitest_baacc2d::*;

pub fn encrypt_instructions(
    glwe_key:&GlweSecretKeyOwned<u64>,
    message_modulus:u64,
    delta:u64,
    glwe_modular_std_dev:StandardDev,
    polynomial_size:PolynomialSize,
    mut encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    glwe_dimension:GlweDimension,
    instructions:Vec<Vec<u64>>,
    ciphertext_modulus:CiphertextModulus<u64>)
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
            accumulator_u64,
        ciphertext_modulus);
        accumulators.push(accumulator);
    }
  return accumulators
}

pub fn decrypt_instructions(
    glwe_key:&GlweSecretKeyOwned<u64>,
    delta:u64,
    polynomial_size:PolynomialSize,
    ciphertext:&mut Vec<GlweCiphertext<Vec<u64>>>
   )

{
    let cipher = ciphertext.into_iter().nth(0).unwrap();
    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_key, &cipher, &mut output_plaintext_list);

    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    output_plaintext_list
        .iter_mut()
        .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

    // Get the raw vector
    let mut cleartext_list = output_plaintext_list.into_container();
    // Remove the encoding
    cleartext_list.iter_mut().for_each(|elt| *elt = *elt /delta);
    // Get the list immutably
    let cleartext_list = cleartext_list;

    // Check we recovered the original message for each plaintext we encrypted
    println!("instructions {:?}", cleartext_list);
}