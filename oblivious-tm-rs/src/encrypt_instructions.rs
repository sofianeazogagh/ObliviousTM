use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use tfhe::ServerKey;
use tfhe::shortint::ClientKey;
use crate::headers::{Context, LUT, PrivateKey};
use crate::helpers::{encrypt_accumulator_as_glwe_ciphertext, generate_accumulator_via_vector};

pub fn encrypt_instructions(
    cks: &ClientKey,
    sks: &ServerKey,
    delta: u64,
    instructions:Vec<Vec<u64>>)
    ->Vec<GlweCiphertext<Vec<u64>>>

{
    let mut accumulators = Vec::new();
    for f in instructions.clone() {
        let accumulator_u64 = generate_accumulator_via_vector(cks.parameters.polynomial_size(), cks.parameters.message_modulus()as usize, delta, f.clone(), );
        let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
            cks,
            cks.parameters.glwe_modular_std_dev(),
            &mut encryption_generator,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            accumulator_u64);
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