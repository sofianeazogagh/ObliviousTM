use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use crate::headers::{Context, PrivateKey};
use crate::helpers::{encrypt_accumulator_as_glwe_ciphertext, generate_accumulator_via_vector};
use crate::unitest_baacc2d::*;

pub fn encrypt_instructions(
    mut ctx: &mut Context,
    private_key: &PrivateKey,
    instructions:Vec<Vec<u64>>)
    ->Vec<GlweCiphertext<Vec<u64>>>

{


    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in instructions.clone(){
        let accumulator_u64 = generate_accumulator_via_vector(ctx.polynomial_size(),  ctx.message_modulus().0, ctx.delta(),f.clone(),);
        let pt = PlaintextList::from_container(accumulator_u64);

        let mut accumulator_glwe= GlweCiphertext::new(0,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size(),ctx.ciphertext_modulus());
        private_key.encrypt_glwe(&mut accumulator_glwe, pt, &mut ctx);
        accumulators.push(accumulator_glwe);
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