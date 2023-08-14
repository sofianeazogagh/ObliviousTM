use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use itertools::all;
use tfhe::ServerKey;
use tfhe::shortint::ClientKey;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{encrypt_accumulator_as_glwe_ciphertext, generate_accumulator_via_vector};


pub fn encrypt_instructions_LUT(
    mut ctx: &mut Context,
    private_key: &PrivateKey,
    instructions:Vec<Vec<u64>>)
    ->Vec<LUT>

{


    let mut accumulators = Vec::new();
    for f in instructions.clone(){
        let array = LUT::from_vec(&f,&private_key,&mut ctx);


        accumulators.push(array);
    }
    return accumulators
}

pub fn encrypt_instructions(
    public_key: &PublicKey,
    private_key: &PrivateKey,
    instructions:Vec<Vec<u64>>,
    mut ctx: &mut Context)
    ->Vec<GlweCiphertext<Vec<u64>>>

{
    let mut accumulators = Vec::new();
    for f in instructions.clone() {
        let accumulator_u64 = generate_accumulator_via_vector(ctx.polynomial_size(), ctx.message_modulus().0 as usize, ctx.delta(), f.clone(), );
        let accumulator: GlweCiphertextOwned<u64> = private_key.allocate_and_encrypt_glwe(PlaintextList::from_container(accumulator_u64,),&mut ctx);
        accumulators.push(accumulator);
    }
    return accumulators
}

pub fn decrypt_instructions(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
    ciphertext:&mut Vec<GlweCiphertext<Vec<u64>>>
)

{

    let cipher = ciphertext.into_iter().nth(0).unwrap();
    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
    decrypt_glwe_ciphertext(&private_key.get_glwe_sk(), &cipher, &mut output_plaintext_list);

    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    output_plaintext_list
        .iter_mut()
        .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

    // Get the raw vector
    let mut cleartext_list = output_plaintext_list.into_container();
    // Remove the encoding
    cleartext_list.iter_mut().for_each(|elt| *elt = *elt /ctx.delta());
    // Get the list immutably
    let cleartext_list = cleartext_list;

    // Check we recovered the original message for each plaintext we encrypted
    println!("instructions {:?}", cleartext_list);
}