use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};
use crate::headers::{Context, LUT, PrivateKey};
use crate::helpers::{encrypt_accumulator_as_glwe_ciphertext, generate_accumulator_via_vector};
use crate::unitest_baacc2d::*;

pub fn encrypt_instructions(
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

pub fn decrypt_instructions(
    private_key:&PrivateKey,
    ctx:& Context,
    ciphertext:&Vec<LUT>
   )

{
    let mut result= Vec::new();
    for i in ciphertext{
        let res = i.print_lut(&private_key,&ctx);
        result.push(res);
    }
    println!("instructions {:?}", result);
}