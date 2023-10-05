// mod oblivious_tm;
// use oblivious_tm::*;



// mod unitest_baacc2d;
// mod encrypt_instructions;
// mod test_glwe;
// mod headers;
// mod helpers;
// mod blind_array_access_2d;
// mod blind_insertion;
// mod blind_permutation;
// mod blind_pop;
// mod blind_retrieve;
// mod blind_push;
// mod private_insert;
// mod OTM;

// use aligned_vec::ABox;
// use itertools::all;
// use num_complex::Complex;
// use tfhe::core_crypto::prelude::*;
// use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
// use crate::unitest_baacc2d::*;
// use crate::test_glwe::glwe_ciphertext_add;
// use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
// use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
// use tfhe::shortint::parameters::{PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_3_CARRY_0_KS_PBS, PARAM_MESSAGE_3_CARRY_1, PARAM_MESSAGE_4_CARRY_0};
// use crate::blind_array_access_2d::blind_array_access2d;
// use crate::blind_insertion::blind_insertion;
// use crate::blind_permutation::blind_permutation;
// use crate::blind_pop::blind_pop;
// use crate::blind_push::blind_push;
// use crate::blind_retrieve::blind_retrieve;
// use crate::headers::{Context, LUT, PrivateKey, PublicKey};
// use crate::helpers::{bootstrap_glwe_LUT, bootstrap_glwe_LUT_with_actual_bootstrap, generate_accumulator_via_vector, LWEaddu64, negacycle_vector, one_lwe_to_lwe_ciphertext_list};
// use crate::private_insert::private_insert;


// use revolut::{Context,PrivateKey,PublicKey,LUT,LUTStack};
// use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;
// use crate::OTM::{change_head_position, get_new_state, OTM, read_cell_content, write_new_cell_content};


mod oblivious_tm;

use std::time::Instant;
use rayon::prelude::*;
use revolut::{Context, LUT, PrivateKey, PublicKey};
use tfhe::core_crypto::algorithms::{keyswitch_lwe_ciphertext, programmable_bootstrap_lwe_ciphertext};
use tfhe::core_crypto::prelude::LweCiphertext;
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_0, PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_4_CARRY_0, PARAM_MESSAGE_5_CARRY_0, PARAM_MESSAGE_6_CARRY_0, PARAM_MESSAGE_7_CARRY_0};
// use oblivious_tm::*;


mod oblivious_tm_tensor;
use oblivious_tm_tensor::*;

pub fn main() {
    // oblivious_tm(); // from oblivious_tm.rs
    test_step()


}


pub fn test_step(){

    let param = PARAM_MESSAGE_6_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![1,0,];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(2_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    println!("Tape Encrypted");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    println!("State Encrypted");


    println!("---------------  INVERSE 0 and 1 ---------------");
    let mut instruction_write = vec![
        vec![1,0,],
        vec![1,0,],



    ];
    encode_instruction_write(&mut instruction_write, &ctx);
    let instruction_position = vec![
        vec!['D','D',],
        vec!['N','N',],



    ];
    let instruction_position = encode_instruction_position(&instruction_position, &ctx);
    let instruction_state = vec![
        vec![1,0,],
        vec![1,0,],



    ];

    let instruction_table = vec![instruction_write,instruction_position,instruction_state];
    let tensor_instruction = encode_tensor_into_matrix(instruction_table);
    let ct_tensor_instruction = private_key.encrypt_matrix_with_padding(&mut ctx, &tensor_instruction);

    let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);




    let start =Instant::now();
    for i in 0..10 {
        println!("--- STEP {} ",i);

        let cell_content = read_cell_content(&tape, &public_key, &ctx);
        state = get_new_state_after_writing_and_moving(&mut tape, &cell_content, &state, &ct_tensor_instruction, &mut nb_of_move, public_key, &ctx, &private_key);
    }
    let duration = start.elapsed();let duration_divided = (duration.as_secs() as f64)/10 as f64;

    println!("BTA Duration = {duration:?}, duration divided = {duration_divided}")

}





