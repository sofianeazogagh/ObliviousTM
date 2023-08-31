mod unitest_baacc2d;
mod encrypt_instructions;
mod test_glwe;
mod headers;
mod helpers;
mod blind_array_access_2d;
mod blind_insertion;
mod blind_permutation;
mod blind_pop;
mod blind_retrieve;
mod blind_push;
mod private_insert;
mod OTM;

use aligned_vec::ABox;
use itertools::all;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
use crate::unitest_baacc2d::*;
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_0;
use crate::blind_array_access_2d::blind_array_access2d;
use crate::blind_insertion::blind_insertion;
use crate::blind_permutation::blind_permutation;
use crate::blind_pop::blind_pop;
use crate::blind_push::blind_push;
use crate::blind_retrieve::blind_retrieve;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{bootstrap_glwe_LUT, bootstrap_glwe_LUT_with_actual_bootstrap, generate_accumulator_via_vector, LWEaddu64, negacycle_vector, one_lwe_to_lwe_ciphertext_list};
use crate::OTM::{get_new_state, OTM, read_cell_content};
use crate::private_insert::private_insert;


pub fn main() {
    // OTM()
    test_state();
}

pub fn test_write() {
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);


    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    println!("Key generated");

    //creation de tape
    let mut tape_vec = vec![0_u64, 0, 0,0];
    while tape_vec.len() < ctx.message_modulus().0 {
        tape_vec.push(0_u64);
    }
    println!("{:?}", tape_vec);

    let mut tape = LUT::from_vec(&tape_vec, &private_key, &mut ctx);
    let mut tape2 = LUT {0:tape.0.to_owned()};


    let mut vec_of_result=Vec::new();


    let newCellContent =private_key.allocate_and_encrypt_lwe_big_key(0,&mut ctx);

    for i in 0..100 {

        // let test = private_key.decrypt_lwe_big_key(&newCellContent,&ctx);
        // println!("newcellcontent bacc = {test}");

        let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &newCellContent, &mut switched);


        // let test = private_key.decrypt_lwe(&switched,&ctx);
        // println!("switched = {test}");


        let mut input = LUT::from_lwe(&switched,&public_key,&ctx).0;

        //private_key.debug_glwe("input ", &input, &ctx );
        // bootstrap_glwe_LUT_with_actual_boostrap_for_first_element(&input,&public_key,&ctx,&private_key);

        tape.0 = glwe_ciphertext_add(tape.0.to_owned(), input.to_owned(), );
        let tape = bootstrap_glwe_LUT_with_actual_bootstrap(&tape.0, &public_key, &ctx);
        let result = private_key.decrypt_and_decode_glwe(&tape.0, &ctx);
        vec_of_result.push(result[0].to_owned());

        println!("{i}");
    }

    println!("resultat cellcontent = {:?}\n",vec_of_result);


    let mut vec_of_result=Vec::new();
    tape=tape2;


    let switched =private_key.allocate_and_encrypt_lwe(0,&mut ctx);

    for i in 0..100 {


        let mut input = LUT::from_lwe(&switched,&public_key,&ctx).0;
        tape.0 = glwe_ciphertext_add(tape.0.to_owned(), input.to_owned(), );

        // println!("{i}");
        let result = private_key.decrypt_and_decode_glwe(&tape.0, &ctx);
        vec_of_result.push(result[0].to_owned());

    }

    println!("resultat cellcontent = {:?}\n",vec_of_result);
    // OTM();
}

pub fn test_state() {
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);


    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    println!("Key generated");

    //creation de tape
    let mut tape_vec = vec![2_u64, 0, 0,0];
    while tape_vec.len() < ctx.message_modulus().0 {
        tape_vec.push(0_u64);
    }
    println!("{:?}", tape_vec);

    let mut tape = LUT::from_vec(&tape_vec, &private_key, &mut ctx);
    let mut tape2 = LUT {0:tape.0.to_owned()};



    let mut instruction_write = vec![
        vec![0, 0, 1, 0, 1, 0, 0],
        vec![0, 0, 7, 0, 7, 0, 0],
        vec![0, 0, 0, 0, 7, 0, 0],
    ];

    let mut instruction_position = vec![
        vec![1, 1, 15, 15, 1, 1, 0],
        vec![1, 1, 15, 15, 15, 1, 0],
        vec![1, 15, 1, 15, 1, 1, 0],
    ];

    let mut instruction_state = vec![
        vec![0, 1, 2, 3, 0, 5, 6],
        vec![0, 1, 3, 3, 4, 5, 6],
        vec![1, 2, 5, 4, 0, 6, 6],
    ];
    // println!("tape = {:?}",instruction_state);



    let instruction_write = encrypt_instructions(&mut ctx, &private_key, instruction_write);
    let instruction_position = encrypt_instructions(&mut ctx, &private_key, instruction_position);
    let instruction_state = encrypt_instructions(&mut ctx, &private_key, instruction_state);
    println!("Instructions Encrypted");


    let mut vec_of_result=Vec::new();


    let cellContent =read_cell_content(&mut tape.0,&public_key,&ctx);
    // let result = private_key.decrypt_lwe(&cellContent,&ctx);
    // println!("cellcontent {result}");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);

    println!("State Encrypted");

    for i in 0..5 {
        state = get_new_state(cellContent.clone(), state.clone(), &instruction_state, &public_key, &ctx, &private_key);
        vec_of_result.push(private_key.decrypt_lwe(&state,&ctx));

        println!("{i}");
    }

    println!("resultat state = {:?}\n",vec_of_result);



}



