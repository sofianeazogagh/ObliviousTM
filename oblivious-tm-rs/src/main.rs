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
use std::io::{Write};
use std::fs::{File, OpenOptions};
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
    compare_performance_step();


}

fn generate_matrix(n: usize, m: usize, p: u64) -> Vec<Vec<u64>> {
    let mut matrix = Vec::with_capacity(n);
    for _ in 0..n {
        let row = (0..m).map(|_| 0).collect();
        matrix.push(row);
    }
    matrix
}

pub fn compare_performance_step() {



    //Fichier resultat
    let mut output_file_step = File::create("resultats_step.txt").expect("Impossible de créer le fichier");
    let mut output_file_step = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_step.txt")
        .expect("Impossible d'ouvrir le fichier");

    // En tête
    writeln!(output_file_step, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");

    let params_crypto = vec![PARAM_MESSAGE_3_CARRY_0,PARAM_MESSAGE_4_CARRY_0,PARAM_MESSAGE_5_CARRY_0,PARAM_MESSAGE_6_CARRY_0];
    let mut j = 2;

    for params in params_crypto {

        j = j+1;
        println!("\nPARAM_MESSAGE_{j}_CARRY_0\n");


        let mut ctx = Context::from(params);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        // Our input message
        let index_line = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
        let index_column = private_key.allocate_and_encrypt_lwe(0, &mut ctx);



        let matrix_size = vec![(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(9,9),(10,10),(11,11),(12,12),(13,14),(15,15),(16,16),(16,16),(17,17),(18,18),(19,19),(20,20),(21,21)];

        let mut i = 0;
        for (n,m) in matrix_size{


            if params.message_modulus.0 >= 3*n && params.message_modulus.0 >= 3*m {
                i+=1;
                println!("calcul {i}");

                let matrix0 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix1 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix2 = generate_matrix(n, m, ctx.full_message_modulus() as u64);

                let instruction_table = vec![matrix0,matrix1,matrix2];
                let tensor_instruction = encode_tensor_into_matrix(instruction_table);
                let ct_tensor_instruction = private_key.encrypt_matrix(&mut ctx, &tensor_instruction);

                let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

                //creation of tape
                let mut tape = vec![1,0,];
                while tape.len() < ctx.message_modulus().0 {
                    tape.push(2_u64);
                }

                let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
                let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);


                let num_iterations = 25;
                for execution in 0..num_iterations {


                    // Temps d'exécution de la première fonction (BMA)
                    let start_time_step = Instant::now();
                    let cell_content = read_cell_content(&tape, &public_key, &ctx);
                    state = get_new_state_after_writing_and_moving(&mut tape, &cell_content, &state, &ct_tensor_instruction, &mut nb_of_move, public_key, &ctx, &private_key);
                    let elapsed_time_step = start_time_step.elapsed();




                    // Écrire les temps dans le fichier
                    writeln!(output_file_step, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_step.as_millis()).expect("Impossible d'écrire dans le fichier");

                }
            }

        }
    }





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
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//1
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//2
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//3
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//4
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//5
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//6
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//7
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//8
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//9
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//10
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//11
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//12
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//13
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//14
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//15
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//16
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//17
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//18


    ];
    encode_instruction_write(&mut instruction_write, &ctx);
    let instruction_position = vec![
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//1
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//2
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//3
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//4
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//5
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//6
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//7
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//8
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//9
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//10
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//11
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//12
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//13
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//14
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//15
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//16
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//17
        vec!['D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D','D',],//18




    ];
    let instruction_position = encode_instruction_position(&instruction_position, &ctx);
    let instruction_state = vec![
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//1
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//2
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//3
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//4
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//5
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//6
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//7
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//8
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//9
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//10
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//11
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//12
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//13
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//14
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//15
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//16
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//17
        vec![1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,],//18

    ];

    let instruction_table = vec![instruction_write,instruction_position,instruction_state];
    let tensor_instruction = encode_tensor_into_matrix(instruction_table);
    let ct_tensor_instruction = private_key.encrypt_matrix(&mut ctx, &tensor_instruction);

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





