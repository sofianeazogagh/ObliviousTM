use std::time::Instant;

use rayon::prelude::*;

use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::ABox;


use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

#[path = "./headers.rs"] mod headers;
use self::headers::PrivateKey;
use self::headers::PublicKey;
use self::headers::Context;
use self::headers::LUT;



pub fn blind_insert(){


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our original array
    let original_array = vec![2,4,6];
    let lut = LUT::from_vec(&original_array, &private_key, &mut ctx);

    // Our private permutation
    let to_insert_u64 = 8_u64;
    let to_insert = private_key.allocate_and_encrypt_lwe(to_insert_u64, &mut ctx);


    let start_insert = Instant::now();

    // One LUT to many lwe
    let mut many_lwe = lut.to_many_lwe(public_key, &ctx);

    // Insert in many lwe
    let index_insertion = 0;
    many_lwe.insert(index_insertion, to_insert);


    // many_lwe to one LUT
    let res_lut = LUT::from_vec_of_lwe(many_lwe, public_key, &ctx);

    let duration_insert = start_insert.elapsed();


    let output_glwe = private_key.decrypt_and_decode_glwe(&res_lut.0, &ctx);

    println!("GLWE : {:?}", output_glwe);




    let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus()as usize;
    let half_box_size = box_size / 2;

    // Result of the permutation
    let mut result_vec_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for i in 0..ctx.full_message_modulus(){

        let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size());
        extract_lwe_sample_from_glwe_ciphertext(
            &res_lut.0,
            &mut lwe_sample,
            MonomialDegree((i*ctx.delta_tilde() + half_box_size) as usize));

        let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);
        
        // the result will be modulo 32
        let mut output = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
        trivially_encrypt_lwe_ciphertext(&mut output, Plaintext(2 * ctx.full_message_modulus() as u64 ));
        lwe_ciphertext_sub_assign(&mut output,&switched);
        result_vec_lwe.push(output);
    }



    let mut result_insert_u64 : Vec<u64> = Vec::new();
    for lwe in result_vec_lwe{
        let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
        result_insert_u64.push(pt);
    }
    println!("Original array : {:?} ",original_array );
    println!(" Insert {} at index {}",to_insert_u64, index_insertion);
    println!("Result array : {:?} ",result_insert_u64 );



    println!("Time insertion : {:?}",duration_insert);


}

