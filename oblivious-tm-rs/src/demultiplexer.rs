use std::time::Instant;
// use std::cmp::{min, max};


use rayon::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::ciphertext::Degree;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::MaxDegree;

// use crate::one_hot_slot::helpers::{encrypt_accumulator_as_glwe_ciphertext, scalar_greater};

#[path = "./headers.rs"] mod headers;
use self::headers::PrivateKey;
use self::headers::PublicKey;
use self::headers::Context;
use self::headers::LUT;

pub fn demultiplixer()
{
    

    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_3_CARRY_3);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    let max_value = ctx.full_message_modulus() - 1;

    let sks : ServerKey = ServerKey { 
        key_switching_key: public_key.lwe_ksk,
        bootstrapping_key: public_key.fourier_bsk,
        message_modulus: ctx.message_modulus(),
        carry_modulus: ctx.carry_modulus(), 
        max_degree: MaxDegree(max_value)};

    // Our input that will be convert into [0,...,1,...0]
    let input = 5u64;

    let ct_input = private_key.allocate_and_encrypt_lwe(input, &mut ctx);


    // Tree
    let tree = vec![
                                                            vec![4],

                                                    vec![2      ,      6],

                                                vec![1  ,   3   ,     5   ,    7],

                                    //   vec![0,   1  ,    2  ,  3 ,   4  ,  5  ,  6 ,  7], // remplacer par le resultat du multiPBS
    ];
        
    
    // let array2d = vec![
    //     vec![0,1,2,3,4,5,6,7],
    //     vec![2,3,4,5,6,7,0,1],
    //     vec![4,5,6,7,0,1,2,3],
    //     vec![6,7,0,1,2,3,4,5],
    //     vec![1,0,7,6,5,4,3,2],
    //     vec![3,2,1,0,7,6,5,4],
    //     vec![5,4,3,2,1,0,7,6],
    //     vec![7,6,5,4,3,2,1,0],
    // ];


    let ct_root = private_key.allocate_and_trivially_encrypt_lwe(tree[0][0], &mut ctx);
    let ct_one = private_key.allocate_and_trivially_encrypt_lwe(1, &mut ctx);

    let mut not_ct_cp = LweCiphertext::new(0_64,ctx.big_lwe_dimension().to_lwe_size());

    // Multi PBS 
    
    // let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    // for f in array2d{
    //     let accumulator_u64 = helpers::generate_accumulator_via_vector(polynomial_size,  message_modulus.0*carry_modulus.0, delta,f);
    //     // Generate the accumulator for our multiplication by 2 using a simple closure
    //     let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
    //         &glwe_sk,
    //         glwe_modular_std_dev,
    //         &mut encryption_generator,
    //         polynomial_size,
    //         glwe_dimension.to_glwe_size(),
    //         accumulator_u64);
    //     accumulators.push(accumulator);
    // }

   
    // let start_ohs = Instant::now();
    // let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    // pbs_results.par_extend( accumulators
    // .into_par_iter()
    // .map(|acc| {
    //     let mut pbs_ct = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
    //     programmable_bootstrap_lwe_ciphertext(
    //         &ct_col,
    //         &mut pbs_ct,
    //         &acc,
    //         &fourier_bsk,
    //         );
    //         pbs_ct
    //     }),
    // );

    ///////////////////////    First Stage  /////////////////////////////////


    // Scalar CMP
    let ct_cp = greater_or_equal_via_shortint(
        ct_input, 
        ct_root, 
        &sks,
        &ctx);
    
    lwe_ciphertext_sub(&mut not_ct_cp,&ct_one, &ct_cp);


    // Blind Node Selection
    let ct_childs_acc = vec![not_ct_cp, ct_cp];


    
    // ------ABS (par_version)
    let stage_lwe = ct_childs_acc.par_iter().zip(tree[1].par_iter())
    .map(|(ct_child_acc, elmt)| {
        let mut res_abs = ct_child_acc.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res_abs, Cleartext(*elmt));
        res_abs
    }).collect::<Vec<_>>();

    // ------SUM
    let mut ct_res_stage = stage_lwe[0].clone();
    for i in 1..stage_lwe.len(){
        lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    }


    ///////////////////////    Second Stage  /////////////////////////////////
    // CMP
    let ct_cp = greater_or_equal_via_shortint(
        ct_input, 
        ct_res_stage, 
        &sks,
        &ctx);

    let mut not_ct_cp = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size());
    lwe_ciphertext_sub(&mut not_ct_cp, &ct_one, &ct_cp);


    // Acc aggregation (par_version)
    let ct_parents_acc = ct_childs_acc ;

    let ct_childs_acc: Vec<_> = ct_parents_acc
    .par_iter()
    .flat_map(|acc| {
        let ct_child_left = 
            lwe_product_via_shortint(
                acc, 
                &not_ct_cp, 
                &sks,
                &ctx);
        let ct_child_right = 
            lwe_product_via_shortint(
                acc, 
                &ct_cp,
                &sks,
                &ctx);
        vec![ct_child_left, ct_child_right]
    })
    .collect();


    // BNS 

    //------ABS (par_version)
    let stage_lwe = ct_childs_acc.par_iter().zip(tree[2].par_iter())
    .map(|(ct_child_acc, elmt)| {
        let mut res_abs = ct_child_acc.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res_abs, Cleartext(*elmt));
        res_abs
    }).collect::<Vec<_>>();

    //------Sum
    let mut ct_res_stage = stage_lwe[0].clone();
    for i in 1..stage_lwe.len(){
        lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    }


    ///////////////////////    Last Stage  /////////////////////////////////
    // CMP
    let ct_cp = greater_or_equal_via_shortint(
        ct_input, 
        ct_res_stage, 
        &sks,
        &ctx);

    lwe_ciphertext_sub(&mut not_ct_cp,&ct_one, &ct_cp);



    // Acc aggregation (par_version)

    let ct_parents_acc = ct_childs_acc ;

    let ct_childs_acc: Vec<_> = ct_parents_acc
    .par_iter()
    .flat_map(|acc| {
        let ct_child_left = 
            lwe_product_via_shortint(
                acc, 
                &not_ct_cp, 
                &sks,
                &ctx);
        let ct_child_right = 
            lwe_product_via_shortint(
                acc, 
                &ct_cp,
                &sks,
                &ctx);
        vec![ct_child_left, ct_child_right]
    })
    .collect();

    let mut res_ohs : Vec<u64> = Vec::new();
    for lwe in ct_childs_acc{
        let res = private_key.decrypt_lwe(&lwe, &mut ctx);
        res_ohs.push(res);
    }

    println!("For {} we got {:?}", input, res_ohs);


    // // BNS (last one will select the correct LWE Ciphertext)

    // //------Multiplication (par_version)
    // let stage_lwe = pbs_results.par_iter().enumerate()
    // .map(|(i, elmt)| {
    //     let res = ct_childs_acc[i].clone();
    //     let res = lwe_product_via_shortint(
    //         res.clone(), 
    //         elmt.clone(), 
    //         message_modulus, 
    //         carry_modulus,
    //         &sks);
    //     res
    // }).collect::<Vec<_>>();

    // //------Sum
    // let mut ct_res_stage = stage_lwe[0].clone();
    // for i in 1..stage_lwe.len(){
    //     lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    // }

    // let duration_ohs = start_ohs.elapsed();
    // println!("Time for OHS {:?}",duration_ohs);


    

    // Decrypt the result
    
    // let res = decrypt(&big_lwe_sk, ct_res_stage, message_modulus, carry_modulus);



    // println!("Checking result...");
    // println!(
    //     "Result : {res}"
    // );

}

fn decrypt(
    big_lwe_sk: &LweSecretKey<Vec<u64>>, 
    ct_res_stage: LweCiphertext<Vec<u64>>, 
    message_modulus: MessageModulus, 
    carry_modulus: CarryModulus
)
-> u64
{
    let decrypted_encoded: Plaintext<u64> =
        decrypt_lwe_ciphertext(big_lwe_sk, &ct_res_stage);
    
    let decrypted_u64: u64 = decrypted_encoded.0;

    let delta = (1_u64 << 63)
        / (message_modulus.0 * carry_modulus.0)
            as u64;

    //The bit before the message
    let rounding_bit = delta >> 1;

    //compute the rounding bit
    let rounding = (decrypted_u64 & rounding_bit) << 1;

    let res = decrypted_u64.wrapping_add(rounding) / delta;

    return res;
}






fn greater_or_equal_via_shortint(
    ct_left: LweCiphertext<Vec<u64>>,
    ct_right: LweCiphertext<Vec<u64>>,
    sks : &ServerKey,
    ctx : &Context

)
-> LweCiphertext<Vec<u64>> 
{

    let mut ct_shortint_input : Ciphertext = Ciphertext {
        ct: ct_left,
        degree: Degree(ctx.message_modulus().0 as usize - 1),
        message_modulus: ctx.message_modulus(),
        carry_modulus: ctx.carry_modulus() };
    
    let mut ct_shortint_to_compare_with : Ciphertext = Ciphertext { 
        ct: ct_right, 
        degree: Degree(ctx.message_modulus().0 as usize - 1),
        message_modulus: ctx.message_modulus(), 
        carry_modulus: ctx.carry_modulus() };
    
    
    
    let res_cmp_ct = (*sks).unchecked_greater_or_equal(&mut ct_shortint_input, &mut ct_shortint_to_compare_with).ct;

    res_cmp_ct
}





pub fn lwe_product_via_shortint(
    lwe_ciphertext_1: &LweCiphertext<Vec<u64>>, 
    lwe_ciphertext_2: &LweCiphertext<Vec<u64>>,
    sks : &ServerKey,
    ctx : &Context
)
-> LweCiphertext<Vec<u64>>
{

    // Bivariate accumulator
    let acc = sks.generate_accumulator_bivariate(|x, y| x*y );

    let message_modulus = ctx.message_modulus();
    let carry_modulus = ctx.carry_modulus();

    // Ciphertexts created from LweCiphertexts
    let ct1  = Ciphertext { ct: *lwe_ciphertext_1, 
                                        degree: tfhe::shortint::ciphertext::Degree(message_modulus.0 - 1), 
                                        message_modulus, 
                                        carry_modulus,
                                    };
    
    let ct2  = Ciphertext { ct: *lwe_ciphertext_2, 
                                            degree: tfhe::shortint::ciphertext::Degree(message_modulus.0 - 1), 
                                            message_modulus, 
                                            carry_modulus
                                        };


    let ct_res = (*sks).keyswitch_programmable_bootstrap_bivariate(&ct1, &ct2, &acc);

    ct_res.ct

}