// #[cfg(test)]


// mod test{



use std::time::Instant;
use rayon::prelude::*;
// use num_complex::Complex;
// use tfhe::{core_crypto::prelude::*, boolean::parameters};
// use aligned_vec::{ABox};

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::decrypt_instructions;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{encrypt_accumulator_as_glwe_ciphertext, generate_accumulator_via_vector, generate_accumulator_via_vector_of_ciphertext, LWEaddu64};


pub fn bacc2dLUT(
    array2d: &Vec<LUT>,
    lwe_column: LweCiphertext<Vec<u64>>,
    lwe_line: LweCiphertext<Vec<u64>>,
    public_key : &PublicKey,
    ctx : &Context,
    private_key: &PrivateKey,

)
    -> LweCiphertext<Vec<u64>>
{

    // decrypt_instructions(private_key,&ctx,array2d);
    let lwe_line_encoded  = LWEaddu64(&lwe_line,8 as u64,&ctx);
    // let lwe_column_encoded  = LWEaddu64(&lwe_column,8 as u64,&ctx);


    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    // pbs_results.par_extend(
    //     array2d
    //         .into_par_iter()
    //         .map(|acc| {
    //             let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    //             programmable_bootstrap_lwe_ciphertext(
    //                 &lwe_column,
    //                 &mut pbs_ct,
    //                 &acc.0,
    //                 &public_key.fourier_bsk,
    //             );
    //             let result = private_key.decrypt_lwe_big_key(&pbs_ct,&ctx);
    //             println!("pbs_ct = {result}");
    //             let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    //             keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
    //             switched
    //         }),
    // );
    for i in array2d{
        let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());

        programmable_bootstrap_lwe_ciphertext(
            &lwe_column,
            &mut pbs_ct,
            &i.0,
            &public_key.fourier_bsk,
        );

        // programmable_bootstrap_lwe_ciphertext(
        //     &lwe_column_encoded,
        //     &mut pbs_ct,
        //     &i.0,
        //     &public_key.fourier_bsk,
        // );

        let result = private_key.decrypt_lwe_big_key(&pbs_ct,&ctx);
        println!("pbs_ct = {result}");

        let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
        // let result = private_key.decrypt_lwe(&switched,&ctx);
        // println!("pbs_ct switched = {result}");
        pbs_results.push(switched);

    }


    let accumulator_final = LUT::from_vec_of_lwe(pbs_results, public_key, ctx);
    let result = accumulator_final.print_lut(&private_key,&ctx);
    // let result = private_key.decrypt_and_decode_glwe(&accumulator_final.0,&ctx);
    println!("acc = {result:?}\n");
    let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    programmable_bootstrap_lwe_ciphertext(&lwe_line_encoded, &mut ct_res, &accumulator_final.0, &public_key.fourier_bsk,);
    // programmable_bootstrap_lwe_ciphertext(&lwe_line, &mut ct_res, &accumulator_final.0, &public_key.fourier_bsk,);


    ct_res
}


pub fn bacc2d(
    accumulators: Vec<GlweCiphertext<Vec<u64>>>,
    lwe_ciphertext_1: LweCiphertext<Vec<u64>>,
    lwe_ciphertext_final: LweCiphertext<Vec<u64>>,
    public_key : &PublicKey,
    ctx : &Context,
    private_key: &PrivateKey,


) -> LweCiphertext<Vec<u64>>
where
 {


    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
pbs_results.par_extend(
    accumulators
        .into_par_iter()
        .map(|acc| {
            let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_1,
                &mut pbs_ct,
                &acc,
                &public_key.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
            let current_cell = private_key.decrypt_lwe(&switched,&ctx);
            println!("bacc2d  = {}", current_cell);
            switched
        }),
    );

    let accumulator_final = many_lwe_to_glwe_(
        pbs_results,
        &ctx,
        &public_key);

     let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &public_key.fourier_bsk,);
     let current_cell = private_key.decrypt_lwe_big_key(&ct_res,&ctx);
     println!("bacc2d result = {}", current_cell);
    ct_res
}



fn many_lwe_to_glwe_(
    many_lwe: Vec<LweCiphertext<Vec<u64>>>,
    ctx : &Context,
    public_key : &PublicKey
) 
-> GlweCiphertext<Vec<u64>> 
{
    let many_lwe_as_accumulator = generate_accumulator_via_vector_of_ciphertext(
        ctx.polynomial_size(),
        ctx.small_lwe_dimension(),
        ctx.full_message_modulus(),
        many_lwe,
        ctx.delta());

    let mut lwe_container : Vec<u64> = Vec::new();
    for ct in many_lwe_as_accumulator{
        let mut lwe = ct.into_container();
        lwe_container.append(&mut lwe);
    }
    let lwe_ciphertext_list =  LweCiphertextList::from_container(lwe_container,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());

    // Prepare our output GLWE in which we pack our LWEs
    let mut accumulator_final = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());

    // Keyswitch and pack
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &public_key.pfpksk,
        &mut accumulator_final,
        &lwe_ciphertext_list,
    );
    accumulator_final
}



