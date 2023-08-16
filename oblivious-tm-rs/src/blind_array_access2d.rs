
use std::time::Duration;
use std::time::Instant;
use rayon::prelude::*;

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;

use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::LWEaddu64;


pub fn blind_array_access2d() {


    // let mut total_time = Duration::default();

    // for _ in 0..100{


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our input message
    let column = 1u64;
    let line = 0;
    let line_encoded = 16u64 + line;

    // let line = 1u64;
    // let column = 2;


    let lwe_columns = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
    let lwe_line = private_key.allocate_and_encrypt_lwe(line_encoded, &mut ctx);




    let array2d : Vec<Vec<u64>> = vec![
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15],
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15]
    ];


    // let array2d : Vec<Vec<u64>> = vec![
    //     vec![0,1,2,3,0],
    //     vec![4,5,6,7,4,5,6,7],

    // ];

    
    // let array2d : Vec<Vec<u64>> = vec![
    //     vec![0,1,2,3],
    //     vec![4,5,6,7]
    // ];


    let mut vec_of_lut: Vec<LUT> = Vec::new();
    for f in array2d.clone(){
        let lut = LUT::from_vec(&f, &private_key, &mut ctx);
        vec_of_lut.push(lut);
    }

    let start_bacc2d = Instant::now();
    let ct_res = bacc2d(
        &vec_of_lut,
        &lwe_columns,
        &lwe_line,
        &ctx,
        &public_key
    );
    let duration_bacc2d = start_bacc2d.elapsed();
    println!("Time BACC2D = {:?}",duration_bacc2d);

    // let end_bacc2d = Instant::now();
    // let time_bacc2d = end_bacc2d - start_bacc2d;


    // total_time = total_time + time_bacc2d;

    // }
    // let average_time = total_time / 100 as u32;


    // println!("Temps moyen d'exécution bacc2d : {:?}", average_time);


    let result = private_key.decrypt_lwe_big_key(&ct_res, &mut ctx);

    println!("Checking result...");
    println!("BACC2D input ({line},{column}) got {result}");


}


pub fn bacc2d(
    array2d: &Vec<LUT>,
    lwe_column: &LweCiphertext<Vec<u64>>,
    lwe_line: &LweCiphertext<Vec<u64>>,
    ctx : &Context,
    public_key : &PublicKey
)
    -> LweCiphertext<Vec<u64>>
{
    let lwe_line_encoded  = LWEaddu64(&lwe_line,ctx.full_message_modulus() as u64,&ctx);


    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    pbs_results.par_extend(
    array2d
        .into_par_iter()
        .map(|acc| {
            let mut pbs_ct = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            programmable_bootstrap_lwe_ciphertext(
                &lwe_column,
                &mut pbs_ct,
                &acc.0,
                &public_key.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }),
    );

    let accumulator_final = LUT::from_vec_of_lwe(pbs_results, public_key, ctx);
    let mut ct_res = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    programmable_bootstrap_lwe_ciphertext(&lwe_line_encoded, &mut ct_res, &accumulator_final.0, &public_key.fourier_bsk,);
    ct_res
}


