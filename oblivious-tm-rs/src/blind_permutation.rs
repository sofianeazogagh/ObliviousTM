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



pub fn blind_permutation(){


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    // Our array that we want to permut
    // let original_array = vec![7,3,1,5,2,4];
    let original_array = vec![7,3,1,5,2,4,8,9,10,15,11,14,13,6,0,12];

    // Our private permutation
    // let permutation : Vec<u64> = vec![1,0,2,4,5,3];  //---> target = [3,7,1,4,5,2]
    let permutation : Vec<u64> = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];  //---> target = original_array


    println!("Permutation : {:?}",permutation);

    println!("Original array : {:?}",original_array);

    

    assert_eq!(permutation.len(),original_array.len());


    let mut private_permutation : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for perm in permutation{
        let lwe_permutation = private_key.allocate_and_encrypt_lwe((2*ctx.full_message_modulus() as u64)-perm, &mut ctx);
        private_permutation.push(lwe_permutation);
    }

    let accumulator_original_array = LUT::from_vec(&original_array, &private_key, &mut ctx);


    let start_perm = Instant::now();
    // One LUT to many lwe

    let many_lwe = accumulator_original_array.to_many_lwe(public_key, &ctx);

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size());
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(lwe, &ctx);
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &redundancy_lwe);
        many_glwe.push(glwe);
    }


    // Multi Blind Rotate 
    for (glwe,p) in many_glwe.iter_mut().zip(private_permutation.iter()){
        blind_rotate_assign(p, glwe, &public_key.fourier_bsk);
    }


    // Sum all the rotated glwe to get the final glwe permuted
    let mut result = many_glwe[0].clone();
    for i in 1..many_glwe.len(){
        result = _glwe_ciphertext_add(&result,&many_glwe[i]);
    }


    let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus()as usize;
    let half_box_size = box_size / 2;

    // Result of the permutation
    let mut result_perm : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for i in 0..original_array.len(){

        let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size());
        extract_lwe_sample_from_glwe_ciphertext(
            &result,
            &mut lwe_sample,
            MonomialDegree((i*ctx.delta_tilde() + half_box_size) as usize));

        let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);
        
        // the result will be modulo 32
        let mut output = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
        trivially_encrypt_lwe_ciphertext(&mut output, Plaintext(2 * ctx.full_message_modulus() as u64 ));
        lwe_ciphertext_sub_assign(&mut output,&switched);
        result_perm.push(output);
    }
    let duration_perm = start_perm.elapsed();



    let mut result_perm_u64 : Vec<u64> = Vec::new();
    for lwe in result_perm{
        let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
        result_perm_u64.push(pt);
    }
    println!("Permuted array : {:?} ",result_perm_u64 );


    println!("Time permutation : {:?}",duration_perm);


}







fn debug_lwe(
    string : &str,
    lwe : &LweCiphertext<Vec<u64>>,
    lwe_sk: &LweSecretKey<Vec<u64>>, 
    signed_decomposer: &SignedDecomposer<u64>,
    delta: u64){
    //  Decrypt the PBS multiplication result
    let plaintext: Plaintext<u64> =
     decrypt_lwe_ciphertext(&lwe_sk, lwe);

    let result: u64 =
     signed_decomposer.closest_representable(plaintext.0) / delta;


    println!("{} {}",string,result);
}

fn debug_glwe(
    string : &str,
    result: &GlweCiphertext<Vec<u64>>, 
    polynomial_size: PolynomialSize, 
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    signed_decomposer: &SignedDecomposer<u64>, 
    delta: u64, 
    message_modulus: u64){
    let mut plaintext_res = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &result, &mut plaintext_res);

    // To round our 4 bits of message
    // let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
    // could apply the wrapping_neg on our function and remove it here
    let decoded: Vec<_> = plaintext_res
        .iter()
        .map(|x| (signed_decomposer.closest_representable(*x.0) / delta).wrapping_neg() % message_modulus)
        .collect();
    // First 16 cells will contain the double of the original message modulo our message modulus and
    // zeros elsewhere
    println!(" {string} : {decoded:?}");
}




fn one_lwe_to_lwe_ciphertext_list(
    input_lwe: LweCiphertext<Vec<u64>>,
    ctx : &Context
) 
-> LweCiphertextList<Vec<u64>> 
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus() as usize;
    let redundant_lwe = vec![input_lwe.into_container();box_size].concat();
    // let half_box_size = box_size / 2;
    // redundant_lwe.rotate_left(half_box_size);
    let lwe_ciphertext_list =  LweCiphertextList::from_container(
        redundant_lwe,
        ctx.small_lwe_dimension().to_lwe_size());
    

    lwe_ciphertext_list
}




pub fn _glwe_ciphertext_add(
    ct1 : &GlweCiphertext<Vec<u64>>,
    ct2 : &GlweCiphertext<Vec<u64>>,
)
-> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size());

    res.as_mut().iter_mut()
    .zip(
        ct1.as_ref().iter().zip(ct2.as_ref().iter())
        ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
    return res; 
}

