// #[cfg(test)]


// mod test{



use std::time::Instant;
use rayon::prelude::*;
// use num_complex::Complex;
// use tfhe::{core_crypto::prelude::*, boolean::parameters};
// use aligned_vec::{ABox};

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



// #[path = "./helpers.rs"] mod helpers;
// use helpers::CryptoKeyRing;

#[path = "./headers.rs"] mod headers;
use self::headers::PrivateKey;
use self::headers::PublicKey;
use self::headers::Params;





// #[test]
pub fn blind_array_access2d() {


    // let parameters = PARAM_MESSAGE_2_CARRY_2;
    // let special_parameters: SpecialParameters = SpecialParameters::new(parameters);

    // let small_lwe_dimension = parameters.lwe_dimension;
    // let big_lwe_dimension = LweDimension(parameters.polynomial_size.0);

    let parameters = Params::from(PARAM_MESSAGE_2_CARRY_2);
    let private_key =  PrivateKey::new(&parameters);
    let public_key = PublicKey::get_from(&private_key);

    // Our 4 bits message space
    // let message_mod = 1u64 << 4;
    // let message_mod = (parameters.message_modulus().0 * parameters.carry_modulus().0) as u64;

    // Our input message
    let column = 1u64;
    let line = 1;

    // let input_message_final = 16u64 + line;

    let input_message_final = 16u64 + line;


    // Delta used to encode 4 bits of message + a bit of padding on u64
    // let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext_1 = Plaintext(column * parameters.delta);
    let plaintext_final = Plaintext(input_message_final*parameters.delta);

    // let mut encryption_generator = private_key.encryption_generator;

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &private_key.get_small_lwe_sk(),
        plaintext_1,
        parameters.lwe_modular_std_dev(),
        private_key.get_mut_encryption_generator(),
    );

    let lwe_ciphertext_final: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &private_key.get_small_lwe_sk(),
        plaintext_final,
        parameters.lwe_modular_std_dev(),
        private_key.get_mut_encryption_generator(),
    );

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));


    // let mut array2d: Vec<Vec<u64>> = Vec::new();
    // for i in 0..message_modulus-1{
    //     let mut f1 = vec![0_u64;message_modulus as usize];
    //     for (j,f1) in f1.iter_mut().enumerate(){ *f1 = i*j as u64} // f = [0,..,message_modulus]
    //     array2d.push(f1.clone());
    // }

    let array2d = vec![
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15],
        vec![0,1,2,3,0,1,2,3],
        vec![4,5,6,7,4,5,6,7],
        vec![8,9,10,11,8,9,10,11],
        vec![12,13,14,15,12,13,14,15]
    ];

    // let array2d = vec![
    //     vec![0,1],
    //     vec![4,5],
    // ];

    // let accumulator1_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f1.clone(),);

    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in array2d.clone(){
        let accumulator_u64 = generate_accumulator_via_vector(&f, &parameters);
        // Generate the accumulator for our multiplication by 2 using a simple closure
        // let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
        //     &glwe_sk,
        //     parameters.glwe_modular_std_dev(),
        //     &mut encryption_generator,
        //     parameters.polynomial_size(),
        //     parameters.glwe_dimension().to_glwe_size(),
        //     accumulator_u64);
        let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
            accumulator_u64,
            &private_key,
            &parameters
        );
        accumulators.push(accumulator);
    }


    let start_bacc2d = Instant::now();

    let ct_res = bacc2d(
        accumulators,
        lwe_ciphertext_1,
        lwe_ciphertext_final,
        &parameters,
        &public_key
    );
    
    let duration_bacc2d = start_bacc2d.elapsed();
    println!("Temps BACC2D = {:?}",duration_bacc2d);
    
    // Decrypt the PBS multiplication result
    let pbs_plaintext_final: Plaintext<u64> =
        decrypt_lwe_ciphertext(&private_key.get_big_lwe_sk(), &ct_res);

    let pbs_result_final: u64 =
        signed_decomposer.closest_representable(pbs_plaintext_final.0) / parameters.delta;

    println!("Checking result...");
    println!("BACC2D input ({line},{column}) got {pbs_result_final}");


}





pub fn bacc2d(
    accumulators: Vec<GlweCiphertext<Vec<u64>>>, 
    lwe_ciphertext_1: LweCiphertext<Vec<u64>>, 
    lwe_ciphertext_final: LweCiphertext<Vec<u64>>,
    parameters : &Params,
    public_key : &PublicKey
) -> LweCiphertext<Vec<u64>>
where
 {
    
    let start_multi_pbs = Instant::now();
    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
pbs_results.par_extend(
    accumulators
        .into_par_iter()
        .map(|acc| {
            let mut pbs_ct = LweCiphertext::new(0u64, parameters.big_lwe_dimension.to_lwe_size());
            programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_1,
                &mut pbs_ct,
                &acc,
                &public_key.fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, parameters.small_lwe_dimension().to_lwe_size());
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }),
    );
    
    let duration_multi_pbs = start_multi_pbs.elapsed();
    println!("Temps multi pbs + key switch : {:?}",duration_multi_pbs);
    //////////////////// LWE CIPHERTEXT PACKING////////////////////////
    /*
    Create a list of LWE ciphertext which will be converted into a GLWE ciphertext
    */

    let start_packing = Instant::now();
    let accumulator_final = many_lwe_to_glwe_(
        pbs_results,
        &parameters,
        &public_key);
    let duration_packing = start_packing.elapsed();
    println!(" Temps Packing : {:?}",duration_packing);

    //////////////////// FINAL PBS ////////////////////////
    let mut ct_res = LweCiphertext::new(0u64, parameters.big_lwe_dimension().to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &public_key.fourier_bsk,);
    ct_res
}



fn many_lwe_to_glwe_(
    many_lwe: Vec<LweCiphertext<Vec<u64>>>,
    parameters : &Params,
    public_key : &PublicKey
) 
-> GlweCiphertext<Vec<u64>> 
{
    let message_mod = parameters.message_modulus().0 * parameters.carry_modulus().0;
    let many_lwe_as_accumulator = generate_accumulator_via_vector_of_ciphertext(
        parameters.polynomial_size(),
        parameters.small_lwe_dimension(),
        message_mod,
        many_lwe,
        parameters.delta());
    let mut lwe_container : Vec<u64> = Vec::new();
    for ct in many_lwe_as_accumulator{
        let mut lwe = ct.into_container();
        lwe_container.append(&mut lwe);
    }
    let lwe_ciphertext_list =  LweCiphertextList::from_container(lwe_container,parameters.small_lwe_dimension().to_lwe_size());

    // Prepare our output GLWE in which we pack our LWEs
    let mut accumulator_final = GlweCiphertext::new(0, parameters.glwe_dimension().to_glwe_size(), parameters.polynomial_size());

    // Keyswitch and pack
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &public_key.pfpksk,
        &mut accumulator_final,
        &lwe_ciphertext_list,
    );
    accumulator_final
}





// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator_via_vector(
    f: &Vec<u64>,
    parameters : &Params
)  -> Vec<u64>
    where
{

    let message_mod = parameters.message_modulus().0*parameters.carry_modulus().0;
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = parameters.polynomial_size().0 / message_mod;

    // Create the accumulator
    let mut accumulator_u64 = vec![0_u64; parameters.polynomial_size().0];

    // Fill each box with the encoded denoised value
    for i in 0..f.len() {
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for j in index..index + box_size {
            accumulator_u64[j] = f[i] * parameters.delta as u64;
        }
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    accumulator_u64
}



// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator_via_vector_of_ciphertext(
    polynomial_size: PolynomialSize,
    lwe_dimension : LweDimension,
    message_mod: usize,
    many_lwe: Vec<LweCiphertext<Vec<u64>>>,
    _delta: u64,
)  -> Vec<LweCiphertext<Vec<u64>>>
    where
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_mod;

    // Create the accumulator
    let mut output_vec : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    let ct_0 = LweCiphertext::new(0_64, lwe_dimension.to_lwe_size());

    // Fill each box with the encoded denoised value
    for i in 0..message_mod { //many_lwe.len()
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for _j in index..index + box_size {
            if i < many_lwe.len() {
                output_vec.push(many_lwe[i].clone());
            }else {
                output_vec.push(ct_0.clone());
            }
        }
    }

    let half_box_size = box_size / 2;

    output_vec.rotate_left(half_box_size);

    output_vec
}


fn encrypt_accumulator_as_glwe_ciphertext(
    accumulator_u64: Vec<u64>,
    private_key : &PrivateKey<'static>,
    parameters : &Params,
) ->GlweCiphertext<Vec<u64>>
{
    let mut encryption_generator = private_key.get_mut_encryption_generator_2();
    let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
    let mut accumulator = GlweCiphertext::new(0, parameters.glwe_dimension().to_glwe_size(), parameters.polynomial_size());
    encrypt_glwe_ciphertext(
        &private_key.get_glwe_sk(),
        &mut accumulator,
        &accumulator_plaintext,
        parameters.glwe_modular_std_dev(),
        // &private_key.get_mut_encryption_generator_2(),
        &mut encryption_generator
    );
    accumulator
}

// }