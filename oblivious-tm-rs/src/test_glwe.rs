use tfhe::core_crypto::prelude::*;
// use tfhe::core_crypto::prelude::{*, polynomial_algorithms::polynomial_karatsuba_wrapping_mul};


#[path = "./helpers.rs"] mod helpers;



pub fn _glwe_ciphertext_add(
    ct1 : GlweCiphertext<Vec<u64>>,
    ct2 : GlweCiphertext<Vec<u64>>,
)
-> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size(),CiphertextModulus::new_native());

    res.as_mut().iter_mut()
    .zip(
        ct1.as_ref().iter().zip(ct2.as_ref().iter())
        ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
    return res; 
}

pub fn glwe_ciphertext_add(
    ct1 : GlweCiphertext<Vec<u64>>,
    ct2 : GlweCiphertextOwned<u64>,
)
    -> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size(),CiphertextModulus::new_native());

    res.as_mut().iter_mut()
        .zip(
            ct1.as_ref().iter().zip(ct2.as_ref().iter())
        ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
    return res;
}

pub fn _glwe_ciphertext_scalar_mul(
    ct1 : GlweCiphertext<Vec<u64>>,
    scalar : u64
)
-> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size(),CiphertextModulus::new_native());
    res.as_mut().iter_mut()
    .zip(
        ct1.as_ref().iter()
        ).for_each(|(dst, &lhs)| *dst = lhs*scalar);
    return res;
    
}



// pub fn glweciphertext_constant_polynomial_mul(
//     ct1 : GlweCiphertext<Vec<u64>>,
//     constant_polynomial : Polynomial<Vec<u64>>
// )
// -> GlweCiphertext<Vec<u64>>
// {

//     let mut res = GlweCiphertext::new(0,ct1.glwe_size(), ct1.polynomial_size());
//     let (mask_output,body_output) = res.get_mut_mask_and_body();


//     let (mask_input,body_input) = ct1.get_mask_and_body();

//     let mut poly_b = &(body_output.as_polynomial());

//     polynomial_karatsuba_wrapping_mul(poly_b.as_mut(), &constant_polynomial, body_input.as_polynomial().as_ref());



//     return res;


    

// // }



pub fn test_add()
{
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message

    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let big_lwe_dimension = LweDimension(2048);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    // let ks_base_log = DecompositionBaseLog(3);
    // let ks_level = DecompositionLevelCount(5);
    // let pfks_base_log = DecompositionBaseLog(23); //15
    // let pfks_level = DecompositionLevelCount(1); //2
    // let pfks_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer : SignedDecomposer<u64>=
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    // Request the best seeder possible, starting with hardware entropy sources and falling back to
    // /dev/random on Unix systems if enabled via cargo features
    let mut boxed_seeder = new_seeder();
    // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
    let seeder = boxed_seeder.as_mut();

    // Create a generator which uses a CSPRNG to generate secret keys
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
    // noise
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    println!("Generating keys...");

    // Generate an LweSecretKey with binary coefficients
    let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

    // Generate a GlweSecretKey with binary coefficients
    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // Generate the bootstrapping key, we use the parallel variant for performance reason
    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        CiphertextModulus::new_native(),
        &mut encryption_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    // Use the conversion function (a memory optimized version also exists but is more complicated
    // to use) to convert the standard bootstrapping key to the Fourier domain
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
    // We don't need the standard bootstrapping key anymore
    drop(std_bootstrapping_key);


    // Our 4 bits message space
    let message_modulus = 1u64 << 4;


    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;


    // Our input message
    let m = 0;


    // Apply our encoding
    let plaintext_1 = Plaintext(m * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_1,
        lwe_modular_std_dev,
        CiphertextModulus::new_native(),
        &mut encryption_generator,
    );



    let our_test_vect = vec![
        vec![0,1,2,3,0,1,2,3],
        vec![0,1,2,3,0,1,2,3]
    ];


    // let accumulator1_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f1.clone(),);
    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in our_test_vect.clone(){
        let accumulator_u64 = helpers::generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f.clone(),);
        // Generate the accumulator for our multiplication by 2 using a simple closure
        let accumulator: GlweCiphertextOwned<u64> = helpers::encrypt_accumulator_as_glwe_ciphertext(
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            accumulator_u64);
        accumulators.push(accumulator);
    }


    let test_aubin1 = PlaintextList::new(1 * delta,PlaintextCount(polynomial_size.0));
    let mut ct_test_aubin1 = GlweCiphertext::new(0_u64,glwe_dimension.to_glwe_size(),polynomial_size,CiphertextModulus::new_native());
    let test_aubin2 = PlaintextList::new(2 * delta,PlaintextCount(polynomial_size.0));
    let mut ct_test_aubin2 = GlweCiphertext::new(0_u64,glwe_dimension.to_glwe_size(),polynomial_size,CiphertextModulus::new_native());

    encrypt_glwe_ciphertext(
        &glwe_sk,
        &mut ct_test_aubin1,
        &test_aubin1,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    encrypt_glwe_ciphertext(
        &glwe_sk,
        &mut ct_test_aubin2,
        &test_aubin2,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let res_add_glwe = _glwe_ciphertext_add(ct_test_aubin1.clone(), ct_test_aubin2.clone());







    // let res_add_glwe = _glwe_ciphertext_add(accumulators[0].clone(), accumulators[1].clone());
    // let res_abs_glwe = _glwe_ciphertext_scalar_mul(accumulators[0].clone(), 3);
    let mut pbs_res = LweCiphertext::new(0_u64, big_lwe_dimension.to_lwe_size(),CiphertextModulus::new_native());
    // programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_1,&mut pbs_res , &res_add_glwe, &fourier_bsk);
    programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_1,&mut pbs_res , &res_add_glwe, &fourier_bsk);

    // // Decrypting the packed LWE ciphertext
    // let mut plaintext_acc = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    // decrypt_glwe_ciphertext(&glwe_sk, &accumulators[0], &mut plaintext_acc);
    // Decrypting the packed LWE ciphertext
    let mut plaintext_res_test = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    //decrypt_glwe_ciphertext(&glwe_sk, &res_add_glwe, &mut plaintext_res_add);
    decrypt_glwe_ciphertext(&glwe_sk, &res_add_glwe, &mut plaintext_res_test);


    // To round our 4 bits of message
    // let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
    // could apply the wrapping_neg on our function and remove it here
    // let decoded: Vec<_> = plaintext_acc
    //     .iter()
    //     .map(|x| (signed_decomposer.closest_representable(*x.0) / delta).wrapping_neg() % message_modulus)
    //     .collect();
    // // First 16 cells will contain the double of the original message modulo our message modulus and
    // // zeros elsewhere
    // println!(" Accumulator : {decoded:?}");


    // To round our 4 bits of message
    // let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
    // could apply the wrapping_neg on our function and remove it here
    let decoded_res_test: Vec<_> = plaintext_res_test
        .iter()
        .map(|x| (signed_decomposer.closest_representable(*x.0) / delta).wrapping_neg() % message_modulus)
        .collect();
    // First 16 cells will contain the double of the original message modulo our message modulus and
    // zeros elsewhere
    println!(" Res Add : {decoded_res_test:?}");


     // Decrypt the PBS multiplication result
    let pbs_plaintext_final: Plaintext<u64> =
     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_res);

    let pbs_result_final: u64 =
     signed_decomposer.closest_representable(pbs_plaintext_final.0) / delta;


    println!("Result of the pbs applied to {} = {}",m,pbs_result_final)





}