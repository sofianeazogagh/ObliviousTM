use tfhe::core_crypto::prelude::*;

use std::time::{Instant};

pub fn blind_array_access2d() {
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
    // let small_lwe_dimension = LweDimension(742);
    // let glwe_dimension = GlweDimension(1);
    // let polynomial_size = PolynomialSize(2048);
    // let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_base_log = DecompositionBaseLog(23);
    // let pbs_level = DecompositionLevelCount(1);

    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let big_lwe_dimension = LweDimension(2048);
    let polynomial_size = PolynomialSize(2048);
    let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ks_level = DecompositionLevelCount(5);
    let ks_base_log = DecompositionBaseLog(3);
    let pfks_level = DecompositionLevelCount(1); //2
    let pfks_base_log = DecompositionBaseLog(23); //15
    let pfks_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

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


    let mut lwe_ksk = LweKeyswitchKey::new(
        0u64,
        ks_base_log,
        ks_level,
        big_lwe_dimension,
        small_lwe_dimension,
    );
    generate_lwe_keyswitch_key(
        &big_lwe_sk,
        &small_lwe_sk,
        &mut lwe_ksk,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    // Create Packing Key Switch

    let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
        0,
        pfks_base_log,
        pfks_level,
        small_lwe_dimension,
        glwe_dimension.to_glwe_size(),
        polynomial_size,
    );
    // Here there is some freedom for the choice of the last polynomial from algorithm 2
    // By convention from the paper the polynomial we use here is the constant -1
    let mut last_polynomial = Polynomial::new(0, polynomial_size);
    // Set the constant term to u64::MAX == -1i64
    last_polynomial[0] = u64::MAX;
    // Generate the LWE private functional packing keyswitch key
    par_generate_lwe_private_functional_packing_keyswitch_key(
        &small_lwe_sk,
        &glwe_sk,
        &mut pfpksk,
        pfks_modular_std_dev,
        &mut encryption_generator,
        |x| x,
        &last_polynomial,
    );


    // Our 4 bits message space
    let message_modulus = 1u64 << 4;

    // Our input message
    let input_message_1 = 12u64;
    let input_message_2 = 11u64;
    let input_message_3 = 10u64;
    let input_message_4 = 9u64;


    let input_message_final = 0u64;

    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext_1 = Plaintext(input_message_1 * delta);
    let plaintext_2 = Plaintext(input_message_2 * delta);
    let plaintext_3 = Plaintext(input_message_3 * delta);
    let plaintext_4 = Plaintext(input_message_4 * delta);

    let plaintext_final = Plaintext(input_message_final*delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_1,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let lwe_ciphertext_2: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_2,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let lwe_ciphertext_3: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_3,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let lwe_ciphertext_4: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_4,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let lwe_ciphertext_final: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_final,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );



    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    let mut f1 = vec![0_u64;message_modulus as usize];
    for (i,f1) in f1.iter_mut().enumerate(){ *f1 = i as u64} // f = [0,..,message_modulus]

    let mut f2 = vec![0_u64;message_modulus as usize];
    for (i,f2) in f2.iter_mut().enumerate(){ *f2 = i as u64} // f = [0,..,message_modulus]


    let accumulator1_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f1.clone(),);
    let accumulator2_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f2.clone(),);

    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator1: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        accumulator1_u64
    );

    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator2: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        accumulator2_u64
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut pbs_ct1 =
        LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size());
    
    let start_pbs = Instant::now();
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_1,
        &mut pbs_ct1,
        &accumulator1,
        &fourier_bsk,
    );
     let duration_pbs = start_pbs.elapsed();

     println!("Duration PBS : {:?}",duration_pbs);

    let mut pbs_ct2 =
        LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_2,
        &mut pbs_ct2,
        &accumulator2,
        &fourier_bsk,
    );

    let mut pbs_ct3 =
        LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_3,
        &mut pbs_ct3,
        &accumulator2,
        &fourier_bsk,
    );

    let mut pbs_ct4 =
        LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_4,
        &mut pbs_ct4,
        &accumulator2,
        &fourier_bsk,
    );


    ////////////////////KEY SWITCHING////////////////////////
    let mut pbs1_switched = LweCiphertext::new(0, small_lwe_sk.lwe_dimension().to_lwe_size());
    let mut pbs2_switched = LweCiphertext::new(0, small_lwe_sk.lwe_dimension().to_lwe_size());
    let mut pbs3_switched = LweCiphertext::new(0, small_lwe_sk.lwe_dimension().to_lwe_size());
    let mut pbs4_switched = LweCiphertext::new(0, small_lwe_sk.lwe_dimension().to_lwe_size());

    keyswitch_lwe_ciphertext(&lwe_ksk, &pbs_ct1, &mut pbs1_switched);
    keyswitch_lwe_ciphertext(&lwe_ksk, &pbs_ct2, &mut pbs2_switched);
    keyswitch_lwe_ciphertext(&lwe_ksk, &pbs_ct3, &mut pbs3_switched);
    keyswitch_lwe_ciphertext(&lwe_ksk, &pbs_ct4, &mut pbs4_switched);



     //////////////////// LWE CIPHERTEXT PACKING////////////////////////
    /*
    Create a list of LWE ciphertext which will be converted into a GLWE ciphertext
    */
    let many_lwe = vec![pbs1_switched.clone(),pbs2_switched.clone(), pbs3_switched.clone(),pbs4_switched.clone()];
    let many_lwe_as_accumulator = generate_accumulator_via_vector_of_ciphertext(
        polynomial_size,
        small_lwe_dimension, 
        message_modulus as usize, 
        many_lwe);
    let mut lwe_container : Vec<u64> = Vec::new();
    for ct in many_lwe_as_accumulator {
        let mut lwe = ct.into_container();
        lwe_container.append(&mut lwe);
    } // remplir le reste du vecteur par des 0 




    let lwe_ciphertext_list =  LweCiphertextList::from_container(lwe_container,small_lwe_dimension.to_lwe_size());

    // Prepare our output GLWE in which we pack our LWEs
    let mut accumulator_final = GlweCiphertext::new(0, glwe_dimension.to_glwe_size(), polynomial_size);

    // Keyswitch and pack
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &pfpksk,
        &mut accumulator_final,
        &lwe_ciphertext_list,
    );


     //////////////////// FINAL PBS ////////////////////////


     let mut ct_res = LweCiphertext::new(0u64, big_lwe_sk.lwe_dimension().to_lwe_size());
     programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &fourier_bsk,);



    // Decrypting the packed LWE ciphertext
    let mut plaintext_pack = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &accumulator_final, &mut plaintext_pack);

    // To round our 4 bits of message
    // let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
    // could apply the wrapping_neg on our function and remove it here
    let decoded: Vec<_> = plaintext_pack
        .iter()
        .map(|x| (signed_decomposer.closest_representable(*x.0) / delta).wrapping_neg() % message_modulus)
        .collect();
    // First 16 cells will contain the double of the original message modulo our message modulus and
    // zeros elsewhere
    println!("LWE Packed : {decoded:?}");


    // // Decrypt the PBS multiplication result
    // let pbs_plaintext1: Plaintext<u64> =
    //     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_ct1);
    // // Decrypt the PBS multiplication result
    // let pbs_plaintext2: Plaintext<u64> =
    //     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_ct2);

    // Decrypt the PBS multiplication result
    let pbs_plaintext1: Plaintext<u64> =
        decrypt_lwe_ciphertext(&small_lwe_sk, &pbs1_switched);
    // Decrypt the PBS multiplication result
    let pbs_plaintext2: Plaintext<u64> =
        decrypt_lwe_ciphertext(&small_lwe_sk, &pbs2_switched);

    let pbs_plaintext_final: Plaintext<u64> =
        decrypt_lwe_ciphertext(&big_lwe_sk, &ct_res);

    // Round and remove our encoding
    let pbs_result1: u64 =
        signed_decomposer.closest_representable(pbs_plaintext1.0) / delta;
    let pbs_result2: u64 =
        signed_decomposer.closest_representable(pbs_plaintext2.0) / delta;
    let pbs_result_final: u64 =
        signed_decomposer.closest_representable(pbs_plaintext_final.0) / delta;

    println!("Checking result...");
    println!("Expected {input_message_1}, got {pbs_result1}");
    println!("Expected {input_message_2}, got {pbs_result2}");
    println!("BACC2D input {input_message_final} on 
    [{input_message_1},{input_message_2},{input_message_3},{input_message_4}], 
    got {pbs_result_final}");


    






}

// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator_via_vector(
    polynomial_size: PolynomialSize,
    message_modulus: usize,
    delta: u64,
    f: Vec<u64>,
)  -> Vec<u64>
    where
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for j in index..index + box_size {
            accumulator_u64[j] = f[i] * delta as u64;
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
    message_modulus: usize,
    many_lwe: Vec<LweCiphertext<Vec<u64>>>,
)  -> Vec<LweCiphertext<Vec<u64>>>
    where
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut output_vec : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    let ct_0 = LweCiphertext::new(0_64, lwe_dimension.to_lwe_size());

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus { //many_lwe.len()
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for _j in index..index + box_size {
            if i < many_lwe.len(){
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
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise: impl DispersionParameter,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    accumulator_u64: Vec<u64>,
) ->GlweCiphertext<Vec<u64>>
    where
{
    let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
    let mut accumulator = GlweCiphertext::new(0, glwe_size, polynomial_size);
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut accumulator,
        &accumulator_plaintext,
        noise,
        encryption_generator,
    );
    accumulator
}

