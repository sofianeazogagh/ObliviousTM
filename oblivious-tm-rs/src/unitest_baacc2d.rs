use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::{ABox};


pub fn blind_array_access2d() {
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
    let ks_base_log = DecompositionBaseLog(3);
    let ks_level = DecompositionLevelCount(5);
    let pfks_base_log = DecompositionBaseLog(23); //15
    let pfks_level = DecompositionLevelCount(1); //2
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
    let column = 1u64;
    let line = 2;

    // let input_message_final = 16u64 + line;

    let input_message_final = 16u64 + line;


    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext_1 = Plaintext(column * delta);
    let plaintext_final = Plaintext(input_message_final*delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext_1,
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


    // let mut array2d: Vec<Vec<u64>> = Vec::new();
    // for i in 0..message_modulus-1{
    //     let mut f1 = vec![0_u64;message_modulus as usize];
    //     for (j,f1) in f1.iter_mut().enumerate(){ *f1 = i*j as u64} // f = [0,..,message_modulus]
    //     array2d.push(f1.clone());
    // }

    let array2d = vec![
        vec![0,1,2,3],
        vec![4,5,6,7],
        vec![8,9,10,11],
        vec![12,13,14,15]
    ];

    // let accumulator1_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f1.clone(),);

    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in array2d.clone(){
        let accumulator_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f.clone(),);
        // Generate the accumulator for our multiplication by 2 using a simple closure
        let accumulator: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            accumulator_u64);
        accumulators.push(accumulator);
    }

        // let mut pbs_results:Vec<LweCiphertext<Vec<u64>>> = Vec::new();

        // for acc in accumulators{
        //     let mut pbs_ct =
        //     LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
        //     programmable_bootstrap_lwe_ciphertext(
        //         &lwe_ciphertext_1,
        //         &mut pbs_ct,
        //         &acc,
        //         &fourier_bsk,);
        //     pbs_results.push(pbs_ct.clone());
    
        // }
    
        // ////////////////////KEY SWITCHING////////////////////////
        
       
        // let many_lwe= key_switch(
        //     pbs_results.clone(), 
        //     small_lwe_dimension, 
        //     lwe_ksk);
    
        // //////////////////// LWE CIPHERTEXT PACKING////////////////////////
        // /*
        // Create a list of LWE ciphertext which will be converted into a GLWE ciphertext
        // */
        // let accumulator_final = many_lwe_to_glwe(
        //     polynomial_size, 
        //     small_lwe_dimension, 
        //     message_modulus, 
        //     many_lwe.clone(), 
        //     delta, 
        //     glwe_dimension, 
        //     pfpksk);
    
        // //////////////////// FINAL PBS ////////////////////////
        // let mut ct_res = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
        // programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &fourier_bsk,);

    
    let ct_res = bacc2d(
        accumulators, 
        big_lwe_dimension, 
        lwe_ciphertext_1, 
        fourier_bsk, 
        small_lwe_dimension, 
        lwe_ksk, 
        polynomial_size, 
        message_modulus, 
        delta, 
        glwe_dimension, 
        pfpksk, 
        lwe_ciphertext_final);
    
    // Decrypt the PBS multiplication result
    let pbs_plaintext_final: Plaintext<u64> =
        decrypt_lwe_ciphertext(&big_lwe_sk, &ct_res);

    let pbs_result_final: u64 =
        signed_decomposer.closest_representable(pbs_plaintext_final.0) / delta;

    println!("Checking result...");
    println!("BACC2D input ({line},{column}) got {pbs_result_final}");


}

pub fn bacc2d(
    accumulators: Vec<GlweCiphertext<Vec<u64>>>, 
    big_lwe_dimension: LweDimension, 
    lwe_ciphertext_1: LweCiphertext<Vec<u64>>, 
    fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>, 
    small_lwe_dimension: LweDimension, 
    lwe_ksk: LweKeyswitchKey<Vec<u64>>, 
    polynomial_size: PolynomialSize, 
    message_modulus: u64, 
    delta: u64, 
    glwe_dimension: GlweDimension, 
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>, 
    lwe_ciphertext_final: LweCiphertext<Vec<u64>>
) -> LweCiphertext<Vec<u64>>
where
 {
    let mut pbs_results:Vec<LweCiphertext<Vec<u64>>> = Vec::new();



    for acc in accumulators{
        let mut pbs_ct =
        LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
        programmable_bootstrap_lwe_ciphertext(
            &lwe_ciphertext_1,
            &mut pbs_ct,
            &acc,
            &fourier_bsk,);
        pbs_results.push(pbs_ct.clone());

    }

    ////////////////////KEY SWITCHING////////////////////////
    
   
    let many_lwe= key_switch(
        pbs_results.clone(), 
        small_lwe_dimension, 
        lwe_ksk);

    //////////////////// LWE CIPHERTEXT PACKING////////////////////////
    /*
    Create a list of LWE ciphertext which will be converted into a GLWE ciphertext
    */
    let accumulator_final = many_lwe_to_glwe(
        polynomial_size, 
        small_lwe_dimension, 
        message_modulus, 
        many_lwe.clone(), 
        delta, 
        glwe_dimension, 
        pfpksk);

    //////////////////// FINAL PBS ////////////////////////
    let mut ct_res = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &fourier_bsk,);
    ct_res
}




fn key_switch(
    many_lwe_wo_ks: Vec<LweCiphertext<Vec<u64>>>, 
    small_lwe_dimension: LweDimension, 
    lwe_ksk: LweKeyswitchKey<Vec<u64>>
)
-> Vec<LweCiphertext<Vec<u64>>>
{
    let mut many_lwe= Vec::new();
    for ct in many_lwe_wo_ks {
        let mut switched = LweCiphertext::new(0, small_lwe_dimension.to_lwe_size());
        keyswitch_lwe_ciphertext(&lwe_ksk, &ct, &mut switched);
        many_lwe.push(switched);
    }

    return many_lwe;
}

fn many_lwe_to_glwe(
    polynomial_size: PolynomialSize, 
    small_lwe_dimension: LweDimension, 
    message_modulus: u64, 
    many_lwe: Vec<LweCiphertext<Vec<u64>>>, 
    delta: u64, 
    glwe_dimension: GlweDimension, 
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>
) 
-> GlweCiphertext<Vec<u64>> 
{
    let many_lwe_as_accumulator = generate_accumulator_via_vector_of_ciphertext(
        polynomial_size,
        small_lwe_dimension, 
        message_modulus as usize, 
        many_lwe,
        delta);
    let mut lwe_container : Vec<u64> = Vec::new();
    for ct in many_lwe_as_accumulator {
        let mut lwe = ct.into_container();
        lwe_container.append(&mut lwe);
    }
    // remplir le reste du vecteur par des 0 




    let lwe_ciphertext_list =  LweCiphertextList::from_container(lwe_container,small_lwe_dimension.to_lwe_size());

    // Prepare our output GLWE in which we pack our LWEs
    let mut accumulator_final = GlweCiphertext::new(0, glwe_dimension.to_glwe_size(), polynomial_size);

    // Keyswitch and pack
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &pfpksk,
        &mut accumulator_final,
        &lwe_ciphertext_list,
    );
    accumulator_final
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
    for i in 0..f.len() {
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
    _delta: u64,
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

