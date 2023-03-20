use tfhe::core_crypto::prelude::*;
use std::time::{Instant};
// use aligned_vec::ABox;
// use num_complex::Complex;

#[path = "./helpers.rs"] mod helpers;


pub fn test_blind_rotation()
{

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
    // let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // Generate the seeded bootstrapping key to show how to handle entity decompression,
    // we use the parallel variant for performance reason
    let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_modular_std_dev,
        seeder,
    );

    // We decompress the bootstrapping key
    let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
        std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

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

    // Our input message
    let input_message = 1u64;

    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Generate the accumulator
    let mut accumulator: GlweCiphertextOwned<u64> = helpers::generate_accumulator(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        delta,
        |x: u64| 2 * x,
    );

    println!("Performing blind rotation...");
    let start = Instant::now();
    let duration = start.elapsed();
    println!("Duration of blind rotation : {:?}", duration);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));


    // Decrypt rotated polynomial
    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &accumulator, &mut output_plaintext_list);

    output_plaintext_list
        .iter_mut()
        .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

    // Get the raw vector
    let mut cleartext_list = output_plaintext_list.into_container();
    // Remove the encoding
    cleartext_list.iter_mut().for_each(|elt| *elt = *elt >> 60);
    // Get the list immutably
    let cleartext_list = cleartext_list;

    // Check we recovered the original message for each plaintext we encrypted
    println!("Result of blind rotation : {:?}", cleartext_list);

}

// pub fn blind_rotation(context: &mut helpers::FunctionContext)
// {

//     blind_rotate_assign(context.lwe_ciphertext, context.glwe_ciphertext, );

// }



