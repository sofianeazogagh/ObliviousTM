use tfhe::core_crypto::prelude::*;
use aligned_vec::*;
use std::time::{Instant};
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::prelude::*;

pub fn key_generation(small_lwe_dimension:LweDimension,
                      glwe_dimension:GlweDimension,
                      big_lwe_dimension:LweDimension,
                      polynomial_size:PolynomialSize,
                      lwe_modular_std_dev:StandardDev,
                      glwe_modular_std_dev:StandardDev,
                      pbs_base_log:DecompositionBaseLog,
                      pbs_level:DecompositionLevelCount,
                      ks_level:DecompositionLevelCount,
                      ks_base_log:DecompositionBaseLog,
                      pfks_level:DecompositionLevelCount,
                      pfks_base_log:DecompositionBaseLog,
                      pfks_modular_std_dev:StandardDev,
                      ciphertext_modulus:CiphertextModulus<u64>

) -> (LweSecretKeyOwned<u64>, GlweSecretKeyOwned<u64>, LweSecretKeyOwned<u64>, FourierLweBootstrapKey<ABox<[c64]>>, LweKeyswitchKeyOwned<u64>, LwePrivateFunctionalPackingKeyswitchKeyOwned<u64>, EncryptionRandomGenerator<ActivatedRandomGenerator>, LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>) {


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
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
    std_bootstrapping_key.glwe_size(),
    std_bootstrapping_key.polynomial_size(),
    std_bootstrapping_key.decomposition_base_log(),
    std_bootstrapping_key.decomposition_level_count());

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
        ciphertext_modulus
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
        ciphertext_modulus
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
    let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
        &big_lwe_sk,
        &glwe_sk,
        pfks_base_log,
        pfks_level,
        pfks_modular_std_dev,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    return (small_lwe_sk, glwe_sk, big_lwe_sk, fourier_bsk, lwe_ksk, pfpksk, encryption_generator, cbs_pfpksk)
}