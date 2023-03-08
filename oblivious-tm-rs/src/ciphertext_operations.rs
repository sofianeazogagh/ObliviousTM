
use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use tfhe::shortint::prelude::*;


pub fn test_lwe_product()
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
    let carry_modulus = CarryModulus(4);
    let bit_message_modulus = MessageModulus(4);


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


    let message_modulus = 1u64 << 4;
    let input_message_1 = 2u64;
    let input_message_2 = 3u64;

    let delta = (1_u64 << 63) / message_modulus;
    let plaintext_1 = Plaintext(input_message_1 * delta);
    let plaintext_2 = Plaintext(input_message_2 * delta);

    let lwe_ciphertext_1: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &big_lwe_sk,
        plaintext_1,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let lwe_ciphertext_2: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &big_lwe_sk,
        plaintext_2,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let start = Instant::now();
    let result = lwe_product(lwe_ciphertext_1, 
                                            lwe_ciphertext_2,
                                            lwe_ksk,
                                            fourier_bsk,
                                            bit_message_modulus,
                                            carry_modulus);

    let duration = start.elapsed();

    println!("Duration the product : {:?}", duration);

    let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &result);
    
    let signed_decomposer =
    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    let result: u64 =
    signed_decomposer.closest_representable(plaintext.0) / delta;

    println!("{}*{} = {}", input_message_1, input_message_2, result);

}


pub fn lwe_product(lwe_ciphertext_1: LweCiphertext<Vec<u64>>, 
                    lwe_ciphertext_2: LweCiphertext<Vec<u64>>,
                    lwe_ksk: LweKeyswitchKey<Vec<u64>>,
                    fourier_bsk: FourierLweBootstrapKey<aligned_vec::ABox<[num_complex::Complex<f64>]>>,
                    message_modulus: MessageModulus,
                    carry_modulus : CarryModulus) -> LweCiphertext<Vec<u64>>
{

    let max_value = message_modulus.0 * carry_modulus.0 - 1;


    // Generate a ServerKey to compute the bivariate booostrapping

    let sks  = ServerKey {
        bootstrapping_key: fourier_bsk,
        carry_modulus,
        key_switching_key: lwe_ksk,
        max_degree: tfhe::shortint::server_key::MaxDegree(max_value),
        message_modulus

    }; 


    // Bivariate accumulator
    let acc = sks.generate_accumulator_bivariate(|x, y| x*y );

    // Ciphertexts created from LweCiphertexts
    let ct1  = Ciphertext { ct: lwe_ciphertext_1, 
                                        degree: tfhe::shortint::ciphertext::Degree(message_modulus.0 - 1), 
                                        message_modulus, 
                                        carry_modulus
                                    };
    
    let ct2  = Ciphertext { ct: lwe_ciphertext_2, 
                                            degree: tfhe::shortint::ciphertext::Degree(message_modulus.0 - 1), 
                                            message_modulus, 
                                            carry_modulus
                                        };


    let ct_res = sks.keyswitch_programmable_bootstrap_bivariate(&ct1, &ct2, &acc);

    ct_res.ct

}