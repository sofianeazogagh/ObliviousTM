


#[cfg(test)]

mod tests
{

    use tfhe::core_crypto::prelude::*;
    use crate::helpers;

    #[test]
    pub fn test_blind_rotation()
    {

        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);
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
        let input_message = 2u64;

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

        let mut lwe_ciphertext_out: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &big_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        let vector = vec![0,1,2,3,4,5,6];
        let mut accumulator = helpers::generate_accumulator_via_vector(polynomial_size, message_modulus as usize, delta, vector);   

        let mut glwe: GlweCiphertextOwned<u64> = helpers::encrypt_accumulator_as_glwe_ciphertext(
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            accumulator
        );


        blind_rotate_assign(&lwe_ciphertext_in, &mut glwe, &fourier_bsk);
        println!("Performing sample extraction...");
        extract_lwe_sample_from_glwe_ciphertext(
            &glwe,
            &mut lwe_ciphertext_out,
            MonomialDegree(0),
        );
    
        // Decrypt the PBS multiplication result
        let output_plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&big_lwe_sk, &lwe_ciphertext_out);

        let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        // Round and remove our encoding
        let result: u64 =
        signed_decomposer.closest_representable(output_plaintext.0) / delta;

        assert_eq!(input_message, result);
        println!("Success ! Expected {}, got {}", input_message, result);

    }


}
