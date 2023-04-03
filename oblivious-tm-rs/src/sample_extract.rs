#[cfg(test)]

mod tests{

    use tfhe::core_crypto::prelude::*;
    #[test]
    pub fn test_sample_extract()
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
    
        // Create the PRNG
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    
        // Create the encryption key
        let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
    
        // Create the GlweSecretKey
        let glwe_secret_key =  GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_secret_key,
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
    
        // Now we get the equivalent LweSecretKey from the GlweSecretKey
        let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
    
            // Create the plaintext
        let msg = 0u64;
        let encoded_msg = msg << 60;
        let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
    
        let special_value = 1;
        let special_index = 10;
        *plaintext_list.get_mut(special_index).0 = special_value << 60;
    
        // Create a new GlweCiphertext
        let mut glwe = GlweCiphertext::new(0, glwe_dimension.to_glwe_size(), polynomial_size);
    
        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut glwe,
            &plaintext_list,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
    
        let mut extracted_sample =
            LweCiphertext::new(0u64, equivalent_lwe_sk.lwe_dimension().to_lwe_size());
    
        // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
    
        println!("Extracting value at index {}", special_index);
    
        extract_lwe_sample_from_glwe_ciphertext(&glwe, 
            &mut extracted_sample, 
            MonomialDegree(special_index));
    
        let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    
    
    
        let decrypted_plaintext = decrypt_lwe_ciphertext(&equivalent_lwe_sk, &extracted_sample);
    
        // Round and remove encoding        
        let recovered_message = decomposer.closest_representable(decrypted_plaintext.0) >> 60;
        
        // We check we recover our special value instead of the 3 stored in all other slots of the
        assert_eq!(special_value, recovered_message);
        println!("Success ! Expected {}, got {}", special_value, recovered_message);
    
    }
    
    
}
