use criterion::{criterion_group, criterion_main, Criterion};
use tfhe::{core_crypto::prelude::*, shortint::prelude::PARAM_MESSAGE_2_CARRY_2};

#[path = "../src/unitest_baacc2d.rs"] mod unitest_baacc2d;
use crate::unitest_baacc2d::bacc2d;


#[path = "../src/helpers.rs"] mod helpers;
use crate::helpers::*;

fn bench_sample_extract(c: &mut Criterion) 
{

    let parameters = PARAM_MESSAGE_2_CARRY_2;
    // Create the PRNG
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    // Create the encryption key
    let small_lwe_sk =
    LweSecretKey::generate_new_binary(parameters.lwe_dimension, &mut secret_generator);

    // Create the GlweSecretKey
    let glwe_secret_key =  GlweSecretKey::generate_new_binary(parameters.glwe_dimension, parameters.polynomial_size, &mut secret_generator);

    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_secret_key,
        parameters.pbs_base_log,
        parameters.pbs_level,
        parameters.glwe_modular_std_dev,
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
    let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(parameters.polynomial_size.0));

    let special_value = 1;
    let special_index = 10;
    *plaintext_list.get_mut(special_index).0 = special_value << 60;

    // Create a new GlweCiphertext
    let mut glwe = GlweCiphertext::new(0, parameters.glwe_dimension.to_glwe_size(), parameters.polynomial_size);

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe,
        &plaintext_list,
        parameters.glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut extracted_sample =
        LweCiphertext::new(0u64, equivalent_lwe_sk.lwe_dimension().to_lwe_size());
    
    c.bench_function("Sample extraction", |b| b.iter(|| extract_lwe_sample_from_glwe_ciphertext(&glwe, 
        &mut extracted_sample, 
        MonomialDegree(special_index))));
}



fn bench_blind_array_access2d(c: &mut Criterion) {
    
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
    let column = 4u64;
    let line = 4;

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

    let mut group = c.benchmark_group("sample-size-example");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("BACC2D", |b| b.iter(||  bacc2d(
        accumulators.clone(), 
        big_lwe_dimension, 
        lwe_ciphertext_1.clone(), 
        fourier_bsk.clone(), 
        small_lwe_dimension, 
        lwe_ksk.clone(), 
        polynomial_size, 
        message_modulus, 
        delta, 
        glwe_dimension, 
        pfpksk.clone(), 
        lwe_ciphertext_final.clone())));    
        
    group.finish();


}


fn bench_glwe_add(c: &mut Criterion)
{

}

criterion_group!(benches, bench_blind_array_access2d, bench_sample_extract);
criterion_main!(benches);
