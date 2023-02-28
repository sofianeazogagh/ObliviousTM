use std::intrinsics::{unchecked_add, wrapping_add};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_sub_mul_assign;

pub fn test_sample_extract()
{
    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(1024);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

// Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

// Create the GlweSecretKey
    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );

// Create the plaintext
    let msg = 3u64;
    let encoded_msg = msg << 60;
    let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));

    let special_value = 4;
    let special_index = 10;
    *plaintext_list.get_mut(special_index).0 = special_value << 60;

// Create a new GlweCiphertext
    let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size);

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe,
        &plaintext_list,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

// Now we get the equivalent LweSecretKey from the GlweSecretKey
    let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();

    let mut extracted_sample =
        LweCiphertext::new(0u64, equivalent_lwe_sk.lwe_dimension().to_lwe_size());

// Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))

    println!("Extracting value at index {}", special_index);
    let start = Instant::now();
    extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut extracted_sample, MonomialDegree(special_index));
    let duration = start.elapsed();
    println!("Duration of sample extraction : {:?}", duration);
    let decrypted_plaintext = decrypt_lwe_ciphertext(&equivalent_lwe_sk, &extracted_sample);

// Round and remove encoding
// First create a decomposer working on the high 4 bits corresponding to our encoding.
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

    let recovered_message = decomposer.closest_representable(decrypted_plaintext.0) >> 60;

// We check we recover our special value instead of the 3 stored in all other slots of the
// GlweCiphertext

    assert_eq!(special_value, recovered_message);
    println!("Success ! Expected {}, got {}", special_value, recovered_message);
}

pub fn test_sum()
{

    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(1024);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);

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

    let msg1 = 3u64;
    let msg2 = 4u64;

    let encoded_msg1 = msg1 << 60;
    let encoded_msg2 = msg2 << 60;

    let mut plaintext_list1 = PlaintextList::new(encoded_msg1, PlaintextCount(polynomial_size.0));
    let mut plaintext_list2 = PlaintextList::new(encoded_msg2, PlaintextCount(polynomial_size.0));


// Create a new GlweCiphertext
    let mut glwe1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size);
    let mut glwe2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size);

    let glwe_secret_key1 = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );

    let glwe_secret_key2 = allocate_and_generate_new_binary_glwe_secret_key(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
        &mut secret_generator,
    );

    encrypt_glwe_ciphertext(
        &glwe_secret_key1,
        &mut glwe1,
        &plaintext_list1,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    encrypt_glwe_ciphertext(
        &glwe_secret_key2,
        &mut glwe2,
        &plaintext_list2,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    assign


}