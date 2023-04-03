use std::time::Instant;

use rayon::prelude::IntoParallelRefIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;



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



#[cfg(test)]
mod tests
{
    use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::prelude::*;

    use crate::ciphertext_operations::*;

    #[test]
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
        let input_message_1 = 3u64;
        let input_message_2 = 2u64;

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

        let result = lwe_product(lwe_ciphertext_1, 
                                                lwe_ciphertext_2,
                                                lwe_ksk,
                                                fourier_bsk,
                                                bit_message_modulus,
                                                carry_modulus);

        let plaintext: Plaintext<u64> = decrypt_lwe_ciphertext(&big_lwe_sk, &result);
        
        let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        let result: u64 =
        signed_decomposer.closest_representable(plaintext.0) / delta;

    }
}



pub fn create_glev(l: DecompositionLevelCount, 
    beta: DecompositionBaseLog, 
    m: Polynomial<Vec<u64>>, 
    s: GlweSecretKey<Vec<u64>>,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    glwe_modular_std_dev: StandardDev,
    ciphertext_modulus: u64
) -> Vec<GlweCiphertext<Vec<u64>>>
{

    let mut glev_vector: Vec<GlweCiphertext<Vec<u64>>> = Vec::new();

        // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);


    for i in 0..l.0 {
        let mut glwe_ciphertext = GlweCiphertext::new(0, glwe_size, polynomial_size);
        let delta = ciphertext_modulus / ((beta.0 as u64)^(i as u64));

        let mut m_container = m.clone().into_container();

        m_container.par_iter_mut().for_each(|x| {
            *x = *x * delta;
        });

        let plaintext_list = PlaintextList::from_container(m_container);

        encrypt_glwe_ciphertext(&s, 
            &mut glwe_ciphertext, 
            &plaintext_list, 
            glwe_modular_std_dev, 
            &mut encryption_generator);

        glev_vector.push(glwe_ciphertext);


    }

    glev_vector
}


pub fn test_glwe_product()
{

    let glwe_size = GlweSize(2);
    let polynomial_size = PolynomialSize(1024);
    let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    let l = DecompositionLevelCount(4);
    let beta = DecompositionBaseLog(12);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    let glwe_secret_key =
        GlweSecretKey::generate_new_binary(glwe_size.to_glwe_dimension(), polynomial_size, &mut secret_generator);

    // Create the plaintext
    let msg1 = 3u64;
    let msg2 = 2u64;

    let message_modulus = 1 << 4;
    let ciphertext_modulus = 1_u64 << 63;
    let delta = ciphertext_modulus / message_modulus;

    let encoded_msg1 = msg1 * delta;
    let encoded_msg2 = msg2 * delta;


    let plaintext_list1 = PlaintextList::new(encoded_msg1, PlaintextCount(polynomial_size.0));
    let plaintext_list2 = PlaintextList::new(encoded_msg2, PlaintextCount(polynomial_size.0));

    // Create a new GlweCiphertext
    let mut glwe1 = GlweCiphertext::new(0u64, glwe_size, polynomial_size);
    let mut glwe2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size);

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe1,
        &plaintext_list1,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe2,
        &plaintext_list2,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );

    let start = Instant::now();
    let s = glwe_secret_key.as_polynomial_list();
    let s_poly = s.get(0);
    let mut res_product = Polynomial::new(0u64, polynomial_size);

    polynomial_karatsuba_wrapping_mul(&mut res_product, &s_poly, &s_poly);

    let res_product_vec = res_product.into_container();

    let s_quare = GlweSecretKey::from_container(res_product_vec, polynomial_size);

    let t1_prime = multisum_product_over_delta(&glwe1, 
        &glwe2, 
        message_modulus, 
        ciphertext_modulus,
        String::from("T"),
    );

    // println!("{:?}", t1_prime);

    let mut container = t1_prime.into_container();

    container.par_iter_mut().for_each(|x| {
        *x  = *x * 2;
    });

    let r1_1_prime = Polynomial::from_container(container);

    let a1 = multisum_product_over_delta(
        &glwe1, 
        &glwe2, 
        message_modulus, 
        ciphertext_modulus, 
        String::from("A"));

    let b_prime = multisum_product_over_delta(&glwe1, 
        &glwe2, 
        message_modulus,
        ciphertext_modulus, 
        String::from("B"));

    

    let s_quare_poly_list = s_quare.as_polynomial_list();
    let s_quare_poly = s_quare_poly_list.get(0);

    println!("{:?}", s_quare_poly);

    let glev = create_glev(l, 
        beta, 
        m, s, glwe_size, polynomial_size, glwe_modular_std_dev, ciphertext_modulus)

    // let duration = start.elapsed();
    // println!("b_prime =  : {:?}", b_prime);
    // println!("Duration of product : {:?}", duration);



}



fn multisum_product_over_delta(glwe1: &GlweCiphertext<Vec<u64>>, 
    glwe2: &GlweCiphertext<Vec<u64>>, message_modulus: u64,
    ciphertext_modulus: u64,
    mode: String) -> Polynomial<Vec<u64>>
{

    let a1 = glwe1.get_mask();
    let a1_poly_list  = a1.as_polynomial_list();
    
    let a2 = glwe2.get_mask();
    let a2_poly_list  = a2.as_polynomial_list();

    let mut res_product = Polynomial::new(0u64, glwe1.polynomial_size());


    if mode == "T"{
    
        polynomial_wrapping_add_multisum_assign(&mut res_product, &a1_poly_list, &a2_poly_list);

    }

    else if mode == "A" {
        let b1 = glwe1.get_body();
        let b1_poly = b1.as_polynomial();
        let b1_container = b1_poly.into_container();

        let b2 = glwe2.get_body();
        let b2_poly = b2.as_polynomial();
        let b2_container = b2_poly.into_container();

        let a1_poly = a1_poly_list.get(0);
        let a1_container = a1_poly.into_container();

        let a2_poly = a1_poly_list.get(0);
        let a2_container = a2_poly.into_container();

        // println!("\n\n{:?}", a1_container);
        // println!("\n\n{:?}", a2_container);


        let mut a_list = PolynomialList::new(0u64, glwe1.polynomial_size(), PolynomialCount(2));

        let mut a_container = a_list.into_container();

        for i in 0..a1_container.len(){
            a_container[i] = a1_container[i];
        }

        for i in 0..a2_container.len(){
            a_container[i+glwe1.polynomial_size().0] = a2_container[i];
        }

        a_list = PolynomialList::from_container(a_container, glwe1.polynomial_size());

        let mut b_list = PolynomialList::new(0u64, glwe1.polynomial_size(), PolynomialCount(2));

        let mut b_container = b_list.into_container();

        for i in 0..b2_container.len(){
            b_container[i] = b2_container[i];
        }

        for i in 0..b2_container.len(){
            b_container[i+glwe1.polynomial_size().0] = b1_container[i];
        }

        b_list = PolynomialList::from_container(b_container, glwe1.polynomial_size());

        polynomial_wrapping_add_multisum_assign(&mut res_product, &b_list, &a_list);

        

    }
    else if mode == "B"{
        let b1 = glwe1.get_body();
        let b1_poly = b1.as_polynomial();

        let b2 = glwe2.get_body();
        let b2_poly = b2.as_polynomial();

        polynomial_wrapping_add_mul_assign(&mut res_product, &b1_poly, &b2_poly);


    }

    let mut container = res_product.into_container();
    
    container.par_iter_mut().for_each(|x| {
        *x  = *x / (ciphertext_modulus / message_modulus);
        *x = *x % ciphertext_modulus 
    });

    res_product = Polynomial::from_container(container);

    res_product
    


}
