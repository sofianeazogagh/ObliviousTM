use std::time::Instant;

use rayon::prelude::*;

use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use aligned_vec::ABox;


use tfhe::core_crypto::prelude::*;


pub fn blind_permutation(){


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
    // let pfks_base_log = DecompositionBaseLog(15); //15
    // let pfks_level = DecompositionLevelCount(2); //2
    let pfks_modular_std_dev = StandardDev(0.00000000000000029403601535432533);




    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer : SignedDecomposer<u64>=
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));


    let decomposer : SignedDecomposer<u64>=
    SignedDecomposer::new(DecompositionBaseLog(23), DecompositionLevelCount(1));

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

    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;
    // let delta = 1_u64 << 59;


    // Our array that we want to permut
    let max = u64::MAX;
    // let original_array = vec![16-7,16-3,16-1,16-5,16-2,16-4];
    // let original_array = vec![32-7,32-3,32-1,32-5,32-2,32-4];
    let original_array = vec![7,3,1,5,2,4];

    let size_array = original_array.len();

    // Our private permutation
    let permutation : Vec<u64> = vec![1,0,2,4,5,3];  //---> taget = [3,7,1,4,5,2]
    let mut private_permutation : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    for perm in permutation{
        let perm_pt = Plaintext((32-perm)*delta);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_permutation: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            perm_pt,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );
        private_permutation.push(lwe_permutation);
    }

    let accumulator_original_array_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,original_array);
    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator_original_array: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        accumulator_original_array_u64);


    // One glwe to many lwe
    let delta_tilde = polynomial_size.0 / message_modulus as usize;
    let mut many_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    
    debug_glwe("Original GLWE :", &accumulator_original_array, polynomial_size, &glwe_sk, &signed_decomposer, delta, message_modulus);
    for i in 0..size_array{

        let mut lwe_sample = LweCiphertext::new(0_64, big_lwe_dimension.to_lwe_size());
        extract_lwe_sample_from_glwe_ciphertext(
            &accumulator_original_array,
            &mut lwe_sample,
            MonomialDegree(i*delta_tilde as usize));
        let mut lwe_index = LweCiphertext::new(0_u64,small_lwe_dimension.to_lwe_size());
        // trivially_encrypt_lwe_ciphertext(&mut lwe_index, Plaintext((i*delta as usize) as u64));
        // programmable_bootstrap_lwe_ciphertext(&lwe_index, &mut lwe_sample, &accumulator_original_array, &fourier_bsk);


        let mut switched = LweCiphertext::new(0, small_lwe_dimension.to_lwe_size());
        keyswitch_lwe_ciphertext(&lwe_ksk, &mut lwe_sample, &mut switched);

        // debug_lwe("result SE : " ,&lwe_sample, &big_lwe_sk, &signed_decomposer, delta);
        debug_lwe("result SE : " ,&switched, &small_lwe_sk, &signed_decomposer, delta);
        many_lwe.push(switched);
    }

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<GlweCiphertext<Vec<u64>>> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,glwe_dimension.to_glwe_size(),polynomial_size);
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(polynomial_size, message_modulus, lwe, small_lwe_dimension);
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &pfpksk,
            &mut glwe,
            &redundancy_lwe);
        // debug_glwe("result packing", &glwe, polynomial_size, &glwe_sk, &signed_decomposer, delta, message_modulus);
        many_glwe.push(glwe);
    }

    // println!("Many GLWE size = {}",many_glwe.len());

    // Multi Blind Rotate 
    for (glwe,p) in many_glwe.iter_mut().zip(private_permutation.iter()){
        debug_glwe("before BR", glwe, polynomial_size, &glwe_sk, &signed_decomposer, delta, message_modulus);
        debug_lwe("permutation = ", p, &small_lwe_sk, &signed_decomposer, delta);
        blind_rotate_assign(p, glwe, &fourier_bsk);
        debug_glwe("result BR", glwe, polynomial_size, &glwe_sk, &signed_decomposer, delta, message_modulus);
    }


    // Sum all the rotated glwe to get the final glwe permuted
    let mut result : GlweCiphertext<Vec<u64>> = many_glwe[0].clone();
    for i in 1..many_glwe.len(){

       result = _glwe_ciphertext_add(&result, &many_glwe[i]);

    }

    debug_glwe("result permutation", &result, polynomial_size, &glwe_sk, &signed_decomposer, delta, message_modulus);

    let box_size = polynomial_size.0 / message_modulus as usize;
    let half_box_size = box_size / 2;

    for i in 0..size_array{

        let mut lwe_sample = LweCiphertext::new(0_64, big_lwe_dimension.to_lwe_size());
        extract_lwe_sample_from_glwe_ciphertext(
            &result,
            &mut lwe_sample,
            MonomialDegree((i*delta_tilde + half_box_size) as usize));
        // let mut lwe_index = LweCiphertext::new(0_u64,small_lwe_dimension.to_lwe_size());
        // trivially_encrypt_lwe_ciphertext(&mut lwe_index, Plaintext((i*delta as usize) as u64));
        // programmable_bootstrap_lwe_ciphertext(&lwe_index, &mut lwe_sample, &result, &fourier_bsk);



        let mut switched = LweCiphertext::new(0, small_lwe_dimension.to_lwe_size());
        keyswitch_lwe_ciphertext(&lwe_ksk, &mut lwe_sample, &mut switched);

        // debug_lwe("result SE : " ,&lwe_sample, &big_lwe_sk, &decomposer, delta);
        debug_lwe("result SE : " ,&switched, &small_lwe_sk, &signed_decomposer, delta);
    }


}

fn debug_lwe(
    string : &str,
    lwe : &LweCiphertext<Vec<u64>>,
    lwe_sk: &LweSecretKey<Vec<u64>>, 
    signed_decomposer: &SignedDecomposer<u64>,
    delta: u64){
    //  Decrypt the PBS multiplication result
    let plaintext: Plaintext<u64> =
     decrypt_lwe_ciphertext(&lwe_sk, lwe);

    let result: u64 =
     signed_decomposer.closest_representable(plaintext.0) / delta;


    println!("{} {}",string,result);
}

fn debug_glwe(
    string : &str,
    result: &GlweCiphertext<Vec<u64>>, 
    polynomial_size: PolynomialSize, 
    glwe_sk: &GlweSecretKey<Vec<u64>>,
    signed_decomposer: &SignedDecomposer<u64>, 
    delta: u64, 
    message_modulus: u64){
    let mut plaintext_res = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &result, &mut plaintext_res);

    // To round our 4 bits of message
    // let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
    // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
    // could apply the wrapping_neg on our function and remove it here
    let decoded: Vec<_> = plaintext_res
        .iter()
        .map(|x| (signed_decomposer.closest_representable(*x.0) / delta).wrapping_neg() % message_modulus)
        .collect();
    // First 16 cells will contain the double of the original message modulo our message modulus and
    // zeros elsewhere
    println!(" {string} : {decoded:?}");
}




fn one_lwe_to_lwe_ciphertext_list(
    polynomial_size: PolynomialSize, 
    message_modulus: u64, 
    input_lwe: LweCiphertext<Vec<u64>>, 
    lwe_dimension: LweDimension
) 
-> LweCiphertextList<Vec<u64>> 
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus as usize;
    let mut redundant_lwe = vec![input_lwe.into_container();box_size].concat();
    // let half_box_size = box_size / 2;
    // redundant_lwe.rotate_left(half_box_size);
    let lwe_ciphertext_list =  LweCiphertextList::from_container(
        redundant_lwe,
        lwe_dimension.to_lwe_size());
    

    lwe_ciphertext_list
}




pub fn _glwe_ciphertext_add(
    ct1 : &GlweCiphertext<Vec<u64>>,
    ct2 : &GlweCiphertext<Vec<u64>>,
)
-> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size());

    res.as_mut().iter_mut()
    .zip(
        ct1.as_ref().iter().zip(ct2.as_ref().iter())
        ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs + rhs);
    return res; 
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
    
    let start_multi_pbs = Instant::now();
    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
pbs_results.par_extend(
    accumulators
        .into_par_iter()
        .map(|acc| {
            let mut pbs_ct = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
            programmable_bootstrap_lwe_ciphertext(
                &lwe_ciphertext_1,
                &mut pbs_ct,
                &acc,
                &fourier_bsk,
            );
            let mut switched = LweCiphertext::new(0, small_lwe_dimension.to_lwe_size());
            keyswitch_lwe_ciphertext(&lwe_ksk, &mut pbs_ct, &mut switched);
            switched
        }),
    );
    
    let duration_multi_pbs = start_multi_pbs.elapsed();
    println!("Temps multi pbs + key switch : {:?}",duration_multi_pbs);
    //////////////////// LWE CIPHERTEXT PACKING////////////////////////
    /*
    Create a list of LWE ciphertext which will be converted into a GLWE ciphertext
    */

    let start_packing = Instant::now();
    let accumulator_final = many_lwe_to_glwe(
        polynomial_size, 
        small_lwe_dimension, 
        message_modulus, 
        pbs_results, 
        delta, 
        glwe_dimension, 
        pfpksk);
    let duration_packing = start_packing.elapsed();
    println!(" Temps Packing : {:?}",duration_packing);

    //////////////////// FINAL PBS ////////////////////////
    let mut ct_res = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(&lwe_ciphertext_final, &mut ct_res, &accumulator_final, &fourier_bsk,);
    ct_res
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
