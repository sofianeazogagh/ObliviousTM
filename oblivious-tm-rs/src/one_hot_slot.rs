use std::time::Instant;
// use std::cmp::{min, max};


use rayon::prelude::*;
use std::sync::Mutex;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::ciphertext::Degree;
use tfhe::shortint::prelude::*;
use tfhe::shortint::server_key::MaxDegree;

use crate::one_hot_slot::helpers::encrypt_accumulator_as_glwe_ciphertext;

#[path = "./helpers.rs"] mod helpers;

pub fn test_one_hot_slot()
{

    // let small_lwe_dimension = LweDimension(742);
    // let glwe_dimension = GlweDimension(1);
    // let big_lwe_dimension = LweDimension(2048);
    // let polynomial_size = PolynomialSize(2048);
    // let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
    // let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
    // let pbs_base_log = DecompositionBaseLog(23);
    // let pbs_level = DecompositionLevelCount(1);
    // let message_modulus =  MessageModulus(4);
    // let carry_modulus = CarryModulus(4);
    // let ks_level = DecompositionLevelCount(5);
    // let ks_base_log = DecompositionBaseLog(3);
   


    // PARAM_3_CARRY_3
    let    small_lwe_dimension= LweDimension(864);
    let    big_lwe_dimension= LweDimension(8192);
    let    glwe_dimension= GlweDimension(1);
    let    polynomial_size= PolynomialSize(8192);
    let    lwe_modular_std_dev= StandardDev(0.000000757998020150446);
    let    glwe_modular_std_dev= StandardDev(0.0000000000000000002168404344971009);
    let    pbs_base_log= DecompositionBaseLog(15);
    let    pbs_level= DecompositionLevelCount(2);
    let    ks_level= DecompositionLevelCount(6);
    let    ks_base_log= DecompositionBaseLog(3);
    let    message_modulus= MessageModulus(8);
    let    carry_modulus= CarryModulus(8);

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
    let small_lwe_sk : LweSecretKey<Vec<u64>> =
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

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    // let signed_decomposer : SignedDecomposer<u64> =
        // SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
    let signed_decomposer : SignedDecomposer<u64> =
        SignedDecomposer::new(DecompositionBaseLog(9), DecompositionLevelCount(1));

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
    


    let max_value = message_modulus.0 * carry_modulus.0 - 1;

    let sks : ServerKey = ServerKey { 
        key_switching_key: lwe_ksk.clone(),
        bootstrapping_key: fourier_bsk.clone(),
        message_modulus: message_modulus,
        carry_modulus: carry_modulus, 
        max_degree: MaxDegree(max_value)};

    // Our 4 bits message space and our factor encoding delta
    let delta = (1_u64 << 63)
        / (message_modulus.0 * carry_modulus.0)
            as u64;
    // Our input

    let column = 1u64;
    let input = 3u64;



    let input_columns = Plaintext(delta*column);
    let ct_col : LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        input_columns, 
        lwe_modular_std_dev,
        &mut encryption_generator,
    );


    // Tree
    let tree = vec![
                                                            vec![4],

                                                    vec![2      ,      6],

                                                vec![1  ,   3   ,     5   ,    7],

                                    //   vec![0,   1  ,    2  ,  3 ,   4  ,  5  ,  6 ,  7], // remplacer par le resultat du multiPBS
    ];
        
    
    let array2d = vec![
        vec![0,1,2,3,4,5,6,7],
        vec![2,3,4,5,6,7,0,1],
        vec![4,5,6,7,0,1,2,3],
        vec![6,7,0,1,2,3,4,5],
        vec![1,0,7,6,5,4,3,2],
        vec![3,2,1,0,7,6,5,4],
        vec![5,4,3,2,1,0,7,6],
        vec![7,6,5,4,3,2,1,0],
    ];

    // let accumulator1_u64 = generate_accumulator_via_vector(polynomial_size,  message_modulus as usize, delta,f1.clone(),);

    let mut accumulators: Vec<GlweCiphertextOwned<u64>> = Vec::new();
    for f in array2d{
        let accumulator_u64 = helpers::generate_accumulator_via_vector(polynomial_size,  message_modulus.0*carry_modulus.0, delta,f);
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

    let mut pbs_results: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    pbs_results.par_extend( accumulators
    .into_par_iter()
    .map(|acc| {
        let mut pbs_ct = LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size());
        programmable_bootstrap_lwe_ciphertext(
            &ct_col,
            &mut pbs_ct,
            &acc,
            &fourier_bsk,
            );
            pbs_ct
        }),
    );





    let mut tree_lwe : Vec<Vec<LweCiphertext<Vec<u64>>>> = Vec::new();
    for stage in tree.clone(){
        let mut stage_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        for element in stage{
            let element_encoded = Plaintext(element*delta);
            let ct_element = 
                        allocate_and_trivially_encrypt_new_lwe_ciphertext(
                            big_lwe_dimension.to_lwe_size(), element_encoded);
            stage_lwe.push(ct_element);
        }
        tree_lwe.push(stage_lwe);
    }



    let input_plaintext = Plaintext(delta*input);
    let ct_input : LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &big_lwe_sk,
        input_plaintext, 
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let ct_one = allocate_and_trivially_encrypt_new_lwe_ciphertext(big_lwe_dimension.to_lwe_size(), Plaintext(delta));

    let mut not_ct_cp = LweCiphertext::new(0_64,big_lwe_dimension.to_lwe_size());


    ///////////////////////    First Stage  /////////////////////////////////



    let ct_cp = greater_or_equal_via_shortint(ct_input.clone(), 
        tree_lwe[0][0].clone(), 
        message_modulus, 
        carry_modulus, 
        &sks);
    lwe_ciphertext_sub(&mut not_ct_cp,&ct_one, &ct_cp);






    // Blind Node Selection
    let ct_childs_acc = vec![not_ct_cp.clone(), ct_cp];


    
    // ------ABS
    let stage_lwe = ct_childs_acc.par_iter().zip(tree[1].par_iter())
    .map(|(ct_child_acc, elmt)| {
        let mut res_abs = ct_child_acc.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res_abs, Cleartext(*elmt));
        res_abs
    }).collect::<Vec<_>>();

    // ------SUM
    let mut ct_res_stage = stage_lwe[0].clone();
    for i in 1..stage_lwe.len(){
        lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    }


    // CMP
    let ct_cp = greater_or_equal_via_shortint(ct_input.clone(), 
        ct_res_stage.clone(), 
        message_modulus, 
        carry_modulus,
        &sks);
    lwe_ciphertext_sub(&mut not_ct_cp, &ct_one, &ct_cp);

            

    // let ct_parents_acc = ct_childs_acc ;
    // let mut ct_childs_acc : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    // for acc in ct_parents_acc{

    //     let new_acc_left =
        
    //     lwe_product_via_shortint(
    //         acc.clone(), 
    //         not_ct_cp.clone(), 
    //         message_modulus, 
    //         carry_modulus,
    //         &sks);

    //     ct_childs_acc.push(new_acc_left);

    //     let new_acc_right =
    //     lwe_product_via_shortint(
    //         acc.clone(), 
    //         ct_cp.clone(),
    //         message_modulus, 
    //         carry_modulus,
    //         &sks);

    //     ct_childs_acc.push(new_acc_right);
    // }



    // Acc aggregation
    let ct_parents_acc = ct_childs_acc ;
    let ct_childs_acc : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    let ct_childs_acc: Vec<_> = ct_parents_acc
    .par_iter()
    .flat_map(|acc| {
        let ct_child_left = 
            lwe_product_via_shortint(
                acc.clone(), 
                not_ct_cp.clone(), 
                message_modulus, 
                carry_modulus,
                &sks);
        let ct_child_right = 
            lwe_product_via_shortint(
                acc.clone(), 
                ct_cp.clone(),
                message_modulus, 
                carry_modulus,
                &sks);
        vec![ct_child_left, ct_child_right]
    })
    .collect();


    // BNS 

    // Abs


    let stage_lwe = ct_childs_acc.par_iter().zip(tree[2].par_iter())
    .map(|(ct_child_acc, elmt)| {
        let mut res_abs = ct_child_acc.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut res_abs, Cleartext(*elmt));
        res_abs
    }).collect::<Vec<_>>();

    // Sum
    let mut ct_res_stage = stage_lwe[0].clone();
    for i in 1..stage_lwe.len(){
        lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    }



    // CMP
    let ct_cp = greater_or_equal_via_shortint(ct_input.clone(), 
        ct_res_stage.clone(), 
        message_modulus, 
        carry_modulus,
        &sks);

    lwe_ciphertext_sub(&mut not_ct_cp,&ct_one, &ct_cp);



    // Acc aggregation

    let ct_parents_acc = ct_childs_acc ;
    let ct_childs_acc : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

    let ct_childs_acc: Vec<_> = ct_parents_acc
    .par_iter()
    .flat_map(|acc| {
        let ct_child_left = 
            lwe_product_via_shortint(
                acc.clone(), 
                not_ct_cp.clone(), 
                message_modulus, 
                carry_modulus,
                &sks);
        let ct_child_right = 
            lwe_product_via_shortint(
                acc.clone(), 
                ct_cp.clone(),
                message_modulus, 
                carry_modulus,
                &sks);
        vec![ct_child_left, ct_child_right]
    })
    .collect();






    // the last blind node selection

    let mut stage_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();

            // mult in place
    for (i,elmt) in pbs_results.iter().enumerate(){
        let res = ct_childs_acc[i].clone();

        let res = lwe_product_via_shortint(
            res.clone(), 
            elmt.clone(), 
            message_modulus, 
            carry_modulus,
            &sks);
        stage_lwe.push(res);
    }
            // Sum
    let mut ct_res_stage = stage_lwe[0].clone();
    for i in 1..stage_lwe.len(){
        lwe_ciphertext_add_assign(&mut ct_res_stage, &stage_lwe[i]);
    }


    

    // Decrypt the result


    // let ohs_plaintext_final: Plaintext<u64> =
    //             decrypt_lwe_ciphertext(&big_lwe_sk, &ct_res_stage);

    // let ohs_result_final: u64 =
    //                         signed_decomposer.closest_representable(ohs_plaintext_final.0) / delta;
    // println!("{}",ohs_result_final);

    
    let res = decrypt(&big_lwe_sk, ct_res_stage, message_modulus, carry_modulus);

    println!("Checking result...");
    println!(
        "Result : {res}"
    );

}

fn decrypt(
    big_lwe_sk: &LweSecretKey<Vec<u64>>, 
    ct_res_stage: LweCiphertext<Vec<u64>>, 
    message_modulus: MessageModulus, 
    carry_modulus: CarryModulus
)
-> u64
{
    let decrypted_encoded: Plaintext<u64> =
        decrypt_lwe_ciphertext(big_lwe_sk, &ct_res_stage);
    
    let decrypted_u64: u64 = decrypted_encoded.0;

    let delta = (1_u64 << 63)
        / (message_modulus.0 * carry_modulus.0)
            as u64;

    //The bit before the message
    let rounding_bit = delta >> 1;

    //compute the rounding bit
    let rounding = (decrypted_u64 & rounding_bit) << 1;

    let res = decrypted_u64.wrapping_add(rounding) / delta;

    return res;
}






fn greater_or_equal_via_shortint(
    ct_left: LweCiphertext<Vec<u64>>,
    ct_right: LweCiphertext<Vec<u64>>, 
    message_modulus: MessageModulus, 
    carry_modulus: CarryModulus, 
    sks : &ServerKey

)
-> LweCiphertext<Vec<u64>> 
{

    let mut ct_shortint_input : Ciphertext = Ciphertext {
        ct: ct_left,
        degree: Degree(message_modulus.0 as usize - 1),
        message_modulus: message_modulus,
        carry_modulus: carry_modulus };
    
    let mut ct_shortint_to_compare_with : Ciphertext = Ciphertext { 
        ct: ct_right, 
        degree: Degree(message_modulus.0 as usize - 1),
        message_modulus: message_modulus, 
        carry_modulus: carry_modulus };
    
    
    
    let res_cmp_ct = (*sks).unchecked_greater_or_equal(&mut ct_shortint_input, &mut ct_shortint_to_compare_with).ct;

    res_cmp_ct
}





pub fn lwe_product_via_shortint(lwe_ciphertext_1: LweCiphertext<Vec<u64>>, 
                    lwe_ciphertext_2: LweCiphertext<Vec<u64>>,
                    message_modulus: MessageModulus,
                    carry_modulus : CarryModulus,
                    sks : &ServerKey
)
-> LweCiphertext<Vec<u64>>
{

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


    let ct_res = (*sks).keyswitch_programmable_bootstrap_bivariate(&ct1, &ct2, &acc);

    ct_res.ct

}