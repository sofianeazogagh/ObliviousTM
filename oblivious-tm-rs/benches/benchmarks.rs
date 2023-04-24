// use criterion::{criterion_group, criterion_main, Criterion};
// use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;
// use tfhe::{core_crypto::prelude::*, shortint::prelude::PARAM_MESSAGE_2_CARRY_2};

// use crate::headers::*;


// #[path = "../src/unitest_baacc2d.rs"] mod unitest_baacc2d;
// use crate::unitest_baacc2d::bacc2d;


// // #[path = "../src/helpers.rs"] mod helpers;
// // use crate::helpers::*;



// #[path = "../src/headers.rs"] mod headers;
// use crate::headers::*;

// fn bench_sample_extract(c: &mut Criterion) 
// {

//     let parameters = PARAM_MESSAGE_2_CARRY_2;
//     // Create the PRNG
//     let mut boxed_seeder = new_seeder();
//     let seeder = boxed_seeder.as_mut();
//     let mut encryption_generator =
//         EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
//     let mut secret_generator =
//         SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

//     // Create the encryption key
//     let small_lwe_sk =
//     LweSecretKey::generate_new_binary(parameters.lwe_dimension, &mut secret_generator);

//     // Create the GlweSecretKey
//     let glwe_secret_key =  GlweSecretKey::generate_new_binary(parameters.glwe_dimension, parameters.polynomial_size, &mut secret_generator);

//     let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
//         &small_lwe_sk,
//         &glwe_secret_key,
//         parameters.pbs_base_log,
//         parameters.pbs_level,
//         parameters.glwe_modular_std_dev,
//         &mut encryption_generator,
//     );

//     // Create the empty bootstrapping key in the Fourier domain
//     let mut fourier_bsk = FourierLweBootstrapKey::new(
//         std_bootstrapping_key.input_lwe_dimension(),
//         std_bootstrapping_key.glwe_size(),
//         std_bootstrapping_key.polynomial_size(),
//         std_bootstrapping_key.decomposition_base_log(),
//         std_bootstrapping_key.decomposition_level_count(),
//     );

//     // Use the conversion function (a memory optimized version also exists but is more complicated
//     // to use) to convert the standard bootstrapping key to the Fourier domain
//     convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
//     // We don't need the standard bootstrapping key anymore
//     drop(std_bootstrapping_key);

//     // Now we get the equivalent LweSecretKey from the GlweSecretKey
//     let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();

//         // Create the plaintext
//     let msg = 0u64;
//     let encoded_msg = msg << 60;
//     let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(parameters.polynomial_size.0));

//     let special_value = 1;
//     let special_index = 10;
//     *plaintext_list.get_mut(special_index).0 = special_value << 60;

//     // Create a new GlweCiphertext
//     let mut glwe = GlweCiphertext::new(0, parameters.glwe_dimension.to_glwe_size(), parameters.polynomial_size);

//     encrypt_glwe_ciphertext(
//         &glwe_secret_key,
//         &mut glwe,
//         &plaintext_list,
//         parameters.glwe_modular_std_dev,
//         &mut encryption_generator,
//     );

//     let mut extracted_sample =
//         LweCiphertext::new(0u64, equivalent_lwe_sk.lwe_dimension().to_lwe_size());
    
//     c.bench_function("Sample extraction", |b| b.iter(|| extract_lwe_sample_from_glwe_ciphertext(&glwe, 
//         &mut extracted_sample, 
//         MonomialDegree(special_index))));
// }



// fn bench_blind_array_access2d(c: &mut Criterion) {
    
//     // Create Context and generate key
//     let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
//     let private_key =  PrivateKey::new(&mut ctx);
//     let public_key = private_key.get_public_key();


//     // Our input message
//     let column = 1u64;
//     let line = 0;
//     let line_encoded = 16u64 + line;

//     // let line = 1u64;
//     // let column = 2;


//     let lwe_columns = private_key.allocate_and_encrypt_lwe(column, &mut ctx);
//     let lwe_line = private_key.allocate_and_encrypt_lwe(line_encoded, &mut ctx);




//     let array2d : Vec<Vec<u64>> = vec![
//         vec![0,1,2,3,0,1,2,3],
//         vec![4,5,6,7,4,5,6,7],
//         vec![8,9,10,11,8,9,10,11],
//         vec![12,13,14,15,12,13,14,15],
//         vec![0,1,2,3,0,1,2,3],
//         vec![4,5,6,7,4,5,6,7],
//         vec![8,9,10,11,8,9,10,11],
//         vec![12,13,14,15,12,13,14,15]
//     ];


//     // let array2d : Vec<Vec<u64>> = vec![
//     //     vec![0,1,2,3,0],
//     //     vec![4,5,6,7,4,5,6,7],

//     // ];

    

//     // let array2d : Vec<Vec<u64>> = vec![
//     //     vec![0,1,2,3],
//     //     vec![4,5,6,7]
//     // ];


//     let mut vec_of_lut: Vec<LUT> = Vec::new();
//     for f in array2d.clone(){
//         let lut = LUT::from_vec(&f, &private_key, &mut ctx);
//         vec_of_lut.push(lut);
//     }



//     let mut group = c.benchmark_group("sample-size-example");
//     group.sample_size(20);
//     group.bench_function("BACC2D", |b| b.iter(|| bacc2d(
//         vec_of_lut,
//         lwe_columns,
//         lwe_line,
//         &ctx,
//         &public_key
//     )));    
        
//     group.finish();


// }


// fn bench_glwe_add(c: &mut Criterion)
// {

// }

// criterion_group!(benches, bench_blind_array_access2d, bench_sample_extract);
// criterion_main!(benches);


