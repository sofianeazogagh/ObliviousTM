
mod unitest_baacc2d;
mod key_generation;
mod encrypt_instructions;
mod test_glwe;

use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
use crate::key_generation::key_generation;
use crate::unitest_baacc2d::*;
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;


pub fn main() {


    //The number of steps our Turing Machine will run.

    let step = 100;

    //Keys generation

    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message

    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension= GlweDimension(1);
    let big_lwe_dimension = LweDimension(2048);
    let polynomial_size= PolynomialSize(2048);
    let lwe_modular_std_dev= StandardDev(0.000007069849454709433);
    let glwe_modular_std_dev= StandardDev(0.00000000000000029403601535432533);
    let pbs_base_log= DecompositionBaseLog(23);
    let pbs_level= DecompositionLevelCount(1);
    let ks_level= DecompositionLevelCount(5);
    let ks_base_log= DecompositionBaseLog(3);
    let pfks_level= DecompositionLevelCount(1);
    let pfks_base_log= DecompositionBaseLog(23);
    let pfks_modular_std_dev= StandardDev(0.00000000000000029403601535432533);
    let cbs_level= DecompositionLevelCount(0);
    let cbs_base_log= DecompositionBaseLog(0);

    let (small_lwe_sk,
        glwe_sk,
        big_lwe_sk,
        fourier_bsk,
        lwe_ksk,
        pfpksk,
        mut encryption_generator
    )
        = key_generation(small_lwe_dimension,
                         glwe_dimension,
                         big_lwe_dimension,
                         polynomial_size,
                         lwe_modular_std_dev,
                         glwe_modular_std_dev,
                         pbs_base_log,
                         pbs_level,
                         ks_level,
                         ks_base_log,
                         pfks_level,
                         pfks_base_log,
                         pfks_modular_std_dev
    );
    let lwe_size = big_lwe_sk.lwe_dimension().to_lwe_size();
    let glwe_size = glwe_sk.glwe_dimension().to_glwe_size();
    // Our 4 bits message space
    let message_modulus = 1u64 << 4;
    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;




    println!("Key generated");

    //creation of tape
    let mut tape = vec![1_u64, 2, 1];
    while tape.len()<16 {
        tape.push(2_u64); }
    println!("{:?}",tape);
    // for i in 0..tape.len() {
    //      tape[i] = tape[i]<<60;
    //  }
    //let mut tape_plain = PlaintextList::new(&tape,PlaintextCount(polynomial_size.0));


    let accumulator_u64 = generate_accumulator_via_vector(polynomial_size, message_modulus as usize, delta, tape);
    //
    let mut tape: GlweCiphertext<Vec<u64>> = encrypt_accumulator_as_glwe_ciphertext(
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        accumulator_u64);
    println!("Tape Encrypted");
    //creation of state

    let state = 0_u64;
    let plaintext = Plaintext(state * delta);
    let mut state: LweCiphertext<Vec<u64>> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );

    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &tape, &mut output_plaintext_list);

    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    output_plaintext_list
        .iter_mut()
        .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

    // Get the raw vector
    let mut cleartext_list = output_plaintext_list.into_container();
    // Remove the encoding
    cleartext_list.iter_mut().for_each(|elt| *elt = *elt /delta);
    // Get the list immutably
    let cleartext_list = cleartext_list;

    // Check we recovered the original message for each plaintext we encrypted
    // println!("Result of encryption : {:?}", cleartext_list);


    println!("State Encrypted");
    let instruction_write = vec![
        vec![0, 0, 1, 0, 1, 0, 0],
        vec![0, 0, 31 , 0, 31, 0, 0],
        vec![0, 0, 0, 0, 31, 0, 0],

    ];

    let instruction_position = vec![
        vec![31, 31, 1, 1, 31, 31, 0],
        vec![31, 31, 1, 1, 1, 31, 0],
        vec![31, 1, 31, 1, 31, 31, 0],
    ];

    let instruction_state = vec![
        vec![0, 31, 30, 29, 0, 27, 26],
        vec![0, 31, 29, 29, 28, 27, 26],
        vec![31, 30, 27, 28, 0, 26, 26],
    ];

    let instruction_write = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator,glwe_dimension, instruction_write);
    let mut instruction_position  = encrypt_instructions(&glwe_sk,  message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_position);
    let instruction_state = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_state);
    println!("Instructions Encrypted");
    // decrypt_instructions(&glwe_sk,delta,polynomial_size,&mut instruction_position);


    for i in 0..step {
        let mut cellContent=read_cell_content(&mut tape,lwe_size,&lwe_ksk,small_lwe_dimension);
        let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&cellContent);
        let encoded = signed_decomposer.closest_representable(plain.0);
        let cleartext = encoded/delta;
        println!("cell content {}",cleartext);

        let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
        decrypt_glwe_ciphertext(&glwe_sk, &tape, &mut output_plaintext_list);

        output_plaintext_list
            .iter_mut()
            .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

        // Get the raw vector
        let mut cleartext_list = output_plaintext_list.into_container();
        // Remove the encoding
        cleartext_list.iter_mut().for_each(|elt| *elt = *elt /delta);
        // Get the list immutably
        let cleartext_list = cleartext_list;

        // Check we recovered the original message for each plaintext we encrypted
        println!("Result of OTM: {:?}", cleartext_list);


        tape = write_new_cell_content(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),&mut tape,cellContent.clone(),state.clone(),instruction_write.clone(),small_lwe_sk.clone(),glwe_sk.clone());
        change_head_position(big_lwe_sk.clone(),big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),&mut tape,cellContent.clone(),state.clone(),instruction_position.clone());
        state = get_new_state(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),cellContent.clone(),state.clone(),instruction_state.clone(),small_lwe_sk.clone());
        let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&state);
        let encoded = signed_decomposer.closest_representable(plain.0);
        let cleartext = encoded/delta;
        println!("state {}",cleartext);
    }

    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&glwe_sk, &tape, &mut output_plaintext_list);

    output_plaintext_list
        .iter_mut()
        .for_each(|elt| *elt.0 = signed_decomposer.closest_representable(*elt.0));

    // Get the raw vector
    let mut cleartext_list = output_plaintext_list.into_container();
    // Remove the encoding
    cleartext_list.iter_mut().for_each(|elt| *elt = *elt /delta);
    // Get the list immutably
    let cleartext_list = cleartext_list;

    // Check we recovered the original message for each plaintext we encrypted
    // println!("Result of OTM: {:?}", cleartext_list);

}

pub fn read_cell_content(tape:&mut GlweCiphertext<Vec<u64>>,lwe_size:LweSize,lwe_ksk:&LweKeyswitchKey<Vec<u64>>,small_lwe_dimension:LweDimension)->LweCiphertext<Vec<u64>>{
    let mut cellContent=LweCiphertext::new(0u64, lwe_size);
    extract_lwe_sample_from_glwe_ciphertext(&tape, &mut cellContent, MonomialDegree(0));
    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size());
    keyswitch_lwe_ciphertext(lwe_ksk,&cellContent,&mut res);
    return res;
}

pub fn write_new_cell_content(
    big_lwe_dimension:LweDimension,
    fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    small_lwe_dimension: LweDimension,
    lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    polynomial_size: PolynomialSize,
    message_modulus: u64,
    delta: u64,
    glwe_dimension: GlweDimension,
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    tape:&mut GlweCiphertext<Vec<u64>>,
    cellContent:LweCiphertext<Vec<u64>>,
    state:LweCiphertext<Vec<u64>>,
    instruction_write: Vec<GlweCiphertext<Vec<u64>>>,
    small_lwe_sk:LweSecretKeyOwned<u64>,
glwe_sk:GlweSecretKeyOwned<u64>)->GlweCiphertext<Vec<u64>>
    {

    let newCellContent = bacc2d(
        instruction_write,
        big_lwe_dimension,
        state,
        fourier_bsk,
        small_lwe_dimension,
        lwe_ksk.clone(),
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk.clone(),
        cellContent);



    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size());
    keyswitch_lwe_ciphertext(&lwe_ksk,&newCellContent,&mut res);
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
        let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&res);
        let encoded = signed_decomposer.closest_representable(plain.0);
        let cleartext = encoded/delta;
        println!("newcellcontent {}",cleartext);


        let new_cell_content_ciphertext_list = one_lwe_to_lwe_ciphertext_list(res, message_modulus, small_lwe_dimension, polynomial_size);
        let mut newCellContentGlwe:GlweCiphertext<Vec<u64>>= GlweCiphertext::new(0_u64, tape.glwe_size(), tape.polynomial_size());

        // private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pfpksk, &mut newCellContentGlwe,&res);

        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&pfpksk, &mut newCellContentGlwe, &new_cell_content_ciphertext_list);




        let mut result  = GlweCiphertext::new(0_u64, newCellContentGlwe.glwe_size(), newCellContentGlwe.polynomial_size());
        glwe_ciphertext_add(&tape,&newCellContentGlwe,&mut result);
        return result;
}

pub fn change_head_position(
    big_lwe_sk:LweSecretKeyOwned<u64>,
    big_lwe_dimension:LweDimension,
    fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    small_lwe_dimension: LweDimension,
    lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    polynomial_size: PolynomialSize,
    message_modulus: u64,
    delta: u64,
    glwe_dimension: GlweDimension,
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    tape:&mut GlweCiphertext<Vec<u64>>,
    cellContent:LweCiphertext<Vec<u64>>,
    state:LweCiphertext<Vec<u64>>,
    instruction_position:Vec<GlweCiphertext<Vec<u64>>>)
    {
    let positionChange = bacc2d(
        instruction_position,
        big_lwe_dimension,
        state,
        fourier_bsk.clone(),
        small_lwe_dimension,
        lwe_ksk.clone(),
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk,
        cellContent);

        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        let mut plain = decrypt_lwe_ciphertext(&big_lwe_sk,&positionChange);
        let encoded = signed_decomposer.closest_representable(plain.0);
        let cleartext = encoded/delta;
        println!("position change {}",cleartext);

        let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size());
        keyswitch_lwe_ciphertext(&lwe_ksk,&positionChange,&mut res);
    blind_rotate_assign(&res, tape, &fourier_bsk);


}
pub fn get_new_state(
    big_lwe_dimension:LweDimension,
    fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    small_lwe_dimension: LweDimension,
    lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    polynomial_size: PolynomialSize,
    message_modulus: u64,
    delta: u64,
    glwe_dimension: GlweDimension,
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    cellContent:LweCiphertext<Vec<u64>>,
    mut state:LweCiphertext<Vec<u64>>,
    instruction_state:Vec<GlweCiphertext<Vec<u64>>>,
    small_lwe_sk:LweSecretKeyOwned<u64>
    )
    ->LweCiphertext<Vec<u64>>{

    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
    let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&state);
    let encoded = signed_decomposer.closest_representable(plain.0);
    let cleartext = encoded/delta;
    println!("state IN {}",cleartext);



    let statesortie = bacc2d(
        instruction_state,
        big_lwe_dimension,
        state,
        fourier_bsk,
        small_lwe_dimension,
        lwe_ksk.clone(),
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk,
        cellContent);


    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size());
    keyswitch_lwe_ciphertext(&lwe_ksk,&statesortie,&mut res);

    return res;

}


