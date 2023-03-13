mod unitest_baacc2d;
mod key_generation;
//mod blind_array_access_generique;
mod encrypt_instructions;

use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::encrypt_instructions;
use crate::key_generation::key_generation;
use crate::unitest_baacc2d::*;






pub fn main() {

    //The number of steps our Turing Machine will run.

    let step = 10;

    //Keys generation

    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message

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
    let lwe_size = small_lwe_sk.lwe_dimension().to_lwe_size();

    // Our 4 bits message space
    let message_modulus = 1u64 << 4;
    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    //creation of tape
    let tape = vec![0_u64, 0, 0, 0];
    let accumulator_u64 = generate_accumulator_via_vector(polynomial_size, message_modulus as usize, delta, tape);
    let mut tape: GlweCiphertextOwned<u64> = encrypt_accumulator_as_glwe_ciphertext(
        &glwe_sk,
        glwe_modular_std_dev,
        &mut encryption_generator,
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        accumulator_u64);
    //creation of state

    let state = 0_u64;
    let plaintext = Plaintext(state * delta);
    let mut state: LweCiphertext<Vec<u64>> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_modular_std_dev,
        &mut encryption_generator,
    );
    //creation of instructions


    let instruction_write = vec![
        vec![0, 1, 2, 3],
        vec![4, 5, 6, 7],
        vec![8, 9, 10, 11],
        vec![12, 13, 14, 15]
    ];

    let instruction_position = vec![
        vec![0, 1, 2, 3],
        vec![4, 5, 6, 7],
        vec![8, 9, 10, 11],
        vec![12, 13, 14, 15]
    ];

    let instruction_state = vec![
        vec![0, 1, 2, 3],
        vec![4, 5, 6, 7],
        vec![8, 9, 10, 11],
        vec![12, 13, 14, 15]
    ];

    let instruction_write = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator,glwe_dimension, instruction_write);
    let instruction_position = encrypt_instructions(&glwe_sk,  message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_position);
    let instruction_state = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_state);


    for i in 0..step {
        let mut cellContent=read_cell_content(&tape,lwe_size);

        let tape = write_new_cell_content(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),&tape,cellContent.clone(),state.clone(),instruction_write.clone());
        let tape = change_head_position(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),&tape,cellContent,state.clone(),instruction_position.clone());
        let state = get_new_state(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),cellContent.clone(),state.clone(),instruction_state.clone());
    }
}

pub fn read_cell_content(tape:&GlweCiphertextOwned<u64>,lwe_size:LweSize)->LweCiphertext<Vec<u64>>{
    let mut cellContent=LweCiphertext::new(0u64, lwe_size);
    extract_lwe_sample_from_glwe_ciphertext(&tape, &mut cellContent, MonomialDegree(0));
    return cellContent;
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
    mut tape:&GlweCiphertextOwned<u64>,
    cellContent:LweCiphertext<Vec<u64>>,
    state:LweCiphertext<Vec<u64>>,
    instruction_write: Vec<GlweCiphertext<Vec<u64>>>)
    ->&GlweCiphertextOwned<u64>{

    let newCellContent = bacc2d(
        instruction_write,
        big_lwe_dimension,
        state,
        fourier_bsk,
        small_lwe_dimension,
        lwe_ksk,
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk,
        cellContent);
    let mut newCellContentVec:Vec::new() ;
    let newCellContentVec =newCellContentVec.push(newCellContent);
    let RLWEnewCellContent = many_lwe_to_glwe(polynomial_size,small_lwe_dimension,message_modulus,newCellContentVec,delta,glwe_dimension,pfpksk.clone());
    let tape = glwe_addition(tape,RLWEnewCellContent);
    return tape;
}

pub fn change_head_position(
    big_lwe_dimension:LweDimension,
    fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    small_lwe_dimension: LweDimension,
    lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    polynomial_size: PolynomialSize,
    message_modulus: u64,
    delta: u64,
    glwe_dimension: GlweDimension,
    pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    mut tape:&GlweCiphertextOwned<u64>,
    cellContent:LweCiphertext<Vec<u64>>,
    state:LweCiphertext<Vec<u64>>,
    instruction_position:Vec<GlweCiphertext<Vec<u64>>>)
    ->&GlweCiphertextOwned<u64>{

    let positionChange = bacc2d(
        instruction_position,
        big_lwe_dimension,
        state,
        fourier_bsk,
        small_lwe_dimension,
        lwe_ksk,
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk,
        cellContent);
    blind_rotate_assign(&positionChange, &mut tape, &fourier_bsk);
    return tape;

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
    instruction_state:Vec<GlweCiphertext<Vec<u64>>>)
    ->LweCiphertext<Vec<u64>>{

    let state = bacc2d(
        instruction_state,
        big_lwe_dimension,
        state,
        fourier_bsk,
        small_lwe_dimension,
        lwe_ksk,
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk,
        cellContent);
    return state;

}


