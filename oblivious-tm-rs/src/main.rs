mod unitest_baacc2d;
mod key_generation;
mod encrypt_instructions;
mod test_glwe;
mod headers;

use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
use crate::key_generation::key_generation;
use crate::unitest_baacc2d::*;
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;


pub fn main() {


 

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

