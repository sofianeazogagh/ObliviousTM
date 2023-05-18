
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
use crate::test_glwe::_glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch,
};


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
    let cbs_level = DecompositionLevelCount(4);
    let cbs_base_log = DecompositionBaseLog(6);
    let ciphertext_modulus = CiphertextModulus::new_native();


    let (small_lwe_sk,
        glwe_sk,
        big_lwe_sk,
        mut fourier_bsk,
        lwe_ksk,
        pfpksk,
        mut encryption_generator,
        cbs_pfpksk
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
                         pfks_modular_std_dev,
        ciphertext_modulus

    );



    let lwe_size = big_lwe_sk.lwe_dimension().to_lwe_size();
    let glwe_size = glwe_sk.glwe_dimension().to_glwe_size();
    // Our 4 bits message space
    let message_modulus = 1u64 << 4;
    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;




    println!("Key generated");

    // creation of tape
    let mut tape = vec![1_u64, 2, 1];
    while tape.len()<2048 {
        tape.push(2_u64); }
    println!("{:?}",tape);
    for i in 0..tape.len() {
         tape[i] = tape[i]*delta;
      }
    let mut tape_plain = PlaintextList::from_container(tape);

    let mut tape = GlweCiphertext::new(0u64, glwe_size, polynomial_size,ciphertext_modulus) as GlweCiphertext<Vec<u64>>;

    encrypt_glwe_ciphertext(
        &glwe_sk,
        &mut tape,
        &tape_plain,
        glwe_modular_std_dev,
        &mut encryption_generator,
    );
    println!("Tape Encrypted");
    //creation of state

    let state = 0_u64;
    let plaintext = Plaintext(state * delta);
    let mut state: LweCiphertext<Vec<u64>> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_modular_std_dev,
        ciphertext_modulus,
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

    let instruction_position1 = vec![
        vec![0 , 0, 31, 31, 0, 0, 0],
        vec![0, 0, 31, 31, 31, 0, 0],
        vec![0, 31, 0, 31, 0, 0, 0],
    ];

    let instruction_position2 = vec![
        vec![31, 31, 0, 0, 31, 31, 0],
        vec![31, 31, 0, 0, 0, 31, 0],
        vec![31, 0, 31, 0, 31, 31, 0],
    ];

    let instruction_state = vec![
        vec![0, 31, 30, 29, 0, 27, 26],
        vec![0, 31, 29, 29, 28, 27, 26],
        vec![31, 30, 27, 28, 0, 26, 26],
    ];

    let instruction_write = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator,glwe_dimension, instruction_write,ciphertext_modulus);
    let mut instruction_position1  = encrypt_instructions(&glwe_sk,  message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_position1,ciphertext_modulus);
    let mut instruction_position2  = encrypt_instructions(&glwe_sk,  message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_position2,ciphertext_modulus);
    let instruction_state = encrypt_instructions(&glwe_sk, message_modulus,delta,glwe_modular_std_dev, polynomial_size,&mut encryption_generator, glwe_dimension, instruction_state,ciphertext_modulus);
    println!("Instructions Encrypted");
    // decrypt_instructions(&glwe_sk,delta,polynomial_size,&mut instruction_position);

    let plainOne= Plaintext(1_u64*delta);
    let mut One = LweCiphertext::new(0u64, small_lwe_sk.lwe_dimension().to_lwe_size(), ciphertext_modulus) as LweCiphertext<Vec<u64>>;

    encrypt_lwe_ciphertext(&small_lwe_sk,&mut One,plainOne,lwe_modular_std_dev,&mut encryption_generator);


    for i in 0..step {
        let mut cellContent=read_cell_content(&mut tape,lwe_size,&lwe_ksk,small_lwe_dimension,ciphertext_modulus);
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


        tape = write_new_cell_content(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),&mut tape,cellContent.clone(),state.clone(),instruction_write.clone(),small_lwe_sk.clone(),glwe_sk.clone(),ciphertext_modulus);
        tape = change_head_position(big_lwe_sk.clone(), big_lwe_dimension, fourier_bsk.clone(), small_lwe_dimension, lwe_ksk.clone(), polynomial_size, message_modulus, delta, glwe_dimension, pfpksk.clone(), &mut tape, cellContent.clone(), state.clone(), instruction_position1.clone(), instruction_position2.clone(),ciphertext_modulus,  cbs_base_log, cbs_level,cbs_pfpksk.clone(),One.clone(),small_lwe_sk.clone(),glwe_sk.clone());
        state = get_new_state(big_lwe_dimension,fourier_bsk.clone(),small_lwe_dimension,lwe_ksk.clone(),polynomial_size,message_modulus,delta,glwe_dimension,pfpksk.clone(),cellContent.clone(),state.clone(),instruction_state.clone(),small_lwe_sk.clone(),ciphertext_modulus);
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

pub fn read_cell_content(tape:&mut GlweCiphertext<Vec<u64>>, lwe_size:LweSize, lwe_ksk:&LweKeyswitchKey<Vec<u64>>, small_lwe_dimension:LweDimension, ciphertext_modulus: CiphertextModulus<u64>) ->LweCiphertext<Vec<u64>>{
    let mut cellContent=LweCiphertext::new(0u64, lwe_size,ciphertext_modulus);
    extract_lwe_sample_from_glwe_ciphertext(&tape, &mut cellContent, MonomialDegree(0));
    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);
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
    glwe_sk:GlweSecretKeyOwned<u64>,
    ciphertext_modulus: CiphertextModulus<u64>) ->GlweCiphertext<Vec<u64>>
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
        cellContent
        ,ciphertext_modulus);



    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);
    keyswitch_lwe_ciphertext(&lwe_ksk,&newCellContent,&mut res);
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
        let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&res);
        let encoded = signed_decomposer.closest_representable(plain.0);
        let cleartext = encoded/delta;
        println!("newcellcontent {}",cleartext);


        let mut newCellContentGlwe:GlweCiphertext<Vec<u64>>= GlweCiphertext::new(0_u64, tape.glwe_size(), tape.polynomial_size(),ciphertext_modulus);

        // private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pfpksk, &mut newCellContentGlwe,&res);

        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pfpksk, &mut newCellContentGlwe, &res);




        let mut result  = GlweCiphertext::new(0_u64, newCellContentGlwe.glwe_size(), newCellContentGlwe.polynomial_size(),ciphertext_modulus);
        result = _glwe_ciphertext_add(tape,&newCellContentGlwe,ciphertext_modulus);
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
    instruction_position1:Vec<GlweCiphertext<Vec<u64>>>,
    instruction_position2:Vec<GlweCiphertext<Vec<u64>>>,
    ciphertext_modulus: CiphertextModulus<u64>,
    cbs_base_log:DecompositionBaseLog,
    cbs_level_count:DecompositionLevelCount,
    cbs_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
    One: LweCiphertext<Vec<u64>>,
    small_lwe_sk: LweSecretKeyOwned<u64>,
    key: GlweSecretKeyOwned<u64>) -> GlweCiphertextOwned<u64>
{
    let positionChange1 = bacc2d(
        instruction_position1.clone(),
        big_lwe_dimension,
        state.clone(),
        fourier_bsk.clone(),
        small_lwe_dimension,
        lwe_ksk.clone(),
        polynomial_size,
        message_modulus,
        delta,
        glwe_dimension,
        pfpksk.clone(),
        cellContent.clone(),
        ciphertext_modulus);

        let positionChange2 = bacc2d(
            instruction_position2.clone(),
            big_lwe_dimension,
            state.clone(),
            fourier_bsk.clone(),
            small_lwe_dimension,
            lwe_ksk.clone(),
            polynomial_size,
            message_modulus,
            delta,
            glwe_dimension,
            pfpksk.clone(),
            cellContent.clone(),
            ciphertext_modulus);

        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

        let mut res1=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);
        keyswitch_lwe_ciphertext(&lwe_ksk,&positionChange1,&mut res1);
        let mut res2=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);
        keyswitch_lwe_ciphertext(&lwe_ksk,&positionChange2,&mut res2);

        let mut positionChange3 = LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);

        positionChange3 = One.clone();

        lwe_ciphertext_sub_assign(&mut positionChange3,&res1);
        lwe_ciphertext_sub_assign(&mut positionChange3,&res2);

    let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&res1);
    let encoded = signed_decomposer.closest_representable(plain.0);
    let cleartext = encoded/delta;
    println!("res1 {}",cleartext);

    let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&res2);
    let encoded = signed_decomposer.closest_representable(plain.0);
    let cleartext = encoded/delta;
    println!("res2 {}",cleartext);

    let mut plain = decrypt_lwe_ciphertext(&small_lwe_sk,&positionChange3);
    let encoded = signed_decomposer.closest_representable(plain.0);
    let cleartext = encoded/delta;
    println!("res3 {}",cleartext);

        let mut tape1 =tape.clone();
            tape1.as_mut_polynomial_list().iter_mut().for_each(|mut poly|{poly.as_mut().rotate_left(1)});
        let mut tapemoins1 =tape.clone();
            tapemoins1.as_mut_polynomial_list().iter_mut().for_each(|mut poly|{poly.as_mut().rotate_right(1)});

    let mut output_plaintext_list = PlaintextList::new(0, PlaintextCount(polynomial_size.0));
    decrypt_glwe_ciphertext(&key, &tape1, &mut output_plaintext_list);

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
    println!("Tape1: {:?}", cleartext_list);


        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let mut buffers = ComputationBuffers::new();

        let buffer_size_req = circuit_bootstrap_boolean_scratch::<u64>(
            small_lwe_dimension.to_lwe_size(),
            fourier_bsk.output_lwe_dimension().to_lwe_size(),
            fourier_bsk.glwe_size(),
            pfpksk.output_polynomial_size(),
            fft,
        )
            .unwrap()
            .unaligned_bytes_required();

        buffers.resize(buffer_size_req);

        let delta_log = DeltaLog(63);


        let mut GGSWpositionChange1 = GgswCiphertext::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
            CiphertextModulus::new_native(),);

        let mut GGSWpositionChange2 = GgswCiphertext::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
            CiphertextModulus::new_native(),);

        let mut GGSWpositionChange3 = GgswCiphertext::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
            CiphertextModulus::new_native(),);

        circuit_bootstrap_boolean(
            fourier_bsk.as_view(),
            res1.as_view(),
            GGSWpositionChange1.as_mut_view(),
            delta_log,
            cbs_pfpksk.as_view(),
            fft,
            buffers.stack(),
        );

        circuit_bootstrap_boolean(
            fourier_bsk.as_view(),
            res2.as_view(),
            GGSWpositionChange2.as_mut_view(),
            delta_log,
            cbs_pfpksk.as_view(),
            fft,
            buffers.stack(),
        );

        circuit_bootstrap_boolean(
            fourier_bsk.as_view(),
            positionChange3.as_view(),
            GGSWpositionChange3.as_mut_view(),
            delta_log,
            cbs_pfpksk.as_view(),
            fft,
            buffers.stack(),
        );

        let buffer_size_req = add_external_product_assign_mem_optimized_requirement::<u64>(
            tape.glwe_size(),
            polynomial_size,
            fft,
        )
            .unwrap()
            .unaligned_bytes_required();

        let buffer_size_req = buffer_size_req.max(
            convert_standard_ggsw_ciphertext_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );

        buffers.resize(buffer_size_req);

        let mut fourierGGSWpositionChange1 = FourierGgswCiphertext::new(
            tape.glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
        );

        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
            &GGSWpositionChange1,
            &mut fourierGGSWpositionChange1,
            fft,
            buffers.stack(),
        );

        let mut fourierGGSWpositionChange2 = FourierGgswCiphertext::new(
            tape.glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
        );

        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
            &GGSWpositionChange2,
            &mut fourierGGSWpositionChange2,
            fft,
            buffers.stack(),
        );

        let mut fourierGGSWpositionChange3 = FourierGgswCiphertext::new(
            tape.glwe_size(),
            polynomial_size,
            cbs_base_log,
            cbs_level_count,
        );

        convert_standard_ggsw_ciphertext_to_fourier_mem_optimized(
            &GGSWpositionChange3,
            &mut fourierGGSWpositionChange3,
            fft,
            buffers.stack(),
        );

        let mut tape_out = tape.clone();

        add_external_product_assign_mem_optimized(
            &mut tape_out,
            &fourierGGSWpositionChange1,
            &tape,
            fft,
            buffers.stack(),
        );

        let mut tape1_out = tape1.clone();

        add_external_product_assign_mem_optimized(
            &mut tape1_out,
            &fourierGGSWpositionChange2,
            &tape1,
            fft,
            buffers.stack(),
        );

        let mut tapemoins1_out = tapemoins1.clone();

        add_external_product_assign_mem_optimized(
            &mut tapemoins1_out,
            &fourierGGSWpositionChange3,
            &tapemoins1,
            fft,
            buffers.stack(),
        );

        let mut result  = GlweCiphertext::new(0_u64, tape.glwe_size(), tape.polynomial_size(),ciphertext_modulus);
        result = _glwe_ciphertext_add(&tape_out,&tape1_out,ciphertext_modulus);
        result = _glwe_ciphertext_add(&result,&tapemoins1_out,ciphertext_modulus);

    return result;

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
    small_lwe_sk:LweSecretKeyOwned<u64>,
    ciphertext_modulus:CiphertextModulus<u64>
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
        cellContent,
        ciphertext_modulus);


    let mut res=LweCiphertext::new(0_64,small_lwe_dimension.to_lwe_size(),ciphertext_modulus);
    keyswitch_lwe_ciphertext(&lwe_ksk,&statesortie,&mut res);

    return res;

}


