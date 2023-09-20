mod unitest_baacc2d;
mod encrypt_instructions;
mod test_glwe;
mod headers;
mod helpers;
// mod blind_array_access_2d;
// mod blind_insertion;
// mod blind_permutation;
// mod blind_pop;
// mod blind_retrieve;
// mod blind_push;
// mod private_insert;
//  mod OTM;

use aligned_vec::ABox;
use itertools::all;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
use crate::unitest_baacc2d::*;
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::shortint::parameters::{PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_3_CARRY_0_KS_PBS, PARAM_MESSAGE_3_CARRY_1, PARAM_MESSAGE_4_CARRY_0};
// use crate::blind_array_access_2d::blind_array_access2d;
// use crate::blind_insertion::blind_insertion;
// use crate::blind_permutation::blind_permutation;
// use crate::blind_pop::blind_pop;
// use crate::blind_push::blind_push;
// use crate::blind_retrieve::blind_retrieve;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{bootstrap_glwe_LUT, bootstrap_glwe_LUT_with_actual_bootstrap, generate_accumulator, generate_accumulator_via_vector, LWEaddu64, negacycle_vector, one_lwe_to_lwe_ciphertext_list};
 // use crate::OTM::{change_head_position, get_new_state, OTM, read_cell_content, write_new_cell_content};
// use crate::private_insert::private_insert;

// NOTES POUR MARCO :
// toutes les fonctions sont ici ou dans headers (tout context, et gestion des clés)
// ou dans encrypt instruction (il y a aussi un decrypt instructions dedans)
// ou dans test_glwe (addition de 2 glwe), ou dans helpers (LWEaddu64 (utile pour les pbs))
// ou dans unitest_baacc2d (blind array access)

pub fn main() {
    //OTM_test();
    let mut tape = vec![1_u64, 2, 3,4,5,6,7,7];

    let  instruction_write = vec![
        vec![0, ],
    ];
    let  instruction_position = vec![
        vec![0, ],
    ];

    let  instruction_state = vec![
        vec![0, ],
    ];
     OTM_test(tape, instruction_write, instruction_position, instruction_state);
}

/* Tout OTM mais dans le main */
// pub fn OTM_test() {
//     /**************** Client part *****************/
//
//     //Choix des params et création de clés
//     let param = PARAM_MESSAGE_3_CARRY_0;
//     let mut ctx = Context::from(param);
//
//     let private_key = PrivateKey::new(&mut ctx);
//     let public_key = private_key.get_public_key();
//
//     println!("Key generated");
//
//     //creation de la bande, toujours ajouter un 2 à la fin quand tu déclares une bande.
//     let mut tape = vec![1_u64, 2, 1,2];
//     let lenght = tape.len();
//     while tape.len() < ctx.message_modulus().0 {
//         tape.insert(0,2_u64);
//     }
//     println!("{:?}", tape);
//
//     let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
//     public_key.glwe_absorption_monic_monomial(&mut tape.0, MonomialDegree((ctx.polynomial_size().0+lenght*ctx.box_size()) as usize));
//
//     //création de l'état
//     let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
//
//     //création des instructions
//     println!("State Encrypted");
//     let mut instruction_write = vec![
//         vec![0, 0, 1, 0, 1, 0, 0],
//         vec![0, 0, 7, 0, 7, 0, 0],
//         vec![0, 0, 0, 0, 7, 0, 0],
//     ];
//     //Ici les 7 sont chiffrés comme des 15 pour des problèmes de négacyclicité dans la rotation de la bande
//     let mut instruction_position = vec![
//         vec![1, 1, 15, 15, 1, 1, 0],
//         vec![1, 1, 15, 15, 15, 1, 0],
//         vec![1, 15, 1, 15, 1, 1, 0],
//     ];
//
//     let mut instruction_state = vec![
//         vec![0, 1, 2, 3, 0, 5, 6],
//         vec![0, 1, 3, 3, 4, 5, 6],
//         vec![1, 2, 5, 4, 0, 6, 6],
//     ];
//
//     let instruction_write = encrypt_instructions(&mut ctx, &private_key, instruction_write);
//     let instruction_position = encrypt_instructions(&mut ctx, &private_key, instruction_position);
//     let instruction_state = encrypt_instructions(&mut ctx, &private_key, instruction_state);
//     println!("Instructions Encrypted");
//
//
//     /**************** Server part *****************/
//
//     //The number of steps our Turing Machine will run.
//     let step = 40;
//
//     for i in 0..step {
//
//         println!("\n step = {i}");
//
//         // Bande au début du step
//         let result = tape.print_lut(&private_key,&mut ctx);
//         println!("tape = {:?}",result);
//
//         //lecture sur la bande du contenu de la première cellule
//         let cellContent = read_cell_content_test(&mut tape.0, &public_key,&private_key, &ctx);
//
//         /*
//         cellContent : ligne
//         state : colonne
//          */
//
//
//         //affichage de la première cellule et de l'état
//         let current_cell = private_key.decrypt_lwe(&cellContent,&ctx);
//         println!("cellContent = {}", current_cell);
//         let current_state = private_key.decrypt_lwe(&state.to_owned(),&ctx);
//         println!("state = {}", current_state);
//
//
//         // écriture sur la bande
//         tape.0 = write_new_cell_content_test(&mut tape.0, cellContent.clone(), state.clone(),&instruction_write, &public_key, &mut ctx, &private_key);
//         // rotation de la bande
//         tape.0 = change_head_position_test(&mut tape.0, cellContent.clone(), state.clone(), &instruction_position, &public_key, &ctx, &private_key);
//         // màj de l'état
//         state = get_new_state_test(cellContent.clone(), state.clone(), &instruction_state, &public_key, &ctx, &private_key);
//
//     }
// }

pub fn read_cell_content_test(
    tape: &mut GlweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    mut ctx: &Context) -> LweCiphertext<Vec<u64>>
{

    // Lecture et keyswitch du contenu de la cellule 0
    let mut res_temp = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(&tape, &mut res_temp, MonomialDegree(0));
    let mut cellContent = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &res_temp, &mut cellContent);

    //affichage du résultat
    let res = private_key.decrypt_lwe(&cellContent,&ctx);
    println!("cellContent = {}", res);

    //bootstrapping de ce résultat

        let mut inter =LweCiphertext::new(0, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());

    let accumulator: GlweCiphertextOwned<u64> = generate_accumulator(
        ctx.polynomial_size(),
        ctx.glwe_dimension().to_glwe_size(),
        ctx.message_modulus().0 as usize,
        ctx.delta(),
        |x: u64| x,
    );

    programmable_bootstrap_lwe_ciphertext(
        &cellContent,
        &mut inter,
        &accumulator,
        &public_key.fourier_bsk,
    );

    let mut cellContent = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut inter, &mut cellContent);

    //affichage du résultat bootstrappé
    let res = private_key.decrypt_lwe(&cellContent,&ctx);
    println!("cellContent bs = {}", res);

    return cellContent;
}

pub fn write_new_cell_content_test(
    tape: &mut GlweCiphertext<Vec<u64>>,
    cellContent: LweCiphertext<Vec<u64>>,
    state: LweCiphertext<Vec<u64>>,
    instruction_write: &Vec<LUT>,
    public_key: &PublicKey,
    mut ctx: &mut Context,
    private_key: &PrivateKey,
) -> GlweCiphertext<Vec<u64>>
{
    //bacc2d+keyswitch pour obtenir ce que l'on va écrire

    let newCellContent = bacc2dLUT(
        instruction_write,
        state,
        cellContent,
        public_key,
        &ctx,
        private_key,
    );

    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &newCellContent, &mut switched);

    // addition dans la première cellule par addition de glwe
    let mut newCellContentGlwe = LUT::from_lwe(&switched,&public_key,&ctx).0;

    let mut result = glwe_ciphertext_add(tape.to_owned(), newCellContentGlwe.to_owned(),);

    //affichage de ce que l'on additione à la première cellule
    // let newcell_add = private_key.decrypt_lwe(&switched,&ctx);
    // println!("write add = {}", newcell_add);

    return result;
}

pub fn change_head_position_test(
    tape: &mut GlweCiphertext<Vec<u64>>,
    cellContent: LweCiphertext<Vec<u64>>,
    state: LweCiphertext<Vec<u64>>,
    instruction_position: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key: &PrivateKey,

) ->GlweCiphertext<Vec<u64>>
{
    //bacc2d+keyswitch pour obtenir le déplacement voulu et ensuite juste rotation
    let positionChange = bacc2dLUT(
        instruction_position,
        state,
        cellContent,
        public_key,
        &ctx,
        private_key,
    );

    let mut res = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &positionChange, &mut res);
    blind_rotate_assign(&res, tape, &public_key.fourier_bsk);

    //affichage du déplacement
    // let res = private_key.decrypt_lwe(&res,&ctx);
    // println!("test move = {}", res);

    return tape.to_owned()
}

pub fn get_new_state_test(
    cellContent: LweCiphertext<Vec<u64>>,
    state: LweCiphertext<Vec<u64>>,
    instruction_state: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key: &PrivateKey,
) -> LweCiphertext<Vec<u64>>
{
    //Juste un blind array access et un keyswitch pour mettre à jour l'état
    let statesortie = bacc2dLUT(
        instruction_state,
        state,
        cellContent,
        public_key,
        &ctx,
        private_key,
    );

    let mut res = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &statesortie, &mut res);

    return res;
}

pub fn OTM_test(
    tape: Vec<u64>,
    instruction_write: Vec<Vec<u64>>,
    instruction_position: Vec<Vec<u64>>,
    instruction_state: Vec<Vec<u64>>
) {

    //Choix des params et création de clés
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);

    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation de la bande, toujours ajouter un 2 à la fin quand tu déclares une bande.
    let lenght = tape.len();
    println!("{:?}", tape);

    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    public_key.glwe_absorption_monic_monomial(&mut tape.0, MonomialDegree((ctx.polynomial_size().0+lenght*ctx.box_size()) as usize));

    //création de l'état
    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);

    //création des instructions
    println!("State Encrypted");


    let instruction_write = encrypt_instructions(&mut ctx, &private_key, instruction_write);
    let instruction_position = encrypt_instructions(&mut ctx, &private_key, instruction_position);
    let instruction_state = encrypt_instructions(&mut ctx, &private_key, instruction_state);
    println!("Instructions Encrypted");

    //The number of steps our Turing Machine will run.
    let step = 40;

    for i in 0..step {

        println!("\n step = {i}");

        //Bande au début du step
        let result = tape.print_lut(&private_key,&mut ctx);
        println!("tape = {:?}",result);

        //lecture sur la bande du contenu de la première cellule
        let cellContent = read_cell_content_test(&mut tape.0, &public_key,&private_key, &ctx);

        //affichage de la première cellule et de l'état
        let current_cell = private_key.decrypt_lwe(&cellContent,&ctx);
        println!("cellContent = {}", current_cell);
        let current_state = private_key.decrypt_lwe(&state.to_owned(),&ctx);
        println!("state = {}", current_state);


        //écriture sur la bande
        tape.0 = write_new_cell_content_test(&mut tape.0, cellContent.clone(), state.clone(),&instruction_write, &public_key, &mut ctx, &private_key);
        //rotation de la bande
        tape.0 = change_head_position_test(&mut tape.0, cellContent.clone(), state.clone(), &instruction_position, &public_key, &ctx, &private_key);
        //màj de l'état
        state = get_new_state_test(cellContent.clone(), state.clone(), &instruction_state, &public_key, &ctx, &private_key);

    }
}

