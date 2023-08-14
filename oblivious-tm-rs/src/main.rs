mod unitest_baacc2d;
mod encrypt_instructions;
mod test_glwe;
mod headers;
mod helpers;
mod blind_array_access_2d;

use aligned_vec::ABox;
use itertools::all;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
use crate::unitest_baacc2d::*;
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_0;
use crate::blind_array_access_2d::blind_array_access2d;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{bootstrap_glwe_LUT, generate_accumulator_via_vector, LWEaddu64, negacycle_vector, one_lwe_to_lwe_ciphertext_list};


pub fn main() {



        //The number of steps our Turing Machine will run.

        let step = 100;

        let param = PARAM_MESSAGE_3_CARRY_0;
        let mut ctx = Context::from(param);

        let private_key = PrivateKey::new(&mut ctx);
        let public_key = private_key.get_public_key();





    println!("Key generated");

        //creation of tape
        let mut tape = vec![1_u64, 2, 1];
        while tape.len() < ctx.message_modulus().0 {
            tape.push(2_u64);
        }
        println!("{:?}", tape);
        blind_array_access2d();

        let accumulator_u64 = generate_accumulator_via_vector(ctx.polynomial_size(), ctx.message_modulus().0, ctx.delta(), tape);
        let pt = PlaintextList::from_container(accumulator_u64);


        let mut tape = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
        private_key.encrypt_glwe(&mut tape, pt, &mut ctx);

        let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);

        println!("State Encrypted");
        let mut instruction_write = vec![
            vec![0, 0, 1, 0, 1, 0, 0],
            vec![0, 0, 7, 0, 7, 0, 0],
            vec![0, 0, 0, 0, 7, 0, 0],
        ];

        let mut instruction_position = vec![
            vec![1, 1, 15, 15, 1, 1, 0],
            vec![1, 1, 15, 15, 15, 1, 0],
            vec![1, 15, 1, 15, 1, 1, 0],
        ];

        let mut instruction_state = vec![
            vec![0, 1, 2, 3, 0, 5, 6],
            vec![0, 1, 3, 3, 4, 5, 6],
            vec![1, 2, 5, 4, 0, 6, 6],
        ];

        //instruction_write = negacycle_vector(instruction_write, &mut ctx);
        //instruction_position = negacycle_vector(instruction_position, &mut ctx);
        //instruction_state = negacycle_vector(instruction_state, &mut ctx);

    // let mut instruction_write = vec![
    //     vec![0,0,0],
    //     vec![0,0,0],
    //     vec![7,1,0],
    //     vec![0,0,0],
    //     vec![7,1,1],
    //     vec![0,0,0],
    //     vec![0,0,0],
    // ];
    //
    // let mut instruction_position = vec![
    //     vec![7,7,7],
    //     vec![7,7,1],
    //     vec![1,1,7],
    //     vec![1,1,1],
    //     vec![7,1,7],
    //     vec![7,7,7],
    //     vec![0,0,0],
    // ];
    //
    // let mut instruction_state = vec![
    //     vec![0,0,7],
    //     vec![7,7,6],
    //     vec![6,5,3],
    //     vec![5,5,4],
    //     vec![0,4,0],
    //     vec![3,3,2],
    //     vec![2,2,2],
    // ];
        println!("tape = {:?}",instruction_state);



    let instruction_write = encrypt_instructions(&mut ctx, &private_key, instruction_write);
        let instruction_position = encrypt_instructions(&mut ctx, &private_key, instruction_position);
        let instruction_state = encrypt_instructions(&mut ctx, &private_key, instruction_state);
        println!("Instructions Encrypted");


        for i in 0..step {
            let result = private_key.decrypt_and_decode_glwe(&tape,&ctx);
            println!("tape = {:?}",result);
            let current_state = private_key.decrypt_lwe(&state,&ctx);
            println!("state = {}", current_state);

            let mut cellContent = read_cell_content(&mut tape, &public_key, &ctx);
            let current_cell = private_key.decrypt_lwe(&cellContent,&ctx);
            println!("cellContent = {}", current_cell);

            tape = write_new_cell_content(&mut tape, cellContent.clone(), state.clone(),&instruction_write, &public_key, &ctx, &private_key);
            tape = change_head_position(&mut tape, cellContent.clone(), state.clone(), &instruction_position, &public_key, &ctx, &private_key);
            state = get_new_state(cellContent.clone(), state.clone(), &instruction_state, &public_key, &ctx, &private_key);

        }
    }


    pub fn read_cell_content(
        tape: &mut GlweCiphertext<Vec<u64>>,
        public_key: &PublicKey,
        ctx: &Context) -> LweCiphertext<Vec<u64>> {
        let mut cellContent = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        extract_lwe_sample_from_glwe_ciphertext(&tape, &mut cellContent, MonomialDegree(0));
        let mut res_temp = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &cellContent, &mut res_temp);

        return res_temp;
    }


    pub fn write_new_cell_content(
        tape: &mut GlweCiphertext<Vec<u64>>,
        cellContent: LweCiphertext<Vec<u64>>,
        state: LweCiphertext<Vec<u64>>,
        instruction_write: &Vec<LUT>,
        public_key: &PublicKey,
        ctx: &Context,
        private_key: &PrivateKey,
    ) -> GlweCiphertext<Vec<u64>>
    {

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

        let new_cell_content_ciphertext_list = one_lwe_to_lwe_ciphertext_list(&switched, &ctx);

        let mut newCellContentGlwe: GlweCiphertext<Vec<u64>> = GlweCiphertext::new(0_u64, tape.glwe_size(), tape.polynomial_size(), ctx.ciphertext_modulus());
        // private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pfpksk, &mut newCellContentGlwe,&res);

        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&public_key.pfpksk, &mut newCellContentGlwe, &new_cell_content_ciphertext_list);

        let result = glwe_ciphertext_add(tape.to_owned(), newCellContentGlwe,);
        return result;
    }

    pub fn change_head_position(
        tape: &mut GlweCiphertext<Vec<u64>>,
        cellContent: LweCiphertext<Vec<u64>>,
        state: LweCiphertext<Vec<u64>>,
        instruction_position: &Vec<LUT>,
        public_key: &PublicKey,
        ctx: &Context,
        private_key: &PrivateKey,

    ) ->GlweCiphertext<Vec<u64>>
    {
        let positionChange = bacc2dLUT(
            instruction_position,
            state,
            cellContent,
            public_key,
            &ctx,
            private_key,
        );


        let message_modulus = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus()) as LweCiphertext<Vec<u64>>;

        let mut res = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &positionChange, &mut res);
        blind_rotate_assign(&res, tape, &public_key.fourier_bsk);
        //tape.as_mut_polynomial_list().iter_mut().for_each(|mut poly|{polynomial_wrapping_monic_monomial_mul_assign(&mut poly,MonomialDegree(ctx.polynomial_size().0))});

        //return bootstrap_glwe_LUT( tape,&public_key,&ctx);
        return tape.to_owned()
    }

    pub fn get_new_state(
        cellContent: LweCiphertext<Vec<u64>>,
        state: LweCiphertext<Vec<u64>>,
        instruction_state: &Vec<LUT>,
        public_key: &PublicKey,
        ctx: &Context,
        private_key: &PrivateKey,
    ) -> LweCiphertext<Vec<u64>>
    {
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


