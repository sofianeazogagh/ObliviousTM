mod blind_array_access2d;
mod encrypt_instructions;
mod test_glwe;
mod headers;
mod helpers;



use aligned_vec::{ABox, CACHELINE_ALIGN};
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut};
use aligned_vec;
use itertools::izip;
use itertools::all;
use num_complex::Complex;
use tfhe::core_crypto::prelude::*;
use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions, encrypt_instructions_LUT};
use crate::test_glwe::glwe_ciphertext_add;
use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::FourierGgswCiphertextListView;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{circuit_bootstrap_boolean, circuit_bootstrap_boolean_scratch, cmux_tree_memory_optimized_scratch};
use tfhe::core_crypto::fft_impl::fft64::math::fft::FftView;
use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use tfhe::{ClientKey, ServerKey};
use tfhe::shortint::{gen_keys, KeySwitchingKey, ShortintParameterSet};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2_KS_PBS,PARAM_MESSAGE_3_CARRY_1_KS_PBS};
use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::server_key::ShortintBootstrappingKey::Classic;
use crate::blind_array_access2d::bacc2d;
use crate::headers::{Context, LUT, PrivateKey, PublicKey};
use crate::helpers::{extract_fourier, generate_accumulator_via_vector, lwe_to_ciphertext, negacycle_vector};
use tfhe::shortint::wopbs::WopbsKey;



pub fn main() {



    //The number of steps our Turing Machine will run.

    let step = 100;


    let mut wop_params = WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    wop_params.message_modulus.0 = 1 << 3;
    wop_params.carry_modulus.0 = 1 << 1;

    let param = PARAM_MESSAGE_3_CARRY_1_KS_PBS;
    let mut ctx= Context::from_wop(param,wop_params);
    let (cks, sks) = gen_keys(param);
    let bsk=extract_fourier(sks.bootstrapping_key.to_owned(),&ctx) ;
    let private_key = PrivateKey::from(cks.small_lwe_secret_key.to_owned(),cks.glwe_secret_key.to_owned(),cks.large_lwe_secret_key.to_owned(),bsk ,sks.key_switching_key.to_owned(),&mut ctx);
    let public_key = private_key.get_public_key();
    let (wop_key, (associated_lwe_sk, associated_glwe_sk)) =
        WopbsKey::new_wopbs_key_return_secret_keys(&cks, &sks, &wop_params);

    println!("Key generated");

    //creation of tape
    let mut tape_int = vec![1_u64, 2, 1];
    while tape_int.len() < ctx.polynomial_size().0 {
        tape_int.push(2_u64);
    }
    println!("{:?}", tape_int);

    for i in 0..tape_int.len(){
        tape_int[i]*=ctx.delta();
    }

    let tape_pt=PlaintextList::from_container(tape_int);

    let mut tape = private_key.allocate_and_encrypt_glwe(tape_pt, &mut ctx);
    let mut state = cks.encrypt(0).ct;

    println!("State Encrypted");
    let mut instruction_write = vec![
        vec![0, 0, 1, 0, 1, 0, 0],
        vec![0, 0, 7, 0, 7, 0, 0],
        vec![0, 0, 0, 0, 7, 0, 0],
    ];

    let mut instruction_position = vec![
        vec![15, 15, 1, 1, 15, 15, 0],
        vec![15, 15, 1, 1, 1, 15, 0],
        vec![15, 1, 15, 1, 15, 15, 0],
    ];

    let mut instruction_state = vec![
        vec![0, 1, 2, 3, 0, 5, 6],
        vec![0, 1, 3, 3, 4, 5, 6],
        vec![1, 2, 5, 4, 0, 6, 6],
    ];
    instruction_write = negacycle_vector(instruction_write, &mut ctx);
    //instruction_position = negacycle_vector(instruction_position, &mut ctx);
    instruction_state = negacycle_vector(instruction_state, &mut ctx);
    println!("tape = {:?}",instruction_state);



    let instruction_write = encrypt_instructions_LUT(&mut ctx, &private_key, instruction_write);
    let instruction_position = encrypt_instructions_LUT(&mut ctx, &private_key, instruction_position);
    let instruction_state = encrypt_instructions_LUT(&mut ctx, &private_key, instruction_state);
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
        tape = change_head_position(&mut tape, cellContent.clone(), state.clone(), &instruction_position, &public_key, &ctx, &wop_key,&associated_glwe_sk,sks.to_owned(),&private_key);
        state = get_new_state(cellContent.clone(), state.clone(), &instruction_state, &public_key, &ctx, &private_key);

    }
}


pub fn read_cell_content(
    tape: &mut GlweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    ctx: &Context) -> LweCiphertext<Vec<u64>> {
    let mut cellContent = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    extract_lwe_sample_from_glwe_ciphertext(&tape, &mut cellContent, MonomialDegree(0));
    let mut res = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &cellContent, &mut res);

    return res;
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

    let newCellContent = bacc2d(
        instruction_write,
        &state,
        &cellContent,
        ctx,
        public_key,
    );

    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &newCellContent, &mut switched);


    let mut newCellContentGlwe: GlweCiphertext<Vec<u64>> = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
    private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(&public_key.pfpksk, &mut newCellContentGlwe,&switched);
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
    wop_key: &WopbsKey,
    associated_glwe_sk: &GlweSecretKeyOwned<u64>,
    sks: tfhe::shortint::server_key::ServerKey,

    private_key: &PrivateKey,

) ->GlweCiphertext<Vec<u64>>
{
    let positionChange = bacc2d(
        instruction_position,
        &state,
        &cellContent,
        ctx,
        public_key,

    );


    // Lut shifted to the left
    let mut left_shift_tape = tape.clone();
    tape
        .as_polynomial_list()
        .iter()
        .zip(left_shift_tape.as_mut_polynomial_list().iter_mut())
        .for_each(|(src, mut dst)| {
            polynomial_algorithms::polynomial_wrapping_monic_monomial_div(
                &mut dst,
                &src,
                MonomialDegree(1),
            )
        });

    // Lut shifted to the left
    let mut right_shift_tape = tape.clone();
    tape
        .as_polynomial_list()
        .iter()
        .zip(right_shift_tape.as_mut_polynomial_list().iter_mut())
        .for_each(|(src, mut dst)| {
            polynomial_algorithms::polynomial_wrapping_monic_monomial_mul(
                &mut dst,
                &src,
                MonomialDegree(1),
            )
        });

    let mut tape_list = GlweCiphertextList::new(
        0u64,
        tape.glwe_size(),
        tape.polynomial_size(),
        GlweCiphertextCount(4),
        tape.ciphertext_modulus(),
    );

    // Copy tapes to different slots of a GlweCiphertextList
    tape_list
        .get_mut(0)
        .as_mut()
        .copy_from_slice(tape.as_ref());
    tape_list
        .get_mut(1)
        .as_mut()
        .copy_from_slice(left_shift_tape.as_ref());
    tape_list
        .get_mut(2)
        .as_mut()
        .copy_from_slice(right_shift_tape.as_ref());

    let fft = Fft::new(ctx.wop_params.polynomial_size);
    let fft = fft.as_view();

    let mut buffers = ComputationBuffers::new();
    buffers.resize(
        cmux_tree_memory_optimized_scratch::<u64>(
            ctx.wop_params.glwe_dimension.to_glwe_size(),
            ctx.wop_params.polynomial_size,
            // 2 bits to select LUTs
            2,
            fft,
        )
            .unwrap()
            .try_unaligned_bytes_required()
            .unwrap()
            .max(
                circuit_bootstrap_boolean_scratch::<u64>(
                    ctx.wop_params.lwe_dimension.to_lwe_size(),
                    associated_glwe_sk
                        .clone()
                        .into_lwe_secret_key()
                        .lwe_dimension()
                        .to_lwe_size(),
                    ctx.wop_params.glwe_dimension.to_glwe_size(),
                    ctx.wop_params.polynomial_size,
                    fft,
                )
                    .unwrap()
                    .try_unaligned_bytes_required()
                    .unwrap(),
            ),
    );

    let positionChange_ct = lwe_to_ciphertext(positionChange,&ctx);
        // Go to wopbs params
        let positionChange = wop_key.keyswitch_to_wopbs_params(&sks, &positionChange_ct);

        // We will extract the 2 LSBs in our case
        let extracted_bits = wop_key.extract_bits(DeltaLog((ctx.delta().ilog(2))as usize), &positionChange, 2);

        let mut ggsw_ciphertext_list = GgswCiphertextList::new(
            0u64,
            ctx.wop_params.glwe_dimension.to_glwe_size(),
            ctx.wop_params.polynomial_size,
            ctx.wop_params.cbs_base_log,
            ctx.wop_params.cbs_level,
            GgswCiphertextCount(extracted_bits.entity_count()),
            CiphertextModulus::new_native(),
        );

        let fourier_bsk = match &wop_key.wopbs_server_key.bootstrapping_key {
            tfhe::shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk,
            tfhe::shortint::server_key::ShortintBootstrappingKey::MultiBit { .. } => unreachable!(),
        };

        ggsw_ciphertext_list
            .iter_mut()
            .zip(extracted_bits.iter())
            .for_each(|(mut dst, src)| {
                circuit_bootstrap_boolean(
                    fourier_bsk.as_view(),
                    src.as_view(),
                    dst.as_mut_view(),
                    // The bit was put on the MSB by the bit extract
                    DeltaLog(63),
                    wop_key.cbs_pfpksk.as_view(),
                    fft,
                    buffers.stack(),
                )
            });

        let mut fourier_ggsw_list = FourierGgswCiphertextList::new(
            aligned_vec::avec!(
                c64::default();
                ggsw_ciphertext_list.entity_count()
                    * ggsw_ciphertext_list.polynomial_size().0
                    / 2
                    * ggsw_ciphertext_list.glwe_size().0
                    * ggsw_ciphertext_list.glwe_size().0
                    * ggsw_ciphertext_list.decomposition_level_count().0
            )
                .into_boxed_slice(),
            ggsw_ciphertext_list.entity_count(),
            ggsw_ciphertext_list.glwe_size(),
            ggsw_ciphertext_list.polynomial_size(),
            ggsw_ciphertext_list.decomposition_base_log(),
            ggsw_ciphertext_list.decomposition_level_count(),
        );

        fourier_ggsw_list
            .as_mut_view()
            .into_ggsw_iter()
            .zip(ggsw_ciphertext_list.iter())
            .for_each(|(mut dst, src)| {
                dst.as_mut_view()
                    .fill_with_forward_fourier(src.as_view(), fft, buffers.stack())
            });

        let mut glwe_ciphertext = GlweCiphertext::new(
            0u64,
            ctx.wop_params.glwe_dimension.to_glwe_size(),
            ctx.wop_params.polynomial_size,
            CiphertextModulus::new_native(),
        ) as GlweCiphertext<Vec<u64>>;

        // Glwe Selection
        glwe_cmux_tree_memory_optimized(
            glwe_ciphertext.as_mut_view(),
            &tape_list,
            fourier_ggsw_list.as_view(),
            fft,
            buffers.stack(),
        );




    return glwe_ciphertext;



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
    let statesortie = bacc2d(
        instruction_state,
        &state,
        &cellContent,
        ctx,
        public_key,
    );

    let mut res = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &statesortie, &mut res);

    return res;
}

pub fn glwe_cmux_tree_memory_optimized<Scalar: UnsignedTorus + CastInto<usize>>(
    mut output_glwe: GlweCiphertext<&mut [Scalar]>,
    lut_per_layer: &GlweCiphertextList<Vec<Scalar>>,
    ggsw_list: FourierGgswCiphertextListView<'_>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) {
    debug_assert!(lut_per_layer.glwe_ciphertext_count().0 == 1 << ggsw_list.count());

    if ggsw_list.count() > 0 {
        let glwe_size = output_glwe.glwe_size();
        let ciphertext_modulus = output_glwe.ciphertext_modulus();
        let polynomial_size = ggsw_list.polynomial_size();
        let nb_layer = ggsw_list.count();

        debug_assert!(stack.can_hold(
            cmux_tree_memory_optimized_scratch::<Scalar>(glwe_size, polynomial_size, nb_layer, fft)
                .unwrap()
        ));

        // These are accumulator that will be used to propagate the result from layer to layer
        // At index 0 you have the lut that will be loaded, and then the result for each layer gets
        // computed at the next index, last layer result gets stored in `result`.
        // This allow to use memory space in C * nb_layer instead of C' * 2 ^ nb_layer
        let (mut t_0_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );
        let (mut t_1_data, stack) = stack.make_aligned_with(
            polynomial_size.0 * glwe_size.0 * nb_layer,
            CACHELINE_ALIGN,
            |_| Scalar::ZERO,
        );

        let mut t_0 = GlweCiphertextList::from_container(
            t_0_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );
        let mut t_1 = GlweCiphertextList::from_container(
            t_1_data.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        );

        let (mut t_fill, mut stack) = stack.make_with(nb_layer, |_| 0_usize);

        let mut lut_glwe_iter = lut_per_layer.iter();
        loop {
            let even = lut_glwe_iter.next();
            let odd = lut_glwe_iter.next();

            let (lut_2i, lut_2i_plus_1) = match (even, odd) {
                (Some(even), Some(odd)) => (even, odd),
                _ => break,
            };

            let mut t_iter = izip!(t_0.iter_mut(), t_1.iter_mut(),).enumerate();

            let (mut j_counter, (mut t0_j, mut t1_j)) = t_iter.next().unwrap();

            t0_j.as_mut().copy_from_slice(lut_2i.as_ref());

            t1_j.as_mut().copy_from_slice(lut_2i_plus_1.as_ref());

            t_fill[0] = 2;

            for (j, ggsw) in ggsw_list.into_ggsw_iter().rev().enumerate() {
                if t_fill[j] == 2 {
                    let (diff_data, stack) = stack.rb_mut().collect_aligned(
                        CACHELINE_ALIGN,
                        izip!(t1_j.as_ref(), t0_j.as_ref()).map(|(&a, &b)| a.wrapping_sub(b)),
                    );
                    let diff = GlweCiphertext::from_container(
                        &*diff_data,
                        polynomial_size,
                        ciphertext_modulus,
                    );

                    if j != nb_layer - 1 {
                        let (j_counter_plus_1, (mut t_0_j_plus_1, mut t_1_j_plus_1)) =
                            t_iter.next().unwrap();

                        assert_eq!(j_counter, j);
                        assert_eq!(j_counter_plus_1, j + 1);

                        let mut output = if t_fill[j + 1] == 0 {
                            t_0_j_plus_1.as_mut_view()
                        } else {
                            t_1_j_plus_1.as_mut_view()
                        };

                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(output, ggsw, diff, fft, stack);
                        t_fill[j + 1] += 1;
                        t_fill[j] = 0;

                        drop(diff_data);

                        t0_j.as_mut().copy_from_slice( t_0_j_plus_1.as_ref());
                        t1_j.as_mut().copy_from_slice( t_1_j_plus_1.as_ref());
                        j_counter = j_counter_plus_1;
                    } else {
                        let mut output = output_glwe.as_mut_view();
                        output.as_mut().copy_from_slice(t0_j.as_ref());
                        tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::add_external_product_assign(output, ggsw, diff, fft, stack);
                    }
                } else {
                    break;
                }
            }
        }
    } else {
        output_glwe.as_mut().copy_from_slice(lut_per_layer.as_ref());
    }
}


