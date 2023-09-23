// mod unitest_baacc2d;
// mod encrypt_instructions;
// mod test_glwe;
// mod headers;
// mod helpers;
// mod blind_array_access_2d;
// mod blind_insertion;
// mod blind_permutation;
// mod blind_pop;
// mod blind_retrieve;
// mod blind_push;
// mod private_insert;
// mod OTM;

// use aligned_vec::ABox;
// use itertools::all;
// use num_complex::Complex;
// use tfhe::core_crypto::prelude::*;
// use crate::encrypt_instructions::{decrypt_instructions, encrypt_instructions};
// use crate::unitest_baacc2d::*;
// use crate::test_glwe::glwe_ciphertext_add;
// use tfhe::core_crypto::algorithms::lwe_private_functional_packing_keyswitch::private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext;
// use tfhe::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
// use tfhe::shortint::parameters::{PARAM_MESSAGE_3_CARRY_0, PARAM_MESSAGE_3_CARRY_0_KS_PBS, PARAM_MESSAGE_3_CARRY_1, PARAM_MESSAGE_4_CARRY_0};
// use crate::blind_array_access_2d::blind_array_access2d;
// use crate::blind_insertion::blind_insertion;
// use crate::blind_permutation::blind_permutation;
// use crate::blind_pop::blind_pop;
// use crate::blind_push::blind_push;
// use crate::blind_retrieve::blind_retrieve;
// use crate::headers::{Context, LUT, PrivateKey, PublicKey};
// use crate::helpers::{bootstrap_glwe_LUT, bootstrap_glwe_LUT_with_actual_bootstrap, generate_accumulator_via_vector, LWEaddu64, negacycle_vector, one_lwe_to_lwe_ciphertext_list};
// use crate::private_insert::private_insert;


// use revolut::{Context,PrivateKey,PublicKey,LUT,LUTStack};
// use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;
// use crate::OTM::{change_head_position, get_new_state, OTM, read_cell_content, write_new_cell_content};


mod oblivious_tm;
use oblivious_tm::*;


pub fn main() {
    oblivious_tm(); // from oblivious_tm.rs
    
}
