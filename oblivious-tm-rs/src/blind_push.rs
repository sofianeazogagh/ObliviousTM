use std::time::Instant;
use std::vec;

use rayon::prelude::*;

use tfhe::boolean::public_key;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::PARAM_MESSAGE_4_CARRY_0;

#[path = "./headers.rs"] mod headers;
use self::headers::PrivateKey;
use self::headers::PublicKey;
use self::headers::Context;
use self::headers::LUT;
use self::headers::LUTStack;



pub fn blind_push(){


    // Create Context and generate key
    let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
    let private_key =  PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


   
    let original_array = vec![2,4,6,8];
    println!("Original array : {:?} ",original_array );

    let push_u64 = 3_u64;

    let lut_push = LUTStack::from_vec(&original_array, &private_key, &mut ctx);
    let lwe_push = private_key.allocate_and_encrypt_lwe(push_u64, &mut ctx);
    private_key.debug_glwe("lut :", &lut_push.lut.0, &ctx);

    let mut ct_16 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    trivially_encrypt_lwe_ciphertext(&mut ct_16, Plaintext(ctx.full_message_modulus() as u64 * ctx.delta()));
    private_key.debug_lwe("ct_16", &ct_16, &ctx);

    let start_push = Instant::now();

    let mut to_push = LUT::from_lwe(lwe_push, public_key, &ctx, false);
    private_key.debug_glwe("element to push :", &to_push.0, &ctx);


    let stack_len = lut_push.number_of_elements;
    let mut rotation = LweCiphertext::new(0_64,ctx.small_lwe_dimension().to_lwe_size());
    lwe_ciphertext_sub(&mut rotation, &ct_16, &stack_len); // rotation = 16 - index_to_push = - index_to_push 
    private_key.debug_lwe("rotation", &rotation, &ctx);
    blind_rotate_assign(&rotation, &mut to_push.0, &public_key.fourier_bsk);


    // Sum all the rotated glwe to get the final glwe permuted
    let result = _glwe_ciphertext_add(&lut_push.lut.0, &to_push.0 );

    private_key.debug_glwe("after Sum", &result, &ctx);


    let duration_push = start_push.elapsed();


    // verification by extracting lwe 
    let half_box_size = ctx.box_size() / 2;

    let mut result_push: Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    result_push.par_extend(
    (0..ctx.full_message_modulus())
        .into_par_iter()
        .map(|i| {
            let mut lwe_sample = LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size());
            extract_lwe_sample_from_glwe_ciphertext(
                &result,
                &mut lwe_sample,
                MonomialDegree((i*ctx.box_size() + half_box_size - 1) as usize),
            );
            // key switching
            let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
            keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut lwe_sample, &mut switched);
            switched
        }),
    );


    let mut result_push_u64 : Vec<u64> = Vec::new();
    for lwe in result_push{
        let pt = private_key.decrypt_lwe(&lwe, &mut ctx);
        result_push_u64.push(pt);
    }
    println!("Inserted array : {:?} ",result_push_u64 );



    println!("Time insertion : {:?}",duration_push);


}






fn one_lut_to_many_lut(lut: LUT, public_key: &PublicKey, ctx: &Context) -> Vec<LUT> {
    let many_lwe = lut.to_many_lwe(public_key, ctx);

    // Many-Lwe to Many-Glwe
    let mut many_glwe : Vec<LUT> = Vec::new();
    for lwe in many_lwe{
        let mut glwe = GlweCiphertext::new(0_u64,ctx.glwe_dimension().to_glwe_size(),ctx.polynomial_size());
        let redundancy_lwe = one_lwe_to_lwe_ciphertext_list(lwe, ctx);
        private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
            &public_key.pfpksk,
            &mut glwe,
            &redundancy_lwe);
        many_glwe.push(LUT(glwe));
    }
    many_glwe
}








fn one_lwe_to_lwe_ciphertext_list(
    input_lwe: LweCiphertext<Vec<u64>>,
    ctx : &Context
) 
-> LweCiphertextList<Vec<u64>> 
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.

    let redundant_lwe = vec![input_lwe.into_container();ctx.box_size()].concat();
    let lwe_ciphertext_list =  LweCiphertextList::from_container(
        redundant_lwe,
        ctx.small_lwe_dimension().to_lwe_size());
    

    lwe_ciphertext_list
}




pub fn _glwe_ciphertext_add(
    ct1 : &GlweCiphertext<Vec<u64>>,
    ct2 : &GlweCiphertext<Vec<u64>>,
)
-> GlweCiphertext<Vec<u64>>
{
    let mut res = GlweCiphertext::new(0_u64, ct1.glwe_size(), ct1.polynomial_size());

    res.as_mut().iter_mut()
    .zip(
        ct1.as_ref().iter().zip(ct2.as_ref().iter())
        ).for_each(|(dst, (&lhs, &rhs))| *dst = lhs.wrapping_add(rhs));
    return res; 
}



pub fn leq_scalar(
    ct_input: &LweCiphertext<Vec<u64>>,
    scalar : u64,
    public_key : &PublicKey,
    ctx : &Context
) -> LweCiphertext<Vec<u64>> 
{

    let cmp_scalar_accumulator = LUT::from_function(|x| (x <= scalar as u64) as u64, ctx);
    let mut res_cmp = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size());
    programmable_bootstrap_lwe_ciphertext(
        &ct_input,
        &mut res_cmp,
        &cmp_scalar_accumulator.0,
        &public_key.fourier_bsk,
    );
    let mut switched = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size());
    keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &mut res_cmp, &mut switched);

    switched
}





#[cfg(test)]
mod test{

    use super::*;

    #[test]
    fn test_blind_push(){

            blind_push();
        
    }
}