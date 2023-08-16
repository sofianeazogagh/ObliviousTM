use tfhe::{core_crypto::prelude::*};
use tfhe::shortint::prelude::*;
use tfhe::shortint::prelude::CiphertextModulus;
use std::time::{Instant, Duration};
use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::shortint::ciphertext::Degree;
use tfhe::shortint::server_key::ShortintBootstrappingKey;
use tfhe::shortint::server_key::ShortintBootstrappingKey::Classic;
use crate::headers::{Context, LUT, PrivateKey,PublicKey};
use crate::test_glwe::glwe_ciphertext_add;


pub fn generate_accumulator<F>(
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        message_modulus: usize,
        delta: u64,
        f: F,
    ) -> GlweCiphertextOwned<u64>
        where
            F: Fn(u64) -> u64,
    {
        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = polynomial_size.0 / message_modulus;
        let ciphertext_modulus = CiphertextModulus::new_native();
        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

        // Fill each box with the encoded denoised value
        for i in 0..message_modulus {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64)* delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator =
            allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext,ciphertext_modulus,);

        accumulator
        
}



// Here we will define a helper function to generate an accumulator for a PBS
pub fn generate_accumulator_via_vector_of_ciphertext(
    polynomial_size: PolynomialSize,
    lwe_dimension : LweDimension,
    message_modulus: usize,
    many_lwe: Vec<LweCiphertext<Vec<u64>>>,
    _delta: u64,
)  -> Vec<LweCiphertext<Vec<u64>>>
    where
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut output_vec : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    let ciphertext_modulus = CiphertextModulus::new_native();
    let ct_0 = LweCiphertext::new(0_64, lwe_dimension.to_lwe_size(),ciphertext_modulus,);

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus { //many_lwe.len()
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for _j in index..index + box_size {
            if i < many_lwe.len() {
                output_vec.push(many_lwe[i].clone());
            }else {
                output_vec.push(ct_0.clone());
            }
        }
    }

    let half_box_size = box_size / 2;

    output_vec.rotate_left(half_box_size);

    output_vec
}


pub fn encrypt_accumulator_as_glwe_ciphertext(
    glwe_secret_key: &GlweSecretKeyOwned<u64>,
    noise: impl DispersionParameter,
    encryption_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    accumulator_u64: Vec<u64>,
) ->GlweCiphertext<Vec<u64>>
    where
{   let ciphertext_modulus = CiphertextModulus::new_native();
    let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
    let mut accumulator = GlweCiphertext::new(0, glwe_size, polynomial_size,ciphertext_modulus,);
    encrypt_glwe_ciphertext(
        glwe_secret_key,
        &mut accumulator,
        &accumulator_plaintext,
        noise,
        encryption_generator,
    );
    accumulator
}

// Here we will define a helper function to generate an accumulator for a PBS
pub fn generate_accumulator_via_vector(
    polynomial_size: PolynomialSize,
    message_modulus: usize,
    delta: u64,
    f: Vec<u64>,
)  -> Vec<u64>
    where
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..f.len() {
        let index = i * box_size;
        // accumulator_u64[index..index + box_size].iter_mut().for_each(|a| *a = f(i as u64) * delta);
        for j in index..index + box_size {
            accumulator_u64[j] = f[i] * delta as u64;
        }
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    accumulator_u64
}


pub fn generate_accumulator_bivariate<F>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    delta: u64,
    f: F,
) -> GlweCiphertextOwned<u64>
    where
        F: Fn(u64,u64) -> u64,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
    // box, which manages redundancy to yield a denoised value for several noisy values around
    // a true input value.
    let box_size = polynomial_size.0 / message_modulus;
    let ciphertext_modulus = CiphertextModulus::new_native();
    let wrapped_f = |input: u64| -> u64 {
        let lhs = (input / message_modulus as u64) % message_modulus as u64;
        let rhs = input % message_modulus as u64;

        f(lhs, rhs)
    };

    // Create the accumulator
    let mut accumulator_u64 = vec![0_u64; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_u64[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = wrapped_f(i as u64) * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

    let accumulator =
        allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext,ciphertext_modulus,);

    accumulator
}


pub fn scalar_greater(
    cmp_scalar_accumulator : GlweCiphertextOwned<u64>,
    big_lwe_dimension : LweDimension,
    ct_input: LweCiphertext<Vec<u64>>,
    fourier_bsk: FourierLweBootstrapKey<aligned_vec::ABox<[num_complex::Complex<f64>]>>
) -> LweCiphertext<Vec<u64>> 
{
    let ciphertext_modulus = CiphertextModulus::new_native();
    let mut res_cmp =
        LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size(),ciphertext_modulus,
        );
    println!("Computing PBS...");
    programmable_bootstrap_lwe_ciphertext(
        &ct_input, // a remplacer par la difference entre les deux ciphertext à comparer
        &mut res_cmp,
        &cmp_scalar_accumulator,
        &fourier_bsk,
    );
    res_cmp
}


pub fn greater_or_equal(
    cmp_accumulator : GlweCiphertextOwned<u64>,
    message_modulus: u64,
    big_lwe_dimension : LweDimension,
    mut ct_left: LweCiphertext<Vec<u64>>,
    ct_right: LweCiphertext<Vec<u64>>,
    fourier_bsk: FourierLweBootstrapKey<aligned_vec::ABox<[num_complex::Complex<f64>]>>,
    lwe_sk : LweSecretKey<Vec<u64>>,
    delta : u64,
    signed_decomposer : SignedDecomposer<u64>
) 
// -> LweCiphertext<Vec<u64>> 
{
    let ciphertext_modulus = CiphertextModulus::new_native();
    // Decrypt the PBS multiplication result
    let res_pt: Plaintext<u64> =
        decrypt_lwe_ciphertext(&lwe_sk, &ct_left);

    // Round and remove our encoding
    let res: u64 =
        signed_decomposer.closest_representable(res_pt.0) / delta;

    println!("lwe_ciphertext_cleartext_mul_assign(2, {}) = {}", message_modulus, res);
    
    lwe_ciphertext_cleartext_mul_assign(&mut ct_left, Cleartext(message_modulus - 1));

    // Decrypt the PBS multiplication result
    let res_pt: Plaintext<u64> =
        decrypt_lwe_ciphertext(&lwe_sk, &ct_left);

    // Round and remove our encoding
    let res: u64 =
        signed_decomposer.closest_representable(res_pt.0) / delta;

    println!("lwe_ciphertext_cleartext_mul_assign(2, {}) = {}", message_modulus, res);

    // lwe_ciphertext_add_assign(&mut ct_left, &ct_right);

    // let mut res_cmp =
    //     LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size()
    //     );
    // println!("Computing PBS...");
    // programmable_bootstrap_lwe_ciphertext(
    //     &ct_left, // a remplacer par la difference entre les deux ciphertext à comparer
    //     &mut res_cmp,
    //     &cmp_accumulator,
    //     &fourier_bsk,
    // );
    // res_cmp
}


pub fn encrypt_vec_of_LUT(array_2d:Vec<Vec<u64>>,
                          ctx:&mut Context,
                          private_key:&PrivateKey)
                          ->Vec<LUT>
where
{
    let mut vec_of_lut: Vec<LUT> = Vec::new();

    for f in array_2d {

        let lut = LUT::from_vec(&f, &private_key, ctx);
        vec_of_lut.push(lut);

    }

    return vec_of_lut
}

pub fn negacycle_vector(array_2d:Vec<Vec<u64>>,
                        ctx:&mut Context, ) ->Vec<Vec<u64>>
    where
{
    let mut result: Vec<Vec<u64>> = Vec::new();
    for f in array_2d {
        let mut list = Vec::new() as Vec<u64>;
        for i in 0..f.len(){
            list.push((ctx.full_message_modulus() as u64 - f[i] as u64) % ctx.full_message_modulus() as u64);
        }
        result.push(list);
    }
    println!("{:?}",result);
    return result
}

pub fn lwe_to_ciphertext(lwe :LweCiphertext<Vec<u64>>,ctx :&Context)->Ciphertext
{
    let result = Ciphertext{
        ct: lwe,
        degree: Degree(0 as usize),
        message_modulus: ctx.message_modulus(),
        carry_modulus: ctx.carry_modulus(),
        pbs_order: PBSOrder::KeyswitchBootstrap
    };
    result
}

pub fn extract_fourier(input :ShortintBootstrappingKey,ctx :&Context)->FourierLweBootstrapKey<ABox<[Complex<f64>]>>
{
    let test = FourierLweBootstrapKey::new(ctx.big_lwe_dimension(), ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.pbs_base_log(), ctx.pbs_level());
    match input {
    ShortintBootstrappingKey::Classic(FourierLweBootstrapKey) => return FourierLweBootstrapKey,
    other=> return test,
};
}

pub fn one_lwe_to_lwe_ciphertext_list(lwe:&LweCiphertext<Vec<u64>>,ctx:&Context)->LweCiphertextList<Vec<u64>>{

    let zero = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus()) as LweCiphertext<Vec<u64>>;
    let mut output = Vec::with_capacity(ctx.polynomial_size().0);
    for i in 0..ctx.box_size(){
        output.push(lwe.to_owned());
    }


    for i in ctx.box_size()..ctx.polynomial_size().0{
        output.push(zero.to_owned());
    }
    output.rotate_left(ctx.box_size()/2);
    let mut output_list = LweCiphertextList::new(0, ctx.small_lwe_dimension().to_lwe_size(),LweCiphertextCount(ctx.polynomial_size().0), ctx.ciphertext_modulus()) as LweCiphertextList<Vec<u64>>;
    for (mut dst,src) in output_list.iter_mut().zip(output.iter()){
        dst.as_mut().copy_from_slice(src.as_ref());
    }
    output_list
}

pub fn create_monomial(position_0:&LweCiphertext<Vec<u64>>,position_1:&LweCiphertext<Vec<u64>>,public_key:&PublicKey,ctx:&Context)->GlweCiphertext<Vec<u64>> {
    let mut position_last=LweCiphertext::new(1,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus()) as LweCiphertext<Vec<u64>>;
    lwe_ciphertext_sub_assign(&mut position_last,position_1);
    lwe_ciphertext_sub_assign(&mut position_last,position_0);

    let zero = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus()) as LweCiphertext<Vec<u64>>;


    let mut list = Vec::with_capacity(ctx.polynomial_size().0);
    list.push(position_0.to_owned());
    list.push(position_1.to_owned());
    for i in 0..ctx.polynomial_size().0-3{
        list.push(zero.to_owned());
    }
    list.push(position_last.to_owned());
    let mut output_list = LweCiphertextList::new(0, ctx.small_lwe_dimension().to_lwe_size(),LweCiphertextCount(ctx.polynomial_size().0), ctx.ciphertext_modulus()) as LweCiphertextList<Vec<u64>>;
    for (mut dst,src) in output_list.iter_mut().zip(list.iter()){
        dst.as_mut().copy_from_slice(src.as_ref());
    }

    let mut output: GlweCiphertext<Vec<u64>> = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());

    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&public_key.pfpksk, &mut output, &output_list);
    output

}

pub fn bootstrap_glwe_LUT(glwe: &GlweCiphertext<Vec<u64>>, public_key:&PublicKey, ctx :&Context) -> GlweCiphertext<Vec<u64>> {


    let box_size = ctx.polynomial_size().0 / ctx.message_modulus().0;

    // Create the accumulator
    let mut input_vec : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
    let mut ct_small = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus(),);
    let mut ct_big =LweCiphertext::new(0_64, ctx.big_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus(),);

    for i in 0..ctx.message_modulus().0 { //many_lwe.len()
        let index = i * box_size;
        extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut ct_big, MonomialDegree(index));
        keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &ct_big, &mut ct_small);

        input_vec.push(ct_small.to_owned());
    }

    let output_vec = generate_accumulator_via_vector_of_ciphertext(
        ctx.polynomial_size(),
        ctx.small_lwe_dimension() ,
        ctx.message_modulus().0,
        input_vec,
        ctx.delta()
    );


    let output_list = lwe_vec_to_list(&output_vec,&ctx);
    let mut output: GlweCiphertext<Vec<u64>> = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size(), ctx.ciphertext_modulus());
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&public_key.pfpksk, &mut output,&output_list);
    output

}

pub fn lwe_vec_to_list(lwe_vec :&Vec<LweCiphertext<Vec<u64>>>, ctx:&Context) -> LweCiphertextListOwned<u64> {
    let mut lwe_list =LweCiphertextList::new(0,ctx.small_lwe_dimension().to_lwe_size(),LweCiphertextCount(ctx.polynomial_size().0),ctx.ciphertext_modulus());
    for (mut dst,src) in lwe_list.iter_mut().zip(lwe_vec.iter()){
        dst.as_mut().copy_from_slice(src.as_ref());
    }
    lwe_list
}

pub fn LWEaddu64(lwe: &LweCiphertext<Vec<u64>>, constant: u64, mut ctx:&Context) -> LweCiphertextOwned<u64> {

    let mut constant_plain = Plaintext(constant*ctx.delta());

    let mut constant_lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(ctx.small_lwe_dimension().to_lwe_size(),constant_plain,ctx.ciphertext_modulus());
    let mut res = LweCiphertext::new(0,ctx.small_lwe_dimension().to_lwe_size(),ctx.ciphertext_modulus());

    lwe_ciphertext_add(&mut res,&constant_lwe,lwe);
    return res
}



