use tfhe::{core_crypto::prelude::*, shortint::server_key::Accumulator};
use tfhe::shortint::prelude::*;
use std::time::{Instant, Duration};

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
            allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext);

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

    let ct_0 = LweCiphertext::new(0_64, lwe_dimension.to_lwe_size());

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
{
    let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);
    let mut accumulator = GlweCiphertext::new(0, glwe_size, polynomial_size);
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
        allocate_and_trivially_encrypt_new_glwe_ciphertext(glwe_size, &accumulator_plaintext);

    accumulator
}


pub fn scalar_greater(
    cmp_scalar_accumulator : GlweCiphertextOwned<u64>,
    big_lwe_dimension : LweDimension,
    ct_input: LweCiphertext<Vec<u64>>,
    fourier_bsk: FourierLweBootstrapKey<aligned_vec::ABox<[num_complex::Complex<f64>]>>
) -> LweCiphertext<Vec<u64>> 
{

    let mut res_cmp =
        LweCiphertext::new(0u64, big_lwe_dimension.to_lwe_size()
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