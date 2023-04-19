use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::boolean::public_key;
use tfhe::{core_crypto::prelude::*};
use tfhe::shortint::{prelude::*, parameters};


// #[derive(Debug,Clone)]

pub struct Context{
    parameters : Parameters,
    big_lwe_dimension : LweDimension,
    delta : u64,
    full_message_modulus : usize,
    signed_decomposer : SignedDecomposer<u64>,
    encryption_generator : EncryptionRandomGenerator<ActivatedRandomGenerator>,
    secret_generator : SecretRandomGenerator<ActivatedRandomGenerator>
}

impl Context {
    pub fn from(parameters : Parameters) -> Context {
        let big_lwe_dimension = LweDimension(parameters.polynomial_size.0);
        let delta = (1u64 << 63 ) / (parameters.message_modulus.0 * parameters.carry_modulus.0) as u64;
        let full_message_modulus = parameters.message_modulus.0 * parameters.carry_modulus.0;
        let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1)); // a changer peut-être pour les autres params

        // Request the best seeder possible, starting with hardware entropy sources and falling back to
        // /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
        let seeder = boxed_seeder.as_mut();
    
        // Create a generator which uses a CSPRNG to generate secret keys
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    
        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);


        Context{
            parameters,
            big_lwe_dimension,
            delta,
            full_message_modulus,
            signed_decomposer,
            secret_generator,
            encryption_generator
        }
    }

    // getters for each (private) parameters
    pub fn small_lwe_dimension(&self) -> LweDimension {self.parameters.lwe_dimension}
    pub fn big_lwe_dimension(&self) -> LweDimension {self.big_lwe_dimension}
    pub fn glwe_dimension(&self) -> GlweDimension {self.parameters.glwe_dimension}
    pub fn polynomial_size(&self) -> PolynomialSize {self.parameters.polynomial_size}
    pub fn lwe_modular_std_dev(&self) -> StandardDev {self.parameters.lwe_modular_std_dev}
    pub fn glwe_modular_std_dev(&self) -> StandardDev {self.parameters.glwe_modular_std_dev}
    pub fn pbs_base_log(&self) -> DecompositionBaseLog {self.parameters.pbs_base_log}
    pub fn pbs_level(&self) -> DecompositionLevelCount {self.parameters.pbs_level}
    pub fn ks_level(&self) -> DecompositionLevelCount {self.parameters.ks_level}
    pub fn ks_base_log(&self) -> DecompositionBaseLog {self.parameters.ks_base_log}
    pub fn pfks_level(&self) -> DecompositionLevelCount {self.parameters.pfks_level}
    pub fn pfks_base_log(&self) -> DecompositionBaseLog {self.parameters.pfks_base_log}
    pub fn pfks_modular_std_dev(&self) -> StandardDev {self.parameters.pfks_modular_std_dev}
    pub fn message_modulus(&self) -> MessageModulus {self.parameters.message_modulus}
    pub fn carry_modulus(&self) -> CarryModulus {self.parameters.carry_modulus}
    pub fn delta(&self) -> u64 {self.delta}
    pub fn full_message_modulus(&self) -> usize {self.full_message_modulus}



}

pub struct PrivateKey{
    small_lwe_sk: LweSecretKey<Vec<u64>>,
    big_lwe_sk: LweSecretKey<Vec<u64>>,
    glwe_sk: GlweSecretKey<Vec<u64>>,
    public_key : PublicKey,
    // lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    // fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    // pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>
}

impl PrivateKey{

    /// Generate a PrivateKey which contain also the PublicKey
    ///
    /// # Example
    ///
    /// ```rust
    /// // Generate the keys and get them in different variables:
    /// let mut ctx = Context::new(PARAM_MESSAGE_2_CARRY_2)
    /// let private_key = PrivateKey::new(&ctx);
    /// ```
    ///
    pub fn new(ctx: &mut Context) -> PrivateKey {
        
    
        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(ctx.small_lwe_dimension(), &mut ctx.secret_generator);
    
        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk =
            GlweSecretKey::generate_new_binary(ctx.glwe_dimension(), ctx.polynomial_size(), &mut ctx.secret_generator);
    
        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    
        // Generate the bootstrapping key, we use the parallel variant for performance reason
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            ctx.pbs_base_log(),
            ctx.pbs_level(),
            ctx.glwe_modular_std_dev(),
            &mut ctx.encryption_generator,
        );


        // Create the empty bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            std_bootstrapping_key.input_lwe_dimension(),
            std_bootstrapping_key.glwe_size(),
            std_bootstrapping_key.polynomial_size(),
            std_bootstrapping_key.decomposition_base_log(),
            std_bootstrapping_key.decomposition_level_count(),
        );
    
        // Use the conversion function (a memory optimized version also exists but is more complicated
        // to use) to convert the standard bootstrapping key to the Fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
        // We don't need the standard bootstrapping key anymore
        drop(std_bootstrapping_key);
    
    
        let mut lwe_ksk = LweKeyswitchKey::new(
            0u64,
            ctx.ks_base_log(),
            ctx.ks_level(),
            ctx.big_lwe_dimension(),
            ctx.small_lwe_dimension(),
        );
        generate_lwe_keyswitch_key(
            &big_lwe_sk,
            &small_lwe_sk,
            &mut lwe_ksk,
            ctx.lwe_modular_std_dev(),
            &mut ctx.encryption_generator,
        );
    
        // Create Packing Key Switch
    
        let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            0,
            ctx.pfks_base_log(),
            ctx.pfks_level(),
            ctx.small_lwe_dimension(),
            ctx.glwe_dimension().to_glwe_size(),
            ctx.polynomial_size(),
        );

        // Here there is some freedom for the choice of the last polynomial from algorithm 2
        // By convention from the paper the polynomial we use here is the constant -1
        let mut last_polynomial = Polynomial::new(0, ctx.polynomial_size());
        // Set the constant term to u64::MAX == -1i64
        last_polynomial[0] = u64::MAX;
        // Generate the LWE private functional packing keyswitch key
        par_generate_lwe_private_functional_packing_keyswitch_key(
            &small_lwe_sk,
            &glwe_sk,
            &mut pfpksk,
            ctx.pfks_modular_std_dev(),
            &mut ctx.encryption_generator,
            |x| x,
            &last_polynomial,
        );


        let public_key = PublicKey{
            lwe_ksk,
            fourier_bsk,
            pfpksk
        };


        

        PrivateKey{
            small_lwe_sk,
            big_lwe_sk,
            glwe_sk,
            public_key
            // lwe_ksk,
            // fourier_bsk,
            // pfpksk
        }
    }

    // getters for each attribute
    pub fn get_small_lwe_sk(&self) -> &LweSecretKey<Vec<u64>>{&self.small_lwe_sk}
    pub fn get_big_lwe_sk(&self) -> &LweSecretKey<Vec<u64>>{&self.big_lwe_sk}
    pub fn get_glwe_sk(&self) -> &GlweSecretKey<Vec<u64>>{&self.glwe_sk}
    pub fn get_public_key(&self) -> &PublicKey{&self.public_key}


    pub fn allocate_and_encrypt_lwe(&self, input : u64, ctx: &mut Context ) -> LweCiphertext<Vec<u64>> {

        let plaintext = Plaintext(ctx.delta()*input);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &self.small_lwe_sk,
        plaintext,
        ctx.lwe_modular_std_dev(),
        &mut ctx.encryption_generator,
    );
    lwe_ciphertext
    }

    pub fn decrypt_lwe(&self, ciphertext : &LweCiphertext<Vec<u64>>, ctx: &mut Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&self.small_lwe_sk, &ciphertext);
        let result: u64 =
        ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        result
    }

    pub fn decrypt_lwe_big_key(&self, ciphertext : &LweCiphertext<Vec<u64>>, ctx: &mut Context) -> u64 {
        // Decrypt the PBS multiplication result
        let plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&self.big_lwe_sk, &ciphertext);
        let result: u64 =
        ctx.signed_decomposer.closest_representable(plaintext.0) / ctx.delta();
        result
    }

    pub fn allocate_and_encrypt_glwe(&self, pt_list : PlaintextList<Vec<u64>>, ctx: &mut Context) -> GlweCiphertext<Vec<u64>> {
        let mut output_glwe = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size());
        encrypt_glwe_ciphertext(
            self.get_glwe_sk(),
            &mut output_glwe,
            &pt_list,
            ctx.glwe_modular_std_dev(),
            &mut ctx.encryption_generator,
        );
        output_glwe   
    }

    pub fn encrypt_glwe(&self, output_glwe: &mut GlweCiphertext<Vec<u64>>, pt : PlaintextList<Vec<u64>>, ctx: &mut Context){
        encrypt_glwe_ciphertext(
            self.get_glwe_sk(),
            output_glwe,
            &pt,
            ctx.glwe_modular_std_dev(),
            &mut ctx.encryption_generator,
        );
    }

    fn decrypt_and_decode_glwe(&self, input_glwe : GlweCiphertext<Vec<u64>>, ctx: &Context ) -> Vec<u64>{
        let mut plaintext_res = PlaintextList::new(0, PlaintextCount(ctx.polynomial_size().0));
        decrypt_glwe_ciphertext(&self.glwe_sk, &input_glwe, &mut plaintext_res);
    
        // To round our 4 bits of message
        // In the paper we return the complicated sum times -1, so here we invert that -1, otherwise we
        // could apply the wrapping_neg on our function and remove it here
        let decoded: Vec<_> = plaintext_res
            .iter()
            .map(|x| (ctx.signed_decomposer.closest_representable(*x.0) / ctx.delta).wrapping_neg() % ctx.full_message_modulus() as u64)
            .collect();

        decoded
        
    }




  
}





pub struct PublicKey {
    pub lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    pub fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    pub pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>
}



impl PublicKey{

    pub fn wrapping_neg_lwe(&self, lwe : &mut LweCiphertext<Vec<u64>>,)
    {
        for ai in lwe.as_mut(){
            *ai = (*ai).wrapping_neg();
        }
    }
}



pub struct LUT(pub(crate) GlweCiphertext<Vec<u64>>);


impl LUT {

    pub fn add_redundancy_many_u64(vec : &Vec<u64>, ctx : &Context) -> Vec<u64> {

        // N/(p/2) = size of each block, to correct noise from the input we introduce the notion of
        // box, which manages redundancy to yield a denoised value for several noisy values around
        // a true input value.
        let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus();

        // Create the output
        let mut accumulator_u64 = vec![0_u64; ctx.polynomial_size().0];

        // Fill each box with the encoded denoised value
        for i in 0..vec.len() {
            let index = i * box_size;
            for j in index..index + box_size {
                accumulator_u64[j] = vec[i] * ctx.delta() as u64;
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

    pub fn from_vec(vec : &Vec<u64>, private_key : &PrivateKey, ctx : &mut Context) -> LUT {

        let mut lut_as_glwe = GlweCiphertext::new(0_u64, ctx.glwe_dimension().to_glwe_size() , ctx.polynomial_size());
        let redundant_lut = Self::add_redundancy_many_u64(vec, ctx);
        let accumulator_plaintext = PlaintextList::from_container(redundant_lut);
        private_key.encrypt_glwe(&mut lut_as_glwe, accumulator_plaintext, ctx);
        LUT(lut_as_glwe)

    }


    fn add_redundancy_many_lwe(many_lwe : Vec<LweCiphertext<Vec<u64>>>, public_key : &PublicKey, ctx : &Context) -> Vec<LweCiphertext<Vec<u64>>>{

        let box_size = ctx.polynomial_size().0 / ctx.full_message_modulus();
        // Create the vector which will contain the redundant lwe
        let mut redundant_many_lwe : Vec<LweCiphertext<Vec<u64>>> = Vec::new();
        let ct_0 = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size());

        let size_many_lwe = many_lwe.len();
        // Fill each box with the encoded denoised value
        for i in 0..size_many_lwe{ 
            let index = i * box_size;
            for j in index..index + box_size {
                    redundant_many_lwe.push(many_lwe[i].clone());
            }
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients to manage negacyclicity and rotate
        for a_i in redundant_many_lwe[0..half_box_size].iter_mut() {
            public_key.wrapping_neg_lwe(a_i);
        }
        redundant_many_lwe.resize(ctx.full_message_modulus()*box_size, ct_0);
        redundant_many_lwe.rotate_left(half_box_size);
        redundant_many_lwe
        
    }


    pub fn from_vec_of_lwe(many_lwe : Vec<LweCiphertext<Vec<u64>>>, public_key : &PublicKey, ctx : &Context) -> LUT{

    let many_lwe_as_accumulator = Self::add_redundancy_many_lwe(many_lwe, public_key, ctx);
    let mut lwe_container : Vec<u64> = Vec::new();
    for ct in many_lwe_as_accumulator{
        let mut lwe = ct.into_container();
        lwe_container.append(&mut lwe);
    }
    let lwe_ciphertext_list =  LweCiphertextList::from_container(lwe_container,ctx.small_lwe_dimension().to_lwe_size());

    // Prepare our output GLWE in which we pack our LWEs
    let mut glwe = GlweCiphertext::new(0, ctx.glwe_dimension().to_glwe_size(), ctx.polynomial_size());
    

    // Keyswitch and pack
    private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
        &public_key.pfpksk,
        &mut glwe,
        &lwe_ciphertext_list,
    );
    LUT(glwe)

    }


}








#[cfg(test)]

mod test{


    // use tfhe::core_crypto::prelude::*;
    use tfhe::shortint::{parameters::PARAM_MESSAGE_4_CARRY_0, public_key};

    use super::*;

    #[test]
    fn test_lwe_enc(){
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let input : u64 = 3;
        let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        assert_eq!(input,clear);
    }


    #[test]
    fn test_lut_enc(){
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let array = vec![0,1,2,3,4];
        let lut = LUT::from_vec(&array, &private_key, &mut ctx);
    }


    #[test]
    fn test_neg_lwe(){
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let input : u64 = 3;
        let mut lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
        public_key.wrapping_neg_lwe(&mut lwe);
        let clear = private_key.decrypt_lwe(&lwe, &mut ctx);
        println!("Test encryption-decryption");
        println!("neg_lwe = {}", clear);
        // assert_eq!(input,16-clear);
    }

    #[test]
    fn test_many_lwe_to_glwe(){
        let mut ctx = Context::from(PARAM_MESSAGE_4_CARRY_0);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;
        let our_input : Vec<u64> = vec![1,2,3,15];
        let mut many_lwe : Vec<LweCiphertext<Vec<u64>>> = vec![];
        for input in our_input {
            let lwe = private_key.allocate_and_encrypt_lwe(input, &mut ctx);
            many_lwe.push(lwe);
        }
        let lut = LUT::from_vec_of_lwe(many_lwe, public_key, &ctx);
        let output_pt =  private_key.decrypt_and_decode_glwe(lut.0, &ctx);
        println!("Test many LWE to one GLWE");
        println!("{:?}", output_pt);

    }
    

}