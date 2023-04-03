use aligned_vec::ABox;
use num_complex::Complex;
use tfhe::boolean::parameters;
use tfhe::{core_crypto::prelude::*, shortint::server_key::Accumulator};
use tfhe::shortint::prelude::*;
use std::time::{Instant, Duration};
use concrete_csprng::generators::NeonAesRandomGenerator;





pub struct Params{
    pub(crate) parameters : Parameters,
    pub big_lwe_dimension : LweDimension,
    pub delta : u64,
}

impl Params {
    pub fn from(parameters : Parameters) -> Params {
        let big_lwe_dimension = LweDimension(parameters.polynomial_size.0);
        let delta = (1u64 << 63 ) / (parameters.message_modulus.0 * parameters.carry_modulus.0) as u64;
        Params{
            big_lwe_dimension,
            delta,
            parameters,
        }
    }

    pub fn small_lwe_dimension(&self) -> LweDimension {
        self.parameters.lwe_dimension
    }
    
    // pas necessaire
    pub fn big_lwe_dimension(&self) -> LweDimension {
        self.big_lwe_dimension
    }
    
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.parameters.glwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.parameters.polynomial_size
    }

    pub fn lwe_modular_std_dev(&self) -> StandardDev {
        self.parameters.lwe_modular_std_dev
    }

    pub fn glwe_modular_std_dev(&self) -> StandardDev {
        self.parameters.glwe_modular_std_dev
    }

    pub fn pbs_base_log(&self) -> DecompositionBaseLog {
        self.parameters.pbs_base_log
    }

    pub fn pbs_level(&self) -> DecompositionLevelCount {
        self.parameters.pbs_level
    }

    pub fn ks_level(&self) -> DecompositionLevelCount {
        self.parameters.ks_level
    }

    pub fn ks_base_log(&self) -> DecompositionBaseLog {
        self.parameters.ks_base_log
    }

    pub fn pfks_level(&self) -> DecompositionLevelCount {
        self.parameters.pfks_level
    }

    pub fn pfks_base_log(&self) -> DecompositionBaseLog {
        self.parameters.pfks_base_log
    }

    pub fn pfks_modular_std_dev(&self) -> StandardDev {
        self.parameters.pfks_modular_std_dev
    }

    pub fn message_modulus(&self) -> MessageModulus {
        self.parameters.message_modulus
    }

    pub fn carry_modulus(&self) -> CarryModulus {
        self.parameters.carry_modulus
    }


    // pas nécessaire 
    pub fn delta(&self) -> u64 {
        self.delta
    }

}


pub struct PublicKey {
    pub lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    pub fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    pub pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>
}

impl PublicKey {
    pub fn get_from(private_key : &PrivateKey) -> PublicKey{
        PublicKey { 
            lwe_ksk: private_key.lwe_ksk,
            fourier_bsk: private_key.fourier_bsk,
            pfpksk: private_key.pfpksk }
    }
    pub fn get_lwe_ksk(self) -> LweKeyswitchKey<Vec<u64>>{
        self.lwe_ksk
    }
    pub fn get_fourrier_bsk(self) -> FourierLweBootstrapKey<ABox<[Complex<f64>]>>{
        self.fourier_bsk
    }
    pub fn get_pfpksk(self) -> LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>{
        self.pfpksk
    }
    
}


pub struct PrivateKey<'a>{

    small_lwe_sk: LweSecretKey<Vec<u64>>,
    big_lwe_sk: LweSecretKey<Vec<u64>>,
    glwe_sk: GlweSecretKey<Vec<u64>>,
    pub lwe_ksk: LweKeyswitchKey<Vec<u64>>,
    pub fourier_bsk: FourierLweBootstrapKey<ABox<[Complex<f64>]>>,
    pub pfpksk: LwePrivateFunctionalPackingKeyswitchKey<Vec<u64>>,
    encryption_generator: &'a EncryptionRandomGenerator::<ActivatedRandomGenerator>

}

impl PrivateKey<'_> {

    /// Generate a PrivateKey which contain also the PublicKey
    ///
    /// # Example
    ///
    /// ```rust
    /// // Generate the keys and get them in different variables:
    /// let parameters = Params::new(PARAM_MESSAGE_2_CARRY_2)
    /// let private_key = PrivateKey::new(&parameters);
    /// ```
    ///
    pub fn new(parameters: &Params) -> PrivateKey {
        
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
            &EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
    
    
        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(parameters.small_lwe_dimension(), &mut secret_generator);
    
        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk =
            GlweSecretKey::generate_new_binary(parameters.glwe_dimension(), parameters.polynomial_size(), &mut secret_generator);
    
        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
    
        // Generate the bootstrapping key, we use the parallel variant for performance reason
        let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
            &small_lwe_sk,
            &glwe_sk,
            parameters.pbs_base_log(),
            parameters.pbs_level(),
            parameters.glwe_modular_std_dev(),
            &mut encryption_generator,
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
            parameters.ks_base_log(),
            parameters.ks_level(),
            parameters.big_lwe_dimension(),
            parameters.small_lwe_dimension(),
        );
        generate_lwe_keyswitch_key(
            &big_lwe_sk,
            &small_lwe_sk,
            &mut lwe_ksk,
            parameters.lwe_modular_std_dev(),
            &mut encryption_generator,
        );
    
        // Create Packing Key Switch
    
        let mut pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
            0,
            parameters.pfks_base_log(),
            parameters.pfks_level(),
            parameters.small_lwe_dimension(),
            parameters.glwe_dimension().to_glwe_size(),
            parameters.polynomial_size(),
        );

        // Here there is some freedom for the choice of the last polynomial from algorithm 2
        // By convention from the paper the polynomial we use here is the constant -1
        let mut last_polynomial = Polynomial::new(0, parameters.polynomial_size());
        // Set the constant term to u64::MAX == -1i64
        last_polynomial[0] = u64::MAX;
        // Generate the LWE private functional packing keyswitch key
        par_generate_lwe_private_functional_packing_keyswitch_key(
            &small_lwe_sk,
            &glwe_sk,
            &mut pfpksk,
            parameters.pfks_modular_std_dev(),
            &mut encryption_generator,
            |x| x,
            &last_polynomial,
        );

        PrivateKey{
            small_lwe_sk,
            big_lwe_sk,
            glwe_sk,
            lwe_ksk,
            fourier_bsk,
            pfpksk,
            encryption_generator: &encryption_generator
        }
    }

    pub fn get_small_lwe_sk(&self) -> LweSecretKey<Vec<u64>>{
        self.small_lwe_sk
    }

    pub fn get_big_lwe_sk(&self) -> LweSecretKey<Vec<u64>>{
        self.big_lwe_sk
    }

    pub fn get_glwe_sk(&self) -> GlweSecretKey<Vec<u64>>{
        self.glwe_sk
    }

    pub fn get_mut_encryption_generator(&self) -> &mut EncryptionRandomGenerator<ActivatedRandomGenerator>{
        &mut &self.encryption_generator
    }

    pub fn get_mut_encryption_generator_2(&self) -> &EncryptionRandomGenerator<ActivatedRandomGenerator>{
        self.encryption_generator
    }

    // pub fn get_mut_encryption_generator_via_ref(self) -> &EncryptionRandomGenerator<ActivatedRandomGenerator>{
    //     &mut &self.encryption_generator
    // }
    
    

}


