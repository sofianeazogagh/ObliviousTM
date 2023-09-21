use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



pub fn oblivious_tm()
{
    //The number of steps our Turing Machine will run.

    let step = 10;
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![1,2,1,2];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(6_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    tape.print(&private_key, &ctx);

    print!("Tape Encrypted");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    println!("State Encrypted");



    let instruction_write = vec![
        vec![0, 0, 1, 0, 1, 0, 0],
        vec![0, 0, 7, 0, 7, 0, 0],
        vec![0, 0, 0, 0, 1, 0, 0],
    ];

    // let instruction_position = vec![
    //     vec![1, 1, 15, 15, 1, 1, 0],
    //     vec![1, 1, 15, 15, 15, 1, 0],
    //     vec![1, 15, 1, 15, 1, 1, 0],
    // ];

    // POUR FAIRE QUE LA BANDE TOURNE À GAUCHE IL FAUT METTRE 32 - RATATE_LEFT
    let instruction_position = vec![
        vec![1, 1, 7, 7, 1, 1, 30],
        vec![1, 1, 7, 7, 7, 1, 30],
        vec![1, 7, 1, 7, 1, 1, 30],
    ];
    

    let instruction_state = vec![
        vec![0, 1, 2, 3, 0, 5, 6],
        vec![0, 1, 3, 3, 4, 5, 6],
        vec![1, 2, 5, 4, 0, 6, 6],
    ];



    let ct_instruction_write = private_key.encrypt_matrix(&mut ctx, &instruction_write);
    let ct_instruction_position = private_key.encrypt_matrix(&mut ctx, &instruction_position);
    let ct_instruction_state = private_key.encrypt_matrix(&mut ctx, &instruction_state);

    println!("Instructions Encrypted");
    // private_key.debug_glwe("Tape glwe", &tape.0, &ctx);

    println!("Oblivious TM Start..");
    for i in 0..step {

        println!("--- STEP {} ",i);


        // tape.print(&private_key,&mut ctx);
        // private_key.debug_glwe("Tape before writing", &tape.0, &ctx);
        let cell_content = read_cell_content(&tape, &public_key, &ctx);

        private_key.debug_lwe("State ", &state, &ctx);
        private_key.debug_lwe("Cell content", &cell_content, &ctx);
        


        write_new_cell_content(&tape, &cell_content, &state, &ct_instruction_write, public_key, &ctx); // ecris 0 - 7 - 0 - 0
        tape.print(&private_key, &ctx);
        // private_key.debug_glwe("Tape after writing", &tape.0, &ctx);
        change_head_position(&mut tape, &cell_content, &state, &ct_instruction_position, public_key, &ctx); // rotate de 1 - 7 - 0 - 0
        tape.print(&private_key, &ctx);
        // private_key.debug_glwe("Tape head's changed", &tape.0, &ctx);
        state = get_new_state(&cell_content, &state, &ct_instruction_state, public_key, &ctx); // 1 - 3 - 0 - 6 -
        tape.print(&private_key, &ctx);
        // private_key.debug_lwe("new state", &state, &ctx);


    }



}




pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context
) -> LweCiphertext<Vec<u64>> 
{
    // let mut cell_content = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    // extract_lwe_sample_from_glwe_ciphertext(&tape.0, &mut cell_content, MonomialDegree(0));
    // let mut switched = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    // keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &cell_content, &mut switched);

    let mut ct_0 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);
    return cell_content;
}



pub fn write_new_cell_content(
    tape: &LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_write: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
)
{


    let new_cell_content = public_key.blind_matrix_access(&ct_instruction_write, &state, &cell_content, &ctx);
    let lut_new_cell_content = LUT::from_lwe(&new_cell_content,&public_key,&ctx);
    public_key.glwe_sum(&tape.0, &lut_new_cell_content.0);
}



pub fn change_head_position(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_position: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
)
{

    let position_change = public_key.blind_matrix_access(&ct_instruction_position,&state , &cell_content, &ctx);
    blind_rotate_assign(&position_change, &mut tape.0, &public_key.fourier_bsk);

}

pub fn get_new_state(
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_state: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
) -> LweCiphertext<Vec<u64>>
{

    let new_state = public_key.blind_matrix_access(&ct_instruction_state, &state, &cell_content, &ctx);
    return new_state
}