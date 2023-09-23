
const DEBUG: bool = false;

use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



pub fn oblivious_tm()
{
    //The number of steps our Turing Machine will run.

    let step = 7;
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![0,0,0,0];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(2_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    tape.print(&private_key, &ctx);

    print!("Tape Encrypted");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    println!("State Encrypted");




    // POUR FAIRE QUE LA BANDE TOURNE À GAUCHE IL FAUT METTRE 2*FULL_MOD - ROTATE_LEFT ? donc 31 dans le cas 4_0  


    // //// Multiplication par 2
    // let instruction_write = vec![
    //     vec![0,0,2], // pourquoi qd je lis 1 je fais 1 + 1 pour avoir 0 ? parce que je lis 15 (-1) et pas 1 donc il faut faire 15 + 1 = 16 = 0
    //     vec![0,0,0]

    // ];
    // let instruction_position = vec![ // mouvement de la tête à gauche = mouvement de la bande à droite = rotation de 31
    //     vec![1,1,0], // mouvement de la tête à droite = mouvement de la bande à gauche = rotation de 1
    //     vec![0,0,0]
    // ];
    // let instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,1,1]
    // ];





    // //// soustraire 1 
    // let instruction_write = vec![
    //     vec![0,0,0], // pourquoi qd je lis 1 je fais 1 + 1 pour avoir 0 ? parce que je lis 15 (-1) et pas 1 donc il faut faire 15 + 1 = 16 = 0
    //     vec![15,1,0],
    //     vec![0,0,0]

    // ];
    // let instruction_position = vec![ // mouvement de la tête à gauche = mouvement de la bande à droite = rotation de 31
    //     vec![1,1,31], // mouvement de la tête à droite = mouvement de la bande à gauche = rotation de 1
    //     vec![31,31,31],
    //     vec![0,0,0]
    // ];
    // let instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,2,2],
    //     vec![2,2,2]
    // ];



    //// inverser 0 et 1 
    let instruction_write = vec![ // pourquoi qd je lis 0 je fais 0 + 15 pour avoir 0 ? parce que je lis 0 et je veux ecrire 1  donc 0 + 15 = -1 = 1
        vec![15,1,0], // qd je lis 1 je fais 1 + 1 pour avoir 0, parce que je lis 15 (=-1) et pas 1 donc il faut faire 15 + 1 = 16 = 0
        vec![0,0,0],
        vec![0,0,0]
    ];
    let instruction_position = vec![
        vec![1,1,0],
        vec![0,0,0],
        vec![0,0,0]
    ];
    let instruction_state = vec![
        vec![0,0,1],
        vec![1,1,1],
        vec![2,2,2]
    ];


    let ct_instruction_write = private_key.encrypt_matrix(&mut ctx, &instruction_write);
    let ct_instruction_position = private_key.encrypt_matrix(&mut ctx, &instruction_position);
    let ct_instruction_state = private_key.encrypt_matrix(&mut ctx, &instruction_state);

    println!("Instructions Encrypted");

    let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

    println!("Oblivious TM Start..");
    for i in 0..step {

        println!("--- STEP {} ",i);

        let cell_content = read_cell_content(&tape, &public_key, &ctx);

        if DEBUG {
        private_key.debug_lwe("State ", &state, &ctx); //line
        private_key.debug_lwe("Cell content", &cell_content, &ctx); //column
        }

        write_new_cell_content(&mut tape, &cell_content, &state, &ct_instruction_write, public_key, &ctx,&private_key);
        change_head_position(&mut tape, &cell_content, &state, &ct_instruction_position, public_key, &ctx, &mut nb_of_move, &private_key); 
        state = get_new_state(&cell_content, &state, &ct_instruction_state, public_key, &ctx,&private_key);
        print!("New Tape : ");
        tape.print(&private_key, &ctx);

    }

    println!("Oblivious TM End... \nReordering the tape..");
    public_key.wrapping_neg_lwe(&mut nb_of_move);
    blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);



    println!("---------------  FINAL TAPE ---------------");
    tape.print(&private_key, &ctx);


    



}




pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
) -> LweCiphertext<Vec<u64>> 
{
    let mut ct_0 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}



pub fn write_new_cell_content(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_write: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key : &PrivateKey
)
{


    let new_cell_content = public_key.blind_matrix_access(&ct_instruction_write, &state, &cell_content, &ctx);
    let lut_new_cell_content = LUT::from_lwe(&new_cell_content,&public_key,&ctx);
    if DEBUG{
    private_key.debug_lwe("(W) new cell content = ", &new_cell_content, ctx);
    }
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);
}



pub fn change_head_position(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_position: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    nb_of_move : &mut LweCiphertext<Vec<u64>>,
    private_key : &PrivateKey
)
{

    let position_change = public_key.blind_matrix_access(&ct_instruction_position,&state , &cell_content, &ctx);
    if DEBUG {
    private_key.debug_lwe("(P) next move = ", &position_change, ctx);
    }
    lwe_ciphertext_add_assign(nb_of_move, &position_change);
    blind_rotate_assign(&position_change, &mut tape.0, &public_key.fourier_bsk);

}

pub fn get_new_state(
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_state: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key : &PrivateKey
) -> LweCiphertext<Vec<u64>>
{

    let new_state = public_key.blind_matrix_access(&ct_instruction_state, &state, &cell_content, &ctx);
    if DEBUG{
    private_key.debug_lwe("(S) new state = ", &new_state, ctx);
    }

    return new_state
}

