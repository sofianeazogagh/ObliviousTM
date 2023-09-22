use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



pub fn oblivious_tm()
{
    //The number of steps our Turing Machine will run.

    let step = 14;
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![1,0,0,1];
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

    //// inverser 0 et 1 sans retour de la tête de lecture
    let instruction_write = vec![
        vec![1,1,0], // pourquoi qd je lis 1 je fais 1 + 1 pour avoir 0 ? parce que je lis 15 (-1) et pas 1 donc il faut faire 15 + 1 = 16 = 0
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



    //// inverser 0 et 1 avec retour de la tête de lecture (sensible et long avec 4_0)
    // let instruction_write = vec![
    //     vec![1,1,0],
    //     vec![0,0,0],
    //     vec![0,0,0]

    // ];
    // // complete_matrix(&mut instruction_write, ctx.message_modulus().0, ctx.message_modulus().0);
    
    // let mut instruction_position = vec![
    //     vec![1,1,31],
    //     vec![31,31,0],
    //     vec![0,0,1]
    // ];
    // // complete_matrix(&mut instruction_position, ctx.message_modulus().0, ctx.message_modulus().0);
    // // instruction_position[1][ctx.message_modulus().0 - 2] = 31; // 1 dans la partie negacyclic


    // let mut instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,1,2],
    //     vec![2,2,2]
    // ];
    // complete_matrix(&mut instruction_state, ctx.message_modulus().0, ctx.message_modulus().0);
    // instruction_state[1][ctx.message_modulus().0 - 2] = 30; // 2 dans la partie negacyclic



    let ct_instruction_write = private_key.encrypt_matrix(&mut ctx, &instruction_write);
    let ct_instruction_position = private_key.encrypt_matrix(&mut ctx, &instruction_position);
    let ct_instruction_state = private_key.encrypt_matrix(&mut ctx, &instruction_state);

    println!("Instructions Encrypted");

    println!("Oblivious TM Start..");
    for i in 0..step {

        println!("--- STEP {} ",i);

        let cell_content = read_cell_content(&tape, &public_key, &ctx,&private_key);
        private_key.debug_lwe("State ", &state, &ctx); //line
        private_key.debug_lwe("Cell content", &cell_content, &ctx); //column


        write_new_cell_content(&mut tape, &cell_content, &state, &ct_instruction_write, public_key, &ctx,&private_key); // ecris 0 - 7 - 0 - 0
        change_head_position(&mut tape, &cell_content, &state, &ct_instruction_position, public_key, &ctx,&private_key); // rotate de 1 - 7 - 0 - 0
        state = get_new_state(&cell_content, &state, &ct_instruction_state, public_key, &ctx,&private_key); // 1 - 3 - 0 - 6 -
        print!("New Tape : ");
        tape.print(&private_key, &ctx);

    }


    println!("---------------  FINAL TAPE ---------------");
    tape.print(&private_key, &ctx);


    



}




pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
    private_key : &PrivateKey

) -> LweCiphertext<Vec<u64>> 
{
    // let mut cell_content = LweCiphertext::new(0u64, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    // extract_lwe_sample_from_glwe_ciphertext(&tape.0, &mut cell_content, MonomialDegree(0));
    // let mut switched = LweCiphertext::new(0_64, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    // keyswitch_lwe_ciphertext(&public_key.lwe_ksk, &cell_content, &mut switched);

    let mut ct_0 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);
    // private_key.debug_lwe("cell_content = ", &cell_content, ctx);

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
    private_key.debug_lwe("(W) new cell content = ", &new_cell_content, ctx);

    // print!("lut new cell content ");
    // lut_new_cell_content.print(&private_key, &ctx);

    // println!("BEFORE GLWE SUM");

    // private_key.debug_glwe("tape = ", &tape.0, &ctx);
    // private_key.debug_glwe("lut new cell ", &lut_new_cell_content.0, &ctx);
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);
    // private_key.debug_glwe("AFTER GLWE SUM \n", &tape.0, &ctx);
}



pub fn change_head_position(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_position: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key : &PrivateKey
)
{

    let position_change = public_key.blind_matrix_access(&ct_instruction_position,&state , &cell_content, &ctx);
    private_key.debug_lwe("(P) next move = ", &position_change, ctx);
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
    private_key.debug_lwe("(S) new state = ", &new_state, ctx);

    return new_state
}


fn complete_matrix(matrix: &mut Vec<Vec<u64>>, target_rows: usize, target_cols: usize) {
    // Vérifier si la matrice doit être agrandie en ajoutant des zéros en bas
    while matrix.len() < target_rows {
        matrix.push(vec![0; matrix[0].len()]);
    }

    // Vérifier si la matrice doit être agrandie en ajoutant des zéros à droite
    for row in matrix.iter_mut() {
        while row.len() < target_cols {
            row.push(0);
        }
    }
}