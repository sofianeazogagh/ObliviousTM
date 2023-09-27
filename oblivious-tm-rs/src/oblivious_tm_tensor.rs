
const DEBUG: bool = false;
use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



pub fn oblivious_tm_tensor()
{
    //The number of steps our Turing Machine will run.

    let step = 7;
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![1,0,1,1];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(2_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    println!("Tape Encrypted");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    println!("State Encrypted");


    // println!("---------------  MUTIPLICATION BY 2 ---------------");
    // let mut instruction_write = vec![
    //     vec![0,1,0], 
    //     vec![0,1,2]

    // ];
    // encode_instruction_write(&mut instruction_write, &ctx);
    // let instruction_position = vec![
    //     vec!['D','D','N'],
    //     vec!['N','N','N']
    // ];
    // let instruction_position = encode_instruction_position(&instruction_position, &ctx);
    // let instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,1,1]
    // ];


    // println!("---------------  INVERSE 0 and 1 ---------------");
    // let mut instruction_write = vec![ 
    //     vec![1,0,2],
    //     vec![0,1,2],
    //     vec![0,1,2]
    // ];
    // encode_instruction_write(&mut instruction_write, &ctx);
    // let instruction_position = vec![
    //     vec!['D','D','N'],
    //     vec!['N','N','N'],
    //     vec!['N','N','N']
    // ];
    // let instruction_position = encode_instruction_position(&instruction_position, &ctx);
    // let instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,1,1],
    //     vec![2,2,2]
    // ];


    println!("--------------- SOUSTRAIRE 1 ---------------");
    let mut instruction_write = vec![
        vec![0,1,2], 
        vec![1,0,2],
        vec![0,1,2]
    ];
    encode_instruction_write(&mut instruction_write, &ctx);

    let instruction_position = vec![ 
        vec!['D','D','G'], 
        vec!['G','G','G'],
        vec!['N','N','N']
    ];
    let instruction_position = encode_instruction_position(&instruction_position, &ctx);

    let instruction_state = vec![
        vec![0,0,1],
        vec![1,2,2],
        vec![2,2,2]
    ];


    let instruction_table = vec![instruction_write,instruction_position,instruction_state];
    let tensor_instruction = encode_tensor_into_matrix(instruction_table);
    let ct_tensor_instruction = private_key.encrypt_matrix(&mut ctx, &tensor_instruction);


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

        state = get_new_state_after_writing_and_moving(&mut tape, &cell_content, &state, &ct_tensor_instruction, &mut nb_of_move, public_key, &ctx, &private_key);

        print!("New Tape : ");
        tape.print(&private_key, &ctx);

    }

    println!("Oblivious TM End... \nReordering the tape..");
    public_key.wrapping_neg_lwe(&mut nb_of_move);
    blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);



    println!("---------------  FINAL TAPE ---------------");
    tape.print(&private_key, &ctx);


    



}




pub fn get_new_state_after_writing_and_moving(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_tensor_instruction: &Vec<LUT>,
    nb_of_move : &mut LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    ctx: &Context,
    private_key : &PrivateKey
)
-> LweCiphertext<Vec<u64>>
{



    // get the actions (writing, moving, changing state)
    let action = public_key.blind_tensor_access(&ct_tensor_instruction, &state, &cell_content, 3, &ctx);

    //write
    let lut_new_cell_content = LUT::from_lwe(&action[0],&public_key,&ctx);
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);


    //move
    lwe_ciphertext_add_assign(nb_of_move, &action[1]);
    blind_rotate_assign(&action[1], &mut tape.0, &public_key.fourier_bsk);

    //new state 
    let new_state = action[2].clone();


    if DEBUG{
        private_key.debug_lwe("(W) new cell content = ", &action[0], ctx);
        private_key.debug_lwe("(P) next move = ", &action[1], ctx);
        private_key.debug_lwe("(S) new state = ", &new_state, ctx);

    }

    return new_state;


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



/// Encode the matrix instruction_write appropriatly
fn encode_instruction_write(
    instruction_write : &mut Vec<Vec<u64>>,
    ctx: &Context
)
{
    let rows = instruction_write.len();

    for i in 0..rows {
        // Read 0
        match instruction_write[i][0] {
            0 => instruction_write[i][0] = 0,
            1 => instruction_write[i][0] = (ctx.message_modulus().0 - 1) as u64,
            2 => instruction_write[i][0] = (ctx.message_modulus().0 - 2) as u64,
            _ => (),
        }
        // Read 1
        match instruction_write[i][1] {
            0 => instruction_write[i][1] = 1,
            1 => instruction_write[i][1] = 0,
            2 => instruction_write[i][1] = (ctx.message_modulus().0 - 1) as u64,
            _ => (),
        }

        // Read 2
        match instruction_write[i][2] {
            0 => instruction_write[i][2] = 2,
            1 => instruction_write[i][2] = 3,
            2 => instruction_write[i][2] = 0,
            _ => (),
        }
    }
}



/// Encode the matrix instruction_position appropriatly
fn encode_instruction_position(
    instruction_position: &Vec<Vec<char>>,
    ctx: &Context
) -> Vec<Vec<u64>> 
{
    let encoded_matrix: Vec<Vec<u64>> = instruction_position
        .iter()
        .map(|row| {
            row.iter()
                .map(|&col| match col {
                    'D' => 1,
                    'G' => (2*ctx.message_modulus().0 - 1) as u64,
                    'N' => 0,
                    _ => unreachable!(),
                })
                .collect()
        })
        .collect();

    encoded_matrix
}




pub fn encode_tensor_into_matrix(channels : Vec<Vec<Vec<u64>>>)
-> Vec<Vec<u64>>
{

    let t_rows = channels[0].len()*3;
    let t_col = channels[0][0].len();

    let mut tensor_encoded = vec![vec![0; t_col]; t_rows];
    

    for i in 0.. channels[0].len(){
        for j in 0..t_col{
            for k in 0..channels.len(){
                tensor_encoded[i*3 + k][j] = channels[k][i][j];
            }
        }
    
    }

    tensor_encoded
}