
const DEBUG: bool = false;

use std::fs::*;
use std::io::Write;
use std::time::{Instant, Duration};

use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;



pub fn oblivious_tm()
{
    //The number of steps our Turing Machine will run.

    let step = 7;
    let param = PARAM_MESSAGE_5_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();

    println!("Key generated");

    //creation of tape
    let mut tape = vec![1,0,1,0,1,1];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(2_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    println!("Tape Encrypted");

    let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);
    println!("State Encrypted");


    println!("---------------  MUTIPLICATION BY 2 ---------------");
    let mut instruction_write = vec![
        vec![0,1,0], 
        vec![0,1,2]

    ];
    encode_instruction_write(&mut instruction_write, &ctx);
    let instruction_position = vec![
        vec!['D','D','N'],
        vec!['N','N','N']
    ];
    let instruction_position = encode_instruction_position(&instruction_position, &ctx);
    let instruction_state = vec![
        vec![0,0,1],
        vec![1,1,1]
    ];


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


    // println!("--------------- SOUSTRAIRE 1 ---------------");
    // let mut instruction_write = vec![
    //     vec![0,1,2], 
    //     vec![1,0,2],
    //     vec![0,1,2]
    // ];
    // encode_instruction_write(&mut instruction_write, &ctx);

    // let instruction_position = vec![ 
    //     vec!['D','D','G'], 
    //     vec!['G','G','G'],
    //     vec!['N','N','N']
    // ];
    // let instruction_position = encode_instruction_position(&instruction_position, &ctx);

    // let instruction_state = vec![
    //     vec![0,0,1],
    //     vec![1,2,2],
    //     vec![2,2,2]
    // ];



    let ct_instruction_write = private_key.encrypt_matrix(&mut ctx, &instruction_write);
    let ct_instruction_position = private_key.encrypt_matrix(&mut ctx, &instruction_position);
    let ct_instruction_state = private_key.encrypt_matrix(&mut ctx, &instruction_state);

    println!("Instructions Encrypted");

    let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);
    println!("Oblivious TM Start..");

    let mut total_time_step = Duration::new(0, 0);
    for i in 0..step {

        println!("--- STEP {} ",i);
        let start_time_step = Instant::now();

        let cell_content = read_cell_content(&tape, &public_key, &ctx);
        if DEBUG {
        private_key.debug_lwe("State ", &state, &ctx); //line
        private_key.debug_lwe("Cell content", &cell_content, &ctx); //column
        }
        write_new_cell_content(&mut tape, &cell_content, &state, &ct_instruction_write, public_key, &ctx,&private_key);
        change_head_position(&mut tape, &cell_content, &state, &ct_instruction_position, public_key, &ctx, &mut nb_of_move, &private_key); 
        state = get_new_state(&cell_content, &state, &ct_instruction_state, public_key, &ctx,&private_key);

        let elapsed_time_step = start_time_step.elapsed();
        total_time_step += elapsed_time_step;


        if DEBUG {
            print!("New Tape : ");
            tape.print(&private_key, &ctx);
        }

    }


    let average_time_step = total_time_step / step;
    println!("Temps moyen d'execution d'un step avec BMA : {:?}", average_time_step);

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


fn generate_matrix(n: usize, m: usize, p: u64) -> Vec<Vec<u64>> {
    let mut matrix = Vec::with_capacity(n);
    for _ in 0..n {
        let row = (0..m).map(|_| 0).collect();
        matrix.push(row);
    }
    matrix
}



pub fn compare_performance_step_with_bma_leaky() {



    //Fichier resultat
    let mut output_file_step = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_step_with_bma_leaky.txt")
        .expect("Impossible d'ouvrir le fichier");

    // En tête
    // writeln!(output_file_step, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");

    let params_crypto = vec![PARAM_MESSAGE_4_CARRY_0,PARAM_MESSAGE_5_CARRY_0];

    // let params_crypto = vec![PARAM_MESSAGE_5_CARRY_0];

    for params in params_crypto {


        let mut ctx = Context::from(params);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        let matrix_size = vec![(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(9,9),(10,10),
        (11,11),(12,12),(13,14),(15,15),(16,16),(16,16),(17,17),(18,18),(19,19),(20,20),(21,21)];

        let mut i = 0;
        for (n,m) in matrix_size{


            if params.message_modulus.0 >= n{
                i+=1;
                println!("calcul {i}");

                let matrix0 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix1 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix2 = generate_matrix(n, m, ctx.full_message_modulus() as u64);


                let ct_matrix0 = private_key.encrypt_matrix(&mut ctx, &matrix0);
                let ct_matrix1 = private_key.encrypt_matrix(&mut ctx, &matrix1);
                let ct_matrix2 = private_key.encrypt_matrix(&mut ctx, &matrix2);

                let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

                //creation of tape
                let mut tape = vec![1,0,];
                while tape.len() < ctx.message_modulus().0 {
                    tape.push(2_u64);
                }

                let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
                let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);


                let num_iterations = 25;
                for execution in 0..num_iterations {


                    // Temps d'exécution de la première fonction (BMA)
                    let start_time_step = Instant::now();
                    let cell_content = read_cell_content(&tape, &public_key, &ctx);
                    write_new_cell_content(&mut tape, &cell_content, &state, &ct_matrix0, public_key, &ctx,&private_key);
                    change_head_position(&mut tape, &cell_content, &state, &ct_matrix1, public_key, &ctx, &mut nb_of_move, &private_key); 
                    state = get_new_state(&cell_content, &state, &ct_matrix2, public_key, &ctx,&private_key);
                    let elapsed_time_step = start_time_step.elapsed();


                    // Écrire les temps dans le fichier
                    writeln!(output_file_step, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_step.as_millis()).expect("Impossible d'écrire dans le fichier");

                }
            }

        }
    }





}

pub fn compare_performance_step_with_bma_robust(){



    //Fichier resultat
    let mut output_file_step = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_step_with_bma_robust.txt")
        .expect("Impossible d'ouvrir le fichier");

    // En tête
    writeln!(output_file_step, "execution,matrix_size,params,time").expect("Impossible d'écrire dans le fichier");


    let params_crypto = vec![PARAM_MESSAGE_3_CARRY_0,PARAM_MESSAGE_4_CARRY_0,PARAM_MESSAGE_5_CARRY_0];


    for params in params_crypto {


        let mut ctx = Context::from(params);
        let private_key = PrivateKey::new(&mut ctx);
        let public_key = &private_key.public_key;

        let matrix_size = vec![(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(9,9),(10,10),
        (11,11),(12,12),(13,13),(14,14),(15,15),(16,16),(17,17),(18,18),(19,19),(20,20),(21,21)];

        let mut i = 0;
        for (n,m) in matrix_size{


            if params.message_modulus.0 >= n{
                i+=1;
                println!("calcul {i}");

                let matrix0 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix1 = generate_matrix(n, m, ctx.full_message_modulus() as u64);
                let matrix2 = generate_matrix(n, m, ctx.full_message_modulus() as u64);


                let ct_matrix0 = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix0);
                let ct_matrix1 = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix1);
                let ct_matrix2 = private_key.encrypt_matrix_with_padding(&mut ctx, &matrix2);

                let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

                //creation of tape
                let mut tape = vec![1,0,];
                while tape.len() < ctx.message_modulus().0 {
                    tape.push(2_u64);
                }

                let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
                let mut state = private_key.allocate_and_encrypt_lwe(0, &mut ctx);


                let num_iterations = 25;
                for execution in 0..num_iterations {


                    // Temps d'exécution de la première fonction (BMA)
                    let start_time_step = Instant::now();
                    let cell_content = read_cell_content(&tape, &public_key, &ctx);
                    write_new_cell_content(&mut tape, &cell_content, &state, &ct_matrix0, public_key, &ctx,&private_key);
                    change_head_position(&mut tape, &cell_content, &state, &ct_matrix1, public_key, &ctx, &mut nb_of_move, &private_key); 
                    state = get_new_state(&cell_content, &state, &ct_matrix2, public_key, &ctx,&private_key);
                    let elapsed_time_step = start_time_step.elapsed();


                    // Écrire les temps dans le fichier
                    writeln!(output_file_step, "{:?},{:?},{:?},{:?}",execution,n,params.message_modulus.0,elapsed_time_step.as_millis()).expect("Impossible d'écrire dans le fichier");

                }
            }

        }
    }





}


