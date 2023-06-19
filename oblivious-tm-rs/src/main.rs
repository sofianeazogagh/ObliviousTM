#![allow(dead_code)]
#![allow(unused_variables)]

mod blind_array_access2d;
use crate::blind_array_access2d::blind_array_access2d;

mod blind_permutation;
use crate::blind_permutation::blind_permutation;

mod blind_insertion;
use crate::blind_insertion::blind_insertion;

mod blind_push;
use crate::blind_push::blind_push;

mod blind_pop;
use crate::blind_pop::blind_pop;

mod blind_retrieve;
use crate::blind_retrieve::blind_retrieve;

mod private_insert;
use crate::private_insert::private_insert;







// mod demultiplexer;
// use crate::demultiplexer::demultiplixer;

// mod gist;
// use crate::gist::*;



// mod blind_rotation;
// mod helpers;

// mod headers;

pub fn main() {

    // blind_array_access2d(); // from unitest_bacc2d

    // blind_permutation(); // from blind_permutation

    // blind_insertion(); // from blind_insertion

    // blind_push(); // from blind_push

    // blind_pop(); // from blind_pop

    blind_retrieve(); // from blind_retrieve

    // private_insert(); // from private_insert

    

    // test_glwe(); // from test_glwe 

    // test_one_hot_slot(); // from one_hot_slot

    // demultiplixer(); // from demultiplexer

    // gist::lwe_to_glwe();


}

