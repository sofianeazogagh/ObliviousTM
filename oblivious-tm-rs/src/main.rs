#![allow(dead_code)]
#![allow(unused_variables)]

mod unitest_baacc2d;
use crate::unitest_baacc2d::blind_array_access2d;

// mod optim_multi_pbs;
// use crate::optim_multi_pbs::test_multi_pbs;

// mod test_glwe;
// use crate::test_glwe::test_add2;
// use crate::test_glwe::test_add;
// use crate::test_glwe::*;

// mod one_hot_slot;
// use crate::one_hot_slot::test_one_hot_slot;


mod blind_permutation;
use crate::blind_permutation::blind_permutation;


mod blind_insert;
use crate::blind_insert::blind_insert;

// mod demultiplexer;
// use crate::demultiplexer::demultiplixer;



// mod gist;
// use crate::gist::*;


mod headers;


// mod blind_rotation;
// mod helpers;


pub fn main() {

    // blind_array_access2d(); // from unitest_bacc2d

    blind_permutation(); // from blind_permutation

    // blind_insert(); // from blind_insert


    // demultiplixer(); // from demultiplexer



    // test_multi_pbs();

    // test_glwe(); // from test_glwe

    // test_one_hot_slot(); // from one_hot_slot

    // blind_permutation(); // from private_computing

    // gist::lwe_to_glwe();


}

