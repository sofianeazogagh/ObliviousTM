#!/bin/bash

# This script runs the Oblivious Turing Machine program with specified options.

# Define default values
STEP=7
PROGRAM=0
INPUT=10

# Parse command line arguments
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -s|--step)
        STEP="$2"
        shift
        shift
        ;;
        -p|--program)
        PROGRAM="$2"
        shift
        shift
        ;;
        -i|--input)
        INPUT="$2"
        shift
        shift
        ;;
        *)
        shift
        ;;
    esac
done

# Run the Rust program with specified options
cargo run --release -- -step=$STEP -program=$PROGRAM -input=$INPUT
