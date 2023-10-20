# Oblivious Turing Machine (OTM)

This script allows you to execute a proof of concept of an Oblivious Turing Machine with various configurations.

## Dependancies 

You need to install Rust and Cargo to use it with tfhe-rs.

First, install the needed Rust toolchain:
```bash
rustup toolchain install nightly
```

Then, you can either:

1. Manually specify the toolchain to use in each of the cargo commands:
For example:
```bash
cargo +nightly build
cargo +nightly run
```
2. Or override the toolchain to use for the current project:
```bash
rustup override set nightly
```

Cargo will use the `nightly` toolchain.
```
cargo build
```

## Usage 

3. Navigate to the project directory:

```bash
cd oblivious-tm-rs
```

4. Make sure the `otm.sh` script is executable:

```
chmod +x otm.sh
```

5. Run the script with the desired options:

```
./otm.sh -s=7 -p=1 -i=10
```

## Options

- `-s` or `--step`: Specifies the number of steps the Turing Machine will execute.

- `-p` or `--program`: Chooses the program to execute:
    - `0`: Binary multiplication by 2.
    - `1`: Bit inversion.
    - `2`: Binary subtraction.

- `-i` or `--input`: Provides the integer to be evaluated by the Turing Machine.

Example:

```bash
./otm.sh -s=7 -p=1 -i=10
```

This command will execute the Oblivious Turing Machine with the following configurations:
- 7 steps
- Bit inversion program
- Input value of 10


---

Please make sure to customize the placeholders (e.g., `https://github.com/yourusername/oblivious-turing-machine.git`) with your actual repository URL and adjust any other details specific to your project.