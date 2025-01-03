# Porth

Like Tsoding mentioned it is Forth but in python.

## Usage

For simulating the program written in test.porth
```shell
./porth.py sim test.porth
```

For compiling the program written in test.porth and writing to an ELF executable `output` (you can check the generated assembly in `output.asm`)
```shell
./porth.py com test.porth
./output
```

## TODOs
- Add support for defining and calling functions
- Add library builtin functions
- Achieve bootstrapped compiler

