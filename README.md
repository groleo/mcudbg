# mcudbg

Helpers I use toghether with OpenOCD and ARMGCC to run and debug on the mimxrt1170-evk board.

### swo_parse.py

No-dependency ITM Packet parser.
By default it opens ./swo-out.txt. You can specify the input file with the --input argument.

### Gdbc.py

It loads and starts an ELF file using the pygdbmi python module.
