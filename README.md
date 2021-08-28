# mcudbg

Helpers I use toghether with OpenOCD and ARMGCC to run and debug on the mimxrt1170-evk board.

ARMGCC's *bin* directory is assumed to be in $PATH.


### swo_parse.py

No-dependency ITM Packet parser.
By default it opens ./swo-out.txt. You can specify the input file with the --input argument.


### Gdbc.py

It loads and starts an ELF file using the pygdbmi python module.


### dwt-to-gmon.py

OpenOCD can dump the SWO incoming packets to a file; swo_parse.py can parse that file and
extract the Program Counters sampled by the DWT unit.
These samples are then translated to a gmon.out file, using dwt-to-gmon.py.

Here's an example of this process:

```shell
./parse_swo.py | grep dwt-pc: | sed -e 's/dwt-pc://' > dwt-pc.txt
./dwt-to-gmon.py --input dwt-pc.txt
arm-none-eabi-gprof.exe $binary_path/$binary_file > report.txt
```
