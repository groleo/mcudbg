# mcudbg

Helpers I use toghether with OpenOCD and ARMGCC to run and debug on the mimxrt1170-evk board.

ARMGCC's *bin* directory is assumed to be in $PATH.


### parse_swo.py

No-dependency ITM Packet parser.
By default it opens ./swo-out.txt.
Input file is specified with the --input argument while --ascii <PORT> and --raw <PORT> <BYTES IN WORD>
control which ports are ascii or raw.
  
Here's an example which parses ITM port 1 (memory traces),
extracts the backtraces
and then sorts them over the allocated size:
  
```shell
./parse_swo.py --raw 1 4 &> memtrace-hex.txt
sed -i -e 's/^.*port:1 \(.*\)/\1/g' memtrace-hex.txt
./track_mem.py --input memtrace-hex.txt &> memtrace-bt.txt
sort -n -k 3 -t , memtrace-bt.txt  > memtrace-bt-sorted.txt
```


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


### exidx-backtrace

Traverses the ARM Exception Table to obtain an execution backtrace.
