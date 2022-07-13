#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author: Adrian Negreanu
#
# vim:ts=8:sw=8:noet

import sys
import json
import logging
import argparse

from pygdbmi import gdbcontroller
from pygdbmi.constants import GdbTimeoutError


CFG_GDB_EXEC = [r"arm-none-eabi-gdb", "--nx", "--quiet", "--interpreter=mi3"]

global_timeout = 3


class Gdbc:
    def __init__(self):
        self.gdbmi = gdbcontroller.GdbController(command=CFG_GDB_EXEC)
        self.itm_ports = [
                           'on', # log
                           'off',# mem
                           'off',# lock
                           'off',# signal
                           'off',# vidmem
                           'off',# hook
                           'off',# strtab
                         ]

    def run_cmd(self, cmd_id, cmd, timeout_sec=global_timeout, msg=r'done'):
        self.gdbmi.write(cmd, read_response=False)
        logging.info("%s> %s" %(cmd_id,cmd))
        while True:
            try:
                response = self.gdbmi.get_gdb_response(timeout_sec)
                for r in response:
                    logging.info("%s< %s" % (cmd_id,json.dumps(r,indent=4)))
                    if r['message'] == msg or r['payload'] == '^done\r':
                        return r
                    if msg != 'error' and r['message'] == 'error':
                        raise BaseException("Unexpected error: %s" % r)
                return response
            except GdbTimeoutError as e:
                logging.error("%s", e)
    def port_enable(self, port):
        self.itm_ports[port] = 'on'
    def port_disable(self, port):
        self.itm_ports[port] = 'off'

    def push_elf_to_board(self, elf_file):
        try:
            self.run_cmd( 1,'-list-thread-groups', timeout_sec=8)
            self.run_cmd( 2,'-enable-pretty-printing')
            self.run_cmd( 3,'-gdb-set breakpoint pending on')
            self.run_cmd( 4,'-gdb-set python print-stack none')
            self.run_cmd( 5,'-gdb-set print object on')
            self.run_cmd( 6,'-gdb-set print sevenbit-strings on')
            self.run_cmd( 7,'-gdb-set charset ISO-8859-1')
            self.run_cmd( 8,'-gdb-set auto-solib-add on')
            self.run_cmd( 9,'-file-exec-and-symbols --thread-group i1 %s' % elf_file)
            self.run_cmd(10,'-gdb-set pagination off')
            # stop all threads
            self.run_cmd(11,'-gdb-set non-stop off')
            # mi-async is 'off' by default;
            # that means GDB waits for program termination
            # before issuing new commands.
            # 'set mi-async on' so we can do '-exec-interrupt --all'
            self.run_cmd(12,'-gdb-set mi-async on')
            self.run_cmd(13,'-target-select extended-remote 127.0.0.1:3333', timeout_sec=3, msg='connected')
            self.run_cmd(14,'-interpreter-exec console "monitor reset"', timeout_sec=20)
            self.run_cmd(15,'-interpreter-exec console "monitor halt"', timeout_sec=20)
            self.run_cmd(16,'-gdb-set mem inaccessible-by-default off')
            self.run_cmd(17,'-data-list-register-names --thread-group i1')
            self.run_cmd(18,'-gdb-set arm force-mode thumb')
            self.run_cmd(19,'-data-list-register-values --thread 1 --frame 0 x 14')
            self.run_cmd(20,'-data-list-register-values --thread 1 --frame 0 x 13')
            self.run_cmd(21,'-gdb-set remote hardware-breakpoint-limit 8')
            self.run_cmd(22,'-gdb-set range-stepping on')
            self.run_cmd(23,'-interpreter-exec console "monitor arm semihosting enable"')
            self.run_cmd(24,'-interpreter-exec console "monitor arm semihosting_cmdline app_freertos.elf"')
            # The DWT unit generates PC samples at fixed time intervals, with
            # an accuracy of one clock cycle.
            # The POSTCNT counter period determines the PC sampling interval,
            # and software configures the DWT_CTRL.CYCTAP field to
            # determine how POSTCNT relates to the processor cycle counter, CYCCNT.
            # The DWT_CTRL.PCSAMPLENA bit enables PC sampling.
            # pg799
            # Bit 12, PCSAMPLEENA - Enables use of POSTCNT counter as a timer for Periodic PC sample packet generation
            # Bit 9, CYCTAP - Selects the position of the POSTCNT tap on the CYCCNT counter
            #             0 - (Processor clock)/64
            #             1 - (Processor clock)/1024
            # Bits 4:1, POSTPRESET - Reload value for the POSTCNT counter.
            # Bit 0, CYCCNTENA - Enables CYCCNT.
            # sampling_freq = cpu_freq / (7*1024)
            #self.run_cmd(25,'-interpreter-exec console "monitor cm7.cpu mww 0xE0001000 0x%x"' % 0b1001000000001)
            # Configure SWO
            self.run_cmd(25,f'-interpreter-exec console "monitor cm7.cpu itm configure -tx on -swo on -trace-bus-id 1"')
            for port_id,port_state in enumerate(self.itm_ports):
                self.run_cmd(25,f'-interpreter-exec console "monitor cm7.cpu itm port {port_id} {port_state}"')
            self.run_cmd(25,f'-interpreter-exec console "monitor cm7.cpu itm enable"')
            self.run_cmd(29,f'-interpreter-exec console "monitor cm7.apb.swo enable"')
            # Download
            self.run_cmd(30,'-target-download', msg='done')
            self.run_cmd(31,'-list-thread-groups')
            # after we're stopped in main, do -exec-continue.
            self.run_cmd(32,'-exec-continue --thread-group i1', timeout_sec=10, msg='running')
        except GdbTimeoutError as e:
            logging.exception(e)
            return False

        return True

    def exec_abort(self):
        self.run_cmd(50,'-exec-abort', timeout_sec=10)

    def interrupt(self):
        self.run_cmd(60,'-exec-interrupt --all', timeout_sec=40, msg='stopped')

    def backtrace(self):
        try:
            self.interrupt()
            rsp = self.run_cmd(70,'-thread-info')
            for thrd in rsp['payload']['threads']:
                self.run_cmd(70,'-stack-list-frames --thread %s'%thrd['id'], timeout_sec=20, msg='done')

        except GdbTimeoutError as e:
            logging.exception(e)
            return False
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="with GDB-MI.")
    parser.add_argument('--input', required=True, help='Input ELF file to load.')
    parser.add_argument('--debug', required=False, help='Enable logging.DEBUG', action='count', default=0)
    parser.add_argument('--mem', required=False, help='Enable the Memory ITM Port (1)', action='store_true')
    parser.add_argument('--lock', required=False, help='Enable the Lock ITM Port (2)', action='store_true')
    parser.add_argument('--signal', required=False, help='Enable the Signal ITM Port (3)', action='store_true')
    parser.add_argument('--vidmem', required=False, help='Enable the Vidmem ITM Port (4)', action='store_true')
    parser.add_argument('--hook', required=False, help='Enable the Hook ITM Port (5)', action='store_true')
    parser.add_argument('--strtab', required=False, help='Enable the String ITM Port (6)', action='store_true')

    args = parser.parse_args()
    logging_level = logging.INFO
    if args.debug:
        logging_level = logging.DEBUG
    logging.basicConfig(format="%(asctime)s - %(levelname)-8s: %(message)s", level=logging_level)

    gdbc = Gdbc()

    if args.mem: gdbc.port_enable(1)
    if args.lock: gdbc.port_enable(2)
    if args.signal: gdbc.port_enable(3)
    if args.vidmem: gdbc.port_enable(4)
    if args.hook: gdbc.port_enable(5)
    if args.strtab: gdbc.port_enable(6)

    try:
        gdbc.push_elf_to_board(args.input)
    except BaseException as e:
        print(e)
        sys.exit(1)

    print()
    print("* press any key to interrupt execution")
    sys.stdin.read(1)
    gdbc.backtrace()
