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

from pygdbmi import gdbcontroller
from pygdbmi.constants import GdbTimeoutError


CFG_GDB_EXEC = [r"arm-none-eabi-gdb", "--nx", "--quiet", "--interpreter=mi3"]

global_timeout = 3


class Gdbc:
    def __init__(self):
        self.gdbmi = gdbcontroller.GdbController(command=CFG_GDB_EXEC)

    def run_cmd(self, cmd_id, cmd, timeout_sec=global_timeout, msg=r'done'):
        self.gdbmi.write(cmd, read_response=False)
        logging.info("%s> %s" %(cmd_id,cmd))
        while True:
            response = self.gdbmi.get_gdb_response(timeout_sec)
            for r in response:
                logging.info("%s< %s" % (cmd_id,json.dumps(r,indent=4)))
                if r['message'] == msg or r['payload'] == '^done\r':
                    return r

                if msg != 'error' and r['message'] == 'error':
                    raise BaseException("Unexpected error: %s" % r)
            return response


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
            # Configure DWT_CTRL : 0x1207
            # Bit 12: PCSAMPLEENA
            # Bit 9: CYCTAP
            # Bits 4-1: POSTPRESET
            # Bit 0: CYCCNTENA
            self.run_cmd(25,'-interpreter-exec console "monitor cm7.cpu mww 0xE0001000 0x1207"')
            # Configure SWO
            self.run_cmd(25,'-interpreter-exec console "monitor cm7.cpu itm port 0 on"')
            # Port 1: memory allocations
            self.run_cmd(26,'-interpreter-exec console "monitor cm7.cpu itm port 1 off"')
            # Port 2: locking
            self.run_cmd(27,'-interpreter-exec console "monitor cm7.cpu itm port 2 off"')
            # Port 3: signals
            self.run_cmd(28,'-interpreter-exec console "monitor cm7.cpu itm port 3 off"')
            self.run_cmd(29,'-interpreter-exec console "monitor cm7.apb.swo enable"')
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
    if len(sys.argv) != 2:
        print("usage: Gdbc.py <elf_file>")
        print("")
        sys.exit(1)
    elf_file = sys.argv[1]
    logging.basicConfig(format="%(asctime)s - %(levelname)-8s: %(message)s", level=logging.DEBUG)
    gdbc = Gdbc()
    try:
        gdbc.push_elf_to_board(elf_file)
    except BaseException as e:
        print(e)
        sys.exit(1)
    print()
    print("* press any key to interrupt execution")
    sys.stdin.read(1)
    gdbc.backtrace()
