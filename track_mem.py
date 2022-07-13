#! /usr/bin/env python3
import re
import sys
import subprocess
import argparse

# 0x6d6.SIZE
# allocated address
# allocated size

regex = re.compile("(?P<op>0x6d6[e,4])(?P<nb_elem>[0-9a-f]+)$", re.I)

allocations = {}

class addr2line:
    def __init__(self, binary, addr2line):
        self.process = subprocess.Popen(
                                        [ addr2line,
                                          "-f",
                                          "-e",
                                          binary
                                        ],
                                        universal_newlines=True,
                                        stdin = subprocess.PIPE,
                                        stdout = subprocess.PIPE
                                       )

    def lookup(self, addr):
        dbg_info = None
        try:
            self.process.stdin.write("%s\r\n" % addr)
            self.process.stdin.flush()
            func_name = self.process.stdout.readline().rstrip()
            file_and_line = self.process.stdout.readline().rstrip()
        except IOError:
            raise Error(
                "Communication error with addr2line.")
        finally:
            ret = self.process.poll();
            if ret != None:
                raise Error(
                    "addr2line terminated unexpectedly (%i)." % (ret))

        (file, line) = file_and_line.rsplit(":", 1)
        if file == "??":
            return (func_name, "N/A", line)
        if line == "0":
            return (func_name, file, "0")

        return (func_name, file, line)

def dump_stack(stack,a2l):
    ret = []
    for addr in stack:
        func_name, file, line = a2l.lookup(addr)
        if func_name == "??":
            ret.append([func_name])
        else:
            ret.append([func_name, file, line])
    ret.reverse()
    return ret

OP_MATCH = 0
BACKTRACE = 1
STATISTIC = 2
MADDR_NEW = 3
MADDR_DEL = 4
MADDR_SIZE = 5

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Track memory allocations.")
    parser.add_argument('--input', required=True, help='Memory traces.', default='memtrace.txt')
    parser.add_argument('--elf', required=False, help='ELF file that generated the memory traces.', default='tiger_freertos.elf')
    parser.add_argument('--addr2line', required=False, help='Path to addr2line.', default='Armgcc/gcc-arm-none-eabi-10-2020-q4-major/bin/arm-none-eabi-addr2line.exe')

    args = parser.parse_args()

    a2l = addr2line(args.elf, args.addr2line)

    with open(args.input) as mem:
        state = OP_MATCH
        nb_elem = 0
        addr = ''
        size = ''
        op = ''
        stack = []
        max_mem = 0
        for line in mem:
            m = regex.match(line)
            if state == OP_MATCH and m and m.group('op') == '0x6d6e':
                nb_elem = int(m.group('nb_elem'))
                state = MADDR_NEW
                op = 'new'
                continue
            if state == OP_MATCH and m and m.group('op') == '0x6d64':
                nb_elem = int(m.group('nb_elem'))
                state = MADDR_DEL
                op = 'del'
                continue
            if state == MADDR_NEW:
                addr = line.rstrip()
                state = MADDR_SIZE
                continue
            if state == MADDR_SIZE:
                size = int(line.rstrip(), 16)
                state = BACKTRACE
                continue
            if state == MADDR_DEL:
                addr = line.rstrip()
                state = BACKTRACE
                continue
            if state == BACKTRACE:
                stack.append(line.rstrip())
                nb_elem -= 1
                if nb_elem <= 0:
                    state = STATISTIC
                continue
            if state == STATISTIC:
                if op == 'new':
                    if addr in allocations and allocations[addr]['lotted'] == 1:
                        print("New:ERROR: memory already allocated: %s" % addr)
                    else:
                        allocations[addr] = {'size': size, 'stack': stack, 'lotted': 1}
                        print("New,%s, %s, %s" % (addr, size, dump_stack(stack, a2l)))
                        max_mem += size
                if op == 'del':
                    if addr not in allocations:
                        print("Del:ERROR: address was never allocated: %s" % addr)
                    elif allocations[addr]['lotted'] == 0:
                        print("Del:ERROR: address already freed: %s" % addr)
                    else:
                        allocations[addr]['lotted'] = 0
                        print("Del,%s, %s" % (addr, dump_stack(stack, a2l)))
                state = OP_MATCH
                nb_elem = 0
                addr = ''
                size = ''
                op = ''
                stack = []

    #####
    for addr in allocations:
        if allocations[addr]['lotted'] == 1:
            print("leak(%s) %s B -> %s"% (addr, allocations[addr]['size'], dump_stack(allocations[addr]['stack'], a2l)))
    print("max_mem: %d" % max_mem)
