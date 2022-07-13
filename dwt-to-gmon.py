#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author: Adrian Negreanu

import sys
import struct
import argparse
import re

from ctypes import *
from enum import IntEnum

regex = re.compile("(?:.*dwt-pc:)(?P<pc>0x[0-9a-f]{8})$", re.I)


# From https://gist.github.com/lmyyao/355709b35b717c9e47c6795de7b45ccd
def convert_struct_to_bytes(st):
    buffer = create_string_buffer(sizeof(st))
    memmove(buffer, addressof(st), sizeof(st))
    return buffer.raw


class RecordTag(IntEnum):
    TIME_HIST = 0,# Histogram
    CG_ARC = 1,   # Call-Graph Arc (not-supported)
    BB_COUNT = 2  # Basic-Block Exec count (not-supported)


class FileHeader(Structure):
    _pack_ = 1
    _fields_ = [("cookie", c_char * 4),
                ("version", c_int32),
                ("spare", c_char * 12)
               ]


class HistogramHeader(Structure):
    _pack_ = 1
    _fields_ = [("tag",  c_uint8),
                ("low_pc", c_uint32),
                ("high_pc", c_uint32),
                ("hist_size", c_uint32),
                ("prof_rate", c_uint32),
                ("dimen", c_char * 15),
                ("dimen_abbrev", c_char)
               ]


def read_dwt_pc(fname):
    hist = {}
    with open(fname, 'rt') as f:
        for line in f:
            m = regex.match(line)
            if not m: continue
            addr = int(m.group('pc'), 16)
            #print("ADDR:%s" % addr)
            if addr not in hist:
                hist[addr] = 1
            else:
                hist[addr] += 1
    return hist


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Consumes DWT PC-addresses and generates a gmon.out.")
    parser.add_argument('--input', required=False, help='Input file with PC-addresses, one per line.', default='dwt-pc.txt')
    args = parser.parse_args()

    hist = read_dwt_pc(args.input)
    hist_size = len(hist)

    if hist_size == 0:
        print(f"no 'dwt-pc:' entries in '{args.input}'")
        sys.exit(-1)

    low_pc = min(hist.items(), key = lambda x: x[0])[0]
    high_pc = max(hist.items(), key = lambda x: x[0])[0]
    address_space = high_pc - low_pc
    num_buckets = address_space // 2

    # Profiling clock rate.
    # See the DWT CTRL setup in Gdbc.py
    prof_rate = 140000

    file_hdr = FileHeader(b"gmon", 0x00000001)
    # +1 to account for the Histogram header too.
    # "s" for "seconds"  "m" for "milliseconds"
    hist_hdr = HistogramHeader(RecordTag.TIME_HIST, low_pc, high_pc, num_buckets+1, prof_rate, b"milliseconds", b"m")

    print(f'low_pc:{low_pc:x}')
    print(f'high_pc:{high_pc:x}')
    print(f'hist_size:{len(hist)}')
    print("writing gmon.out")
    with open('gmon.out', 'wb') as f:
        f.write(convert_struct_to_bytes(file_hdr))
        f.write(convert_struct_to_bytes(hist_hdr))
        # +2 to include high_pc too.
        for addr in range(low_pc, high_pc+2, 2):
            value = 0
            if addr in hist:
                value = hist[addr]
                del hist[addr]
            #print("0x%x -> %d" % (addr, value))
            f.write((value & 0xFFFF).to_bytes(2, byteorder='little'))

    # addresses that were not dumped (there shouldn't be any)
    for key,value in hist.items():
        print(f"{key:x} {value}")
