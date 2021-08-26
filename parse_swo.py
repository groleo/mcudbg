#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author: Adrian Negreanu
#
# vim:ts=8:sw=8:noet

import socket
import time
import sys
import logging
import argparse


class Stream:
    def __init__(self, id, header = '', tcl_socket = None):
        self.id = id;
        self._buffer = []
        self._header = header
        self.tcl_socket = tcl_socket

    def _add_byte(self, inb):
        if inb == 0x0a:
            self._output(self._header + ''.join(self._buffer))
            self._buffer = []
            return

        self._buffer.append(chr(inb))

    def _output(self, s):
        print("%s" % s)

    def add_bytes(self, s):
        for i in s:
            self._add_byte(i)


class PACKET_TYPE:
    START = 0
    LTS1_HEADER = 1
    LTS1 = 2
    LTS2 = 3
    SOURCE_INSTRUMENTATION_HEADER = 4
    SOURCE_INSTRUMENTATION = 5
    OVERFLOW = 6
    EXTENSION_ITM = 7
    EXTENSION = 8
    HW_INSTRUMENTATION_HEADER = 9
    HW_INSTRUMENTATION = 10
    RESERVED_HEADER = 11
    RESERVED = 12


class StreamManager:
    def __init__(self):
        self.streams = dict()
        self.itm_accumulator = b''
        self.timestamp_accumulator = 0
        self.dwt_accumulator = 0
        self.trace_bytes = b''
        self.continuation_pos = 0
        self.payload_size = 0
        self.itm_port = 0
        self.current_state = PACKET_TYPE.START

    def _add_stream(self, stream):
        self.streams[stream.id] = stream

    def _handle_start(self):
        header = self.trace_bytes[0]

        if header == 0b01110000:
            self.current_state = PACKET_TYPE.OVERFLOW
            return True

        # * Local Timestamp 2
        # 0b0DDD0000
        # D = data (!=000, !=111) : time
        # Payload: 0-4 bytes
        if (
            header & 0b00001111 == 0b00000000
        and header & 0b10000000 == 0b00000000
        and header & 0b01110000 != 0b00000000
        and header & 0b01110000 != 0b01110000
           ):
            self.current_state = PACKET_TYPE.LTS2
            return True

        # * Local Timestamp 1
        # 0bCDDD0000
        # D = data (!=000) : time
        # C = Continuation bit, a byte follows.
        # Payload: 0-4 bytes
        if (
            header & 0b00001111 == 0b00000000
        and header & 0b11000000 == 0b11000000
           ):
            self.current_state = PACKET_TYPE.LTS1_HEADER
            return True

        # 0b10T10100
        if header & 0b11111111 == 0b10010100:
            self.current_state = PACKET_TYPE.GTS1
            return True

        # 0b10T10100
        if header & 0b11111111 == 0b10110100:
            self.current_state = PACKET_TYPE.GTS2
            return True

        # 0bCDDD1S00
        if header & 0b00001011 == 0b00001000:
            self.current_state = PACKET_TYPE.EXTENSION
            return True

        # 0bAAAAA0SS, SS not 0b00
        if (
            header & 0b100 == 0b000
        and header & 0b011 != 0b000
           ):
            self.current_state = PACKET_TYPE.SOURCE_INSTRUMENTATION_HEADER
            return True

        # 0bAAAAA1SS, SS not 0b00
        if (
            header & 0b100 == 0b100
        and header & 0b011 != 0b000
           ):
            self.current_state = PACKET_TYPE.HW_INSTRUMENTATION_HEADER
            return True

        # Reserved
        # 0bCxxx0100
        # 0b0xxx0100
        # 0b10x00100
        # 0b11xx0100
        # 0bx1110000
        if (
            header & 0b1111 == 0b0100
         or header & 0b01111111 == 0b01110000
           ):
            self.current_state = PACKET_TYPE.RESERVED_HEADER
            return True

        return False

    def _handle_local_timestamp(self):
        # Local Timestamp 1 and 2
        # 0bCDDD0000
        # D = data (!=000) - time
        # C = Continuation bit, a byte follows.
        # Payload: 0-4 bytes
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]

        if self.current_state == PACKET_TYPE.LTS2:
            ts = (header & 0b01110000) >> 4
            logging.debug("Local Timestamp2: ts:%d [%s] [%s]", ts, "{0:#x}".format(header), "{0:#010b}".format(header))
            ##print("timestamp:%d" % ts)
            self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.LTS1_HEADER:
            logging.debug("Local Timestamp1 Header: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            if header & 0b10000000:
                logging.debug("\tcontinuation [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                self.continuation_pos = 0
                self.current_state = PACKET_TYPE.LTS1
            else:
                self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.LTS1:
            self.timestamp_accumulator |= (header & 0b01111111) << (self.continuation_pos*7)
            self.continuation_pos += 1
            if header & 0b10000000:
                logging.debug("\tcontinuation-%d [%s] [%s]", self.continuation_pos, "{0:#x}".format(header), "{0:#010b}".format(header))
            else:
                if (self.continuation_pos > 4):
                    print("Error: PACKET_TYPE.LTS1: too many continuation bytes")
                logging.debug("\tlast [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                logging.debug("Local Timestamp1 done %s", self.timestamp_accumulator)
                ##print("timestamp:%d" % self.timestamp_accumulator)
                self.continuation_pos = 0
                self.timestamp_accumulator = 0
                self.current_state = PACKET_TYPE.START

        return True

    def _handle_source_instrumentation(self):
        # Source Instrumentation Packet
        # 0bAAAAA0SS
        # SS = size (!=00) of payload
        # A = Source Address
        # Payload: 1,2 or 4 bytes
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]

        if self.current_state == PACKET_TYPE.SOURCE_INSTRUMENTATION_HEADER:
            self.payload_size = 2**((header & 0b00000011) - 1)
            self.itm_port = header >> 3
            logging.debug("Instrumentation Header: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            logging.debug("\tpayload_size:0x%02x itm_port:0x%02x" % (self.payload_size, self.itm_port))
            if self.itm_port not in self.streams:
                self._add_stream(Stream(self.itm_port, ''))
            self.current_state = PACKET_TYPE.SOURCE_INSTRUMENTATION

        elif self.current_state == PACKET_TYPE.SOURCE_INSTRUMENTATION:
            if self.payload_size > 0:
                logging.debug("\tpayload [0x%02x]" % header)
                self.itm_accumulator += bytes([header])
                self.payload_size -= 1

            if self.payload_size == 0:
                self.current_state = PACKET_TYPE.START
                self.streams[self.itm_port].add_bytes(self.itm_accumulator)
                self.itm_accumulator = b''
                logging.debug("Instrumentation done")

        return True

    def _handle_overflow(self):
        # Overflow
        # Payload: None
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]
        logging.debug("Overflow Packet: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
        self.current_state = PACKET_TYPE.START
        return True

    def _handle_extension_itm(self):
        # The ITM uses a single-byte Extension packet to transmit the stimulus
        # port page number for subsequent Instrumentation packets.
        # 0 PAGE[2:0] 1 0 00
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]
        if self.current_state == PACKET_TYPE.EXTENSION_ITM:
            logging.debug("Extension ITM Packet [0x%02x]" % header)
            page = (header & 0b01110000) >> 4
            logging.debug("\tpage: 0x%x" % page)
            self.current_state = PACKET_TYPE.START
            return True
        return False

    def _handle_extension(self):
        # 1 PAGE[2:0] 1 SH 00
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]
        if self.current_state == PACKET_TYPE.EXTENSION:
            logging.debug("Extension Packet [0x%02x]" % header)
            if (header & 0b10000000) == 0:
                self.current_state = PACKET_TYPE.START
                logging.debug("extension done [0x%02x]" % header)
            return True
        return False


    def _handle_hardware_source(self):
        # Hardware Source Packet
        # 0bAAAAA1SS
        # 0b01100101
        # SS = size (!=00) of payload
        # A = # SW Source Address (the Packet Type discriminator ID)
        # Payload: 1,2 or 4 bytes
        # The DWT unit generates Hardware source packets,
        # that it forwards to the ITM for prioritization and transmission
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]

        if self.current_state == PACKET_TYPE.HW_INSTRUMENTATION_HEADER:
            self.payload_size = 2**(header & 0b00000011 - 1)
            self.source_address = 0
            discriminator_id = header >> 3
            logging.debug("Hardware Source packet: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            logging.debug("\tsize:0x%02x address:0x%02x discriminator_id:%x", self.payload_size, self.source_address, discriminator_id)
            self.current_state = PACKET_TYPE.HW_INSTRUMENTATION

        elif self.current_state == PACKET_TYPE.HW_INSTRUMENTATION:
            if self.payload_size > 0:
                logging.debug("\tpayload [0x%02x]" % header)
                self.dwt_accumulator = self.dwt_accumulator + (int(header) << 8*(4-self.payload_size))
                self.payload_size -= 1

            if self.payload_size == 0:
                self.current_state = PACKET_TYPE.START
                print("address [0x%02x]" % self.dwt_accumulator)
                self.dwt_accumulator = 0
                logging.debug("Instrumentation done")

        return True

    def _handle_reserved(self):
        # Reserved
        # 0bCxxx0100
        # 0b0xxx0100
        # 0b10x00100
        # 0b11xx0100
        # 0bx1110000
        # C = Continuation bit, a byte follows.
        header = self.trace_bytes[0]
        self.trace_bytes = self.trace_bytes[1:]
        if self.current_state == PACKET_TYPE.RESERVED_HEADER:
            logging.debug("Reserved Header: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            if header & 0b10000000:
                logging.debug("\tcontinuation [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                self.current_state = PACKET_TYPE.RESERVED
            else:
                self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.RESERVED:
            if header & 0b10000000:
                logging.debug("\tcontinuation-%d [%s] [%s]", self.continuation_pos, "{0:#x}".format(header), "{0:#010b}".format(header))
            else:
                self.current_state = PACKET_TYPE.START
        return True



    handler_table = {
            PACKET_TYPE.START                     : _handle_start,
            PACKET_TYPE.LTS1_HEADER               : _handle_local_timestamp,
            PACKET_TYPE.LTS1                      : _handle_local_timestamp,
            PACKET_TYPE.LTS2                      : _handle_local_timestamp,
            PACKET_TYPE.SOURCE_INSTRUMENTATION_HEADER  : _handle_source_instrumentation,
            PACKET_TYPE.SOURCE_INSTRUMENTATION         : _handle_source_instrumentation,
            PACKET_TYPE.OVERFLOW                  : _handle_overflow,
            PACKET_TYPE.EXTENSION_ITM             : _handle_extension_itm,
            PACKET_TYPE.EXTENSION                 : _handle_extension,
            PACKET_TYPE.HW_INSTRUMENTATION_HEADER : _handle_hardware_source,
            PACKET_TYPE.HW_INSTRUMENTATION        : _handle_hardware_source,
            PACKET_TYPE.RESERVED_HEADER           : _handle_reserved,
            PACKET_TYPE.RESERVED                  : _handle_reserved,
    }
    def _packet_handler(self, packet_type):
        return self.handler_table[packet_type](self)


    def _parse_trace_bytes(self, itm_bytes):
        self.trace_bytes = self.itm_accumulator + itm_bytes

        while len(self.trace_bytes) > 0:
            rv = self._packet_handler(self.current_state)
            if not rv:
                b = self.trace_bytes[0]
                print("Unknown byte [%s] [%s]" % ("{0:#x}".format(b), "{0:#010b}".format(b)))
                print("state: %s" % self.current_state)
                self.trace_bytes = self.trace_bytes[1:]
                sys.exit(1)


def parse_file(filename):
    streams = StreamManager()
    with open(filename,"rb") as f:
        while True:
            b = f.read(1024)
            if b == b'':
                break
            streams._parse_trace_bytes(b)

# Documentation: ARM DDI 0403E.b, "ARM®v7-M Architecture Reference Manual"
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse an OpenOCD ITM file.")
    parser.add_argument('--input', required=False, help='Input file to parse', default='swo-out.txt')
    parser.add_argument('--debug', required=False, help='Enable logging.DEBUG', action='count', default=0)

    args = parser.parse_args()

    logging_level = logging.INFO
    if args.debug:
        logging_level = logging.DEBUG
    logging.basicConfig(format="%(asctime)s - %(levelname)-8s: %(message)s", level=logging_level)

    parse_file(args.input)
