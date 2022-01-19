#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Author: Adrian Negreanu

import socket
import time
import sys
import logging
import argparse


class PACKET_TYPE:
    START = 0
    LTS1_HEADER = 1
    LTS1 = 2
    LTS2 = 3
    SW_SOURCE_HEADER = 4
    SW_SOURCE = 5
    OVERFLOW = 6
    EXTENSION_ITM = 7
    EXTENSION = 8
    HW_SOURCE_HEADER = 9
    HW_SOURCE = 10
    RESERVED_HEADER = 11
    RESERVED = 12


class Stream:
    def __init__(self, id, header = ''):
        self.id = id
        self._buffer = []
        self._header = header

    def add_bytes(self, s):
        pass
        if len(s) == 1:
            inb = s[0]
            if inb == 0x0a:
                logging.info("port:%s %s" % (self.id, self._header + ''.join(self._buffer)) )
                self._buffer = []
                return
            if 0x20 < inb and inb < 0x7E:
                self._buffer.append(chr(inb))
        if len(s) > 1:
            logging.info('0x', end='')
            for inb in s:
                self._buffer.append(f'{inb:02x}')
                logging.info("port:%s %s" % (self.id, self._header + ''.join(self._buffer)), end='')
                self._buffer = []
            #print()


class RawStream(Stream):
    def __init__(self, id, header = ''):
        super().__init__(id, header)

    def add_bytes(self, s):
        for inb in s:
            self._buffer.append(f'{inb:02x}')
            logging.info("port:%s %s" % (self.id, self._header + ''.join(self._buffer)))
            self._buffer = []
        #print()


class Uint32Stream(Stream):
    def __init__(self, id, header = ''):
        super().__init__(id, header)
        self.__bcount = 0

    def add_bytes(self, s):
        for inb in s:
            self._buffer.append(f'{inb:02x}')
            self.__bcount += 1
            if self.__bcount >= 4:
                logging.info("port:%s 0x%s" % (self.id, self._header + ''.join(self._buffer)))
                self.__bcount = 0
                self._buffer = []
        #print()


class AsciiStream(Stream):
    def __init__(self, id, header = ''):
        super().__init__(id, header)

    def add_bytes(self, s):
        for inb in s:
            if inb == 0x0a:
                logging.info("port:%s %s" % (self.id, self._header + ''.join(self._buffer)) )
                self._buffer = []
                continue

            if 0x20 <= inb and inb <= 0x7E:
                self._buffer.append(chr(inb))
            else:
                logging.error(f"port:{self.id} non-printable byte [0x{inb:02x}]")


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

    def add_raw_stream(self, port):
        self._add_stream(RawStream(port, ''))

    def add_uint32_stream(self, port):
        self._add_stream(Uint32Stream(port, ''))

    def add_ascii_stream(self, port):
        self._add_stream(AsciiStream(port, ''))

    def _add_stream(self, stream):
        self.streams[stream.id] = stream

    def _handle_start(self):
        header = self._peek_byte()

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
            self.current_state = PACKET_TYPE.SW_SOURCE_HEADER
            return True

        # 0bAAAAA1SS, SS not 0b00
        if (
            header & 0b100 == 0b100
        and header & 0b011 != 0b000
           ):
            self.current_state = PACKET_TYPE.HW_SOURCE_HEADER
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
        header = self._peek_byte()
        self._pop_byte()

        if self.current_state == PACKET_TYPE.LTS2:
            ts = (header & 0b01110000) >> 4
            logging.debug("Local Timestamp2: ts:%d [%s] [%s]", ts, "{0:#x}".format(header), "{0:#010b}".format(header))
            ##print("timestamp:%d" % ts)
            self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.LTS1_HEADER:
            logging.debug("Local Timestamp1 Header: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            if header & 0b10000000:
                logging.debug("    continuation [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                self.continuation_pos = 0
                self.current_state = PACKET_TYPE.LTS1
            else:
                self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.LTS1:
            self.timestamp_accumulator |= (header & 0b01111111) << (self.continuation_pos*7)
            self.continuation_pos += 1
            if header & 0b10000000:
                logging.debug("    continuation-%d [%s] [%s]", self.continuation_pos, "{0:#x}".format(header), "{0:#010b}".format(header))
            else:
                if (self.continuation_pos > 4):
                    logging.error("PACKET_TYPE.LTS1: too many continuation bytes")
                logging.debug("    last [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                logging.debug("Local Timestamp1 done %s", self.timestamp_accumulator)
                ##print("timestamp:%d" % self.timestamp_accumulator)
                self.continuation_pos = 0
                self.timestamp_accumulator = 0
                self.current_state = PACKET_TYPE.START

        return True

    def _handle_sw_source(self):
        # Source Instrumentation Packet
        # 0bAAAAA0SS
        # SS = size (!=00) of payload
        # A = Source Address
        # Payload: 1,2 or 4 bytes
        header = self._peek_byte()
        self._pop_byte()

        if self.current_state == PACKET_TYPE.SW_SOURCE_HEADER:
            self.payload_size = 2**((header & 0b00000011) - 1)
            self.itm_port = header >> 3
            logging.debug("SW_SOURCE: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            logging.debug("    payload_size:0x%02x itm_port:0x%02x" % (self.payload_size, self.itm_port))
            if self.itm_port not in self.streams:
                logging.error("SW_SOURCE: unknown port [%d]" % self.itm_port)
                self.itm_accumulator = b''
                self.current_state = PACKET_TYPE.START
                self.itm_port = 0
                ##sys.exit(1)
                return False
            self.current_state = PACKET_TYPE.SW_SOURCE

        elif self.current_state == PACKET_TYPE.SW_SOURCE:
            if self.payload_size > 0:
                logging.debug("    payload [0x%02x]" % header)
                self.itm_accumulator = bytes([header]) + self.itm_accumulator
                self.payload_size -= 1

            if self.payload_size == 0:
                self.current_state = PACKET_TYPE.START
                self.streams[self.itm_port].add_bytes(self.itm_accumulator)
                self.itm_accumulator = b''
                logging.debug("SW_SOURCE done")

        return True

    def _handle_overflow(self):
        # Overflow
        # Payload: None
        header = self._peek_byte()
        self._pop_byte()
        logging.debug("Overflow Packet: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
        self.current_state = PACKET_TYPE.START
        return True

    def _handle_extension_itm(self):
        # The ITM uses a single-byte Extension packet to transmit the stimulus
        # port page number for subsequent Instrumentation packets.
        # 0 PAGE[2:0] 1 0 00
        header = self._peek_byte()
        self._pop_byte()
        if self.current_state == PACKET_TYPE.EXTENSION_ITM:
            logging.debug("Extension ITM Packet [0x%02x]" % header)
            page = (header & 0b01110000) >> 4
            logging.debug("    page: 0x%x" % page)
            self.current_state = PACKET_TYPE.START
            return True
        return False

    def _handle_extension(self):
        # 1 PAGE[2:0] 1 SH 00
        header = self._peek_byte()
        self._pop_byte()
        if self.current_state == PACKET_TYPE.EXTENSION:
            logging.debug("Extension Packet [0x%02x]" % header)
            if (header & 0b10000000) == 0:
                self.current_state = PACKET_TYPE.START
                logging.debug("extension done [0x%02x]" % header)
            return True
        return False


    def _handle_hw_source(self):
        # Hardware Source Packet
        # 0bAAAAA1SS
        # 0b00011101
        # SS = size (!=00) of payload
        # A = # SW Source Address (the Packet Type discriminator ID)
        # Payload: 1,2 or 4 bytes
        # The DWT unit generates Hardware source packets,
        # that it forwards to the ITM for prioritization and transmission
        header = self._peek_byte()
        self._pop_byte()

        if self.current_state == PACKET_TYPE.HW_SOURCE_HEADER:
            self.payload_size = 2**(header & 0b00000011 - 1)
            self.source_address = 0
            discriminator_id = header >> 3
            logging.debug("HW_SOURCE: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            logging.debug("    size:0x%02x address:0x%02x discriminator_id:%x", self.payload_size, self.source_address, discriminator_id)
            if discriminator_id not in [0, 1, 2, *range(8,23)]:
                logging.error(f"HW_SOURCE: invalid discriminator_id [{discriminator_id}]")
                self.current_state = PACKET_TYPE.START
                self.dwt_accumulator = 0
                return False
            self.current_state = PACKET_TYPE.HW_SOURCE

        elif self.current_state == PACKET_TYPE.HW_SOURCE:
            if self.payload_size > 0:
                logging.debug("    payload [0x%02x]" % header)
                self.dwt_accumulator = self.dwt_accumulator + (int(header) << 8*(4-self.payload_size))
                self.payload_size -= 1

            # D4.3 DWT use of Hardware source packets
            # D4.3.3   Periodic PC sample packets, discriminator ID2
            if self.payload_size == 0:
                self.current_state = PACKET_TYPE.START
                logging.info("dwt-pc:0x%08x" % self.dwt_accumulator)
                self.dwt_accumulator = 0
                logging.debug("HW_SOURCE done")

        return True

    def _handle_reserved(self):
        # Reserved
        # 0bCxxx0100
        # 0b0xxx0100
        # 0b10x00100
        # 0b11xx0100
        # 0bx1110000
        # C = Continuation bit, a byte follows.
        header = self._peek_byte()
        self._pop_byte()
        if self.current_state == PACKET_TYPE.RESERVED_HEADER:
            logging.debug("Reserved Header: [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
            if header & 0b10000000:
                logging.debug("    continuation [%s] [%s]", "{0:#x}".format(header), "{0:#010b}".format(header))
                self.current_state = PACKET_TYPE.RESERVED
            else:
                self.current_state = PACKET_TYPE.START

        elif self.current_state == PACKET_TYPE.RESERVED:
            if header & 0b10000000:
                logging.debug("    continuation-%d [%s] [%s]", self.continuation_pos, "{0:#x}".format(header), "{0:#010b}".format(header))
            else:
                self.current_state = PACKET_TYPE.START
        return True


    handler_table = {
            PACKET_TYPE.START             : _handle_start,
            PACKET_TYPE.LTS1_HEADER       : _handle_local_timestamp,
            PACKET_TYPE.LTS1              : _handle_local_timestamp,
            PACKET_TYPE.LTS2              : _handle_local_timestamp,
            PACKET_TYPE.SW_SOURCE_HEADER  : _handle_sw_source,
            PACKET_TYPE.SW_SOURCE         : _handle_sw_source,
            PACKET_TYPE.OVERFLOW          : _handle_overflow,
            PACKET_TYPE.EXTENSION_ITM     : _handle_extension_itm,
            PACKET_TYPE.EXTENSION         : _handle_extension,
            PACKET_TYPE.HW_SOURCE_HEADER  : _handle_hw_source,
            PACKET_TYPE.HW_SOURCE         : _handle_hw_source,
            PACKET_TYPE.RESERVED_HEADER   : _handle_reserved,
            PACKET_TYPE.RESERVED          : _handle_reserved,
    }
    def _packet_handler(self, packet_type):
        return self.handler_table[packet_type](self)

    def _peek_byte(self):
        return self.trace_bytes[0]

    def _pop_byte(self):
        logging.debug("<< 0x%02x", self.trace_bytes[0])
        self.trace_bytes = self.trace_bytes[1:]

    def _parse_bytes(self, itm_bytes):
        self.trace_bytes = self.itm_accumulator + itm_bytes

        while len(self.trace_bytes) > 0:
            rv = self._packet_handler(self.current_state)
            if not rv:
                b = self._peek_byte()
                self._pop_byte()
                logging.error("unknown byte [%s] [%s]" % ("{0:#x}".format(b), "{0:#010b}".format(b)))
                logging.error("state: %s" % self.current_state)
                ##sys.exit(1)
                return False


def parse_file(filename, streams):
    try:
        with open(filename,"rb") as f:
            while True:
                b = f.read(1024)
                if b == b'':
                    break
                streams._parse_bytes(b)
    except FileNotFoundError as e:
        logging.error("%s", e)

# Documentation: ARM DDI 0403E.b, "ARM®v7-M Architecture Reference Manual"
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse an OpenOCD ITM file.")
    parser.add_argument('--input', required=False, help='Input file to parse', default='c:/Users/nxf25307/workspace/debug/openocd-code-2/swo-cm7.bin')
    parser.add_argument('--debug', required=False, help='Enable logging.DEBUG', action='count', default=0)
    parser.add_argument('--ascii', required=False, help='Port data is ascii', type=int, action='append')
    parser.add_argument('--uint32', required=False, help='Port data is uint32', type=int, action='append')

    args = parser.parse_args()

    logging_level = logging.INFO
    if args.debug:
        logging_level = logging.DEBUG
    logging.basicConfig(format="%(asctime)s - %(levelname)-8s: %(message)s", level=logging_level)

    streams = StreamManager()
    streams.add_ascii_stream(0)

    if args.ascii:
        for port in args.ascii:
            streams.add_ascii_stream(port)

    if args.uint32:
        for port in args.uint32:
            streams.add_uint32_stream(port)

    parse_file(args.input, streams)
