# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
from struct import unpack
from collections import defaultdict
# External imports
from scapy.fields import (ByteEnumField, IntField, ByteField, LenField,
                          StrFixedLenField, ConditionalField, FieldLenField,
                          PacketListField, BitField, LEIntField, PacketField,
                          SignedIntField, StrField, SignedShortField,
                          ByteEnumKeysField, PadField, ShortField)

from pysap.SAPDiagRFC import bind_rfcitem
from pysap.utils.fields import PacketNoPadded
import pysapcompress
from pysapcompress import DecompressError, CompressError


class SAPDiagRFCOne(PacketNoPadded):
    name = "SAP Diag RFC One"
    fields_desc = [
        StrField("value", "")
    ]

bind_rfcitem(SAPDiagRFCOne, 0x01, 0x06, 0x00, 0x15)

class SAPDiagRFCItemsEnd(PacketNoPadded):
    name = "SAP Diag RFC Items End"
    fields_desc = [
    ]

bind_rfcitem(SAPDiagRFCItemsEnd, 0xff, 0xff)

class SAPDiagRFCTableName(PacketNoPadded):
    name = "SAP Diag RFC Table Name"
    fields_desc = [
        StrField("table_name", "")
    ]

bind_rfcitem(SAPDiagRFCTableName, 0x02, 0x13, 0x03, 0x01)

class SAPDiagRFCTableDimensions(PacketNoPadded):
    name = "SAP Diag RFC Table Dimensions"
    fields_desc = [
        IntField("fill_length", 0),
        IntField("width_length", 0)
    ]

bind_rfcitem(SAPDiagRFCTableDimensions, 0x03, 0x01, 0x03, 0x02)

class SAPDiagRFCTable(PacketNoPadded):
    def do_compress(self, s):
        """Compress a string using SAP compression C++ extension.

        :param s: string to compress
        :type s: C{string}

        :return: string compression header plus the compressed string
        :rtype: C{string}

        :raise pysapcompress.Error: when a compression error is raised
        """
        if len(s) > 0:
            # Compress the payload and return the output
            (_, _, outbuffer) = pysapcompress.compress(s, pysapcompress.ALG_LZH)
            return outbuffer

    def do_decompress(self, s, length):
        """Decompress a string using SAP compression C++ extension.

        :param s: compression header plus compressed string
        :type s: C{string}

        :param length: reported compressed length
        :type length: ``int``

        :return: decompressed string
        :rtype: C{string}

        :raise pysapcompress.Error: when a decompression error is raised
        """
        if len(s) > 0:
            # Decompress the payload and return the output
            (_, _, outbuffer) = pysapcompress.decompress(s, length)
            return outbuffer

    # def pre_dissect(self, s):
    #     """Prepares the packet for dissection. If the compression flag is set,
    #     decompress the payload.
    #     """
    #     # If the compression flag is set, decompress everything after the headers
    #     if s[7] == "\x01":
    #         # First need to get the reported decompressed length
    #         (reported_length,) = unpack("<I", s[8:12])
    #
    #         # Then return the headers (Diag and Compression) and the payload (message field)
    #         try:
    #             return s[:16] + self.do_decompress(s[8:], reported_length)
    #         except DecompressError:
    #             return s
    #     # Uncompressed packet, just return them
    #     return s
    #
    # def post_build(self, p, pay):
    #     """Compress the payload. If the compression flag is set, compress both
    #     the message field and the payload.
    #     """
    #     if pay is None:
    #         pay = ''
    #     if self.compress == 1:
    #         payload = "".join([str(item) for item in self.message]) + pay
    #         if len(payload) > 0:
    #             try:
    #                 return p[:8] + self.do_compress(payload)
    #             except CompressError:
    #                 return p + pay
    #     return p + pay

class SAPDiagRFCTableCompressionHeader(PacketNoPadded):
    name = "SAP Diag RFC Table Compression Header"
    fields_desc = [
        LEIntField("uncompressed_length", 0),
        ByteField("compression_algorithm", 0),
        ShortField("magic_bytes", 0),
        ByteField("special", 0),

    ]

class SAPDiagRFCTableContentFirst(SAPDiagRFCTable):
    name = "SAP Diag RFC Table Content First"
    fields_desc = [
        StrFixedLenField("pad", "\x7b\x02\x1c\xea", 4),
        IntField("table_content_length", 0),
        PacketField("table_compression_header", None, SAPDiagRFCTableCompressionHeader),
        StrField("table_content", "")
    ]

bind_rfcitem(SAPDiagRFCTableContentFirst, 0x03, 0x02, 0x03, 0x05)

class SAPDiagRFCTableContent(SAPDiagRFCTable):
    name = "SAP Diag RFC Table Content"
    fields_desc = [
        StrField("table_content", "")
    ]

bind_rfcitem(SAPDiagRFCTableContent, 0x03, 0x05, 0x03, 0x05)