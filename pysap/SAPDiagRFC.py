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
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers
from scapy.fields import (ByteEnumField, IntField, ByteField, LenField,
                          StrFixedLenField, ConditionalField, FieldLenField,
                          PacketListField, BitField, LEIntField, PacketField,
                          SignedIntField, StrField, SignedShortField,
                          ByteEnumKeysField, ShortField)
# Custom imports
import pysapcompress

from pysap.SAPDiag import bind_diagitem
from pysap.SAPNI import SAPNI
from pysap.SAPSNC import SAPSNCFrame
from pysap.utils.fields import (PacketNoPadded, ByteMultiEnumKeysField, MutablePacketField,
                                StrNullFixedLenField, StrEncodedPaddedField)


class SAPDiagUH(Packet):
    """SAP Diag RFC Unicode Header packet

    This packet is used for initialization of Diag connections. Usually
    there's no need to change any value more that the terminal.
    """
    name = "SAP Diag RFC Unicode Header"
    fields_desc = [  # Unicode Header
        IntField("code_page", 0),
        ByteField("CE", 0),  # unknown
        ByteField("ET", 0),  # unknown
        ByteField("CS", 0),  # unknown
        IntField("return_code", 0),
    ]


# RFC Item ID1
rfc_item_id1 = {
    0x00: "0x00",  # unknown, but seen
    0x01: "0x01",  # unknown, but seen
    0x02: "0x02",  # unknown, but seen
    0x03: "0x03",  # unknown, but seen
    0x04: "0x04",  # unknown, but seen
    0x05: "0x05",  # unknown, but seen
    0x06: "0x06",  # unknown, but seen
    0x3c: "0x3C",  # unknown, but seen
    0xff: "END",
}
"""RFC Item ID1"""

# RFC Item ID2
rfc_item_id2 = {
    0x01: "0x01",  # unknown, but seen
    0x02: "0x02",  # unknown, but seen
    0x05: "0x05",  # unknown, but seen
    0x06: "0x06",  # unknown, but seen
    0x0b: "0x0b",  # unknown, but seen
    0x09: "0x09",  # unknown, but seen
    0x11: "0x11",  # unknown, but seen
    0x12: "0x12",  # unknown, but seen
    0x13: "0x13",  # unknown, but seen
    0x14: "0x14",  # unknown, but seen
    0x15: "0x15",  # unknown, but seen
    0x17: "0x17",  # unknown, but seen
    0x20: "0x20",  # unknown, but seen
    0x36: "0x36",  # unknown, but seen
    0x37: "0x37",  # unknown, but seen
    0xff: "END",
}
"""RFC Item ID2"""

# RFC Item ID3
rfc_item_id3 = {
    0x00: "0x00",  # unknown, but seen
    0x01: "0x01",  # unknown, but seen
    0x02: "0x02",  # unknown, but seen
    0x03: "0x03",  # unknown, but seen
    0x04: "0x04",  # unknown, but seen
    0x05: "0x05",  # unknown, but seen
    0x06: "0x06",  # unknown, but seen
    0xff: "END",
}
"""RFC Item ID3"""

# RFC Item ID4
rfc_item_id4 = {
    0x00: "0x00",  # unknown, but seen
    0x01: "0x01",  # unknown, but seen
    0x02: "0x02",  # unknown, but seen
    0x03: "0x03",  # unknown, but seen
    0x04: "0x04",  # unknown, but seen
    0x05: "0x05",  # unknown, but seen
    0x06: "0x06",  # unknown, but seen
    0x15: "0x15",  # unknown, but seen
    0xff: "END",
}
"""RFC Item ID4"""

rfc_item_classes = {}
"""Dictionary for registering Diag item classes """


def bind_rfcitem(item_class, item_id1, item_id2, item_id3=None, item_id4=None):
    """Registers a Diag item class associated to a given type, ID and SID.

    :param item_class: item class to associate
    :type item_class: :class:`SAPDiagItem` class

    :param item_type: item type to associate
    :type item_type: ``int`` or ``string``

    :param item_id: item ID to associate
    :type item_id: ``int``

    :param item_sid: item SID to associate
    :type item_sid: ``int``
    """
    try:
        rfc_item_classes[item_id1]
    except KeyError:
        rfc_item_classes[item_id1] = {}
    try:
        rfc_item_classes[item_id1][item_id2]
    except KeyError:
        rfc_item_classes[item_id1][item_id2] = {}
    if item_id3 and item_id4:
        try:
            rfc_item_classes[item_id1][item_id2][item_id3]
        except KeyError:
            rfc_item_classes[item_id1][item_id2][item_id3] = {}
        # rfc_item_classes[item_id1][item_id2][item_id3][item_id4] must be a dictionary now
        rfc_item_classes[item_id1][item_id2][item_id3][item_id4] = item_class
    else:
        rfc_item_classes[item_id1][item_id2] = item_class


rfc_unregistered_ids = []


def rfc_item_get_class(pkt, item_id1, item_id2, item_id3=None, item_id4=None):
    """Obtains the Diag item class according to the type, ID and SID of the packet.
    If the Type/ID/SID is not registered, returns None.

    :param pkt: the item to look at
    :type pkt: :class:`SAPDiagItem`

    :param item_type: function that returns the item type
    :type item_type: ``int``

    :param item_id: function that returns the item ID
    :type item_id: ``int``

    :param item_sid: functions that returns the item SID
    :type item_sid: ``int``

    :return: the associated :class:`SAPDiagItem` class if registered or None
    """
    if item_id1 in rfc_item_classes and \
            item_id2 in rfc_item_classes[item_id1]:
        if item_id3 and item_id4 and \
                item_id3 in rfc_item_classes[item_id1][item_id2] and \
                item_id4 in rfc_item_classes[item_id1][item_id2][item_id3]:
            return rfc_item_classes[item_id1][item_id2][item_id3][item_id4]
        if not isinstance(rfc_item_classes[item_id1][item_id2], dict):
            return rfc_item_classes[item_id1][item_id2]
    rfc_unregistered_ids.append((item_id1, item_id2, item_id3, item_id4, pkt))
    return SAPDiagRFCGeneric


# Diag RFC items
class SAPDiagRFCItem(PacketNoPadded):
    name = "SAP Diag RFC Item"
    fields_desc = [
        ByteEnumKeysField("item_id1", 0x00, rfc_item_id1),
        ByteEnumKeysField("item_id2", 0x00, rfc_item_id2),
        ConditionalField(ByteEnumKeysField("item_id3", 0x00, rfc_item_id3), lambda pkt: pkt.item_id1 != 0xff),
        ConditionalField(ByteEnumKeysField("item_id4", 0x00, rfc_item_id4), lambda pkt: pkt.item_id1 != 0xff),
        ShortField("item_length", 0),
        MutablePacketField(
            "item_value",
            None,
            # length_from=lambda pkt: pkt.item_length, # should fit
            length_from=lambda pkt: pkt.item_length,  # should fit
            get_class=rfc_item_get_class,
            evaluators=[
                lambda item: item.item_id1,
                lambda item: item.item_id2,
                lambda item: item.item_id3,
                lambda item: item.item_id4
            ],
        )
    ]


# Diag RFC
class SAPDiagRFC(PacketNoPadded):
    name = "SAP Diag RFC"
    fields_desc = [
        StrFixedLenField("protocol",
                         "\x01\x01\x00\x08\x01\x01\x01\x01\x04\x01\x01\x00\x01\x01\x01\x03"
                         "\x00\x04\x00\x00\x0e\x0b\x01\x03\x01\x06\x00\x0b", 28),
        MutablePacketField("header", None, length_from=lambda x: 11, get_class=lambda x: SAPDiagUH),
        PacketListField("message", None, SAPDiagRFCItem)
    ]

    def get_item(self, item_id1, item_id2, item_id3=None, item_id4=None):
        return [self.message[i] for i in self.get_item_indexes(item_id1, item_id2, item_id3, item_id4)]

    def get_item_indexes(self, item_id1, item_id2, item_id3=None, item_id4=None):
        """Get an item from the packet's message. Returns None if the message
        is not found, or a list if the item is found multiple times.

        :param item_type: item type byte or string value
        :type item_type: ``int`` or C{string} or ``list``

        :param item_id: item ID byte or string value
        :type item_id: ``int`` or C{string} or ``list``

        :param item_sid: item SID byte or string value
        :type item_sid: ``int`` or C{string} or ``list``

        :return: list of items found on the packet or None
        :rtype: ``list`` of :class:`SAPDiagItem`
        """
        # Expand list lookups
        items = []
        if item_id1 is not None and type(item_id1) == list:
            for iid in item_id1:
                items.extend(self.get_item_indexes(iid, item_id2, item_id3, item_id4))
            return items
        if item_id2 is not None and type(item_id2) == list:
            for iid in item_id2:
                items.extend(self.get_item_indexes(item_id1, iid, item_id3, item_id4))
            return items
        if item_id3 is not None and type(item_id3) == list:
            for iid in item_id3:
                items.extend(self.get_item_indexes(item_id1, item_id2, iid, item_id4))
            return items
        if item_id4 is not None and type(item_id4) == list:
            for iid in item_id4:
                items.extend(self.get_item_indexes(item_id1, item_id2, item_id3, iid))
            return items

        # Perform name lookups
        if item_id1 is not None and isinstance(item_id1, str):
            item_id1 = list(rfc_item_id1.keys())[list(rfc_item_id1.values()).index(item_id1)]
        if item_id2 is not None and isinstance(item_id2, str):
            item_id2 = list(rfc_item_id2.keys())[list(rfc_item_id2.values()).index(item_id2)]
        if item_id3 is not None and isinstance(item_id3, str):
            item_id3 = list(rfc_item_id3.keys())[list(rfc_item_id3.values()).index(item_id3)]
        if item_id4 is not None and isinstance(item_id4, str):
            item_id4 = list(rfc_item_id4.keys())[list(rfc_item_id4.values()).index(item_id4)]

        # Filter and return items
        if item_id3 is None and item_id4:
            items = [i for i, item in enumerate(self.message) if
                     hasattr(item, "item_id1") and item.item_id1 == item_id1 and item.item_id2 == item_id2]
        else:
            items = [i for i, item in enumerate(self.message) if
                     hasattr(item,
                             "item_id1") and item.item_id1 == item_id1 and item.item_id2 == item_id2 and item.item_id3 == item_id3 and item.item_id4 == item_id4]

        return items

    def get_items_following(self, item_id1, item_id2, item_id3=None, item_id4=None, types=None, attribute=None):
        chains = []
        if types is None:
            types = []
        elif type(types) is tuple:
            types = [types]
        for i in self.get_item_indexes(item_id1, item_id2, item_id3, item_id4):
            items = []
            while i + len(items) < len(self.message):
                item = self.message[i + len(items)]
                if (len(items) == 0 or types is None or (types and (item.item_id1, item.item_id2, item.item_id3, item.item_id4) in types)):
                    if attribute:
                        items.append(getattr(item, attribute))
                    else:
                        items.append(item)
                else:
                    # if a non-matching element is found, stop appending
                    break
            chains.append(items)
        return chains


bind_diagitem(SAPDiagRFC, 0x10, 0x08, 0x04)


class SAPDiagRFCGeneric(PacketNoPadded):
    name = "SAP Diag RFC Generic Item"
    fields_desc = [
        StrField("item_value", "")
    ]
