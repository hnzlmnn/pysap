#!/usr/bin/env python
#
# Utilities for creating and parsing SAP Diag Packages


# Standard imports
import logging
from re import escape
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
from scapy.packet import bind_layers
# Custom imports
import pysap
from pysap.SAPNI import SAPNI
from pysap.SAPDiagItems import *
from pysap.SAPDiag import (SAPDiag, SAPDiagDP)
from pysap.SAPDiagRFC import SAPDiagRFC, SAPDiagRFCItem
from pysap.SAPDiagRFCItems import *

# Bind the SAPDiag layer
bind_layers(SAPNI, SAPDiag, )
bind_layers(SAPNI, SAPDiagDP, )
bind_layers(SAPDiagDP, SAPDiag, )
bind_layers(SAPDiag, SAPDiagItem, )
bind_layers(SAPDiagItem, SAPDiagItem, )
bind_layers(SAPDiagItem, SAPDiagRFC, )
bind_layers(SAPDiagRFC, SAPDiagRFCItem, )

class SAPDiagError(Exception):
    pass

class SAPDiagUtils:

    @staticmethod
    def is_duplicate_login(response):
        if response[SAPDiag].get_item("APPL4", "DYNT", "DYNT_ATOM"):
            for item in response[SAPDiag].get_item("APPL4", "DYNT", "DYNT_ATOM"):
                try:
                    for atom in item.item_value.items:
                        if atom.dlg_flag_1 is 0 and atom.dlg_flag_2 is 0 and atom.field2_text:
                            if "is already logged on in" in atom.field2_text:
                                return True, atom.field2_text
                except AttributeError:
                    pass
        return False, ""

    @staticmethod
    def is_successful_login(response, username):
        # If the response contain a MESSAGE item, it could be a error message of the user requesting a password change
        if response[SAPDiag].get_item("APPL", "ST_R3INFO", "MESSAGE"):
            status = response[SAPDiag].get_item("APPL", "ST_R3INFO", "MESSAGE")[0].item_value
            if status == "Enter a new password":
                return False, "Expired password"
            elif status == "E: Log on with a dialog user":
                return False, "No Dialog user (log on with RFC)"
            elif status[:10] == "E: Client ":  # E: Client XXX is not available in this system
                return False, "Client does not exist"
        # Check if the user is already logged in
        elif SAPDiagUtils.is_duplicate_login(response)[0]:
            return False, "Duplicate login"
        # If the ST_USER USERNAME item is set to the username, the login was successful
        elif response[SAPDiag].get_item("APPL", "ST_USER", "USERNAME"):
            st_username = response[SAPDiag].get_item("APPL", "ST_USER", "USERNAME")[0].item_value
            if st_username == username:
                return True, ""
        # If the response doesn't contain a message item but the Internal Mode Number is set to 1, we have found a
        # successful login
        elif response[SAPDiag].get_item("APPL", "ST_R3INFO", "IMODENUMBER"):
            imodenumber = response[SAPDiag].get_item("APPL", "ST_R3INFO", "IMODENUMBER")[0].item_value
            if imodenumber == "\x00\x01":
                return True, ""
        print(response.show())
        return False, "Unknow error"

    @staticmethod
    def dump_rfc_data(responses):
        for response in responses:
            try:
                rfc = response[SAPDiag].get_rfc()
                # for response in rfc:
                #     print(response.show())
                tables = rfc[0].item_value.get_items_following(
                    0x03, 0x02, 0x03, 0x05,
                    types=(0x03, 0x05, 0x03, 0x05),
                    attribute="item_value"
                )
                from pprint import pprint
                for table in tables:
                    # pprint(table)
                    ch = None
                    compressed = ""
                    for chunk in table:
                        if isinstance(chunk, SAPDiagRFCTableContentFirst):
                            ch = chunk.table_compression_header
                        compressed += chunk.table_content
                    # print(ch.uncompressed_length)
                        (_, _, decompressed) = pysapcompress.decompress(str(ch) + compressed, ch.uncompressed_length)
                    print("length", len(decompressed), "type", type(decompressed), "decompressed:", decompressed)

                # print(response[SAPDiag].get_item("APPL", "RFC_TR", "RFC_TR_MOR")[0].item_value)
                # print(response[SAPDiagRFC])
                # print(response.show2())
                continue
            except IndexError as error:
                print("IndexError", error)
                pass
            except AttributeError as error:
                print("AttributeError", error)
                pass
            except TypeError as error:
                print("TypeError", error)
                pass
            except:
                raise
            print("No RFC")
        from SAPDiagRFC import rfc_unregistered_ids
        # print(rfc_unregistered_ids)

    @staticmethod
    def support_data():
        from pysap.SAPDiagItems import support_data_sapgui_702_java5 as support_data
        # support_data_sapnw_750.setfieldval("RFC_DIALOG", 0)
        # support_data.setfieldval("NORFC", 1)
        return support_data

    @staticmethod
    def get_error(response):
        try:
            print(response[SAPDiag].info)
            if response[SAPDiag].info == u"\u6e69\u6176\u696c\u2064\u7567\u2069\u6f63\u6e6e\u6365\u2074\u6164\u6174":
                return "Invalid GUI connect data"
            elif response[SAPDiag].info == "\x69\x6e\x76\x61\x6c\x69\x64\x20\x67\x75\x69\x20\x64\x61\x74\x61":
                return "Invalid GUI connect data"

        except:
            pass
        return None

    @staticmethod
    def raise_if_error(response):
        error = SAPDiagUtils.get_error(response)
        if error:
            raise SAPDiagError(error)