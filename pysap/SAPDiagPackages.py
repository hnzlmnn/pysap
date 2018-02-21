#!/usr/bin/env python


# Standard imports
import logging
from re import escape
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
from scapy.packet import bind_layers
# Custom imports
import pysap
from pysap import SAPRFC
from pysap.SAPNI import SAPNI
from pysap.SAPDiagItems import *
from pysap.SAPDiagClient import SAPDiagConnection
from pysap.SAPDiag import (SAPDiag, SAPDiagDP, diag_appl_ids, diag_appl_sids,
                           diag_item_types)
# adding for text info rendering # gelim
from collections import OrderedDict

# Bind the SAPDiag layer
bind_layers(SAPNI, SAPDiag, )
bind_layers(SAPNI, SAPDiagDP, )
bind_layers(SAPDiagDP, SAPDiag, )
bind_layers(SAPDiag, SAPDiagItem, )
bind_layers(SAPDiagItem, SAPDiagItem, )


class SAPDiagPackages:

    @staticmethod
    def eom():
        return SAPDiagItem(item_type=0x0c)

    @staticmethod
    def ses(**fields):
        return SAPDiagItem(item_value=SAPDiagSES(**fields), item_type=0x01)

    @staticmethod
    def xmlblob(xml, type):
        return SAPDiagItem(item_value=xml, item_type=type)

    @staticmethod
    def empty_xml_block(type):
        return SAPDiagPackages.xmlblob("""<?xml version="1.0" encoding="sap*"?><DATAMANAGER></DATAMANAGER>""", type)

    @staticmethod
    def tcode(tcode):
        return SAPDiagItem(item_value=tcode, item_type=0x10, item_id=0x0c, item_sid=0x04)

    @staticmethod
    def dialog_step_number(stepnumber):
        return SAPDiagItem(item_value=SAPDiagStep(step=stepnumber),
                           item_type=0x10, item_id=0x04, item_sid=0x26)

    @staticmethod
    def appl_dynn_chl(**fields):
        return SAPDiagItem(item_value=SAPDiagAPPL_DYNN_CHL(**fields), item_type=0x10, item_id=0x05, item_sid=0x01)

    @staticmethod
    def login(username, password, client):
        return SAPDiagItem(
            item_value=SAPDiagDyntAtom(items=[
                SAPDiagDyntAtomItem(field2_text=client, field2_maxnrchars=3, row=0, group=0, dlg_flag_2=0, dlg_flag_1=0,
                                    etype=130, field2_mlen=3, attr_DIAG_BSD_YES3D=1, field2_dlen=len(client), block=1,
                                    col=20),
                SAPDiagDyntAtomItem(field2_text=username, field2_maxnrchars=12, row=2, group=0, dlg_flag_2=1,
                                    dlg_flag_1=0,
                                    etype=130, field2_mlen=12, attr_DIAG_BSD_YES3D=1, field2_dlen=len(username),
                                    block=1, col=20),
                SAPDiagDyntAtomItem(field2_text=password, field2_maxnrchars=40, row=3, group=0, dlg_flag_2=1,
                                    dlg_flag_1=4,
                                    etype=130, field2_mlen=12, attr_DIAG_BSD_YES3D=1, attr_DIAG_BSD_INVISIBLE=1,
                                    field2_dlen=len(password), block=1, col=20)]),
            item_type=0x12,
            item_id=0x09,
            item_sid=0x02
        )
