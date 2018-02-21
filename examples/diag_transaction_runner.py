#!/usr/bin/env python
# ===========
#
# Modifications for screen text elements parsing + tech info
# Copyright (C) 2016-2017 by Mathieu Geli, ERPScan
#
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
from pysap.SAPDiag import (SAPDiag, SAPDiagDP, diag_appl_ids, diag_appl_sids,
                           diag_item_types)
# adding for text info rendering # gelim
from collections import OrderedDict

from pysap.SAPDiagActions import SAPDiagActions

# Bind the SAPDiag layer
bind_layers(SAPNI, SAPDiag, )
bind_layers(SAPNI, SAPDiagDP, )
bind_layers(SAPDiagDP, SAPDiag, )
bind_layers(SAPDiag, SAPDiagItem, )
bind_layers(SAPDiagItem, SAPDiagItem, )

gui_lang = {"0": "Serbian",
            "1": "Chinese",
            "2": "Thai",
            "3": "Korean",
            "4": "Romanian",
            "5": "Slovenian",
            "6": "Croatian",
            "7": "Malaysian",
            "8": "Ukrainian",
            "9": "Estonian",
            "A": "Arabic",
            "B": "Hebrew",
            "C": "Czech",
            "D": "German",
            "E": "English",
            "F": "French",
            "G": "Greek",
            "H": "Hungarian",
            "I": "Italian",
            "J": "Japanese",
            "K": "Danish",
            "L": "Polish",
            "M": "trad.",
            "N": "Dutch",
            "O": "Norwegian",
            "P": "Portuguese",
            "Q": "Slovakian",
            "R": "Russian",
            "S": "Spanish",
            "T": "Turkish",
            "U": "Finnish",
            "V": "Swedish",
            "W": "Bulgarian",
            "X": "Lithuanian",
            "Y": "Latvian",
            "Z": "reserve",
            "a": "Afrikaans",
            "b": "Icelandic",
            "c": "Catalan",
            "d": "(Latin)",
            "i": "Indonesian",
            }

serv_info = {'DBNAME': lambda s: s,
             'CPUNAME': lambda s: s,
             'CLIENT': lambda s: s,
             'LANGUAGE': lambda s: gui_lang.get(s, 'Language unkonwn (%s)' % s),
             'SESSION_ICON': lambda s: s,
             'SESSION_TITLE': lambda s: s,
             'KERNEL_VERSION': lambda s: '.'.join(s[:-1].split('\x00')),
             }

key_len = 20
val_len = 60


def show_all(item):
    """
    Print the information about each item: type, ID, SID and value.

    """
    print("\tType = %s\tId = %s\tSID = %s\tValue = %s" % (diag_item_types[item.item_type],
                                                          diag_appl_ids[item.item_id],
                                                          diag_appl_sids[item.item_id][item.item_sid],
                                                          escape(str(item.item_value))))


def show_serv_info(item):
    """
    Print server information displayed in login screen

    """
    isid = diag_appl_sids[item.item_id][item.item_sid]
    if isid in serv_info.keys():
        print ("%s" % isid).ljust(key_len) + "\t" + ("%s" % serv_info[isid](item.item_value)).ljust(val_len)


def show_text_info(item):
    """
    Print (only) text information rendered in login screen

    """
    isid = diag_appl_sids[item.item_id][item.item_sid]
    iid = diag_appl_ids[item.item_id]

    if iid == 'DYNT' and isid == 'DYNT_ATOM':
        dico = OrderedDict()
        items = item.item_value.items

        for it in items:
            var = it.getfieldval('name_text')
            value = it.getfieldval("field1_text")
            if value is None:
                value = it.getfieldval("field2_text")
            key = '%s_%s' % (it.row, it.col)
            if key not in dico.keys():
                dico[key] = {'var': key, 'value': value}
            if value:
                dico[key]['value'] = value.strip()
            if var:
                dico[key]['var'] = var

        # second pass to bind left text to right value (in screen)
        dico_final = OrderedDict()
        for pos in dico.keys():
            var = dico[pos]['var']
            value = dico[pos]['value']
            dico_final[var] = value

        # final rendering
        for k in dico_final.keys():
            if dico_final[k]:
                print ("%s" % k).ljust(key_len) + "\t" + ("%s" % dico_final[k]).ljust(val_len)


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():
    description = "This example script runs transaction codes on a SAP Netweaver Application Server using valid credentials." \
                  "This can be used to extract information from Tables or Lists."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=3200,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    credentials = OptionGroup(parser, "Credentials")
    credentials.add_option("-u", "--username", dest="username",
                           help="Username")
    credentials.add_option("-l", "--password", dest="password",
                           help="Password")
    credentials.add_option("-m", "--client", dest="client", default="000",
                           help="Client number [%default]")

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    misc.add_option("--terminal", dest="terminal", default=None, help="Terminal name")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")

    return options


def run_transaction_rsusr003_1(connection, tcode, verbose):
    # SES item
    ses = SAPDiagSES(eventarray=0)

    return connection.interact([
        SAPDiagItem(item_value=ses, item_type=1),
        SAPDiagItem(item_value=tcode, item_type=16, item_id=12, item_sid=4),
        SAPDiagItem(
            item_value='\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            item_type=16, item_id=5, item_sid=1),
    ])


def run_transaction_rsusr003_2(connection, tcode, verbose):
    # SES item
    ses = SAPDiagSES(eventarray=0)

    return connection.interact([
        SAPDiagItem(item_value=ses, item_type=1),
        SAPDiagItem(item_value=tcode, item_type=16, item_id=12, item_sid=4),
        SAPDiagItem(
            item_value='\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            item_type=16, item_id=5, item_sid=1),
    ])


def is_duplicate_login(response):
    if response[SAPDiag].get_item("APPL4", "DYNT", "DYNT_ATOM"):
        for item in response[SAPDiag].get_item("APPL4", "DYNT", "DYNT_ATOM"):
            if item.item_value:
                for atom in item.item_value.items:
                    if atom.dlg_flag_1 is 0 and atom.dlg_flag_2 is 0 and atom.field2_text:
                        if "is already logged on in" in atom.field2_text:
                            return True, atom.field2_text
    return False, ""


def run(options):
    # print "[+] Dumping technical information"
    # for item in login_screen[SAPDiag].get_item(["APPL"],
    #                                            ["ST_R3INFO", "ST_USER", "VARINFO"]):
    #     show_serv_info(item)
    # print
    # print "[+] Login Screen text"
    # for item in login_screen[SAPDiag].get_item(["APPL", "APPL4"],
    #                                            ["DYNT"]):
    #     show_text_info(item)
    # print "-" * key_len + "-" * val_len

    actions = SAPDiagActions(host=options.remote_host,
                             port=options.remote_port,
                             terminal=options.terminal,
                             route=options.route_string,
                             verbose=options.verbose,
                             username=options.username,
                             password=options.password,
                             client=options.client
                             )

    # try to login
    login_status = actions.loggedin
    print(login_status)

    if not login_status:
        return

    # rsusr003 = run_transaction_rsusr003_1(connection, "rsusr003", options.verbose)
    # print(rsusr003[SAPDiag].get_item("APPL", "ST_R3INFO", "CONTEXTID")[0].item_value))

    zbasic = actions.run_tcode("rsusr003", 5)

    # zbasic[0].show()

    from pysap.SAPDiagUtils import SAPDiagUtils
    for table in SAPDiagUtils.get_tables(zbasic):
        print(len(table), table)

    # print(zbasic)
    # print(zbasic[0][SAPDiag].get_item("APPL", "ST_USER", "DIALOG_STEP_NUMBER"))

    actions.finish()


def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)
        from scapy.config import conf
        conf.debug_dissector = 1

    run(options)


if __name__ == "__main__":
    main()
