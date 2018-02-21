#!/usr/bin/env python
from scapy.utils import rdpcap

from SAPDiagPackages import SAPDiagPackages
from pysap.SAPDiagUtils import SAPDiagUtils
from pysap.SAPDiagClient import SAPDiagConnection

class SAPDiagActions:
    initialized = False
    loggedin = False

    def __init__(self, host=None, port=3200, route=None, terminal=None, init=True, username=None, password=None,
                 client=None, verbose=False):
        if not host:
            raise ValueError("Host cannot be None")
        self.verbose = verbose
        if self.verbose:
            print("[*] Connecting to %s:%d" % (host, port))

        # from pysap.SAPDiagItems import support_data_sapnw_750
        # self.connection = SAPDiagConnection(host, port, init=False, terminal=terminal, route=route)
        self.connection = SAPDiagConnection(host, port, init=False, terminal=terminal, route=route, support_data=SAPDiagUtils.support_data())
        # To login, the connection needs to be initialized first
        if init or (username and password and client):
            self.init()
        if username and password and client:
            self.loggedin = self.login(username, password, client)

    def init(self):
        self.login_screen = self.connection.init()
        self.initialized = True
        SAPDiagUtils.raise_if_error(self.login_screen)
        return self.login_screen

    def interact(self, message, stepnumber=None):
        assert self.initialized
        if stepnumber is not None:
            print("stepnumber", stepnumber)
            message.insert(0, SAPDiagPackages.dialog_step_number(stepnumber)),
            message.append(SAPDiagPackages.eom())
            print(message)
            return self.connection.sr_message(message)
        # interact appends step number and eom
        return self.connection.interact(message)

    def login(self, username, password, client):
        # Send the login using the given username, password and client
        response = self.interact([
            SAPDiagPackages.ses(eventarray=1),
            SAPDiagPackages.appl_dynn_chl(scrflg=0x05),
            SAPDiagPackages.login(username, password, client),
            SAPDiagPackages.empty_xml_block(0x11),
        ])

        result, status = SAPDiagUtils.is_successful_login(response, username)
        if not result and self.verbose:
            print(status)
        return result

    def run_tcode(self, tcode, response_count=2, **fields):
        step = None
        try:
            step = fields["step"]
        except KeyError:
            pass
        pcap = None
        try:
            pcap = fields["pcap"]
        except KeyError:
            pass
        if pcap:
            return rdpcap(pcap)
        responses = [
            self.interact([
                SAPDiagPackages.ses(eventarray=0),
                SAPDiagPackages.tcode(tcode),
                SAPDiagPackages.appl_dynn_chl(scrflg=0x11),
                SAPDiagPackages.empty_xml_block(0x11),
            ], step)
        ]
        for i in range(response_count - 1):
            responses.append(self.connection.receive())
        return responses

    def finish(self):
        self.connection.close()
