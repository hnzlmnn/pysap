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
        SAPDiagUtils.assert_no_error(self.login_screen)
        return self.login_screen

    def interact(self, message, count=1):
        assert self.initialized
        responses = [self.connection.interact(message)]
        responses.extend(self.receive(count - 1))
        # interact appends step number and eom
        return responses

    def receive(self, count=1):
        assert self.initialized
        responses = []
        for i in range(0, count):
            responses.append(self.connection.receive())
        # interact appends step number and eom
        return responses

    def login(self, username, password, client):
        # Send the login using the given username, password and client
        responses = self.interact([
            SAPDiagPackages.ses(eventarray=1),
            SAPDiagPackages.appl_dynn_chl(scrflg=0x05),
            SAPDiagPackages.login(username, password, client),
            SAPDiagPackages.empty_xml_block(0x11),
        ])
        result, status = SAPDiagUtils.is_successful_login(responses[0], username)
        if not result and self.verbose:
            print(status)
        if result:
            responses.extend(self.receive(4))
        return result

    def run_tcode(self, tcode, count=1, **fields):
        pcap = None
        try:
            pcap = fields["pcap"]
        except KeyError:
            pass
        if pcap:
            return rdpcap(pcap)
        responses = self.interact([
            SAPDiagPackages.ses(eventarray=0),
            SAPDiagPackages.tcode(tcode),
            SAPDiagPackages.appl_dynn_chl(scrflg=0x11),
            SAPDiagPackages.empty_xml_block(0x11),
        ], count)
        return responses

    def finish(self):
        self.connection.close()

    def read_all_responses(self, timeout=10, count=1):
        for i in range(0, count):
            self.connection.receive()
