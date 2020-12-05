#!/usr/bin/env python

import scapy
from scapy.layers.ssl_tls import *  # https://github.com/tintinweb/scapy-ssl_tls
from optparse import OptionParser
import re
import socket
import os
import base64, sys


def readPemChainFromFile(
    fileObj,
    startMarker="-----BEGIN CERTIFICATE-----",
    endMarker="-----END CERTIFICATE-----",
):
    cert_chain = []
    state = 0
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        certLine = certLine.strip()
        if state == 0:
            if certLine == startMarker:
                certLines = []
                state = 1
                continue
        if state == 1:
            if certLine == endMarker:
                state = 2
            else:
                certLines.append(certLine)
        if state == 2:
            substrate = ""
            for certLine in certLines:
                if sys.version_info[0] <= 2:
                    substrate = substrate + base64.decodestring(certLine)
                else:
                    if not substrate:
                        substrate = substrate.encode()
                    substrate = substrate + base64.decodebytes(certLine.encode())
            cert_chain.append(substrate)
            state = 0
    return cert_chain


# Usage and options
usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
parser.add_option(
    "-i",
    "--interface",
    type="string",
    dest="interface",
    default="0.0.0.0",
    help="Listening interface",
)
parser.add_option(
    "-p", "--port", type="int", dest="port", default="443", help="Listening port"
)
parser.add_option(
    "-c", "--cert", type="string", dest="certfile", help="PEM Certificate File"
)
(options, args) = parser.parse_args()

ifre = re.compile("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
# Check options
if (
    not options.interface
    or not ifre.match(options.interface)
    or options.port < 1
    or options.port > 65535
    or not options.certfile
    or not os.path.isfile(options.certfile)
):
    parser.print_help()
    exit()

cert_chain = readPemChainFromFile(open(options.certfile))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((options.interface, options.port))
s.listen(0)

# Wait until Keyboard Interrupt
try:

    while True:

        (client, address) = s.accept()

        client_hello = SSL(client.recv(1024))
        ch_cipher_suites = client_hello.records[0][2].cipher_suites
        cs = min(ch_cipher_suites)

        random_session_id = os.urandom(32)
        server_hello = (
            TLSRecord()
            / TLSHandshake()
            / TLSServerHello(session_id=random_session_id, cipher_suite=cs)
        )
        client.sendall(str(server_hello))

        # print "--------------------------"
        # print str(cert_chain[0])
        # print "--------------------------"
        # print str(cert_chain[1])
        # print "--------------------------"
        # print str(cert_chain[2])
        # print "--------------------------"

        ssl_certificates = []
        for cert in cert_chain:
            ssl_certificates.append(TLSCertificate(data=cert))

        certificates = (
            TLSRecord()
            / TLSHandshake()
            / TLSCertificateList(certificates=ssl_certificates)
        )
        client.sendall(str(certificates))

        server_hello_done = (
            TLSRecord() / TLSHandshake() / TLSServerHelloDone(length=0, data="")
        )
        client.sendall(str(server_hello_done))

        raw_response = client.recv(1024)
        SSL(raw_response).show()

        try:
            client.shutdown(socket.SHUT_RDWR)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except:
            client.close()
            continue

except KeyboardInterrupt:
    print "Exited"

s.close()
