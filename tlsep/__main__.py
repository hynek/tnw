# -*- test-case-name: tlsep.test.test_scripts -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

"""
eg tlsep full.cert.getdnsapi.net 443 tcp
"""

import sys

from twisted.internet import task, threads, defer

from tlsep import _dane, _tls


def printResult(res):
    tlsaRecord, serverCertificate = res
    print tlsaRecord.matchesCertificate(serverCertificate)
    print tlsaRecord

def _main(reactor, parent_domain, port, proto):
    d = defer.gatherResults([
        threads.deferToThread(_dane.lookup_tlsa_records, parent_domain, port, proto),
        _tls.retrieveCertificate(parent_domain, port)
    ])
    d.addCallback(printResult)
    return d


def main():
    if len(sys.argv) != 4:
        print "Usage: {0} parent_domain port protocol".format(sys.argv[0])
        sys.exit(1)

    task.react(_main, sys.argv[1:])
