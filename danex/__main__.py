# -*- test-case-name: danex.test.test_scripts -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

from __future__ import absolute_import, division, print_function


"""
eg danex full.cert.getdnsapi.net 443 tcp
"""

import sys

from twisted.internet import task, threads, defer

from . import _dane, _tls


def printResult(res):
    (trusted, tlsaRecords), serverCertificate = res
    numRecs = len(tlsaRecords)
    print("{} TLSA record{} found.{}".format(
        numRecs,
        "s" if numRecs != 1 else "",
        " (UNTRUSTED)" if numRecs and not trusted else "",
    ))

    for tlsa in tlsaRecords:
        print(tlsa)

    print()
    if isinstance(tlsa, _dane.InvalidTLSARecord):
        print(
            "INVALID TLSA records received."
        )
    elif tlsa.matchesCertificate(serverCertificate):
        print(
            "The server-sent certificate matches at least one of the TLSA "
            "records."
        )
    else:
        print("The server-sent certificate did NOT match any TLSA record.")


def _main(reactor, parent_domain, port, proto):
    d = defer.gatherResults([
        threads.deferToThread(
            _dane.lookup_tlsa_records, parent_domain, port, proto
        ),
        _tls.retrieveCertificate(parent_domain, port)
    ])
    d.addCallback(printResult)
    return d


def main():
    if len(sys.argv) != 4:
        print("Usage: {0} parent_domain port protocol".format(sys.argv[0]))
        sys.exit(1)

    task.react(_main, sys.argv[1:])
