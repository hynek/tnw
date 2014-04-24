from __future__ import (absolute_import, division, print_function)

import json

from twisted.internet.protocol import Factory, Protocol, connectionDone
from twisted.internet import task, threads, defer

from danex import _dane, _tls


class DaneDoctorProtocol(Protocol):
    def dataReceived(self, data):

        domain = data.strip(" \n")
        port = 443
        proto = "tcp"

        d = defer.gatherResults([
            threads.deferToThread(
                _dane.lookup_tlsa_records, domain, port, proto
            ),
            _tls.retrieveCertificate(domain, port)
        ])

        def onResults(res):
            (trusted, tlsaRecords), serverCertificate = res
            numRecs = len(tlsaRecords)
            doesMatch = False
            recs = []

            for tlsa in tlsaRecords:
                if isinstance(tlsa, _dane.InvalidTLSARecord):
                    newRec = {"error": tlsa.error}
                else:
                    newRec = {
                        "usage": tlsa.usage.name,
                        "selector": tlsa.selector.name,
                        "matchingType": tlsa.matchingType.name,
                    }
                    if tlsa.matchesCertificate(serverCertificate):
                        newRec["matches"] = doesMatch = True
                recs.append(newRec)

            rv = {
                "trusted": trusted,
                "doesMatch": doesMatch,
                "numRecs": numRecs,
                "tlsaRecords": recs,
            }
            self.transport.write(json.dumps(rv))
            self.transport.loseConnection()

        d.addCallback(onResults)
        return d
