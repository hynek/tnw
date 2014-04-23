# -*- test-case-name: tlsep.test.test_tls -*-

from __future__ import absolute_import, division, print_function

import socket

import idna

from twisted.internet import threads
from OpenSSL import SSL


def retrieveCertificate(hostname, port):
    """
    @type hostname: L{unicode}
    @type port: int

    @rtype: deferred that fires with an x509
    """

    def handshake():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_ctx = SSL.Context(SSL.SSLv23_METHOD)
        conn = SSL.Connection(
            tls_ctx,
            sock
        )
        conn.connect((idna.encode(hostname).encode("ascii"), 443))
        conn.do_handshake()
        cert = conn.get_peer_certificate()
        conn.shutdown()
        conn.close()
        return cert

    return threads.deferToThread(handshake)
