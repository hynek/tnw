# -*- test-case-name: tlsep.test.test_x509 -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

from __future__ import absolute_import, division, print_function

from OpenSSL import _util


def extractPublicKey(cert):
    """
    Extract the public key from a certificate.

    @param cert: Certificate to be dissected.
    @type cert: x509

    @return: Public key in ASN.1.
    @rtype: L{bytes}
    """
    pk = cert.get_pubkey()

    b = _util.binding
    l = b.lib
    ffi = b.ffi
    rsa = l.EVP_PKEY_get1_RSA(pk._pkey)
    buf = ffi.new("unsigned char **")
    length = l.i2d_RSA_PUBKEY(rsa, buf)
    pk = buf[0]
    ffi.gc(pk, l.OpenSSL_free)
    return ffi.buffer(pk, length)[:]
