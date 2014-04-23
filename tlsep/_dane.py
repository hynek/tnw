# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.
import binascii
import getdns


from OpenSSL import crypto

from twisted.python.util import FancyStrMixin


def tlsaDomainName(parentDomain, port, proto):
    """
    Return a TLSA domain name.

    @param parentDomain: The domain with which the TLSA record is associated.
    @param port: The port number with which the TLSA record is associated.
    @param proto: The IP protocol with which the TLSA record is associated.
    """
    return "_%s._%s.%s" % (port, proto, parentDomain)


class LookupError(FancyStrMixin, Exception):
    """
    Raised for any getdns return status that isn't GOOD.
    """

    showAttributes = ('errorCode', 'errorText')
    def __init__(self, errorCode):
        self.errorCode = errorCode


    @property
    def errorText(self):
        for k, v in getdns.__dict__.items():
            if k.startswith('GETDNS_RESPSTATUS_'):
                if getattr(getdns, k) == self.errorCode:
                    return k



class TLSA_Cert(FancyStrMixin, object):
    type = 0
    def __init__(self, cert):
        """
        """
        self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert[:])


class TLSA_SPKI(FancyStrMixin, object):
    type = 1

    showAttributes = ('spki',)

    def __init__(self, spki):
        """
        """
        self.spki = binascii.hexlify(spki)


TLSA_SELECTOR_MAP = {}
for t in (TLSA_Cert, TLSA_SPKI):
    TLSA_SELECTOR_MAP[t.type] = t


def tlsa(parentDomain, port, proto, getdns=getdns):
    """
    Lookup a TLSA record and return a TLSA type depending on the TLSA
    selector type in the record.

    @see: U{http://tools.ietf.org/html/draft-ietf-dane-registry-acronyms-01#section-2.2}

    @param parentDomain: The domain with which the TLSA record is associated.
    @param port: The port number with which the TLSA record is associated.
    @param proto: The IP protocol with which the TLSA record is associated.
    @param getdns: An optional getdnsapi object. For testing purposes.

    @returns: A TLSA record instance corresponding to the selector type of the
        record.
    """
    ctx = getdns.context_create()
    extensions = {
        "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE,
        "dnssec_return_only_secure" : getdns.GETDNS_EXTENSION_TRUE
    }
    results = getdns.general(ctx,
                             request_type=getdns.GETDNS_RRTYPE_TLSA,
                             name=tlsaDomainName(parentDomain, port, proto),
                             extensions=extensions)

    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        tlsaType = TLSA_SELECTOR_MAP[results['replies_tree'][0]['answer'][0]['rdata']['selector']]
        return tlsaType(results['replies_tree'][0]['answer'][0]['rdata']['certificate_association_data'])

    raise LookupError(results['status'])
