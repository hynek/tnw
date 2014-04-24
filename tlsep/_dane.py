# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

import hashlib
import getdns


from OpenSSL import crypto

from twisted.python.constants import ValueConstant, Values
from twisted.python.util import FancyStrMixin

from tlsep._x509 import extractPublicKey


def tlsaDomainName(parentDomain, port, proto):
    """
    Return a TLSA domain name.

    @param parentDomain: The domain with which the TLSA record is associated.
    @param port: The port number with which the TLSA record is associated.
    @param proto: The IP protocol with which the TLSA record is associated.
    """
    return "_{}._{}.{}".format(port, proto, parentDomain)


class GetdnsResponseError(FancyStrMixin, Exception):
    """
    Raised for any getdns response that isn't GOOD.
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


class USAGE(Values):
    PKIX_TA = ValueConstant(0)
    PKIX_EE = ValueConstant(1)
    DANE_TA = ValueConstant(2)
    DANE_EE = ValueConstant(3)


class SELECTOR(Values):
    CERT = ValueConstant(0)
    SPKI = ValueConstant(1)


class MATCHING_TYPE(Values):
    FULL = ValueConstant(0)
    SHA_256 = ValueConstant(1)
    SHA_512 = ValueConstant(2)


SELECTOR_MAP = {
    SELECTOR.CERT: lambda other: crypto.dump_certificate(
        crypto.FILETYPE_ASN1,
        other
    ),
    SELECTOR.SPKI: extractPublicKey,
}

MATCHING_TYPE_MAP = {
    MATCHING_TYPE.FULL: lambda other: other,
    MATCHING_TYPE.SHA_256: lambda other: hashlib.sha256(other).digest(),
    MATCHING_TYPE.SHA_512: lambda other: hashlib.sha512(other).digest(),
}


class TLSARecord(FancyStrMixin, object):
    showAttributes = ('usage', 'selector', 'matchingType')

    def __init__(self, payload, usage, selector, matchingType):
        self.payload = bytes(payload)

        self.usage = USAGE.lookupByValue(usage)
        self.selector = SELECTOR.lookupByValue(selector)
        self.matchingType = MATCHING_TYPE.lookupByValue(matchingType)

        self._select = SELECTOR_MAP.get(self.selector)
        if self._select is None:
            raise ValueError("Invalid selector: {}".format(selector))

        self._transform = MATCHING_TYPE_MAP.get(self.matchingType)
        if self._transform is None:
            raise ValueError("Invalid matching type: {}".format(matchingType))


    def matchesCertificate(self, cert):
        """
        @type cert: x509

        @rtype: bool
        """
        return self.payload == self._transform(self._select(cert))



def lookup_tlsa_records(parentDomain, port, proto, getdns=getdns):
    """
    Lookup a TLSA record and return a TLSA type depending on the TLSA
    selector type in the record.

    @see: U{http://tools.ietf.org/html/draft-ietf-dane-registry-acronyms-01#section-2.2}

    @param parentDomain: The domain with which the TLSA record is associated.
    @param port: The port number with which the TLSA record is associated.
    @param proto: The IP protocol with which the TLSA record is associated.
    @param getdns: An optional getdnsapi object. For testing purposes.

    @returns: A list of TLSA record instances corresponding to the selector
        type of the record.
    """
    ctx = getdns.context_create()
    extensions = {
        "return_both_v4_and_v6": getdns.GETDNS_EXTENSION_TRUE,
        "dnssec_return_only_secure": getdns.GETDNS_EXTENSION_FALSE,
    }
    results = getdns.general(ctx,
                             request_type=getdns.GETDNS_RRTYPE_TLSA,
                             name=tlsaDomainName(parentDomain, port, proto),
                             extensions=extensions)

    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        rv = []
        for answer in results['replies_tree'][0]['answer']:
            if answer["type"] != getdns.GETDNS_RRTYPE_TLSA:
                continue
            rdata = answer['rdata']
            rv.append(TLSARecord(
                rdata['certificate_association_data'],
                3,
                rdata["selector"],
                rdata["matching_type"],
            ))
        return rv

    raise GetdnsResponseError(results['status'])
