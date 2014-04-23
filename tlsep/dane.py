# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.
import binascii
import getdns


def tlsaDomainName(parentDomain, port, proto):
    """
    Return a TLSA domain name.

    @param parentDomain: The domain with which the TLSA record is associated.
    @param port: The port number with which the TLSA record is associated.
    @param proto: The IP protocol with which the TLSA record is associated.
    """
    return "_%s._%s.%s" % (port, proto, parentDomain)


class LookupError(Exception):
    """
    Raised for any getdns return status that isn't GOOD.
    """
    pass


class TLSAFullCertificate(object):
    pass


class TLSASubjectPublicInfo(object):
    pass


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
        return binascii.hexlify(results['replies_tree'][0]['answer'][0]['rdata']['certificate_association_data'])

    raise LookupError(results['status'])
