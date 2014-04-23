# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.
import binascii
import getdns


def tlsaDomainName(parent_domain, port, proto):
    """
    Return a TLSA domain name.
    """
    return "_%s._%s.%s" % (port, proto, parent_domain)



class LookupError(Exception):
    pass



def tlsa(parent_domain, port, proto, getdns=getdns):
    ctx = getdns.context_create()
    extensions = {
        "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE,
        "dnssec_return_only_secure" : getdns.GETDNS_EXTENSION_TRUE
    }
    results = getdns.general(ctx,
                             request_type=getdns.GETDNS_RRTYPE_TLSA,
                             name=tlsaDomainName(parent_domain, port, proto),
                             extensions=extensions)

    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        return binascii.hexlify(results['replies_tree'][0]['answer'][0]['rdata']['certificate_association_data'])

    raise LookupError(results['status'])
