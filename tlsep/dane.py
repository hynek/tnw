# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.

import getdns, pprint, sys


def tlsaDomainName(parent_domain, port, proto):
    """
    Return a TLSA domain name.
    """
    return "_%s._%s.%s" % (port, proto, parent_domain)



def tlsa(parent_domain, port, proto):
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
        sys.stdout.write("Addresses: ")

        for addr in results["just_address_answers"]:
            print " {0}".format(addr["IPSTRING"])
        sys.stdout.write("\n\n")
        print "Entire results tree: "
        pprint.pprint(results)
    if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "{0} not found".format(sys.argv[1])
