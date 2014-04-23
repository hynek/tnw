# -*- test-case-name: tlsep.test.test_dane -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.

import getdns, pprint, sys

def address(hostname):
    ctx = getdns.context_create()
    extensions = { "return_both_v4_and_v6" : getdns.GETDNS_EXTENSION_TRUE }
    results = getdns.address(ctx, name=hostname, extensions=extensions)
    if results["status"] == getdns.GETDNS_RESPSTATUS_GOOD:
        sys.stdout.write("Addresses: ")

        for addr in results["just_address_answers"]:
            print " {0}".format(addr["IPSTRING"])
        sys.stdout.write("\n\n")
        print "Entire results tree: "
        pprint.pprint(results)
    if results["status"] == getdns.GETDNS_RESPSTATUS_NO_NAME:
        print "{0} not found".format(sys.argv[1])
