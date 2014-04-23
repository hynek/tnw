# -*- test-case-name: tlsep.test.test_scripts -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

"""
eg tlsep full.cert.getdnsapi.net 443 tcp
"""

import sys

from twisted.internet import task, threads

from tlsep import _dane

def main():
    if len(sys.argv) != 4:
        print "Usage: {0} parent_domain port protocol".format(sys.argv[0])
        sys.exit(1)

    def _main(reactor):
        return threads.deferToThread(_dane.lookup_tlsa_records, *sys.argv[1:])

    task.react(_main)
