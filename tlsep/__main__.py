# -*- test-case-name: tlsep.test.test_scripts -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.

"""
eg tlsep full.cert.getdnsapi.net 443 tcp
"""

import sys

from twisted.internet import task, threads

from tlsep import dane


def main():
    if len(sys.argv) != 4:
        print "Usage: {0} parent_domain port protocol".format(sys.argv[0])
        sys.exit(1)

    def _main(reactor):
        return threads.deferToThread(dane.tlsa, *sys.argv[1:])

    task.react(_main)
