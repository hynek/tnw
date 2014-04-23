# -*- test-case-name: tlsep.test.test_scripts -*-
# Copyright (c) Richard Wall, Hynek Schwlack
# See LICENSE for details.

import sys

from twisted.internet import task, threads

from tlsep import dane



def verify_main():
    if len(sys.argv) != 2:
        print "Usage: {0} hostname".format(sys.argv[0])
        sys.exit(1)

    def _main(reactor):
        return threads.deferToThread(dane.address, sys.argv[1])

    task.react(_main)
