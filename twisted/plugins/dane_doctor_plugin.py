# -*- test-case-name: danex.test.test_dane -*-
# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

from __future__ import absolute_import, division, print_function

from twisted.application.service import ServiceMaker


serviceMaker = ServiceMaker(b'dane_doctor',
                            b'dane_doctor.tap',
                            b'Examine TLSA setups.',
                            b'dane_doctor')
