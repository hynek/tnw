# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

from __future__ import absolute_import, division, print_function

import hashlib

from OpenSSL import crypto
from twisted.trial.unittest import SynchronousTestCase

from danex._x509 import extractPublicKey


class TestX509(SynchronousTestCase):
    def test_extractReturnsBytes(self):
        """
        extractPublicKey returns a byte string.
        """
        pk = extractPublicKey(CERT)
        self.assertIsInstance(pk, bytes)

    def test_extractExtractsCorrectPublicKey(self):
        """
        extractPublicKey returns the correct public key.
        """
        pk = extractPublicKey(CERT)
        self.assertEqual(
            CERT_SHA256,
            hashlib.sha256(pk).hexdigest()
        )


CERT_SHA256 = (
    "9d73567ec8e8a7ee26f38defd52b02d8dbfd87b13da6485600e765ad1598b5ee"
)
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIF1zCCA7+gAwIBAgIDDpWTMA0GCSqGSIb3DQEBDQUAMHkxEDAOBgNVBAoTB1Jv
b3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEiMCAGA1UEAxMZ
Q0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYSc3VwcG9y
dEBjYWNlcnQub3JnMB4XDTE0MDIyNzE1MDQ1OFoXDTE0MDgyNjE1MDQ1OFowGDEW
MBQGA1UEAxMNZ2V0ZG5zYXBpLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANwCJrLJ56oHmZJzDQlTDo0U/XS+rYh/EDmouqeii2jMNYxFU2Sm1PY5
ODEHL4u7KOoEJWgzd56jyEGGexSmWf4klYKbeuHCHGvB9c5j40If2FHFzTObdxZt
K/TLc4qGkI0EOeGx3/t80KPqkfqjbf7S9PxTFalnZOCC34zA9pi2J48bH1irJ89T
rBgnzWm5ecRXM/zIyVMgZfPxw16TP3w7bK9WF234UgdrAZXcC4SKTLx8SjjgfqOb
GlUQSIi9y7pp0NyPMpgALjbhwIK7GkjLR4KWeMPG51PoEFZcvRto4mMEaDmTXi0m
MfT4VGlUDlDqAcVN6Nl94fkptuGowYECAwEAAaOCAccwggHDMAwGA1UdEwEB/wQC
MAAwDgYDVR0PAQH/BAQDAgOoMDQGA1UdJQQtMCsGCCsGAQUFBwMCBggrBgEFBQcD
AQYJYIZIAYb4QgQBBgorBgEEAYI3CgMDMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2FjZXJ0Lm9yZy8wMQYDVR0fBCowKDAmoCSgIoYg
aHR0cDovL2NybC5jYWNlcnQub3JnL3Jldm9rZS5jcmwwggEDBgNVHREEgfswgfiC
DWdldGRuc2FwaS5uZXSgGwYIKwYBBQUHCAWgDwwNZ2V0ZG5zYXBpLm5ldIIRd3d3
LmdldGRuc2FwaS5uZXSgHwYIKwYBBQUHCAWgEwwRd3d3LmdldGRuc2FwaS5uZXSC
DWdldGRuc2FwaS5vcmegGwYIKwYBBQUHCAWgDwwNZ2V0ZG5zYXBpLm9yZ4IRd3d3
LmdldGRuc2FwaS5vcmegHwYIKwYBBQUHCAWgEwwRd3d3LmdldGRuc2FwaS5vcmeC
E2dldGRucy5ubG5ldGxhYnMubmygIQYIKwYBBQUHCAWgFQwTZ2V0ZG5zLm5sbmV0
bGFicy5ubDANBgkqhkiG9w0BAQ0FAAOCAgEAaUEwv/4PhAYsXbyVJmiM3e9l6jup
+IK/FxUEpt492jTjcauC/Fsv/RhZjEtIzsbk7Juj16S71QFhAWlMjyq8sn+uebOS
626uNjn6YRJFIGQRvvhoLq3wBgxEySkiE5annzMgzIR8pKrSt+ZcNEVaL8Rxt4dt
hI0+4KnH+zIyN9hUmrk1bIqsFskNqg8fnrPNdKa2IU4oqCx+b+ojDi1oenEiyPOx
MTv6oewKfqqJuN5TXRpBT01bTpmNUhIJaBfIXQHhO0zWW17o6yc/XGghNwKHQzN2
itil7mQfNOoqNIbZlgz/CsOGBHCYe+8r0KoWwaRCxwRzydPKE5hhVIsY4o6XcdEf
8MNZz2c2Co78Fe9sC7VA8oBadG53q0IGYXGdvCo1HnDyb2FTiAxD2jzTF+IUCsll
/YDPeE+jrp223MUWCAJCthtFvdqKQ06ZxjTzsTBxtD4Xd0hXaMqDoQmgNdildJl3
nJRzQLe2jk2hZHzqvx9/zpTZBI5H1plzn0l3Bf2ABz3i3waG3/BtjtXpeGChX+gM
rg6eko2tZnQZurbdrCWjZDjm6s5F9sBvGxi5bmjCh3TlLhSoJjDBdGaxjQjWeZp6
+YcMlCAqQwhuDJaj04SwVBNsCXxH8/4WNNfCfiqK4BMkdpC+8r6WyOZj0miGXpeU
Jt/cLUlys3pkux0=
-----END CERTIFICATE-----"""
CERT = crypto.load_certificate(crypto.FILETYPE_PEM, CERT_PEM)
