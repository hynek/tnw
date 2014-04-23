from twisted.trial.unittest import SynchronousTestCase

from tlsep import dane

class TLSADomainNameTests(SynchronousTestCase):
    def test_tlsaDomainName(self):
        """
        L{dane.tlsaDomainName} returns the port, proto and parent domain as labels
        of a new domain name string.
        """
        self.assertEqual(
            "_443._tcp.example.com",
            dane.tlsaDomainName(443, 'tcp', 'example.com')
        )
