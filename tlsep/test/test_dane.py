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
            dane.tlsaDomainName('example.com', 443, 'tcp')
        )



class FakeGetdns(object):
    """
    An in memory fake of the getdns api for testing.
    """
    GETDNS_EXTENSION_TRUE = -1
    GETDNS_RRTYPE_TLSA = -1
    GETDNS_RESPSTATUS_GOOD = -1
    GETDNS_RESPSTATUS_NO_NAME = -1

    def context_create(self):
        """
        """


    def general(self, context, name, request_type, extensions):
        """
        """
        return {'status':None}



class TLSATests(SynchronousTestCase):
    def test_tlsa(self):
        """
        """
        self.assertEqual(
            "",
            dane.tlsa('example.com', 443, 'tcp', getdns=FakeGetdns())
        )
