import binascii
from twisted.trial.unittest import SynchronousTestCase
import getdns
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


def createResults(status=getdns.GETDNS_RESPSTATUS_GOOD,
                  certificate_association_data=b""):
    return {'answer_type': 800,
            'canonical_name': '_443._tcp.getdnsapi.org.',
            'just_address_answers': [],
#             'replies_full': [<read-only buffer ptr 0x7fe2e0029e80, size 636 at 0x7fe2e4e58fb0>],
            'replies_tree': [{'answer': [{'class': 1,
                                          'name': '_443._tcp.getdnsapi.org.',
                                          'rdata': {
                                              'certificate_association_data': certificate_association_data,
                                              # 'certificate_usage': 3,
                                              # 'matching_type': 1,
                                              # 'rdata_raw': "",
                                              # 'selector': 1
                                          },
                                          # 'ttl': 450,
                                          # 'type': 52},
                                         # {'class': 1,
                                         #  'name': '_443._tcp.getdnsapi.org.',
                                         #  'rdata': {'algorithm': 7,
                                         #            'key_tag': 49262,
                                         #            'labels': 4,
                                         #            'original_ttl': 450,
                                         #            'rdata_raw': <read-only buffer ptr 0x7fe2e0261b70, size 161 at 0x7fe2e4e60130>,
                                         #            'signature': <read-only buffer ptr 0x7fe2e0254c40, size 128 at 0x7fe2e4e60170>,
                                         #            'signature_expiration': 1399325172,
                                         #            'signature_inception': 1398100703,
                                         #            'signers_name': 'getdnsapi.org.',
                                         #            'type_covered': 52},
                                         #  'ttl': 450,
                                         #  'type': 46
                                      }
                                     ],
                               'answer_type': 800,
                              # 'authority': [{'class': 1,
                              #                'name': 'getdnsapi.org.',
                              #                'rdata': {'nsdname': 'ns.secret-wg.org.',
                              #                          'rdata_raw': 'ns.secret-wg.org.'},
                              #                'ttl': 450,
                              #                'type': 2},
                              #               {'class': 1,
                              #                'name': 'getdnsapi.org.',
                              #                'rdata': {'nsdname': 'mcvax.nlnetlabs.nl.',
                              #                          'rdata_raw': 'mcvax.nlnetlabs.nl.'},
                              #                'ttl': 450,
                              #                'type': 2},
                              #               {'class': 1,
                              #                'name': 'getdnsapi.org.',
                              #                'rdata': {'nsdname': 'open.nlnetlabs.nl.',
                              #                          'rdata_raw': 'open.nlnetlabs.nl.'},
                              #                'ttl': 450,
                              #                'type': 2},
                              #               {'class': 1,
                              #                'name': 'getdnsapi.org.',
                              #                'rdata': {'algorithm': 7,
                              #                          'key_tag': 49262,
                              #                          'labels': 2,
                              #                          'original_ttl': 450,
                              #                          'rdata_raw': <read-only buffer ptr 0x7fe2e0261f90, size 161 at 0x7fe2e4e601f0>,
                              #                          'signature': <read-only buffer ptr 0x7fe2e0028120, size 128 at 0x7fe2e4e60230>,
                              #                          'signature_expiration': 1399278072,
                              #                          'signature_inception': 1398093503,
                              #                          'signers_name': 'getdnsapi.org.',
                              #                          'type_covered': 2},
                              #                'ttl': 450,
                              #                'type': 46}],
                              'canonical_name': '_443._tcp.getdnsapi.org.',
                              'dnssec_status': 400,
                              'header': {'aa': 0,
                                         'ad': 1,
                                         'ancount': 2,
                                         'arcount': 0,
                                         'cd': 0,
                                         'id': 0,
                                         'nscount': 4,
                                         'opcode': 0,
                                         'qdcount': 1,
                                         'qr': 1,
                                         'ra': 1,
                                         'rcode': 0,
                                         'rd': 1,
                                         'tc': 0,
                                         'z': 0},
                              'question': {'qclass': 1,
                                           'qname': '_443._tcp.getdnsapi.org.',
                                           'qtype': 52}}],
            'status': status}




class FakeGetdns(object):
    """
    An in memory fake of the getdns api for testing.
    """


    def __init__(self, generalResult=None):
        self._generalResult = generalResult

        for k, v in getdns.__dict__.items():
            if k.startswith('GETDNS_'):
                setattr(self, k, v)


    def context_create(self):
        """
        """


    def general(self, context, name, request_type, extensions):
        """
        """
        return self._generalResult





class TLSATests(SynchronousTestCase):
    def test_tlsaGood(self):
        """
        L{dane.tlsa} returns a hex encoded signature if the domain name exists and a
        verfied record is found.
        """
        expected = b'FOOBAR'
        self.assertEqual(
            binascii.hexlify(expected),
            dane.tlsa('example.com', 443, 'tcp', getdns=FakeGetdns(generalResult=createResults(certificate_association_data=expected)))
        )


    def test_tlsaNoname(self):
        """
        L{dane.tlsa} raises LookupError if the domain name does not exist.
        """
        e = self.assertRaises(
            dane.LookupError,
            dane.tlsa, 'example.com', 443, 'tcp', getdns=FakeGetdns(generalResult=createResults(status=getdns.GETDNS_RESPSTATUS_NO_NAME))
        )
        self.assertEqual(
            getdns.GETDNS_RESPSTATUS_NO_NAME,
            e.args[0]
        )
