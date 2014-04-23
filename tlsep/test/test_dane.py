import binascii
from OpenSSL import crypto
from twisted.trial.unittest import SynchronousTestCase
import getdns
from tlsep import _dane


class TLSADomainNameTests(SynchronousTestCase):
    def test_tlsaDomainName(self):
        """
        L{_dane.tlsaDomainName} returns the port, proto and parent domain as
        labels of a new domain name string.
        """
        self.assertEqual(
            "_443._tcp.example.com",
            _dane.tlsaDomainName('example.com', 443, 'tcp')
        )



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
    def test_tlsaCert(self):
        """
        L{_dane.tlsa} returns a TLSACert instance if the domain name exists and
        a verified record is found and the record selector type is CERT.
        """
        fakeGetdns = FakeGetdns(
            generalResult=createResults(status=getdns.GETDNS_RESPSTATUS_GOOD,
                                        selector=0,
                                        certificate_association_data=CERT_FULL))
        res = _dane.tlsa('example.com', 443, 'tcp', getdns=fakeGetdns)
        self.assertEqual(
            (0, crypto.X509),
            (res.type, type(res.cert))
        )


    def test_tlsaSPKI(self):
        """
        L{_dane.tlsa} returns a TLSASPKI instance if the domain name exists and
        a verfied record is found and the record selector type is SPKI.
        """
        expected = b'FOOBAR'
        fakeGetdns = FakeGetdns(
            generalResult=createResults(status=getdns.GETDNS_RESPSTATUS_GOOD,
                                        selector=1,
                                        certificate_association_data=expected))
        self.assertEqual(
            binascii.hexlify(expected),
            _dane.tlsa('example.com', 443, 'tcp', getdns=fakeGetdns).spki
        )


    def test_tlsaNoname(self):
        """
        L{_dane.tlsa} raises LookupError if the domain name does not exist.
        """
        e = self.assertRaises(
            _dane.LookupError,
            _dane.tlsa, 'example.com', 443, 'tcp', getdns=FakeGetdns(
                generalResult=createResults(
                    status=getdns.GETDNS_RESPSTATUS_NO_NAME
                )
            )
        )
        self.assertEqual(
            getdns.GETDNS_RESPSTATUS_NO_NAME,
            e.errorCode
        )



# A full certificate from full.cert.getdnsapi.net
CERT_FULL = binascii.unhexlify("308205d7308203bfa00302010202030e9593300d06092a864886f70d01010d050030793110300e060355040a1307526f6f74204341311e301c060355040b1315687474703a2f2f7777772e6361636572742e6f7267312230200603550403131943412043657274205369676e696e6720417574686f726974793121301f06092a864886f70d0109011612737570706f7274406361636572742e6f7267301e170d3134303232373135303435385a170d3134303832363135303435385a3018311630140603550403130d676574646e736170692e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100dc0226b2c9e7aa079992730d09530e8d14fd74bead887f1039a8baa7a28b68cc358c455364a6d4f6393831072f8bbb28ea04256833779ea3c841867b14a659fe2495829b7ae1c21c6bc1f5ce63e3421fd851c5cd339b77166d2bf4cb738a86908d0439e1b1dffb7cd0a3ea91faa36dfed2f4fc5315a96764e082df8cc0f698b6278f1b1f58ab27cf53ac1827cd69b979c45733fcc8c9532065f3f1c35e933f7c3b6caf56176df852076b0195dc0b848a4cbc7c4a38e07ea39b1a55104888bdcbba69d0dc8f3298002e36e1c082bb1a48cb47829678c3c6e753e810565cbd1b68e263046839935e2d2631f4f85469540e50ea01c54de8d97de1f929b6e1a8c1810203010001a38201c7308201c3300c0603551d130101ff04023000300e0603551d0f0101ff0404030203a830340603551d25042d302b06082b0601050507030206082b0601050507030106096086480186f8420401060a2b0601040182370a0303303306082b0601050507010104273025302306082b060105050730018617687474703a2f2f6f6373702e6361636572742e6f72672f30310603551d1f042a30283026a024a0228620687474703a2f2f63726c2e6361636572742e6f72672f7265766f6b652e63726c308201030603551d110481fb3081f8820d676574646e736170692e6e6574a01b06082b06010505070805a00f0c0d676574646e736170692e6e657482117777772e676574646e736170692e6e6574a01f06082b06010505070805a0130c117777772e676574646e736170692e6e6574820d676574646e736170692e6f7267a01b06082b06010505070805a00f0c0d676574646e736170692e6f726782117777772e676574646e736170692e6f7267a01f06082b06010505070805a0130c117777772e676574646e736170692e6f72678213676574646e732e6e6c6e65746c6162732e6e6ca02106082b06010505070805a0150c13676574646e732e6e6c6e65746c6162732e6e6c300d06092a864886f70d01010d05000382020100694130bffe0f84062c5dbc9526688cddef65ea3ba9f882bf171504a6de3dda34e371ab82fc5b2ffd18598c4b48cec6e4ec9ba3d7a4bbd5016101694c8f2abcb27fae79b392eb6eae3639fa611245206411bef8682eadf0060c44c929221396a79f3320cc847ca4aad2b7e65c34455a2fc471b7876d848d3ee0a9c7fb323237d8549ab9356c8aac16c90daa0f1f9eb3cd74a6b6214e28a82c7e6fea230e2d687a7122c8f3b1313bfaa1ec0a7eaa89b8de535d1a414f4d5b4e998d5212096817c85d01e13b4cd65b5ee8eb273f5c68213702874333768ad8a5ee641f34ea2a3486d9960cff0ac3860470987bef2bd0aa16c1a442c70473c9d3ca139861548b18e28e9771d11ff0c359cf67360a8efc15ef6c0bb540f2805a746e77ab420661719dbc2a351e70f26f6153880c43da3cd317e2140ac965fd80cf784fa3ae9db6dcc516080242b61b45bdda8a434e99c634f3b13071b43e1777485768ca83a109a035d8a57499779c947340b7b68e4da1647ceabf1f7fce94d9048e47d699739f497705fd80073de2df0686dff06d8ed5e97860a15fe80cae0e9e928dad667419bab6ddac25a36438e6eace45f6c06f1b18b96e68c28774e52e14a82630c17466b18d08d6799a7af9870c94202a43086e0c96a3d384b054136c097c47f3fe1634d7c27e2a8ae013247690bef2be96c8e663d268865e979426dfdc2d4972b37a64bb1d")



def createResults(status=getdns.GETDNS_RESPSTATUS_GOOD,
                  selector=None,
                  certificate_association_data=b"",):
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
                                              'selector': selector
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
