# Copyright (c) Hynek Schlawack, Richard Wall
# See LICENSE for details.

from __future__ import absolute_import, division, print_function

from twisted.application.internet import StreamServerEndpointService
from twisted.application.service import MultiService
from twisted.internet.endpoints import serverFromString
from twisted.python import usage
from twisted.internet.protocol import Factory, Protocol, connectionDone
from twisted.python.filepath import FilePath
from twisted.web.resource import ForbiddenResource, Resource
from twisted.web.server import Site
from twisted.web.static import File

from txsockjs.factory import SockJSResource

from .protocol import DaneDoctorProtocol


class Options(usage.Options):
    pass


class NoListDirFile(File):
    """
    Behaves like Twisted's File but refuses to list directories.
    """
    def directoryListing(self):
        return ForbiddenResource(message=b'Nope.')


class DaneDoctorService(MultiService, object):
    def __init__(self, reactor, config):
        MultiService.__init__(self)
        self._config = config
        self._reactor = reactor

    def startService(self):
        MultiService.startService(self)

        staticPath = FilePath(__file__).sibling("static")
        root = NoListDirFile(staticPath.path)
        root.putChild('api', SockJSResource(
            Factory.forProtocol(DaneDoctorProtocol))
        )

        webService = StreamServerEndpointService(
            serverFromString(self._reactor, "tcp:8080"),
            Site(root)
        )
        webService.setServiceParent(self)


def makeService(options):
    from twisted.internet import reactor

    # with open(options[b'config']) as f:
    #     config = yaml.safe_load(f)
    config = {}

    return DaneDoctorService(reactor, config)
