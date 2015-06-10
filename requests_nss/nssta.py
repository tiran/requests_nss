# Copyright (C) 2015, Red Hat, Inc.
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import socket


from requests.packages.urllib3.connectionpool import HTTPConnectionPool
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util.timeout import Timeout

from requests.adapters import HTTPAdapter
from requests.adapters import DEFAULT_POOLBLOCK

from .httplib_example import NSSConnection, NSPRConnection

from nss import io

DEFAULT_TIMEOUT = io.PR_INTERVAL_NO_TIMEOUT
TW_TIMEOUT = io.PR_INTERVAL_NO_TIMEOUT - 1

TICKS_SEC = io.seconds_to_interval(1)
SEC_TICKS = 1. / TICKS_SEC


class TimeoutWrapper(object):
    """Wrap NSS socket to support timeout on an object level

    nss.io.Socket and nss.ssl.SSLSocket objects  don't have a gettimeout()
    and settimeout() method. Their methods like connect() and recv() have a
    timeout argument instead.
    """
    __slots__ = ('_sock', '_timeout')

    def __init__(self, sock):
        self._sock = sock
        self._timeout = DEFAULT_TIMEOUT

    def __getattr__(self, name):
        # Don't support file-like methods directly
        if name in {'read', 'readline', 'readlines'}:
            raise AttributeError(name)
        return getattr(self._sock, name)

    def __setattr__(self, name, value):
        if name in type(self).__slots__:
            super(TimeoutWrapper, self).__setattr__(name, value)
        else:
            raise AttributeError(name)

    def settimeout(self, timeout):
        if timeout is Timeout.DEFAULT_TIMEOUT:
            timeout = socket.getdefaulttimeout()
        if timeout is None:
            timeout = io.PR_INTERVAL_NO_TIMEOUT
        elif isinstance(timeout, float):
            # fraction of seconds
            timeout = int(TICKS_SEC * timeout)
        else:
            timeout = io.seconds_to_interval(timeout)
        self._timeout = timeout

    def gettimeout(self):
        if self._timeout == io.PR_INTERVAL_NO_TIMEOUT:
            return None
        return self._timeout * SEC_TICKS

    def connect(self, addr, timeout=TW_TIMEOUT):
        if timeout == TW_TIMEOUT:
            timeout = self._timeout
        return self._sock.connect(addr, timeout)

    def recv(self, amount, timeout=TW_TIMEOUT):
        if timeout == TW_TIMEOUT:
            timeout = self._timeout
        return self._sock.recv(amount, timeout)

    def send(self, buf, timeout=TW_TIMEOUT):
        if timeout == TW_TIMEOUT:
            timeout = self._timeout
        return self._sock.send(buf, timeout)

    def sendall(self, buf, timeout=TW_TIMEOUT):
        if timeout == TW_TIMEOUT:
            timeout = self._timeout
        return self._sock.sendall(buf, timeout)

    def makefile(self, mode='r', buffering=-1):
        """Use file wrapper from socket library

        None of the read methods of NSS has a timeout argument.
        """
        return socket._fileobject(self, mode, buffering)


class TimeoutNSPRConnection(NSPRConnection):
    """Timeout wrapped NSPR connect (plain TCP)"""
    def __init__(self, host, port=None, timeout=DEFAULT_TIMEOUT,
                 strict=None, dbdir=None):
        NSPRConnection.__init__(self, host, port, strict=strict)
        self._timeout = timeout

    def connect(self):
        # old style class
        rv = NSPRConnection.connect(self)
        self.sock = TimeoutWrapper(self.sock)
        self.sock.settimeout(self._timeout)
        return rv


class TimeoutNSSConnection(NSSConnection):
    """Timeout wrapped NSS connect (TLS/SSL over TCP)"""
    def __init__(self, host, port=None, timeout=DEFAULT_TIMEOUT,
                 strict=None, dbdir=None):
        NSSConnection.__init__(self, host, port, strict=strict, dbdir=dbdir)
        self._timeout = timeout

    def _create_socket(self, family):
        # old style class
        rv = NSSConnection._create_socket(self, family)
        self.sock = TimeoutWrapper(self.sock)
        self.sock.settimeout(self._timeout)
        return rv


class NSPRConnectionPool(HTTPConnectionPool):
    """Pool for NSPR TCP connections"""
    scheme = 'http'
    ConnectionCls = TimeoutNSPRConnection


class NSSConnectionPool(HTTPConnectionPool):
    """Pool for NSS TLS/SSL connections"""
    scheme = 'https'
    ConnectionCls = TimeoutNSSConnection


class NSSPoolManager(PoolManager):
    """Pool manager for NSPR and NSS connection pools"""
    pool_classes = {
        'http': NSPRConnectionPool,
        'https': NSSConnectionPool,
    }

    def _new_pool(self, scheme, host, port):
        cls = self.pool_classes.get(scheme)
        if cls is None:
            raise ValueError("Unsupported scheme '{}'".format(scheme))
        return cls(host, port, **self.connection_pool_kw)


class NSSTransportAdapter(HTTPAdapter):
    """Transport adapter for NSS and NSPR connections"""
    def __init__(self, dbdir, *args, **kwargs):
        self.dbdir = dbdir
        super(NSSTransportAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK,
                         **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.dbdir = pool_kwargs.get('dbdir', self.dbdir)
        self.poolmanager = NSSPoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block,
            strict=True,
            dbdir=self.dbdir,
            **pool_kwargs
        )
