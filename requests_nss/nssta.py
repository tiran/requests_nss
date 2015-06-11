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

import errno
import getpass
import httplib
import logging
import socket

from requests.packages.urllib3.connectionpool import HTTPConnectionPool
from requests.packages.urllib3.poolmanager import PoolManager

from requests.adapters import HTTPAdapter
from requests.adapters import DEFAULT_POOLBLOCK

from nss import io
from nss import nss
from nss import ssl
from nss.error import NSPRError

try:
    from nss.ssl import SSL_REQUIRE_SAFE_NEGOTIATION
    from nss.ssl import SSL_ENABLE_RENEGOTIATION
    from nss.ssl import SSL_RENEGOTIATE_REQUIRES_XTN
except ImportError:
    SSL_REQUIRE_SAFE_NEGOTIATION = 21
    SSL_ENABLE_RENEGOTIATION = 21
    SSL_RENEGOTIATE_REQUIRES_XTN = 2


logger = logging.getLogger('nssta')

DEFAULT_TIMEOUT = io.PR_INTERVAL_NO_TIMEOUT
TW_TIMEOUT = io.PR_INTERVAL_NO_TIMEOUT - 1

TICKS_SEC = io.seconds_to_interval(1)
SEC_TICKS = 1. / TICKS_SEC


class NSSAdapterException(Exception):
    pass


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
        if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
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


# old style classes
class AbstractNSPRConnection(httplib.HTTPConnection):
    default_port = None
    #  Socket.set_socket_option(option, ...)
    socket_options = []

    def __init__(self, host, port=None, strict=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 certdb=None, log=None):
        httplib.HTTPConnection.__init__(self, host, port, strict, timeout)
        if not nss.nss_is_initialized():
            NSSAdapterException('NSS is not initialized')

        if not isinstance(certdb, nss.CertDB):
            raise TypeError(certdb)
        self.certdb = certdb
        self.log = log if log is not None else logger

    def _create_socket(self, net_addr):
        raise NotImplementedError

    def connect(self):
        self.log.debug("connect: host=%s port=%s", self.host, self.port)
        try:
            addr_info = io.AddrInfo(self.host)
        except Exception:
            self.log.exception("could not resolve host address '%s'",
                               self.host)
            raise

        for net_addr in addr_info:
            net_addr.port = self.port
            self._create_socket(net_addr)
            try:
                self.log.debug("try connect: %s", net_addr)
                self.sock.connect(net_addr)
                self.log.debug("connected to: %s", net_addr)
                return
            except Exception as e:
                self.log.exception("connect failed: %s (%s)", net_addr, e)

        raise IOError(errno.ENOTCONN,
                      "could not connect to %s at port %d" %
                      (self.host, self.port))

    def _close_socket(self):
        raise NotImplementedError

    def close(self):
        if self.sock is not None:
            self.log.debug('Closing connection')
            self._close_socket()
            self.sock = None


class TimeoutNSPRConnection(AbstractNSPRConnection):
    """Timeout wrapped NSPR connect (plain TCP)
    """
    default_port = httplib.HTTPConnection.default_port

    def _create_socket(self, net_addr):
        sock = io.Socket(net_addr.family)
        for option in self.socket_options:
            sock.set_socket_option(*option)
        self.sock = TimeoutWrapper(sock)
        self.sock.settimeout(self.timeout)

    def _close_socket(self):
        self.sock.close()


class TimeoutNSSConnection(AbstractNSPRConnection):
    """Timeout wrapped NSS connect (TLS/SSL over TCP)
    """
    default_port = httplib.HTTPSConnection.default_port

    # SSLSocket.set_ssl_version_range(min_version, max_version)
    ssl_version_range = [
        ssl.SSL_LIBRARY_VERSION_TLS_1_1,
        ssl.SSL_LIBRARY_VERSION_TLS_1_2
    ]

    # SSLSocket.set_ssl_option(option value)
    # SSL_SECURITY and SSL_HANDSHAKE_AS_CLIENT are always set
    ssl_options = [
        (SSL_REQUIRE_SAFE_NEGOTIATION, True),
        (SSL_ENABLE_RENEGOTIATION, SSL_REQUIRE_SAFE_NEGOTIATION),
    ]

    # SSLSocket.set_cipher_pref(cipher, enabled)
    cipher_pref = []

    # SSLSocket.set_pkcs11_pin_arg()
    pkcs11_pin_arg = ()

    def _create_socket(self, net_addr):
        # old style class
        sock = ssl.SSLSocket(net_addr.family)
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        sock.set_ssl_version_range(*self.ssl_version_range)
        sock.set_hostname(self.host)
        # buggy in 0.16
        # sock.set_certificate_db(self.certdb)

        for option in self.socket_options:
            sock.set_socket_option(*option)

        for option, value in self.ssl_options:
            sock.set_ssl_option(option, value)

        sock.set_pkcs11_pin_arg(*self.pkcs11_pin_arg)

        # Provide a callback which notifies us when the handshake is complete
        sock.set_handshake_callback(self.handshake_callback)

        # Provide a callback to verify the servers certificate
        sock.set_auth_certificate_callback(self.auth_certificate_callback)

        self.sock = TimeoutWrapper(sock)
        self.sock.settimeout(self.timeout)

    def _close_socket(self):
        # clear reference cycle to self
        cb = lambda: None
        self.sock.set_handshake_callback(cb)
        self.sock.set_auth_certificate_callback(cb)
        self.sock.set_client_auth_data_callback(cb)
        self.sock.set_pkcs11_pin_arg(None)
        self.sock.close()

    def auth_certificate_callback(self, sock, check_sig, is_server):
        cert_is_valid = False

        cert = sock.get_peer_certificate()

        self.log.debug("auth_certificate_callback: check_sig=%s "
                       "is_server=%s %s", check_sig, is_server, cert.subject)

        pin_args = sock.get_pkcs11_pin_arg()
        if pin_args is None:
            pin_args = ()

        # Define how the cert is being used based upon the is_server flag.
        # This may seem backwards, but isn't. If we're a server we're trying
        # to validate a client cert. If we're a client we're trying to
        # validate a server cert.
        if is_server:
            intended_usage = nss.certificateUsageSSLClient
        else:
            intended_usage = nss.certificateUsageSSLServer

        try:
            # If the cert fails validation it will raise an exception, the
            # errno attribute will be set to the error code matching the
            # reason why the validation failed and the strerror attribute
            # will contain a string describing the reason.
            approved_usage = cert.verify_now(self.certdb, check_sig,
                                             intended_usage, *pin_args)
        except Exception as e:
            self.log.exception('cert validation failed for "%s" (%s)',
                               cert.subject, e)
            cert_is_valid = False
            return cert_is_valid

        self.log.debug("approved_usage = %s intended_usage = %s",
                       ', '.join(nss.cert_usage_flags(approved_usage)),
                       ', '.join(nss.cert_usage_flags(intended_usage)))

        # Is the intended usage a proper subset of the approved usage
        if approved_usage & intended_usage:
            cert_is_valid = True
        else:
            cert_is_valid = False

        # If this is a server, we're finished
        if is_server or not cert_is_valid:
            self.log.debug('cert valid %s for "%s"', cert_is_valid,
                           cert.subject)
            return cert_is_valid

        # Certificate is OK.  Since this is the client side of an SSL
        # connection, we need to verify that the name field in the cert
        # matches the desired hostname.  This is our defense against
        # man-in-the-middle attacks.

        hostname = sock.get_hostname()
        try:
            # If the cert fails validation it will raise an exception
            cert_is_valid = cert.verify_hostname(hostname)
        except Exception, e:
            self.log.error('failed verifying socket hostname "%s" matches '
                           'cert subject "%s" (%s)', hostname,
                           cert.subject, e.strerror)
            cert_is_valid = False
            return cert_is_valid

        self.log.debug('cert valid %s for "%s"', cert_is_valid, cert.subject)
        return cert_is_valid

    def handshake_callback(self, sock):
        """Verify callback. If we get here then the certificate is ok.
        """
        channel = sock.get_ssl_channel_info()
        suite = ssl.get_cipher_suite_info(channel.cipher_suite)
        self.log.debug("handshake complete, peer = %s", sock.get_peer_name())
        self.log.debug('Protocol: %s' % channel.protocol_version_str.upper())
        self.log.debug('Cipher: %s' % suite.cipher_suite_name)

    def client_auth_data_callback(self, ca_names, chosen_nickname=None,
                                  password=None):
        """Client authentication callback (client cert)

        The password argument is passed down to the password callback.
        """
        cert = None
        if chosen_nickname:
            try:
                cert = nss.find_cert_from_nickname(chosen_nickname, password)
                priv_key = nss.find_key_by_any_cert(cert, password)
                return cert, priv_key
            except NSPRError:
                return False
        else:
            nicknames = nss.get_cert_nicknames(self.certdb,
                                               nss.SEC_CERT_NICKNAMES_USER)
            for nickname in nicknames:
                try:
                    cert = nss.find_cert_from_nickname(nickname, password)
                    if cert.check_valid_times():
                        if cert.has_signer_in_ca_names(ca_names):
                            priv_key = nss.find_key_by_any_cert(cert,
                                                                password)
                            return cert, priv_key
                except NSPRError:
                    pass
            return False


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
    PoolManagerCls = NSSPoolManager

    __attrs__ = HTTPAdapter.__attrs__ + ['certdb']

    def __init__(self, certdb=None, log=None, *args, **kwargs):
        if not nss.nss_is_initialized():
            NSSAdapterException('NSS is not initialized')
        if certdb is None:
            self.certdb = nss.get_default_certdb()
        else:
            self.certdb = certdb
        self.log = log if log is not None else logger
        super(NSSTransportAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK,
                         **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.certdb = pool_kwargs.get('certdb', self.certdb)
        self.poolmanager = self.PoolManagerCls(
            num_pools=connections, maxsize=maxsize,
            block=block,
            strict=True,
            certdb=self.certdb,
            log=self.log,
            **pool_kwargs
        )


def password_callback(slot, retry, password=None):
    """thread local password callback
    """
    if not retry and password:
        return password
    return getpass.getpass("Enter password for %s: " % slot.token_name)


def initialize_nss(dbdir):
    """Initialize NSS

    nss_init() initializes NSS and the DB globally.
    """
    # global settings
    nss.nss_init(dbdir)
    ssl.set_domestic_policy()
    ssl.clear_session_cache()
    # thread local callback
    nss.set_password_callback(password_callback)
