#!/usr/bin/python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import getpass
import httplib
import logging
import sys
import urlparse

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

#------------------------------------------------------------------------------

timeout_secs = 3

#------------------------------------------------------------------------------

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    cert_is_valid = False

    cert = sock.get_peer_certificate()

    logging.debug("auth_certificate_callback: check_sig=%s is_server=%s\n%s",
                  check_sig, is_server, str(cert))

    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    # Define how the cert is being used based upon the is_server flag.  This may
    # seem backwards, but isn't. If we're a server we're trying to validate a
    # client cert. If we're a client we're trying to validate a server cert.
    if is_server:
        intended_usage = nss.certificateUsageSSLClient
    else:
        intended_usage = nss.certificateUsageSSLServer

    try:
        # If the cert fails validation it will raise an exception, the errno attribute
        # will be set to the error code matching the reason why the validation failed
        # and the strerror attribute will contain a string describing the reason.
        approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
    except Exception, e:
        logging.error('cert validation failed for "%s" (%s)', cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    logging.debug("approved_usage = %s intended_usage = %s",
                  ', '.join(nss.cert_usage_flags(approved_usage)),
                  ', '.join(nss.cert_usage_flags(intended_usage)))

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        logging.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
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
        logging.error('failed verifying socket hostname "%s" matches cert subject "%s" (%s)',
                      hostname, cert.subject, e.strerror)
        cert_is_valid = False
        return cert_is_valid

    logging.debug('cert valid %s for "%s"', cert_is_valid,  cert.subject)
    return cert_is_valid

def password_callback(slot, retry, password):
    if not retry and password: return password
    return getpass.getpass("Enter password for %s: " % slot.token_name);

def handshake_callback(sock):
    """
    Verify callback. If we get here then the certificate is ok.
    """
    logging.debug("handshake complete, peer = %s", sock.get_peer_name())
    pass

class NSSConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPSConnection.default_port

    def __init__(self, host, port=None, strict=None, dbdir=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)

        if not dbdir:
            raise RuntimeError("dbdir is required")

        logging.debug('%s init host=%s dbdir=%s', self.__class__.__name__, host, dbdir)
        if not nss.nss_is_initialized(): nss.nss_init(dbdir)
        self.sock = None
        ssl.set_domestic_policy()
        nss.set_password_callback(password_callback)

    def _create_socket(self, family):
        self.sock = ssl.SSLSocket(family)
        self.sock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        self.sock.set_hostname(self.host)

        # Provide a callback which notifies us when the SSL handshake is complete
        self.sock.set_handshake_callback(handshake_callback)

        # Provide a callback to verify the servers certificate
        self.sock.set_auth_certificate_callback(auth_certificate_callback,
                                           nss.get_default_certdb())


    def connect(self):
        logging.debug("connect: host=%s port=%s", self.host, self.port)
        try:
            addr_info = io.AddrInfo(self.host)
        except Exception, e:
            logging.error("could not resolve host address \"%s\"", self.host)
            raise

        for net_addr in addr_info:
            net_addr.port = self.port
            self._create_socket(net_addr.family)
            try:
                logging.debug("try connect: %s", net_addr)
                self.sock.connect(net_addr, timeout=io.seconds_to_interval(timeout_secs))
                logging.debug("connected to: %s", net_addr)
                return
            except Exception, e:
                logging.debug("connect failed: %s (%s)", net_addr, e)

        raise IOError(errno.ENOTCONN, "could not connect to %s at port %d" % (self.host, self.port))

class NSPRConnection(httplib.HTTPConnection):
    default_port = httplib.HTTPConnection.default_port

    def __init__(self, host, port=None, strict=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)

        logging.debug('%s init %s', self.__class__.__name__, host)
        if not nss.nss_is_initialized(): nss.nss_init_nodb()
        self.sock = None

    def connect(self):
        logging.debug("connect: host=%s port=%s", self.host, self.port)
        try:
            addr_info = io.AddrInfo(self.host)
        except Exception, e:
            logging.error("could not resolve host address \"%s\"", self.host)
            raise

        for net_addr in addr_info:
            net_addr.port = self.port
            self.sock = io.Socket(net_addr.family)
            try:
                logging.debug("try connect: %s", net_addr)
                self.sock.connect(net_addr, timeout=io.seconds_to_interval(timeout_secs))
                logging.debug("connected to: %s", net_addr)
                return
            except Exception, e:
                logging.debug("connect failed: %s (%s)", net_addr, e)

        raise IOError(errno.ENOTCONN, "could not connect to %s at port %d" % (self.host, self.port))
