from sslyze.server_connectivity import ServerConnectivityInfo, \
    ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, \
    Tlsv11ScanCommand, Tlsv12ScanCommand, Sslv20ScanCommand, Sslv30ScanCommand
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import \
    OpenSslCcsInjectionScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.http_headers_plugin import HttpHeadersScanCommand
from sslyze.utils.ssl_connection import SSLHandshakeRejected
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import logging
import socket
import httplib2

logger = logging.getLogger(__name__)


class SSLScanner(object):

    def __init__(self, hostname):
        self.hostname = hostname
        self.ciphers = {
            'ssl20': [],
            'ssl30': [],
            'tls10': [],
            'tls11': [],
            'tls12': [],
        }
        self.cert_info = False
        self.cert_chain = []
        self.vulnerabilities = {
            'heartbleed': False,
            'opensslccs': False,
        }
        self.headers = False
        self.redirects_http = False
        self.errors = []
        self.connected = False
        try:
            self.server_info = ServerConnectivityInfo(
                    hostname=self.hostname,
                    tls_server_name_indication=self.hostname,
            )
            self.server_info.test_connectivity_to_server(network_timeout=1)
        except ServerConnectivityError as e:
            # Could not establish an SSL connection to the server
            logger.error('RuntimeError: {}'.format(e.error_msg))
            self.errors.append('RuntimeError: {}'.format(e.error_msg))
            # raise RuntimeError(
            #         'Error when connecting to {}: {}'.format(
            #                 hostname, e.error_msg)
            # )
            return
        logger.debug('connectivity o.k.')
        self.synchronous_scanner = SynchronousScanner()
        self.connected = True
        logger.debug('init complete')

    @property
    def hsts_header(self):
        if not self.connected:
            return None
        if not self.headers.hsts_header:
            return None
        rv = 'Maxage: {}'.format(self.headers.hsts_header.max_age)
        rv += ', preload: '
        if self.headers.hsts_header.preload:
            rv += 'YES'
        else:
            rv += 'NO'
        rv += ', include subdomains: '
        if self.headers.hsts_header.include_subdomains:
            rv += 'YES'
        else:
            rv += 'NO'
        return rv

    @property
    def hpkp_header(self):
        if not self.connected:
            return None
        if not self.headers.hpkp_header:
            return None
        rv = 'Maxage: {}'.format(self.headers.hpkp_header.max_age)
        rv += ', include subdomains: '
        if self.headers.hpkp_header.include_subdomains:
            rv += 'YES'
        else:
            rv += 'NO'
        rv += ', number of keys: {}'.format(
                len(self.headers.hpkp_header.pin_sha256_list))
        return rv

    @property
    def cert0_subject(self):
        if not self.connected:
            return None
        rv = ''
        cert = self.cert_info.certificate_chain[0]
        for attrib in cert.subject:
            if rv != '':
                rv += ', '
            rv += attrib.value
        return rv

    @property
    def public_key(self):
        if not self.connected:
            return None
        public_key = self.cert_info.certificate_chain[0].public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return 'RSA key: {}bit, Exponent {}'.format(
                    public_key.key_size, public_key.public_numbers().e)
        return 'TBD'

    @property
    def signature(self):
        if not self.connected:
            return None
        cert = self.cert_info.certificate_chain[0]
        return cert.signature_hash_algorithm.name

    def _get_certificate_info(self):
        command = CertificateInfoScanCommand()
        self.cert_info = self.synchronous_scanner.run_scan_command(
                self.server_info, command)
        if self.cert_info.certificate_matches_hostname:
            logger.debug('Server certificate matches hostname.')
        else:
            logger.debug('Server certificate does not match hostname.')
        for cert in self.cert_info.certificate_chain:
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                logger.debug('RSA key: {} bit'.format(public_key.key_size))
            for issuer in cert.issuer.get_attributes_for_oid(
                    NameOID.COMMON_NAME):
                logger.debug(
                        'Issuer: {} (until {})'.format(
                                issuer.value, cert.not_valid_after)
                )

    def _get_ciphers(self):
        # SSL 2.0
        command = Sslv20ScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except ConnectionResetError:
            logger.error('Sslv20ScanCommand: ConnectionResetError')
            self.errors.append('Sslv20ScanCommand: ConnectionResetError')
        except SSLHandshakeRejected:
            logger.error('Sslv20ScanCommand: SSLHandshakeRejected')
            self.errors.append('Sslv20ScanCommand: SSLHandshakeRejected')
        except Exception as e:
            logger.exception('Sslv20ScanCommand failed with {}'.format(e))
            self.errors.append('Sslv20ScanCommand failed with {}'.format(e))
        for cipher in scan_result.accepted_cipher_list:
            self.ciphers['ssl20'].append(cipher)
        # SSL 3.0
        command = Sslv30ScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except ConnectionResetError:
            logger.error('Sslv30ScanCommand: ConnectionResetError')
            self.errors.append('Sslv30ScanCommand: ConnectionResetError')
        except SSLHandshakeRejected:
            logger.error('Sslv30ScanCommand: SSLHandshakeRejected')
            self.errors.append('Sslv30ScanCommand: SSLHandshakeRejected')
        except Exception as e:
            logger.exception('Sslv30ScanCommand failed with {}'.format(e))
            self.errors.append('Sslv30ScanCommand failed with {}'.format(e))
        for cipher in scan_result.accepted_cipher_list:
            self.ciphers['ssl30'].append(cipher)
        # TLS 1.0
        command = Tlsv10ScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except ConnectionResetError:
            logger.error('Tlsv10ScanCommand: ConnectionResetError')
            self.errors.append('Tlsv10ScanCommand: ConnectionResetError')
        except SSLHandshakeRejected:
            logger.error('Tlsv10canCommand: SSLHandshakeRejected')
            self.errors.append('Tlsv10canCommand: SSLHandshakeRejected')
        except Exception as e:
            logger.exception('Tlsv10ScanCommand failed with {}'.format(e))
            self.errors.append('Tlsv10ScanCommand failed with {}'.format(e))
        for cipher in scan_result.accepted_cipher_list:
            self.ciphers['tls10'].append(cipher)
        # TLS 1.1
        command = Tlsv11ScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except ConnectionResetError:
            logger.error('Tlsv11ScanCommand: ConnectionResetError')
            self.errors.append('Tlsv11ScanCommand: ConnectionResetError')
        except SSLHandshakeRejected:
            logger.error('Tlsv11canCommand: SSLHandshakeRejected')
            self.errors.append('Tlsv11canCommand: SSLHandshakeRejected')
        except Exception as e:
            logger.exception('Tlsv11ScanCommand failed with {}'.format(e))
            self.errors.append('Tlsv11ScanCommand failed with {}'.format(e))
        for cipher in scan_result.accepted_cipher_list:
            self.ciphers['tls11'].append(cipher)
        # TLS 1.2
        command = Tlsv12ScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except ConnectionResetError:
            logger.error('Tlsv12ScanCommand: ConnectionResetError')
            self.errors.append('Tlsv12ScanCommand: ConnectionResetError')
        except SSLHandshakeRejected:
            logger.error('Tlsv12canCommand: SSLHandshakeRejected')
            self.errors.append('Tlsv12canCommand: SSLHandshakeRejected')
        except Exception as e:
            logger.exception('Tlsv12ScanCommand failed with {}'.format(e))
            self.errors.append('Tlsv12ScanCommand failed with {}'.format(e))
        for cipher in scan_result.accepted_cipher_list:
            self.ciphers['tls12'].append(cipher)

    def headerscan(self):
        command = HttpHeadersScanCommand()
        try:
            self.headers = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except socket.timeout:
            logger.error('headerscan timed out')
            self.errors.append('headerscan timed out')
        except ConnectionResetError:
            logger.error('ConnectionResetError on headerscan')
            self.errors.append('ConnectionResetError on headerscan')
        except SSLHandshakeRejected:
            logger.error('SSLHandshakeRejected on headerscan')
            self.errors.append('SSLHandshakeRejected on headerscan')
        except Exception as e:
            logger.exception('headerscan failed with {}'.format(e))
            self.errors.append('headerscan failed with {}'.format(e))

    def scan_heartbleed(self):
        command = HeartbleedScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except socket.timeout:
            logger.error('heartbleed timed out')
            self.errors.append('heartbleed timed out')
            return
        except ConnectionResetError:
            logger.error('ConnectionResetError on heartbleedscan')
            self.errors.append('ConnectionResetError on heartbleedscan')
            return
        except SSLHandshakeRejected:
            logger.error('SSLHandshakeRejected on heartbleedscan')
            self.errors.append('SSLHandshakeRejected on heartbleedscan')
            return
        except Exception as e:
            logger.exception('heartbleed failed with {}'.format(e))
            self.errors.append('heartbleed failed with {}'.format(e))
            return
        self.vulnerabilities['heartbleed'] = \
            scan_result.is_vulnerable_to_heartbleed

    def scan_opensslccs(self):
        command = OpenSslCcsInjectionScanCommand()
        try:
            scan_result = self.synchronous_scanner.run_scan_command(
                    self.server_info, command)
        except socket.timeout:
            logger.error('opensslccs timed out')
            self.errors.append('opensslccs timed out')
            return
        except ConnectionResetError:
            logger.error('ConnectionResetError on opensslccsscan')
            self.errors.append('ConnectionResetError on opensslccsscan')
            return
        except SSLHandshakeRejected:
            logger.error('SSLHandshakeRejected on opensslccsscan')
            self.errors.append('SSLHandshakeRejected on opensslccsscan')
            return
        except Exception as e:
            logger.exception('opensslccs failed with {}'.format(e))
            self.errors.append('opensslccs failed with {}'.format(e))
            return
        self.vulnerabilities['opensslccs'] = \
            scan_result.is_vulnerable_to_ccs_injection

    def check_http_redirect(self):
        h = httplib2.Http(".cache", timeout=2)
        h.follow_redirects = False
        http_url = 'http://{}/'.format(self.hostname)
        logger.debug('check http redirect on {}...'.format(http_url))
        try:
            resp, content = h.request(http_url)
            logger.debug('got response {}'.format(resp))
            if resp.status == 301 and \
                    resp.get('location').startswith('https'):
                self.redirects_http = True
        except Exception as e:
            logger.error(
                    'Got exception {} when checking http redirect'.format(e))

    def scan(self):
        if not self.connected:
            return
        self.check_http_redirect()
        logger.debug('check_http_redirect() done')
        self._get_certificate_info()
        logger.debug('_get_certificate_info() done')
        self._get_ciphers()
        logger.debug('_get_ciphers() done')
        self.headerscan()
        logger.debug('headerscan() done')
        self.scan_heartbleed()
        logger.debug('scan_heartbleed() done')
        self.scan_opensslccs()
        logger.debug('scan_opensslccs done')
