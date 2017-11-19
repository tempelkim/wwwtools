import logging
import re

logger = logging.getLogger(__name__)

KEX_ALGORITHMS = {
    'NULL': {
        'anon': True
    },
    'DH_anon': {
        'anon': True,
        'type': 'dh',
    },
    'DH_anon_EXPORT': {
        'anon': True,
        'export': True,
        'type': 'dh',
    },
    'DH_anon_EXPORT': {
        'anon': True,
        'type': 'ec',
    },
    'ECDH_anon': {
        'anon': True,
        'type': 'ec',
    },
    'ECDH_anon_EXPORT': {
        'anon': True,
        'export': True,
        'type': 'ec',
    },
    'RSA': {
        'pubkey': 'rsa',
    },
    'RSA_FIPS': {
        'pubkey': 'rsa',
    },
    'RSA_EXPORT': {
        'export': True,
        'pubkey': 'rsa',
        'type': 'rsa',
    },
    'RSA_EXPORT1024': {
        'export': True,
        'pubkey': 'rsa',
        'type': 'rsa',
    },
    'DHE_RSA': {
        'pubkey': 'rsa',
        'type': 'dh',
    },
    'DHE_RSA_EXPORT': {
        'export': True,
        'pubkey': 'rsa',
        'type': 'dh',
    },
    'DHE_DSS': {
        'pubkey': 'dsa',
        'type': 'dh',
    },
    'DHE_DSS_EXPORT': {
        'export': True,
        'pubkey': 'dsa',
        'type': 'dh',
    },
    'DHE_DSS_EXPORT1024': {
        'export': True,
        'pubkey': 'dsa',
        'type': 'dh',
    },
    'DH_DSS': {
        'pubkey': 'dh',
    },
    'DH_DSS_EXPORT': {
        'export': True,
        'pubkey': 'dh',
    },
    'DH_RSA': {
        'pubkey': 'dh',
    },
    'DH_RSA_EXPORT': {
        'export': True,
        'pubkey': 'dh',
    },
    'ECDHE_RSA': {
        'pubkey': 'rsa',
        'type': 'ec'
    },
    'ECDHE_ECDSA': {
        'pubkey': 'ec',
        'type': 'ec'
    },
    'ECDH_ECDSA': {
        'pubkey': 'ec',
    },
    'ECDH_RSA': {
        'pubkey': 'ec',
    },
    'ECDH_ECNRA': {
        'pubkey': 'ec',
    },
    'ECMQV_ECDSA': {
        'pubkey': 'ec',
        'type': 'ecmqv',
    },
    'ECMQV_ECNRA': {
        'pubkey': 'ec',
    },
    'PSK': {
        'pubkey': 'psk',
    },
    'RSA_PSK': {
        'pubkey': 'rsa',
        'type': 'psk',
    },
    'DHE_PSK': {
        'type': 'dh',
    },
    'PSK_DHE': {
        'type': 'dh',
    },
    'ECDHE_PSK': {
        'type': 'ec',
    },
    'SRP_SHA': {
        'type': 'srp',
    },
    'SRP_SHA_DSS': {
        'pubkey': 'dsa',
        'type': 'srp',
    },
    'SRP_SHA_RSA': {
        'pubkey': 'rsa',
        'type': 'srp',
    },
    'FORTEZZA_KEA': {
    },
    'GOSTR341001': {
    },
    'GOSTR341094': {
    },
    'KRB5': {
    },
    'KRB5_EXPORT': {
        'export': True,
    },
}

remdx = re.compile('([mM][dD][245])')
resha1 = re.compile('([sS][hH][aA]1)')


def rsa_equiv(ktype, bits):
    if ktype in ('rsa', 'dsa', 'dh'):
        return bits
    if ktype == 'ec':
        if bits < 160:
            return 512
        elif bits < 224:
            return 1024
        elif bits < 256:
            return 2048
        elif bits < 384:
            return 3072
        elif bits < 512:
            return 7680
        else:
            return 15360
    return None


class CipherSuite:

    def __init__(self, suite_name):
        # see https://github.com/nmap/nmap/blob/master/nselib/tls.lua
        self.name = suite_name
        self.kex = False
        self.cipher = False
        self.mode = False
        self.key_size = False
        self.block_size = False
        self.mode = None
        self.hash = None
        self.draft = False
        self.key_strength = None
        self.score = None

        tokens = suite_name.split('_')
        if tokens[0] == 'OLD':
            tokens.pop(0)
        if tokens[0] != 'TLS' and tokens[0] != 'SSL':
            logger.warn('Not a TLS ciphersuite: {}'.format(suite_name))
            return
        i = 1
        while tokens[i] and tokens[i] != 'WITH':
            i += 1
        if tokens[i] and tokens[i] != 'WITH':
            logger.warn('Can\'t parse (no WITH): : {}'.format(suite_name))
        self.kex = '_'.join(tokens[1:i])
        i += 1
        t = tokens[i]
        self.cipher = t
        if t == '3DES':  # 3DES_EDE
            i += 1
        if t == '3DES':
            self.key_size = 112
        elif t == 'CHACHA20':
            self.key_size = 256
        elif t in ('IDEA', 'SEED'):
            self.key_size = 128
        elif t == 'FORTEZZA':
            self.key_size = 80
        elif t == 'DES':
            self.key_size = 56
        elif t == 'RC2' or t == 'DES40':
            self.key_size = 40
        elif t == 'NULL':
            self.key_size = 0
        else:
            i += 1
            self.key_size = int(tokens[i])
        if t in ('3DES', 'RC2', 'IDEA', 'DES', 'FORTEZZA', 'DES40'):
            self.block_size = 64
        elif t in ('AES', 'CAMELLIA', 'ARIA', 'SEED'):
            self.block_size = 128
        if self.cipher == 'RC4':
            self.mode = 'stream'
        elif self.cipher == 'CHACHA20':
            i += 1
            self.cipher = 'CHACHA20-POLY1305'
            self.mode = 'stream'
        elif self.cipher != 'NULL':
            i += 1
            self.mode = tokens[i]
        if 'EXPORT' in self.kex and int(tokens[i + 1]):
            i += 1
            self.key_size = int(tokens[i])
        if self.cipher == 'RC4':
            self.key_size = min(self.key_size, 80)
        if self.mode == 'CCM':
            self.hash = 'SHA256'
        else:
            i += 1
            if tokens[i].endswith('-draft'):
                self.draft = True
                self.hash = tokens[i][:-6]
            else:
                self.hash = tokens[i]

    def get_key_strength(self, cert):
        try:
            kex = KEX_ALGORITHMS[self.kex]
        except KeyError:
            logger.error('KeyError KEX_ALGORITHMS[{}]'.format(self.kex))
            return
        pubkey = cert.public_key()
        if 'anon' in kex:
            self.key_strength = 0
        elif 'export' in kex:
            if '1024' in self.kex:
                self.key_strength = 1024
            else:
                self.key_strength = 512
        else:
            if 'pubkey' in kex:
                mdx_match = remdx.match(cert.signature_hash_algorithm.name)
                if mdx_match:
                    self.key_strength = 0
                    self.score = 0
                    return
                sha1_match = resha1.match(cert.signature_hash_algorithm.name)
                if sha1_match:
                    if cert.not_valid_before.year >= 2016:
                        self.key_strength = 0
                        self.score = 0
                        return
                self.key_strength = rsa_equiv(kex['pubkey'], pubkey.key_size)
                pk_exponent = pubkey.public_numbers().e
                if pk_exponent == 1:
                    self.key_strength = 0
                    self.score = 0
                    return
        self.get_score()

    def get_score(self):
        kex_score = 0
        if not self.key_strength:
            return
        if self.key_strength == 0:
            self.score = 0
            return
        if self.key_strength < 512:
            kex_score = 0.2
        elif self.key_strength < 1024:
            kex_score = 0.4
        elif self.key_strength < 2048:
            kex_score = 0.8
        elif self.key_strength < 4096:
            kex_score = 0.9
        else:
            kex_score = 1.0
        cipher_score = 0
        if self.key_size == 0:
            self.score = 0
            return
        if self.key_size < 128:
            cipher_score = 0.2
        elif self.key_size < 256:
            cipher_score = 0.8
        else:
            cipher_score = 1.0
        self.score = 0.43 * kex_score + 0.57 * cipher_score

    @property
    def letter_grade(self):
        if not self.score:
            return None
        if self.score >= 0.8:
            return 'A'
        elif self.score >= 0.65:
            return 'B'
        elif self.score >= 0.5:
            return 'C'
        elif self.score >= 0.35:
            return 'D'
        elif self.score >= 0.2:
            return 'E'
        return 'F'


if __name__ == '__main__':
    c1 = CipherSuite('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA')
    c2 = CipherSuite('TLS_KRB5_WITH_3DES_EDE_CBC_MD5')
    c3 = CipherSuite('TLS_RSA_WITH_AES_128_GCM_SHA256')
    c4 = CipherSuite('TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA')
