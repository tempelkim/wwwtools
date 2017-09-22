from urllib.parse import urlparse
from .domain import Domain
import os
from .utility import tex_esc


class URL(object):

    def __init__(self, url_string):
        self.url_string = url_string
        self.url_parts = urlparse(url_string)

    @property
    def netloc(self):
        return self.url_parts.netloc

    @property
    def path(self):
        return self.url_parts.path

    @property
    def scheme(self):
        return self.url_parts.scheme

    @property
    def file_name(self):
        file_name = os.path.basename(self.url_parts.path)
        if file_name.endswith('/') or file_name == '':
            return 'index'
        return file_name

    @property
    def domain(self):
        dpp = self.url_parts.netloc.find(':')
        if dpp > 0:
            return self.url_parts.netloc[:dpp]
        return self.url_parts.netloc

    @property
    def tld(self):
        d = Domain(self.domain)
        return d.tld

    @property
    def is_secure(self):
        if self.url_parts.scheme and self.url_parts.scheme == 'https':
            return True
        return False

    @property
    def ltx_geturl(self):
        return tex_esc(self.url_parts.geturl())

    def geturl(self):
        return self.url_parts.geturl()

    def __str__(self):
        return self.url_parts.geturl()
