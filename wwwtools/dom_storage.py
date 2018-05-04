import logging
import urllib
import re
from .utility import tex_esc
import html.parser

logger = logging.getLogger(__name__)
html_parser = html.parser.HTMLParser()


class DOMStorage(object):

    def __init__(self, storage_event):
        self.action = storage_event['method'][21:]
        if 'key' in storage_event['params']:
            self.key = storage_event['params']['key']
        else:
            self.key = None
        self.value = False
        self.origin = storage_event['params']['storageId']['securityOrigin']
        self.is_local = storage_event['params']['storageId']['isLocalStorage']
        if self.action == 'ItemAdded' or self.action == 'ItemUpdated':
            self.value = storage_event['params']['newValue']

    @property
    def ltx_key(self):
        if self.key:
            if re.match('^[ -~]+$', self.key):
                return tex_esc(urllib.parse.unquote(self.key))
            else:
                return 'DATA (size: {} bytes)'.format(len(self.key))
        else:
            return None

    @property
    def ltx_value(self):
        if self.value:
            if type(self.value) is bool:
                value_size = 1
            else:
                value_size = len(self.value)
            if value_size > 256:
                return 'DATA (size: {} bytes)'.format(value_size)
            if re.match('^[ -~]+$', self.value):
                return tex_esc(html_parser.unescape(self.value))
            else:
                return 'DATA (size: {} bytes)'.format(len(self.value))
        return '-'

    @property
    def cl_key(self):
        if self.key:
            return urllib.parse.unquote(self.key)
        return '-'

    def __str__(self):
        return '{}: {} {}'.format(self.origin, self.action, self.key)
