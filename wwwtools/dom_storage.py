import logging
import urllib
from .utility import tex_esc
import html.parser

logger = logging.getLogger(__name__)
html_parser = html.parser.HTMLParser()


class DOMStorage(object):

    def __init__(self, storage_event):
        self.action = storage_event['method'][21:]
        self.key = storage_event['params']['key']
        self.value = False
        self.origin = storage_event['params']['storageId']['securityOrigin']
        self.is_local = storage_event['params']['storageId']['isLocalStorage']
        if self.action == 'ItemAdded' or self.action == 'ItemUpdated':
            self.value = storage_event['params']['newValue']

    @property
    def ltx_key(self):
        return tex_esc(urllib.parse.unquote(self.key))

    @property
    def ltx_value(self):
        if self.value:
            if type(self.value) is bool:
                value_size = 1
            else:
                value_size = len(self.value)
            if value_size > 256:
                return 'DATA (size {} bytes)'.format(value_size)
            return tex_esc(html_parser.unescape(self.value))
        return '-'

    @property
    def cl_key(self):
        return urllib.parse.unquote(self.key)

    def __str__(self):
        return '{}: {} {}'.format(self.origin, self.action, self.key)
