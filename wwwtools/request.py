import logging
from .geo_ip import GeoIP

logger = logging.getLogger(__name__)


class Request:

    def __init__(self, req_id):
        self.id = req_id
        self.cache_control = None
        self.complete = False
        self.content_length = None
        self.cookie = None
        self.cookie_sent = None
        self.failed = False
        self.from_cache = False
        self.geoip = None
        self.method = 'GET'
        self.mime_type = None
        self.post_data = None
        self.redirected = []
        self.referrer = None
        self.remote_ip = None
        self.server_info = None
        self.size = None
        self.status_code = None
        self.strict_transport = None
        self.timestamp_start = None
        self.timestamp_end = None
        self.url = None

    @property
    def is_viewable(self):
        if self.size > 0 and (
                'java' in self.mime_type or 'text' in self.mime_type):
            return True
        return False

    @property
    def is_javascript(self):
        if self.size > 0 and 'java' in self.mime_type:
            return True
        return False

    @property
    def geo_ip(self):
        if self.remote_ip is None:
            return None
        if self.geoip is None:
            if self.remote_ip.startswith('['):
                self.geoip = GeoIP(self.remote_ip[1:-1])
            else:
                self.geoip = GeoIP(self.remote_ip)
        return self.geoip

    def set_size(self, size):
        self.size = size
