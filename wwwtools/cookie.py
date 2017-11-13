import logging
from .domain import Domain
from datetime import datetime, timedelta, timezone
from .utility import tex_esc

logger = logging.getLogger(__name__)


class Cookie:

    def __init__(self, start_time, cookie_dict):
        self.start_time = start_time
        try:
            exp = cookie_dict['expires']
            if exp > 154419191800:
                exp = exp / 1000
            self.expires = datetime.fromtimestamp(exp, timezone.utc)
        except ValueError:
            self.expires = datetime(2038, 1, 1, tzinfo=timezone.utc)
        self.name = cookie_dict['name']
        self.value = cookie_dict['value']
        self.cookie_domain = cookie_dict['domain']
        self.domain = Domain(cookie_dict['domain'])
        self.session = cookie_dict['session']
        self.size = cookie_dict['size']
        self.httponly = cookie_dict['httpOnly']
        self.path = cookie_dict['path']
        self.secure = cookie_dict['secure']
        if self.expires > self.start_time:
            self.livetime = self.expires - self.start_time
        else:
            self.livetime = timedelta(0)

    @property
    def is_persistent(self):
        return self.livetime > timedelta(0)

    @property
    def is_host_only(self):
        return not self.cookie_domain.startswith('.')

    @property
    def ltx_name(self):
        return tex_esc(self.name)

    @property
    def ltx_value(self):
        # return tex_esc(wrapper.fill(self.value))
        return tex_esc(self.value)

    def __str__(self):
        rv = '------- cookie\n'
        rv += (
                'Name: {}\nValue: {}\nDomain: {}\n'
                'Path: {}\nExpires: {}\n'.format(
                        self.name,
                        self.value,
                        self.domain,
                        self.path,
                        self.expires
                )
        )
        return rv

    def __lt__(self, other):
        if self.domain < other.domain:
            return True
        elif self.domain > other.domain:
            return False
        if self.expires > other.expires:
            return True
        elif self.expires < other.expires:
                return False
        if self.name < other.name:
            return True
        elif self.name > other.name:
            return False
        if self.name < other.name:
            return True
        elif self.name > other.name:
            return False
        return False

    def __eq__(self, other):
        if self.domain == other.domain and self.name == other.name \
                and self.expires == other.expires:
            return True
        return False
