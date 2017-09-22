from .domain import Domain
from .utility import tex_esc


class Server(Domain):

    def __init__(self, domain):
        super().__init__(domain)
        self.refcount = 1
        self.ip = None
        self.info = None
        self.geo_ip = None
        self.strict_transport = None

    @property
    def ltx_info(self):
        if self.info:
            return tex_esc(self.info)
        return '-'
