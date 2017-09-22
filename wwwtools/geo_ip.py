import logging
import geoip2.database
from geoip2.errors import AddressNotFoundError
from _maxminddb_geolite2 import geolite2_database

logger = logging.getLogger(__name__)


class GeoIP(object):

    reader = geoip2.database.Reader(geolite2_database())

    def __init__(self, ip):
        try:
            self.geoip = self.reader.city(ip)
        except AddressNotFoundError:
            self.geoip = False
            logger.error(
                    'IP {} not found in {}'.format(ip, geolite2_database()))
        except ValueError:
            self.geoip = False
            logger.error(
                    'invalid IP {}'.format(ip))

    @property
    def get_flag(self):
        if not self.geoip:
            return 'notfound.png'
        if self.country:
            return '{}.png'.format(self.country.lower())
        if self.continent and self.continent == 'EU':
                return '_European Union.png'
        return 'notfound.png'

    @property
    def ltx(self):
        if not self.geoip:
            return '?'
        return self.country

    @property
    def country(self):
        if not self.geoip:
            return '?'
        return self.geoip.country.iso_code

    @property
    def continent(self):
        if not self.geoip:
            return '?'
        return self.geoip.continent.code
        # return self.geoip['continent']['code']
