import logging
import os
from .url import URL
from .request import Request

logger = logging.getLogger(__name__)


def dict_val(key, dictionary):
    if key in dictionary:
        return dictionary[key]
    elif key.lower() in dictionary:
        return dictionary[key.lower()]
    return None


def dict_intval(key, dictionary):
    if key in dictionary:
        return int(dictionary[key])
    elif key.lower() in dictionary:
        return int(dictionary[key.lower()])
    return None


class RequestList:

    def __init__(self, chrome_log, redirect_only=False):
        self.reqs = []
        requests = {}
        for entry in chrome_log:
            if 'method' not in entry \
                    or not entry['method'].startswith('Network.'):
                continue
            rp = entry['params']
            req_id = rp['requestId']
            # logger.debug('{}: {}'.format(req_id, entry['method']))
            if entry['method'] == 'Network.requestWillBeSent':
                if 'redirectResponse' in rp:
                    rdr = rp['redirectResponse']
                    last_req = requests[req_id]
                    if 'remoteIPAddress' in rdr:
                        last_req.remote_ip = rdr['remoteIPAddress']
                    last_req.server_info = dict_val('Server', rdr['headers'])
                    last_req.strict_transport = dict_val(
                            'strict-transport-security', rdr['headers'])
                    last_req.complete = True
                    last_req.status_code = rdr['status']
                    requests[req_id] = Request(req_id)
                    if len(last_req.redirected) > 0:
                        requests[req_id].redirected = last_req.redirected
                        last_req.redirected = []
                    requests[req_id].redirected.append(last_req)
                else:
                    requests[req_id] = Request(req_id)
                requests[req_id].method = rp['request']['method']
                requests[req_id].url = URL(rp['request']['url'])
                requests[req_id].timestamp_start = rp['timestamp']
                if 'headers' in rp['request']:
                    requests[req_id].referrer = dict_val(
                            'Referer', rp['request']['headers'])
            elif entry['method'] == 'Network.requestServedFromCache':
                if req_id not in requests:
                    continue
                requests[req_id] = Request(req_id)
                requests[req_id].from_cache = True
            elif entry['method'] == 'Network.responseReceived':
                if req_id not in requests:
                    continue
                rpr = rp['response']
                requests[req_id].mime_type = rpr['mimeType']
                requests[req_id].status_code = rpr['status']
                requests[req_id].remote_ip = dict_val(
                        'remoteIPAddress', rpr)
                requests[req_id].cookie = dict_val(
                        'Set-Cookie', rpr['headers'])
                requests[req_id].server_info = dict_val(
                        'Server', rpr['headers'])
                requests[req_id].content_length = dict_intval(
                        'Content-Length', rpr['headers'])
                requests[req_id].strict_transport = dict_val(
                        'strict-transport-security', rpr['headers'])
                requests[req_id].cache_control = dict_val(
                        'Cache-Control', rpr['headers'])
                if 'requestHeaders' in rpr:
                    requests[req_id].cookie_sent = dict_val(
                            'Cookie', rpr['requestHeaders'])
            elif entry['method'] == 'Network.loadingFinished':
                if req_id not in requests:
                    continue
                requests[req_id].timestamp_end = rp['timestamp']
                requests[req_id].complete = True
            elif entry['method'] == 'Network.loadingFailed':
                if req_id not in requests:
                    continue
                requests[req_id].timestamp_end = rp['timestamp']
                requests[req_id].complete = True
                requests[req_id].failed = True
        for req in sorted(requests):
            r = requests[req]
            if r.url is None:
                continue
            if r.url.scheme == 'data':
                continue
            if redirect_only:
                if len(r.redirected) > 0:
                    self.reqs.append(r)
            else:
                self.reqs.append(r)
        self.num_reqs = len(self.reqs)
        self.current = 0

    def set_sizes(self, cache_dir):
        for req in self.reqs:
            if req.content_length:
                req.set_size(req.content_length)
            else:
                content_file = cache_dir + '/{}'.format(req.id)
                if os.path.isfile(content_file):
                    statinfo = os.stat(content_file)
                    req.set_size(statinfo.st_size)
                else:
                    req.set_size(0)

    def __iter__(self):
        return self

    def __next__(self):
        if self.current >= self.num_reqs:
            raise StopIteration
        else:
            self.current += 1
            return self.reqs[self.current - 1]

    def __getitem__(self, index):
        return self.reqs[index]

    def __setitem__(self, index, value):
        self.reqs[index] = value

    def __len__(self):
        return len(self.reqs)
