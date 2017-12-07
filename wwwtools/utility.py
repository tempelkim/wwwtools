import logging
import requests
from datetime import datetime
# dirty fix for SSL: CERTIFICATE_VERIFY_FAILED
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

logger = logging.getLogger(__name__)


def try_dtm_format(v, tformat):
    rv = False
    try:
        rv = datetime.strptime(v, tformat)
    except ValueError:
        pass
    return rv


def get_expire_date(v):
    exp = try_dtm_format(v, '%a, %d-%b-%Y %X %Z')
    if exp:
        return exp
    exp = try_dtm_format(v, '%a, %d-%b-%y %X %Z')
    if exp:
        return exp
    exp = try_dtm_format(v, '%a, %d %b %Y %X %Z')
    if exp:
        return exp
    exp = try_dtm_format(v, '%a, %d %b %y %X %Z')
    if exp:
        return exp
    logger.error('could not read date format \'{}\''.format(v))
    raise


def write_file(fname, content, log_message=False, binary=False):
    if log_message:
        logger.info(log_message)
    if binary:
        f = open(fname, 'wb')
    else:
        f = open(fname, 'w')
    f.write(content)
    f.close()


def fetch_page(page_url, page_file, user_agent=False, retries=3, timeout=10):
    logger.info('fetch page: {}'.format(page_url))
    headers = None
    if user_agent:
        headers = {'User-Agent': user_agent}
    try:
        r = requests.get(page_url, headers=headers, verify=False, timeout=2)
    except requests.exceptions.ConnectionError:
        logger.error('fetch {}: connection error'.format(page_url))
        return (None, None)
    except requests.exceptions.ReadTimeout:
        logger.error('fetch {}: read timeout'.format(page_url))
        return (None, None)
    if r.status_code != 200:
        page_info = '\n'.join(
                '{}: {}'.format(key, val) for key, val in r.headers.items())
        logger.error(
                'fetch {}: status code {}: {}'.format(
                        page_url, r.status_code, page_info)
        )
        return (None, None)
    page_content = r.content
    page_info = '\n'.join(
            '{}: {}'.format(key, val) for key, val in r.headers.items())
    info_file = page_file + '.info'
    write_file(
            page_file,
            page_content,
            'write content to {}'.format(page_file),
            binary=True
    )
    write_file(info_file, page_info, 'write info to {}'.format(info_file))
    return (page_content, r.headers)


def percentage(val1, val2, precision=False):
    if val2 == 0:
        return None
    pc = (100.0 * val1) / val2
    if precision:
        return '{val:.{prc}f}'.format(val=pc, prc=precision)
    return pc


def repl(match):
    print(match.group(0))
    return b'XXXXX'


def ucode_fix(text):
    text = text.replace("😃", ":-)")
    return text


def tex_esc(text):
    text = text.replace("\\", "\\textbackslash")
    text = text.replace('″', '"')
    text = text.replace("⇧", "")
    text = text.replace("_", "\\_")
    text = text.replace("{", "\\{")
    text = text.replace("}", "\\}")
    text = text.replace("&", "\\&")
    text = text.replace("%", "\\%")
    text = text.replace("#", "\\#")
    text = text.replace("$", "\\$")
    text = text.replace("^", "\\textasciicircum{}")
    text = text.replace("~", "\\textasciitilde{}")
    # text = text.replace("😃", ":-)")
    return text
