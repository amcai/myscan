# !/usr/bin/env python3
# @Time    : 2020/11/20
# @Author  : caicai
# @File    : requests_urlencode_patch.py

from urllib3.util import parse_url
from urllib3.exceptions import (LocationParseError)
from requests.exceptions import (MissingSchema, InvalidURL)
from requests._internal_utils import to_native_string, unicode_is_ascii
from requests.utils import (requote_uri)
from requests.compat import (urlunparse, str, bytes)
from myscan.lib.core.const import key_unquote
import requests


def prepare_url(self, url, params):
    """Prepares the given HTTP URL."""
    #: Accept objects that have string representations.
    #: We're unable to blindly call unicode/str functions
    #: as this will include the bytestring indicator (b'')
    #: on python 3.x.
    #: https://github.com/requests/requests/pull/2238
    if isinstance(url, bytes):
        url = url.decode('utf8')
    else:
        url = str(url)
    # Remove leading whitespaces from url
    url = url.lstrip()
    need_quote = True
    if url.startswith(key_unquote):
        need_quote = False
        url = url.replace(key_unquote, "")
    # Don't do any URL preparation for non-HTTP schemes like `mailto`,
    # `data` etc to work around exceptions from `url_parse`, which
    # handles RFC 3986 only.
    if ':' in url and not url.lower().startswith('http'):
        self.url = url
        return

    # Support for unicode domain names and paths.
    try:
        scheme, auth, host, port, path, query, fragment = parse_url(url)
    except LocationParseError as e:
        raise InvalidURL(*e.args)

    if not scheme:
        error = ("Invalid URL {0!r}: No schema supplied. Perhaps you meant http://{0}?")
        error = error.format(to_native_string(url, 'utf8'))

        raise MissingSchema(error)

    if not host:
        raise InvalidURL("Invalid URL %r: No host supplied" % url)

    # In general, we want to try IDNA encoding the hostname if the string contains
    # non-ASCII characters. This allows users to automatically get the correct IDNA
    # behaviour. For strings containing only ASCII characters, we need to also verify
    # it doesn't start with a wildcard (*), before allowing the unencoded hostname.
    if not unicode_is_ascii(host):
        try:
            host = self._get_idna_encoded_host(host)
        except UnicodeError:
            raise InvalidURL('URL has an invalid label.')
    elif host.startswith(u'*'):
        raise InvalidURL('URL has an invalid label.')

    # Carefully reconstruct the network location
    netloc = auth or ''
    if netloc:
        netloc += '@'
    netloc += host
    if port:
        netloc += ':' + str(port)

    # Bare domains aren't valid URLs.
    if not path:
        path = '/'
    if isinstance(params, (str, bytes)):
        params = to_native_string(params)

    enc_params = self._encode_params(params)
    if enc_params:
        if query:
            query = '%s&%s' % (query, enc_params)
        else:
            query = enc_params
    if need_quote:
        url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
    else:
        url = urlunparse([scheme, netloc, path, None, query, fragment])
    self.url = url


def pathch_urlencode():
    requests.models.PreparedRequest.prepare_url = prepare_url
