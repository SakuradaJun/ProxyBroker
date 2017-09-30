import struct
import socket
inet_aton = socket.inet_aton
from abc import ABC, abstractmethod

from aiosocks import InvalidServerReply
from aiosocks import InvalidServerVersion
from aiosocks import LoginAuthenticationFailed
from aiosocks import NoAcceptableAuthMethods
from aiosocks import constants as socks_c

from .errors import BadStatusError, BadResponseError
from .utils import get_headers, get_status_code


__all__ = ['Socks5Ngtr', 'Socks4Ngtr', 'Connect80Ngtr', 'Connect25Ngtr',
           'HttpsNgtr', 'HttpNgtr', 'NGTRS']


SMTP_READY = 220


def _CONNECT_request(host, port, **kwargs):
    kwargs.setdefault('User-Agent', get_headers()['User-Agent'])
    kw = {'host': host, 'port': port, 'headers': '\r\n'.join(
          ('%s: %s' % (k, v) for k, v in kwargs.items()))}
    req = ('CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n'
           '{headers}\r\nConnection: keep-alive\r\n\r\n').format(**kw).encode()
    return req


class BaseNegotiator(ABC):
    """Base Negotiator."""

    name = None
    check_anon_lvl = False
    use_full_path = False

    def __init__(self, proxy):
        self._proxy = proxy

    @abstractmethod
    async def negotiate(self, **kwargs):
        """Negotiate with proxy."""


class Socks5Ngtr(BaseNegotiator):
    """SOCKS5 Negotiator."""

    name = 'SOCKS5'

    async def write_request(self, request):
        bdata = bytearray()

        for item in request:
            if isinstance(item, int):
                bdata.append(item)
            elif isinstance(item, (bytearray, bytes)):
                bdata += item
            else:
                raise ValueError('Unsupported item')

        return (await self._proxy.send(bytes(bdata)))

    async def authenticate(self):
        c = socks_c
        # send available auth methods
        login, password = None, None
        if self._proxy.auth:
            login = self._proxy.auth['login'].encode('utf-8')
            password = self._proxy.auth['password'].encode('utf-8')
            self._proxy.log('Send header with anonymous and pwd auth')
            req = [c.SOCKS_VER5, 0x02,
                   c.SOCKS5_AUTH_ANONYMOUS, c.SOCKS5_AUTH_UNAME_PWD]
        else:
            req = [c.SOCKS_VER5, 0x01, c.SOCKS5_AUTH_ANONYMOUS]

        await self.write_request(req)

        # read/process response and send auth data if necessary
        chosen_auth = await self._proxy.recv(2)

        if chosen_auth[0] != c.SOCKS_VER5:
            raise InvalidServerVersion(
                'SOCKS5 proxy server sent invalid version'
            )

        if chosen_auth[1] == c.SOCKS5_AUTH_UNAME_PWD:
            req = [0x01, chr(len(login)).encode(), login, chr(len(password)).encode(), password]
            self._proxy.log('Send auth request')
            await self.write_request(req)

            # auth_status = await self.read_response(2)
            auth_status = await self._proxy.recv(2)
            if auth_status[0] != 0x01:
                raise InvalidServerReply(
                    'SOCKS5 proxy server sent invalid data'
                )
            if auth_status[1] != c.SOCKS5_GRANTED:
                raise LoginAuthenticationFailed(
                    "SOCKS5 authentication failed"
                )
        # offered auth methods rejected
        elif chosen_auth[1] != c.SOCKS5_AUTH_ANONYMOUS:
            if chosen_auth[1] == c.SOCKS5_AUTH_NO_ACCEPTABLE_METHODS:
                raise NoAcceptableAuthMethods(
                    'All offered SOCKS5 authentication methods were rejected'
                )
            else:
                raise InvalidServerReply(
                    'SOCKS5 proxy server sent invalid data'
                )

    async def negotiate(self, **kwargs):
        try:
            await self.authenticate()
        except Exception as e:
            raise BadResponseError(repr(e))
        self._proxy.log('Socks5Ngtr.authenticate() done')

        bip = inet_aton(kwargs.get('ip'))
        port = kwargs.get('port', 80)

        await self._proxy.send(struct.pack('>8BH', 5, 1, 0, 1, *bip, port))
        resp = await self._proxy.recv(10)

        if resp[0] != 0x05 or resp[1] != 0x00:
            self._proxy.log('Failed (invalid data)', err=BadResponseError)
            raise BadResponseError
        else:
            self._proxy.log('Request is granted')


class Socks4Ngtr(BaseNegotiator):
    """SOCKS4 Negotiator."""

    name = 'SOCKS4'

    async def write_request(self, request):
        bdata = bytearray()

        for item in request:
            if isinstance(item, int):
                bdata.append(item)
            elif isinstance(item, (bytearray, bytes)):
                bdata += item
            else:
                raise ValueError('Unsupported item')

        return (await self._proxy.send(bytes(bdata)))

    async def negotiate(self, **kwargs):
        c = socks_c
        if self._proxy.auth:
            login = self._proxy.auth['login'].encode('utf-8')
        else:
            login = ''.encode('utf-8')

        # prepare destination addr/port
        dst_host = kwargs.get('ip')
        host, port = dst_host, kwargs.get('port', 80)
        cmd = c.SOCKS_CMD_CONNECT
        port_bytes = struct.pack(b'>H', port)
        include_hostname = False

        host_bytes = inet_aton(host)

        # build and send connect command
        req = [c.SOCKS_VER4, cmd, port_bytes,
               host_bytes, login, c.NULL]
        if include_hostname:
            req += [dst_host.encode('idna'), c.NULL]

        await self.write_request(req)

        # read/process result
        resp = await self._proxy.recv(8)

        if resp[0] != c.NULL:
            raise BadResponseError('SOCKS4 proxy server sent invalid data')
        if resp[1] != c.SOCKS4_GRANTED:
            error = c.SOCKS4_ERRORS.get(resp[1], 'Unknown error')
            raise BadResponseError('[Errno {0:#04x}]: {1}'.format(resp[1], error))
        else:
            self._proxy.log('Request is granted')


class Connect80Ngtr(BaseNegotiator):
    """CONNECT Negotiator."""

    name = 'CONNECT:80'

    async def negotiate(self, **kwargs):
        await self._proxy.send(_CONNECT_request(kwargs.get('host'), 80))
        resp = await self._proxy.recv(head_only=True)
        code = get_status_code(resp)
        if code != 200:
            self._proxy.log('Connect: failed. HTTP status: %s' % code,
                            err=BadStatusError)
            raise BadStatusError


class Connect25Ngtr(BaseNegotiator):
    """SMTP Negotiator (connect to 25 port)."""

    name = 'CONNECT:25'

    async def negotiate(self, **kwargs):
        await self._proxy.send(_CONNECT_request(kwargs.get('host'), 25))
        resp = await self._proxy.recv(head_only=True)
        code = get_status_code(resp)
        if code != 200:
            self._proxy.log('Connect: failed. HTTP status: %s' % code,
                            err=BadStatusError)
            raise BadStatusError

        resp = await self._proxy.recv(length=3)
        code = get_status_code(resp, start=0, stop=3)
        if code != SMTP_READY:
            self._proxy.log('Failed (invalid data): %s' % code,
                            err=BadStatusError)
            raise BadStatusError


class HttpsNgtr(BaseNegotiator):
    """HTTPS Negotiator (CONNECT + SSL)."""

    name = 'HTTPS'

    async def negotiate(self, **kwargs):
        await self._proxy.send(_CONNECT_request(kwargs.get('host'), 443))
        resp = await self._proxy.recv(head_only=True)
        code = get_status_code(resp)
        if code != 200:
            self._proxy.log('Connect: failed. HTTP status: %s' % code,
                            err=BadStatusError)
            raise BadStatusError
        await self._proxy.connect(ssl=True)


class HttpNgtr(BaseNegotiator):
    """HTTP Negotiator."""

    name = 'HTTP'
    check_anon_lvl = True
    use_full_path = True

    async def negotiate(self, **kwargs):
        pass


NGTRS = {'HTTP': HttpNgtr, 'HTTPS': HttpsNgtr,
         'SOCKS4': Socks4Ngtr, 'SOCKS5': Socks5Ngtr,
         'CONNECT:80': Connect80Ngtr, 'CONNECT:25': Connect25Ngtr}
