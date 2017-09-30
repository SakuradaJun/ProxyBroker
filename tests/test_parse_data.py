import pytest

import asyncio

from proxybroker import Broker


@pytest.mark.asyncio
async def test_parse_proxylist(mocker):
    proxylist_txt = """
127.0.0.1:3128
logging:password@127.0.0.1:666
socks5://logging:password@127.0.0.1:1080
socks5://logging:wrong@127.0.0.1:1081
socks5://logging:wrong@127.0.0.1:1080
socks5://login:password@172.17.0.4:52489
socks5://login:password2@172.17.0.4:52489
socks5://login:password2@172.17.0.4:52489
    """.strip()

    b = Broker(asyncio.Queue())
    calls = list()
    async def return_async_value(proxy_kwargs, check):
        calls.append(proxy_kwargs)

    with mocker.patch('proxybroker.api.Broker._handle',
                      side_effect=return_async_value):
        await b._load(proxylist_txt)
    assert len(calls) == 7
    assert calls == [
        {'host': '127.0.0.1', 'port': '3128', 'auth': {}, 'types': ()},
        {'host': '127.0.0.1', 'port': '666', 'auth':
            {'login': 'logging', 'password': 'password'}, 'types': ()},
        {'host': '127.0.0.1', 'port': '1080',
         'auth': {'login': 'logging', 'password': 'password'},
         'types': ('SOCKS5',)},
        {'host': '127.0.0.1', 'port': '1081',
         'auth': {'login': 'logging', 'password': 'wrong'},
         'types': ('SOCKS5',)},
        {'host': '127.0.0.1', 'port': '1080',
         'auth': {'login': 'logging', 'password': 'wrong'},
         'types': ('SOCKS5',)},
        {'host': '172.17.0.4', 'port': '52489',
         'auth': {'login': 'login', 'password': 'password'},
         'types': ('SOCKS5',)},
        {'host': '172.17.0.4', 'port': '52489',
         'auth': {'login': 'login', 'password': 'password2'},
         'types': ('SOCKS5',)}
    ]
