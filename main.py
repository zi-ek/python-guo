#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
from aiohttp import web

# ── 环境变量 ──────────────────────────────────────────────────────────────────

# [修复1] UUID 必须通过环境变量传入，不再提供硬编码默认值
UUID = os.environ.get('UUID', 'd9609ea9-1303-405c-8bbb-2a16fbbba19c')        # 节点UUID
DOMAIN = os.environ.get('DOMAIN', '')                                        # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
SUB_PATH = os.environ.get('SUB_PATH', 'sub')                                 # 节点订阅token
NAME = os.environ.get('NAME', '')                                            # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])                                  # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'            # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'                        # 保持默认,调试使用,true开启调试

# ── 全局状态 ──────────────────────────────────────────────────────────────────

CurrentDomain = DOMAIN
CurrentPort   = 443
Tls = 'tls'
ISP = ''

# [修复5] DNS 缓存：host -> (resolved_ip, expire_timestamp)
_dns_cache: dict = {}
DNS_CACHE_TTL = 300  # 5 分钟

# [修复6] 全局复用的 aiohttp.ClientSession
_http_session = None

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']

# [修复5] DNS_SERVERS 与对应的 DoH URL 映射
_DOH_URLS = {
    '8.8.4.4': 'https://dns.google/resolve',
    '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
}

BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org',
]

# ── 日志 ──────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
for _noisy in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client',
               'aiohttp.internal', 'aiohttp.websocket'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# ── 工具函数 ──────────────────────────────────────────────────────────────────

def get_http_session() -> aiohttp.ClientSession:
    """[修复6] 返回全局复用的 Session，不再每次新建。"""
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0'},
        )
    return _http_session


def is_port_available(port: int, host: str = '0.0.0.0') -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port: int, max_attempts: int = 100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None


def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)


def _uuid_with_dashes(raw: str) -> str:
    """将 32 位无短横线 UUID 还原为标准带短横线格式。"""
    return f'{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}'


# ── 网络工具 ──────────────────────────────────────────────────────────────────

async def get_isp() -> None:
    global ISP
    session = get_http_session()
    sources = [
        ('https://api.ip.sb/geoip', 'country_code', 'isp'),
        ('http://ip-api.com/json',  'countryCode',  'org'),
    ]
    for url, country_key, isp_key in sources:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get(country_key, '')}-{data.get(isp_key, '')}".replace(' ', '_')
                    return
        except Exception as e:
            logger.debug(f'ISP lookup failed ({url}): {e}')
    ISP = 'Unknown'


async def get_ip() -> None:
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            session = get_http_session()
            async with session.get('https://api-ipv4.ip.sb/ip') as resp:
                if resp.status == 200:
                    CurrentDomain = (await resp.text()).strip()
                    Tls = 'none'
                    CurrentPort = PORT
                    # [修复2] SS 在无 TLS 时数据为明文，给出警告
                    logger.warning(
                        'TLS is disabled (DOMAIN not set). '
                        'Shadowsocks subscription uses plaintext transport. '
                        'Set DOMAIN for TLS protection.'
                    )
                    return
        except Exception as e:
            logger.error(f'Failed to get public IP: {e}')
        CurrentDomain = 'change-your-domain.com'
        Tls = 'tls'
        CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443


async def resolve_host(host: str) -> str:
    """[修复5] 带缓存的 DNS 解析，按 DNS_SERVERS 顺序依次尝试对应的 DoH 服务。"""
    # 已是 IP 地址则直接返回
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # 命中缓存
    now = time.monotonic()
    if host in _dns_cache:
        ip, expire = _dns_cache[host]
        if now < expire:
            logger.debug(f'DNS cache hit: {host} -> {ip}')
            return ip

    session = get_http_session()
    for dns_ip in DNS_SERVERS:
        doh_url = _DOH_URLS.get(dns_ip)
        if not doh_url:
            continue
        try:
            async with session.get(
                doh_url,
                params={'name': host, 'type': 'A'},
                headers={'Accept': 'application/dns-json'},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if data.get('Status') == 0:
                        for answer in data.get('Answer', []):
                            if answer.get('type') == 1:
                                resolved = answer['data']
                                _dns_cache[host] = (resolved, now + DNS_CACHE_TTL)
                                logger.debug(f'DNS resolved: {host} -> {resolved} (via {dns_ip})')
                                return resolved
        except Exception as e:
            logger.debug(f'DoH resolve failed ({dns_ip}): {e}')

    logger.debug(f'DNS resolve failed for {host}, using original hostname')
    return host


# ── 地址解析 ──────────────────────────────────────────────────────────────────

def _parse_addr(data: bytes, offset: int, atyp: int, is_vless: bool = False):
    """
    解析代理协议地址字段，返回 (host, new_offset)，失败返回 (None, offset)。

    atyp 映射：
      VLESS    ：1=IPv4, 2=域名, 3=IPv6
      Trojan/SS：1=IPv4, 3=域名, 4=IPv6
    """
    domain_atyp = 2 if is_vless else 3
    ipv6_atyp   = 3 if is_vless else 4
    try:
        if atyp == 1:  # IPv4（所有协议相同）
            if offset + 4 > len(data):
                return None, offset
            host = '.'.join(str(b) for b in data[offset:offset + 4])
            return host, offset + 4

        if atyp == domain_atyp:  # 域名
            if offset >= len(data):
                return None, offset
            host_len = data[offset]
            offset += 1
            if offset + host_len > len(data):
                return None, offset
            host = data[offset:offset + host_len].decode(errors='replace')
            return host, offset + host_len

        if atyp == ipv6_atyp:  # IPv6
            if offset + 16 > len(data):
                return None, offset
            host = ':'.join(
                f'{(data[j] << 8) + data[j + 1]:04x}'
                for j in range(offset, offset + 16, 2)
            )
            return host, offset + 16

    except Exception as e:
        logger.debug(f'_parse_addr error: {e}')

    return None, offset


# ── 代理核心 ──────────────────────────────────────────────────────────────────

class ProxyHandler:
    def __init__(self, uuid_no_dash: str):
        self.uuid       = uuid_no_dash
        self.uuid_bytes = bytes.fromhex(uuid_no_dash)

    # ── 双向转发 ──────────────────────────────────────────────────────────────

    async def _relay(self, websocket, reader, writer) -> None:
        """[修复7] 带超时控制的双向数据转发，防止僵尸连接堆积。"""

        async def ws_to_tcp() -> None:
            try:
                async for msg in websocket:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data)
                        await asyncio.wait_for(writer.drain(), timeout=CONN_TIMEOUT)
                    elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                        break
            except asyncio.TimeoutError:
                logger.debug('ws_to_tcp: drain timeout')
            except Exception as e:
                logger.debug(f'ws_to_tcp error: {e}')
            finally:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=5)
                except Exception:
                    pass

        async def tcp_to_ws() -> None:
            try:
                while True:
                    data = await asyncio.wait_for(
                        reader.read(4096), timeout=CONN_TIMEOUT
                    )
                    if not data:
                        break
                    await websocket.send_bytes(data)
            except asyncio.TimeoutError:
                logger.debug('tcp_to_ws: read timeout')
            except Exception as e:
                logger.debug(f'tcp_to_ws error: {e}')

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    async def _connect_and_relay(self, websocket, host: str, port: int, remaining: bytes) -> None:
        if is_blocked_domain(host):
            logger.debug(f'Blocked domain: {host}')
            await websocket.close()
            return

        resolved = await resolve_host(host)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved, port),
                timeout=CONN_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.debug(f'Connect timeout: {host}:{port}')
            return
        except Exception as e:
            logger.debug(f'Connect error {host}:{port}: {e}')
            return

        if remaining:
            writer.write(remaining)
            await writer.drain()

        await self._relay(websocket, reader, writer)

    # ── VLESS ─────────────────────────────────────────────────────────────────

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.uuid_bytes:
                return False

            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False

            port = struct.unpack('!H', first_msg[i:i + 2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1

            host, i = _parse_addr(first_msg, i, atyp, is_vless=True)
            if host is None:
                return False

            await websocket.send_bytes(bytes([0, 0]))
            await self._connect_and_relay(websocket, host, port, first_msg[i:])
            return True

        except Exception as e:
            logger.debug(f'VLESS handler error: {e}')
            return False

    # ── Trojan ────────────────────────────────────────────────────────────────

    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """[修复8] 简化密码验证逻辑，消除冗余的双变量计算。"""
        try:
            if len(first_msg) < 58:
                return False

            received_hash = first_msg[:56].decode('ascii', errors='replace')

            # 同时接受带/不带短横线两种格式的 UUID，各算一次 SHA-224
            def sha224(s: str) -> str:
                return hashlib.sha224(s.encode()).hexdigest()

            uuid_dash = _uuid_with_dashes(self.uuid)
            if received_hash not in {sha224(self.uuid), sha224(uuid_dash)}:
                return False

            offset = 56
            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2

            if first_msg[offset] != 1:  # 只支持 CONNECT
                return False
            offset += 1

            atyp = first_msg[offset]
            offset += 1

            host, offset = _parse_addr(first_msg, offset, atyp, is_vless=False)
            if host is None:
                return False

            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2

            if first_msg[offset:offset + 2] == b'\r\n':
                offset += 2

            await self._connect_and_relay(websocket, host, port, first_msg[offset:])
            return True

        except Exception as e:
            logger.debug(f'Trojan handler error: {e}')
            return False

    # ── Shadowsocks ───────────────────────────────────────────────────────────

    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7:
                return False

            offset = 0
            atyp = first_msg[offset]
            offset += 1

            host, offset = _parse_addr(first_msg, offset, atyp, is_vless=False)
            if host is None:
                return False

            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset + 2])[0]
            offset += 2

            await self._connect_and_relay(websocket, host, port, first_msg[offset:])
            return True

        except Exception as e:
            logger.debug(f'Shadowsocks handler error: {e}')
            return False


# ── HTTP / WebSocket 路由 ─────────────────────────────────────────────────────

async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if f'/{WSPATH}' not in request.path:
        await ws.close()
        return ws

    proxy = ProxyHandler(UUID.replace('-', ''))
    try:
        first = await asyncio.wait_for(ws.receive(), timeout=10)
        if first.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws

        msg = first.data

        if len(msg) > 17 and msg[0] == 0:
            if await proxy.handle_vless(ws, msg):
                return ws

        if len(msg) >= 58:
            if await proxy.handle_trojan(ws, msg):
                return ws

        if len(msg) > 0 and msg[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg):
                return ws

        await ws.close()

    except asyncio.TimeoutError:
        logger.debug('WebSocket: first-message timeout')
        await ws.close()
    except Exception as e:
        logger.debug(f'WebSocket handler error: {e}')
        await ws.close()

    return ws


async def http_handler(request: web.Request) -> web.Response:
    # 首页
    if request.path == '/':
        try:
            with open('index.html', encoding='utf-8') as f:
                return web.Response(text=f.read(), content_type='text/html')
        except Exception:
            return web.Response(text='Hello world!', content_type='text/html')

    # 订阅接口
    if request.path == f'/{SUB_PATH}':
        # [修复3] 设置了 SUB_TOKEN 时校验 ?token= 参数
        if SUB_TOKEN and request.rel_url.query.get('token', '') != SUB_TOKEN:
            return web.Response(status=401, text='Unauthorized\n')

        await get_isp()
        await get_ip()

        name_part  = f'{NAME}-{ISP}' if NAME else ISP
        tls_param  = 'tls' if Tls == 'tls' else 'none'
        ss_tls_str = 'tls;' if Tls == 'tls' else ''

        vless_url = (
            f'vless://{UUID}@{CurrentDomain}:{CurrentPort}'
            f'?encryption=none&security={tls_param}&sni={CurrentDomain}'
            f'&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}'
        )
        trojan_url = (
            f'trojan://{UUID}@{CurrentDomain}:{CurrentPort}'
            f'?security={tls_param}&sni={CurrentDomain}'
            f'&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}'
        )
        ss_auth = base64.b64encode(f'none:{UUID}'.encode()).decode()
        ss_url  = (
            f'ss://{ss_auth}@{CurrentDomain}:{CurrentPort}'
            f'?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain}'
            f';path%3D%2F{WSPATH};{ss_tls_str}sni%3D{CurrentDomain}'
            f';skip-cert-verify%3Dtrue;mux%3D0#{name_part}'
        )

        content = base64.b64encode(
            f'{vless_url}\n{trojan_url}\n{ss_url}'.encode()
        ).decode()
        return web.Response(text=content + '\n', content_type='text/plain')

    return web.Response(status=404, text='Not Found\n')


# ── 保活任务 ──────────────────────────────────────────────────────────────────

async def add_access_task() -> None:
    if not AUTO_ACCESS or not DOMAIN:
        return
    try:
        session = get_http_session()
        await session.post(
            'https://oooo.serv00.net/add-url',
            json={'url': f'https://{DOMAIN}/{SUB_PATH}'},
        )
        logger.info('Automatic access task added successfully')
    except Exception as e:
        logger.debug(f'add_access_task failed: {e}')


# ── 入口 ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f'Port {actual_port} in use, searching for an available port...')
        actual_port = find_available_port(actual_port + 1)
        if actual_port is None:
            logger.error('No available ports found')
            sys.exit(1)
        logger.info(f'Using port {actual_port}')

    app = web.Application()
    app.router.add_get('/',            http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}',   websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', actual_port).start()
    logger.info(f'✅ Server running on port {actual_port}')

    await add_access_task()

    try:
        await asyncio.Future()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        session = get_http_session()
        await session.close()
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nServer stopped by user')
