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
import math
import time
from collections import OrderedDict
from aiohttp import web

# 环境变量
UUID = os.environ.get('UUID', '')                                            # 节点UUID
DOMAIN = os.environ.get('DOMAIN', '')                                        # 项目分配的域名或反代后的域名,不包含https://前缀,例如: domain.xxx.com
SUB_PATH = os.environ.get('SUB_PATH', 'sub')                                 # 节点订阅token
NAME = os.environ.get('NAME', '')                                            # 节点名称
WSPATH = os.environ.get('WSPATH', UUID[:8])                                  # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'            # 自动访问保活,默认关闭,true开启,false关闭,需同时填写DOMAIN变量
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'                        # 保持默认,调试使用,true开启调试

# 全局变量
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']  # 备用 DoH 解析服务器
_DOH_URLS = {
    '8.8.4.4': 'https://dns.google/resolve',
    '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
}
# 测速域名黑名单：防止节点被滥用为公开测速入口，消耗服务器带宽
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org',
]

# ── 日志系统配置 ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
# 抑制 aiohttp 底层高频访问日志，避免干扰核心业务日志
for _noisy in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client',
               'aiohttp.internal', 'aiohttp.websocket'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', 
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://ip-api.com/json',
                                 headers={'User-Agent': 'Mozilla/5.0'},
                                 timeout=3) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('countryCode', '')}-{data.get('org', '')}".replace(' ', '_')
                    return
    except:
        pass
    
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=5) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

class DNSResolver:
    """Bounded TTL/LRU cache and one reusable DoH connection pool per app."""

    def __init__(self, cache_ttl=60.0, cache_size=1024, timeout=2.0,
                 max_pending=256, clock=time.monotonic):
        self.cache_ttl = cache_ttl
        self.cache_size = cache_size
        self.timeout = timeout
        self.max_pending = max_pending
        self._clock = clock
        self._cache = OrderedDict()
        self._pending = {}
        self._session = None
        self._closed = False

    async def resolve(self, host):
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        if self._closed:
            raise RuntimeError('DNS resolver is closed')
        key = host.encode('idna').decode('ascii').lower()
        cached = self._cache.get(key)
        if cached:
            expires, address = cached
            if expires > self._clock():
                self._cache.move_to_end(key)
                return address
            del self._cache[key]

        task = self._pending.get(key)
        if task is None:
            if len(self._pending) >= self.max_pending:
                raise OSError('Too many pending DNS lookups')
            task = asyncio.create_task(self._lookup(key, host), name='proxy-dns')
            self._pending[key] = task

            def finished(done):
                if self._pending.get(key) is done:
                    self._pending.pop(key, None)
                # A disconnected caller must not leave an unobserved exception.
                if not done.cancelled():
                    done.exception()

            task.add_done_callback(finished)
        # One cancelled client must not cancel another client's shared lookup.
        return await asyncio.shield(task)

    async def _lookup(self, key, original_host):
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(limit=32, ttl_dns_cache=60),
            )
        for dns_server in DNS_SERVERS:
            url = _DOH_URLS.get(dns_server)
            if not url:
                continue
            try:
                async with self._session.get(
                    url, params={'name': key, 'type': 'A'},
                    headers={'Accept': 'application/dns-json'},
                ) as response:
                    if response.status != 200:
                        continue
                    # Cloudflare returns application/dns-json, not application/json.
                    data = await response.json(content_type=None)
                    if not isinstance(data, dict) or data.get('Status') != 0:
                        continue
                    answers = data.get('Answer', [])
                    if not isinstance(answers, list):
                        continue
                    for answer in answers:
                        if not isinstance(answer, dict) or answer.get('type') != 1:
                            continue
                        try:
                            address = str(ipaddress.IPv4Address(answer.get('data')))
                        except (ValueError, TypeError, ipaddress.AddressValueError):
                            continue
                        # Respect CNAME TTLs as well as the selected A record.
                        ttls = [item.get('TTL', 0) for item in answers
                                if isinstance(item, dict) and item.get('type') in (1, 5)]
                        try:
                            ttl = min(float(value) for value in ttls)
                            if not math.isfinite(ttl):
                                ttl = 0
                            ttl = max(0.0, min(self.cache_ttl, ttl))
                        except (TypeError, ValueError):
                            ttl = 0
                        if ttl > 0 and self.cache_size > 0:
                            self._cache[key] = (self._clock() + ttl, address)
                            self._cache.move_to_end(key)
                            while len(self._cache) > self.cache_size:
                                self._cache.popitem(last=False)
                        return address
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
                continue
        # Preserve the original system-DNS fallback, but never cache failures.
        return original_host

    async def close(self):
        self._closed = True
        tasks = list(self._pending.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._pending.clear()
        self._cache.clear()
        if self._session is not None:
            await self._session.close()


_dns_resolver = None
CONNECT_TIMEOUT = 10.0
CLOSE_TIMEOUT = 3.0


async def resolve_host(host: str) -> str:
    global _dns_resolver
    if _dns_resolver is None:
        _dns_resolver = DNSResolver()
    return await _dns_resolver.resolve(host)


async def cleanup_network_resources(app):
    global _dns_resolver
    resolver, _dns_resolver = _dns_resolver, None
    if resolver is not None:
        await resolver.close()


async def relay_connection(websocket, host, port, initial_data=b''):
    """Retain 4 KiB reads/backpressure, but close both sides on EOF or error."""
    writer = None
    tasks = []

    async def ws_to_tcp():
        async for msg in websocket:
            if msg.type == aiohttp.WSMsgType.BINARY:
                writer.write(msg.data)
                await writer.drain()

    async def tcp_to_ws():
        while True:
            data = await reader.read(4096)
            if not data:
                return
            await websocket.send_bytes(data)

    try:
        # Includes system-DNS fallback, TCP establishment and cancellation cleanup.
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT,
        )
        if initial_data:
            writer.write(initial_data)
            await writer.drain()
        tasks = [
            asyncio.create_task(ws_to_tcp(), name='proxy-ws-to-tcp'),
            asyncio.create_task(tcp_to_ws(), name='proxy-tcp-to-ws'),
        ]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if writer is not None:
            writer.close()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            if writer is not None:
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=CLOSE_TIMEOUT)
                except Exception:
                    writer.transport.abort()
        finally:
            try:
                await asyncio.wait_for(websocket.close(), timeout=CLOSE_TIMEOUT)
            except Exception:
                pass


class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid = uuid
        self.uuid_bytes = bytes.fromhex(uuid)
        
    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """处理VLS协议"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            # 验证UUID
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:  # 域名
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:  # IPv6
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            
            resolved_host = await resolve_host(host)
            
            try:
                await relay_connection(websocket, resolved_host, port, first_msg[i:])
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False
    
    async def handle_trojan(self, websocket, first_msg: bytes) -> bool:
        """处理Tro协议"""
        try:
            if len(first_msg) < 58:
                return False
            
            received_hash_bytes = first_msg[:56]
            
            # 验证密码 - 支持标准UUID和无短横线UUID
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.uuid.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            
            # 尝试使用标准UUID（带短横线）
            standard_uuid = UUID
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(standard_uuid.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            
            # 转换为hex字符串进行比较
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            
            # 检查是否匹配任一UUID格式
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            
            atyp = first_msg[offset]
            offset += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                await relay_connection(websocket, resolved_host, port, first_msg[offset:])
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"Tro handler error: {e}")
            return False
    
    async def handle_shadowsocks(self, websocket, first_msg: bytes) -> bool:
        """处理ss协议"""
        try:
            if len(first_msg) < 7:
                return False
            
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            
            # 解析地址
            host = ''
            if atyp == 1:  # IPv4
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:  # 域名
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:  # IPv6
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            # 连接目标
            resolved_host = await resolve_host(host)
            
            try:
                await relay_connection(websocket, resolved_host, port, first_msg[offset:])
                
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"Shadowsocks handler error: {e}")
            return False

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path
    
    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID)
    
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        
        # 尝试VLS
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws
        
        # 尝试Tro
        if len(msg_data) >= 58:
            if await proxy.handle_trojan(ws, msg_data):
                return ws
        
        # 尝试ss
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await proxy.handle_shadowsocks(ws, msg_data):
                return ws
        
        await ws.close()
        
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()
    
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    
    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        ss_tls_param = 'tls;' if Tls == 'tls' else ''
        
        # 生成配置链接
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        trojan_url = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        
        ss_method_password = base64.b64encode(f"none:{UUID}".encode()).decode()
        ss_url = f"ss://{ss_method_password}@{CurrentDomain}:{CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{CurrentDomain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#{name_part}"
        
        subscription = f"{vless_url}\n{trojan_url}\n{ss_url}"
        base64_content = base64.b64encode(subscription.encode()).decode()
        
        return web.Response(text=base64_content + '\n', content_type='text/plain')
    
    return web.Response(status=404, text='Not Found\n')

async def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    
    full_url = f"https://{DOMAIN}/{SUB_PATH}"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post("https://oooo.serv00.net/add-url",
                             json={"url": full_url},
                             headers={'Content-Type': 'application/json'})
        logger.info('Automatic Access Task added successfully')
    except:
        pass

async def main():
    actual_port = PORT
    
    # 检查端口是否可用，如果不可用则查找可用端口
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    
    app = web.Application()
    app.on_cleanup.append(cleanup_network_resources)
    
    # 路由
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    # 启动服务
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ server is running on port {actual_port}")

    await add_access_task()
    
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
