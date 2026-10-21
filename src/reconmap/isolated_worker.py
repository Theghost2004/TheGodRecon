"""Stdlib-only transport inside a bubblewrap network/PID/filesystem namespace.

This file is executed with the sandbox's system Python, not imported by scanners.
It has no target-network access. The only host socket mounted into its filesystem
is the per-invocation broker. HTTP CONNECT terminates TLS here; the broker sees
every decrypted request path. It is never a TCP tunnel to the target.
"""
import asyncio
import base64
import ctypes
import json
import os
import resource
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit

MAX_HEADER = 32768
MAX_RPC = 145 * 1024 * 1024


def filter_syscalls(libc):
    """x86-64 seccomp: no alternate socket families/ABIs or io_uring escape.

    Namespace isolation controls INET destinations; only the broker's one Unix
    socket is mounted. The filter is inherited by the executable and descendants.
    """
    class Instruction(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('length',ctypes.c_ushort),('instructions',ctypes.POINTER(Instruction))]
    allow,deny,kill=0x7fff0000,0x00050001,0x80000000
    # BPF load offsets: syscall number=0, architecture=4, first argument=16.
    code=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,kill),
          (0x20,0,0,0),(0x45,0,1,0x40000000),(0x06,0,0,deny)]
    for number in (425,426,427,272,308):
        code += [(0x15,0,1,number),(0x06,0,0,deny)]
    code += [(0x15,1,0,41),(0x06,0,0,allow),(0x20,0,0,16),
             (0x15,4,0,1),(0x15,3,0,2),(0x15,2,0,10),(0x15,1,0,16),
             (0x06,0,0,deny),(0x06,0,0,allow)]
    instructions=(Instruction*len(code))(*(Instruction(*row) for row in code))
    program=Program(len(code),instructions)
    if libc.prctl(22,2,ctypes.byref(program),0,0)!=0:
        raise OSError('Cannot establish socket-family seccomp boundary')


def restrict():
    # Children inherit these limits and no-new-privileges. Scratch storage is a
    # size-limited tmpfs; the binary, inputs, templates and runtime are read-only.
    for kind, limit in ((resource.RLIMIT_AS, 4 * 1024**3),
                        (resource.RLIMIT_FSIZE, 16 * 1024**2),
                        (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_NPROC,256), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (limit, limit))
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError('Cannot establish no-new-privileges')
    filter_syscalls(libc)


async def rpc(message):
    reader, writer = await asyncio.open_unix_connection('/broker.sock', limit=MAX_RPC)
    try:
        writer.write(json.dumps(message).encode() + b'\n')
        await writer.drain()
        data = await asyncio.wait_for(reader.readline(), 310)
        if not data or len(data) > MAX_RPC:
            raise ValueError('Invalid broker response')
        return json.loads(data)
    finally:
        writer.close()
        await writer.wait_closed()


async def header(reader):
    raw = await reader.readuntil(b'\r\n\r\n')
    if len(raw) > MAX_HEADER:
        raise ValueError('Header limit')
    lines = raw.decode('iso-8859-1').split('\r\n')
    method, target, version = lines[0].split(' ')
    if version not in {'HTTP/1.0', 'HTTP/1.1'}:
        raise ValueError('Unsupported HTTP version')
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        key, value = line.split(':', 1)
        key = key.lower()
        if key in headers or key.strip() != key or any(ord(c) < 33 for c in key):
            raise ValueError('Ambiguous header')
        headers[key] = value.strip()
    return method, target, headers


def origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)


async def proxy(reader, writer, context):
    try:
        async with asyncio.timeout(310):
            method, target, headers = await header(reader)
            tunnel = None
            if method == 'CONNECT':
                tunnel = 'https://' + target
                answer = await rpc({'kind': 'connect', 'url': tunnel})
                if not answer.get('allowed'):
                    raise ValueError('CONNECT denied')
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
                await writer.start_tls(context, ssl_handshake_timeout=10)
                method, target, headers = await header(reader)
            if tunnel:
                if not target.startswith('/') or target.startswith('//'):
                    raise ValueError('Invalid tunneled request target')
                url = tunnel + target
            else:
                url = target
            parsed = urlsplit(url)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
                raise ValueError('Invalid absolute request target')
            if 'host' not in headers or origin(parsed.scheme+'://'+headers['host']) != origin(url):
                raise ValueError('Host/request authority mismatch')
            if tunnel:
                # CONNECT requires a port even when the original URL omitted it.
                # The validated Host header retains the HTTP request authority.
                url = parsed.scheme + '://' + headers['host'] + target
            if headers.get('content-length', '0') != '0' or 'transfer-encoding' in headers:
                raise ValueError('Request bodies are not supported')
            answer = await rpc({'kind': 'http', 'method': method, 'url': url,
                                'referer': headers.get('referer',''),
                                'has_credentials': any(k in headers for k in ('cookie','authorization','proxy-authorization'))})
            if not answer.get('allowed'):
                raise ValueError('Request denied')
            body = base64.b64decode(answer['body'], validate=True)
            output = [f"HTTP/1.1 {int(answer['status'])} Observed"]
            blocked = {'content-length','transfer-encoding','connection','content-encoding','keep-alive','trailer','upgrade'}
            for key, value in answer['headers'].items():
                if key.lower() not in blocked and all(c not in key+value for c in '\r\n\x00'):
                    output.append(key+': '+value)
            output += [f'Content-Length: {len(body)}', 'Connection: close', '', '']
            writer.write('\r\n'.join(output).encode('iso-8859-1') + body)
            await writer.drain()
    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        # This local denial is NOT evidence of an HTTP response from the target.
        try:
            writer.write(b'HTTP/1.1 451 Broker Denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
        except (OSError, RuntimeError):
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, TimeoutError):
            pass


class DNS(asyncio.DatagramProtocol):
    def __init__(self):
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if len(data) > 4096 or len(self.tasks) >= 16:
            return
        async def respond():
            try:
                answer = await rpc({'kind': 'dns', 'wire': base64.b64encode(data).decode()})
                self.transport.sendto(base64.b64decode(answer['wire'], validate=True), address)
            except (OSError, ValueError, KeyError, TimeoutError):
                pass
        task = asyncio.create_task(respond())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


async def dns_tcp(reader, writer):
    try:
        async with asyncio.timeout(310):
            size = struct.unpack('!H', await reader.readexactly(2))[0]
            if size > 4096:
                return
            data = await reader.readexactly(size)
            answer = await rpc({'kind': 'dns', 'wire': base64.b64encode(data).decode()})
            wire = base64.b64decode(answer['wire'], validate=True)
            writer.write(struct.pack('!H', len(wire)) + wire)
            await writer.drain()
    except (OSError, ValueError, KeyError, TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def main(argv):
    restrict()
    if argv == ['--probe']:
        print(json.dumps({'netns': os.readlink('/proc/self/ns/net'),
                          'pidns': os.readlink('/proc/self/ns/pid'),
                          'interfaces': [name for _, name in socket.if_nameindex()],
                          'status': open('/proc/self/status', encoding='utf-8').read()}))
        return 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/tls/cert.pem', '/tls/key.pem')
    tasks = set()
    def accept(handler):
        def connected(reader, writer):
            if len(tasks) >= 16:
                writer.close()
                return
            task = asyncio.create_task(handler(reader, writer))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        return connected
    http = await asyncio.start_server(accept(lambda r,w:proxy(r,w,context)), '127.0.0.1', 18080, limit=MAX_HEADER)
    dns = DNS()
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda:dns, local_addr=('127.0.0.1',1053))
    tcp = await asyncio.start_server(accept(dns_tcp), '127.0.0.1', 1053, limit=4096)
    os.makedirs('/tmp/home', exist_ok=True)
    try:
        child = await asyncio.create_subprocess_exec('/tool', *argv, stdin=asyncio.subprocess.DEVNULL)
        print('RECONMAP_TOOL_STARTED', file=sys.stderr, flush=True)
        return await child.wait()
    finally:
        http.close(); tcp.close(); udp.close()
        await http.wait_closed(); await tcp.wait_closed()
        for task in tasks | dns.tasks:
            task.cancel()
        await asyncio.gather(*(tasks | dns.tasks), return_exceptions=True)


if __name__ == '__main__':
    sys.exit(asyncio.run(main(sys.argv[1:])))
