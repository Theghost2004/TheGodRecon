"""Runtime-verified Linux isolation and the sole active-tool network owner."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from .adapters import execute
from .config import normalize_url, request_url
from .security import redact, redact_data
from .storage import artifact_path, timestamp

ACTIVE_TOOLS = frozenset({'dnsx', 'httpx', 'katana', 'nuclei'})
BACKEND = 'linux-bubblewrap-broker-v1'
TEMPLATE_HASHES = {
    'git-head.yaml': 'e0232f98b1ab2eb3182a022f1869dc1beb2e5cb76b1376c2df6fcc0d649b3696',
    'environment.yaml': '0d3d9f7a545db5c525a541d89cead8da8dd8f20f61b6b0c35f0a1beece3adc84',
}


@dataclass(frozen=True)
class Boundary:
    available: bool
    reason: str
    executable: str | None = None
    backend: str = BACKEND


def sandbox_arguments(bwrap, mounts=()):
    argv = [bwrap, '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--clearenv', '--ro-bind', '/usr', '/usr']
    for directory in ('/lib', '/lib64', '/bin', '/sbin'):
        if Path(directory).exists():
            argv += ['--ro-bind', directory, directory]
    argv += ['--proc', '/proc', '--dev', '/dev', '--dir', '/etc',
             '--size', str(64*1024**2), '--tmpfs', '/tmp', '--chdir', '/tmp',
             '--ro-bind', str(Path(__file__).with_name('isolated_worker.py').resolve()), '/worker.py']
    for source, destination in mounts:
        argv += ['--ro-bind', str(source), destination]
    for key, value in {'PATH':'/usr/bin:/bin', 'HOME':'/tmp/home', 'TMPDIR':'/tmp',
                       'XDG_CONFIG_HOME':'/tmp/home', 'XDG_CACHE_HOME':'/tmp/home',
                       'GOMEMLIMIT':'512MiB', 'GOMAXPROCS':'2',
                       'HTTP_PROXY':'http://127.0.0.1:18080', 'HTTPS_PROXY':'http://127.0.0.1:18080',
                       'NO_PROXY':'', 'LANG':'C.UTF-8'}.items():
        argv += ['--setenv', key, value]
    return argv + ['--', '/usr/bin/python3', '/worker.py']


def probe_boundary() -> Boundary:
    """Run a harmless namespace probe. Installed commands alone prove nothing."""
    if platform.system() != 'Linux':
        return Boundary(False, 'No verified active-tool execution backend on this platform; Linux with bubblewrap/user namespaces is required')
    if platform.machine().lower() not in {'x86_64','amd64'}:
        return Boundary(False, 'Reviewed socket-family seccomp backend currently requires Linux x86-64')
    executable = shutil.which('bwrap')
    if not executable or not shutil.which('openssl') or not Path('/usr/bin/python3').exists():
        return Boundary(False, 'Install bubblewrap, OpenSSL and system Python 3.11+; no root scan is required')
    try:
        result = subprocess.run(sandbox_arguments(executable)+['--probe'], capture_output=True, timeout=10, check=False)
        if result.returncode or len(result.stdout) > 65536:
            return Boundary(False, 'Namespace probe failed: '+redact(result.stderr.decode(errors='replace')[:1000]).strip(), executable)
        data = json.loads(result.stdout)
        fields = dict(line.split(':',1) for line in data['status'].splitlines() if ':' in line)
        if (data['netns'] == os.readlink('/proc/self/ns/net') or data['pidns'] == os.readlink('/proc/self/ns/pid')
                or data['interfaces'] != ['lo'] or int(fields['CapEff'].strip(),16) != 0
                or fields['NoNewPrivs'].strip() != '1' or fields['Seccomp'].strip() != '2'):
            raise ValueError('Namespace, capability or no-new-privileges verification failed')
        return Boundary(True, 'Verified isolated network/PID namespaces, loopback-only interfaces and zero capabilities', executable)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        return Boundary(False, 'Execution backend probe failed: '+redact(str(exc)), executable)


def reviewed_templates():
    directory = Path(__file__).with_name('templates')
    for name, digest in TEMPLATE_HASHES.items():
        path = directory/name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Reviewed Nuclei template identity mismatch: '+name)
    return directory


def execution_requirement(config, name, info, boundary=None, target=None):
    """Return a specific prerequisite failure, never a permanent name denial."""
    if config.execution_engines.get(name) == 'native':
        return 'Native engine explicitly selected; incompatible with strict external execution'
    if not info.available:
        return 'Executable not found; run reconmap setup or configure tools.'+name
    if not info.supported:
        return 'Unsupported executable identity/version/flags: '+info.reason
    if name in ACTIVE_TOOLS:
        if config.mode != 'standard':
            return 'Active external execution requires standard mode; demo/offline/passive modes prohibit target traffic'
        boundary = boundary or probe_boundary()
        if not boundary.available:
            return boundary.reason
        if name in {'katana','nuclei'} and 'http' not in config.modules:
            return 'HTTP observation prerequisite not selected; select httpx as well'
        if name == 'nuclei':
            try:
                reviewed_templates()
            except (OSError, ValueError) as exc:
                return str(exc)
            if target:
                from .scope import ScopePolicy
                origin = urlunsplit(urlsplit(target)._replace(path='',query='',fragment=''))
                for path in ('/.git/HEAD','/.env'):
                    allowed, reason = ScopePolicy(config.scope).decision(origin+path)
                    if not allowed:
                        return f'Reviewed Nuclei template GET {path} cannot comply with scope: {reason}'
    elif name in {'subfinder','urlfinder'} and (config.mode in {'demo','offline'} or config.scope.lab):
        return 'Discovery providers are disabled in demo/offline/loopback lab mode'
    return ''


class Broker:
    """Per-invocation IPC capability; no tool controls an upstream socket or IP."""
    def __init__(self, scanner, name):
        self.scanner, self.name = scanner, name
        self.lock = asyncio.Lock()
        self.tasks = set()
        self.metrics = {'http_requests':0, 'dns_queries':0, 'reused_responses':0, 'denied_requests':0}
        self.failures = []
        self.next_dns = 0.0

    def deny(self, subject, reason, *, failure=False):
        self.metrics['denied_requests'] += 1
        reason = redact(str(reason))
        if failure and reason not in self.failures and len(self.failures) < 30:
            self.failures.append(reason)
        if self.metrics['denied_requests'] <= 100:
            self.scanner.store.observed(str(subject)[:8192], 'external-request-denied', {'reason':reason,'backend':BACKEND}, self.name)
        return {'allowed':False, 'reason':reason}

    async def dispatch(self, message):
        from .engine import BudgetStop
        async with self.lock:
            scanner = self.scanner
            try:
                scanner.scheduler.check_time()
                scanner.check_disk_budget()
                if message.get('kind') == 'dns':
                    return await self.dns(message)
                url = normalize_url(message.get('url',''))
                if message.get('kind') == 'connect':
                    # CONNECT opens only a local TLS session. The exact decrypted
                    # path is separately checked before every upstream GET.
                    parsed = urlsplit(url)
                    allowed, reason = scanner.policy.decision(urlunsplit(parsed._replace(path=scanner.config.scope.paths[0],query='')))
                    return {'allowed':True} if allowed else self.deny(url, reason)
                if message.get('kind') != 'http' or self.name == 'dnsx':
                    return self.deny(url, 'Capability does not permit HTTP requests')
                if message.get('method') != 'GET' or message.get('has_credentials'):
                    return self.deny(url, 'Only unauthenticated, body-free GET requests are permitted')
                allowed, reason = scanner.policy.decision(url)
                if not allowed:
                    return self.deny(url, reason)
                return await self.http(url)
            except (BudgetStop, OSError, ValueError, TimeoutError, aiohttp.ClientError, dns.exception.DNSException) as exc:
                if isinstance(exc, BudgetStop):
                    scanner.limit(str(exc))
                return self.deny(message.get('url',self.name), str(exc), failure=True)

    def admit_script_reference(self, url):
        """Validate a tool-proposed URL against captured code before scheduling.

        This is a method/depth safety veto, not a second URL-discovery pass.
        A tool cannot assert an arbitrary Referer to reset crawl depth.
        """
        from .analysis import js_strings
        scanner=self.scanner
        for row in scanner.store.conn.execute("SELECT a.hash,a.path,r.parent,j.depth FROM artifacts a JOIN relationships r ON r.child='artifact:'||a.hash JOIN jobs j ON j.url=r.parent WHERE a.kind='js' AND r.kind='response_body' AND j.state='completed'"):
            if row['depth'] >= scanner.config.budgets.depth:
                continue
            key='broker-js-veto:'+row['hash']
            routes=scanner.store.meta(key)
            if routes is None:
                body=artifact_path(scanner.run,row['path']).read_bytes()
                if hashlib.sha256(body).hexdigest()!=row['hash']:
                    raise ValueError('JavaScript admission evidence hash mismatch')
                routes=js_strings(body.decode('utf-8',errors='replace'))[0]
                scanner.store.set_meta(key,routes)
            blocked={r['value'] for r in routes if r.get('method') not in {None,'GET'}}
            for route in routes:
                try:
                    matches=route['value'] not in blocked and normalize_url(urljoin(row['parent'],route['value']))==url
                except ValueError:
                    matches=False
                if matches:
                    scanner.add_url(url,'katana',row['parent'],row['depth']+1)
                    scanner.store.observed(url,'inferred_endpoint',{'source_url':row['parent'],'hash':row['hash'],
                        'method':route.get('method') or 'UNKNOWN','state':'Katana proposed; captured code checked for method/depth safety'},'katana')
                    return

    async def http(self, url):
        from .engine import Response
        scanner = self.scanner
        url = request_url(url)
        job = scanner.store.conn.execute('SELECT * FROM jobs WHERE url=?',(url,)).fetchone()
        if not job and self.name=='katana':
            self.admit_script_reference(url)
            job = scanner.store.conn.execute('SELECT * FROM jobs WHERE url=?',(url,)).fetchone()
        if self.name == 'nuclei':
            if urlsplit(url).path not in {'/.git/HEAD','/.env'} or urlsplit(url).query:
                return self.deny(url, 'URL is not a reviewed Nuclei template request')
        if not job and self.name == 'nuclei':
            scanner.add_url(url, 'nuclei-template', depth=0)
            job = scanner.store.conn.execute('SELECT * FROM jobs WHERE url=?',(url,)).fetchone()
        if not job:
            return self.deny(url, 'No eligible scheduled input/reference; depth, media and queue quotas remain enforced')
        observed = scanner.store.conn.execute("SELECT data FROM observations WHERE subject=? AND kind='http' ORDER BY rowid DESC LIMIT 1",(url,)).fetchone()
        response = None
        if observed:
            data = json.loads(observed[0])
            artifact = scanner.store.conn.execute('SELECT path FROM artifacts WHERE hash=?',(data.get('hash'),)).fetchone()
            if artifact:
                body = artifact_path(scanner.run,artifact[0]).read_bytes()
                if len(body) <= scanner.config.budgets.response_bytes and hashlib.sha256(body).hexdigest() == data['hash']:
                    response = Response(data['status'], data.get('headers',{}), body, data.get('truncated',False))
                    self.metrics['reused_responses'] += 1
        if response is None:
            if job['state'] not in {'queued','running'}:
                return self.deny(url, 'Input already attempted or deferred; no implicit retry budget reset')
            attempt = job['attempts']+1
            scanner.store.execute("UPDATE jobs SET state='running',attempts=? WHERE url=?",(attempt,url))
            before = scanner.store.meta('requests',0)
            try:
                response = await scanner.request(url)
                scanner.process_response(url,response,job['depth'],attempt,source=self.name)
                scanner.scheduler.throttle(url,response.status,response.headers)
                scanner.store.execute("UPDATE jobs SET state='completed' WHERE url=?",(url,))
            except (OSError, ValueError, TimeoutError, aiohttp.ClientError) as exc:
                scanner.store.execute("UPDATE jobs SET state='failed' WHERE url=?",(url,))
                scanner.store.observed(url,'request_error',{'error':redact(str(exc))},self.name)
                raise
            finally:
                self.metrics['http_requests'] += scanner.store.meta('requests',0)-before
                scanner.scheduler.checkpoint()
        scanner.store.observed(url,'external-response-delivered',{'backend':BACKEND,'status':response.status,
            'hash':hashlib.sha256(response.body).hexdigest(),'reused':observed is not None},self.name)
        return {'allowed':True,'status':response.status,'headers':response.headers,
                'body':base64.b64encode(response.body).decode(),'truncated':response.truncated}

    async def dns(self, message):
        scanner = self.scanner
        wire = base64.b64decode(message.get('wire',''),validate=True)
        if len(wire)>4096:
            raise ValueError('DNS message cap reached')
        query = dns.message.from_wire(wire)
        if len(query.question)!=1 or query.opcode()!=0 or query.flags & dns.flags.QR:
            raise ValueError('Only single-question DNS queries are permitted')
        question = query.question[0]
        host = str(question.name).rstrip('.').lower()
        answer = dns.message.make_response(query)
        if (not scanner.policy.host_allowed(host) or question.rdtype not in {1,5,28}
                or question.rdclass!=1):
            self.deny(host,'DNS name/type outside authorized A/AAAA/CNAME policy')
            answer.set_rcode(dns.rcode.REFUSED)
        elif self.name != 'dnsx':
            # Routing hints only, confined to the child network namespace. These
            # synthetic addresses are NEVER persisted as infrastructure evidence.
            if question.rdtype in {1,28}:
                answer.answer.append(dns.rrset.from_text(host+'.',0,'IN',question.rdtype,
                                                       '127.0.0.1' if question.rdtype==1 else '::1'))
        else:
            from .engine import BudgetStop
            count = int(scanner.store.meta('dns_operations',0))
            if count >= scanner.config.budgets.dns_queries:
                raise BudgetStop('DNS operation cap reached')
            resolver = dns.resolver.Resolver()
            upstream = next((str(value) for value in resolver.nameservers if isinstance(value,str)),None)
            if not upstream:
                raise ValueError('No system DNS resolver available')
            # Enforce rate here; scanner flags are only cooperative hints.
            delay = self.next_dns - time.monotonic()
            if delay > 0:
                if delay >= scanner.scheduler.remaining():
                    raise BudgetStop('Time cap reached while pacing DNS')
                await asyncio.sleep(delay)
            scanner.scheduler.check_time()
            self.next_dns = time.monotonic() + 1 / min(scanner.config.budgets.overall_rps, scanner.config.budgets.per_host_rps)
            scanner.store.set_meta('dns_operations',count+1)
            self.metrics['dns_queries'] += 1
            # One datagram, no library CNAME chasing, retries or hidden queries.
            answer = await dns.asyncquery.udp(query,upstream,port=resolver.port,
                timeout=min(scanner.config.budgets.timeout,scanner.scheduler.remaining()),ignore_unexpected=True)
            if not query.is_response(answer) or answer.flags & dns.flags.TC:
                raise ValueError('Mismatched/truncated DNS response; no unaccounted TCP retry')
            data = {'question':host,'type':dns.rdatatype.to_text(question.rdtype),
                    'rcode':dns.rcode.to_text(answer.rcode()),'response':answer.to_text(),
                    'wire_sha256':hashlib.sha256(answer.to_wire()).hexdigest(),'backend':BACKEND}
            scanner.store.observed(host,'dns-response',data,'dnsx')
            for rrset in answer.answer:
                for record in rrset:
                    scanner.store.execute('INSERT INTO dns(host,address,kind,time,source) VALUES(?,?,?,?,?)',
                        (str(rrset.name).rstrip('.'),record.to_text(),dns.rdatatype.to_text(rrset.rdtype),timestamp(),'dnsx'))
        return {'allowed':True,'wire':base64.b64encode(answer.to_wire()).decode()}

    def accept(self, reader, writer):
        if len(self.tasks)>=4:
            writer.close()
            return
        async def serve():
            try:
                async with asyncio.timeout(310):
                    data = await reader.readline()
                    if len(data)>16384:
                        raise ValueError('Broker request size cap')
                    answer = await self.dispatch(json.loads(data))
                    writer.write(json.dumps(answer).encode()+b'\n')
                    await writer.drain()
            except (OSError, ValueError, TimeoutError, asyncio.LimitOverrunError):
                pass
            finally:
                writer.close()
        task=asyncio.create_task(serve())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


async def run_contained(scanner, info, cwd, arguments, inputs):
    """Only invocation entry point: a failed probe has no direct-spawn fallback."""
    from .engine import SafeResolver
    boundary = await asyncio.to_thread(probe_boundary)
    if not boundary.available:
        raise ValueError(boundary.reason)
    with Path(info.path).open('rb') as binary:
        if hashlib.file_digest(binary,'sha256').hexdigest()!=info.sha256:
            raise ValueError('Executable identity changed after preflight; refusing execution')
    broker = Broker(scanner,info.name)
    with tempfile.TemporaryDirectory(prefix='reconmap-boundary-') as temporary:
        root = Path(temporary)
        # Mount a private, rehashed snapshot rather than a mutable executable
        # pathname between preflight and exec. No executable is downloaded here.
        if shutil.disk_usage(root).free < Path(info.path).stat().st_size + 1024**2:
            raise ValueError('Insufficient free space for verified executable snapshot')
        shutil.copyfile(info.path,root/'binary')
        with (root/'binary').open('rb') as binary:
            if hashlib.file_digest(binary,'sha256').hexdigest()!=info.sha256:
                raise ValueError('Executable identity changed while preparing isolation')
        (root/'binary').chmod(0o500)
        (root/'inputs.txt').write_text('\n'.join(inputs)+'\n',encoding='utf-8')
        (root/'resolvers.txt').write_text('127.0.0.1:1053\n',encoding='utf-8')
        (root/'tls').mkdir()
        cert = await execute([shutil.which('openssl'),'req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(root/'tls/key.pem'),'-out',str(root/'tls/cert.pem'),'-subj','/CN=reconmap.local','-days','1'],root,10,limit=65536)
        if cert.code:
            raise ValueError('Could not create ephemeral internal TLS certificate')
        socket_path = root/'broker.sock'
        server = await asyncio.start_unix_server(broker.accept,path=socket_path,limit=16384)
        socket_path.chmod(0o600)
        mounts = [(root/'binary','/tool'),(root/'inputs.txt','/inputs.txt'),(root/'resolvers.txt','/resolvers.txt'),
                  (root/'tls','/tls'),(socket_path,'/broker.sock')]
        if info.name=='nuclei':
            mounts.append((reviewed_templates(),'/templates'))
        argv = sandbox_arguments(boundary.executable,mounts)+arguments
        connector = aiohttp.TCPConnector(resolver=SafeResolver(scanner.policy,scanner.config,scanner.store),
                                        ttl_dns_cache=0,force_close=True,limit=1)
        previous = scanner.session
        try:
            async with server, aiohttp.ClientSession(connector=connector,auto_decompress=False,trust_env=False,
                    headers={'User-Agent':'reconmap/3 authorized-recon','Accept-Encoding':'identity'},
                    cookie_jar=aiohttp.DummyCookieJar()) as session:
                scanner.session = session
                result = await execute(argv,cwd,min(scanner.config.budgets.provider_seconds,scanner.scheduler.remaining()),
                                       limit=scanner.config.budgets.response_bytes)
                return result, broker
        except BaseException as exc:
            exc.broker = broker
            raise
        finally:
            scanner.session = previous
            server.close()
            await server.wait_closed()
            for task in broker.tasks:
                task.cancel()
            await asyncio.gather(*broker.tasks,return_exceptions=True)
