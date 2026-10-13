from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.resolver

from .engine import BudgetStop
from .storage import timestamp

if TYPE_CHECKING:
    from .engine import Scanner


async def observe_dns(scanner: Scanner) -> None:
    """CNAME destinations are observations, never implicitly authorized targets."""
    if scanner.config.mode in {"passive","demo"}:
        scanner.store.stage("dns", "skipped", "No target DNS in passive/offline demo")
        return
    resolver=dns.asyncresolver.Resolver()
    failures=[]

    def reserve() -> None:
        scanner.scheduler.check_time()
        count=int(scanner.store.meta("dns_operations",0))
        if count >= scanner.config.budgets.dns_queries:
            raise BudgetStop("DNS operation cap reached")
        scanner.store.set_meta("dns_operations",count+1)

    for row in scanner.store.rows("hosts"):
        host=row["host"]
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if scanner.config.scope.lab or scanner.store.meta("cname:"+host):
            continue
        try:
            reserve()
            answer=await resolver.resolve(host,"CNAME",search=False,lifetime=scanner.config.budgets.timeout,raise_on_no_answer=False)
            for record in answer:
                alias=str(record.target).rstrip(".")
                scanner.store.execute("INSERT INTO dns(host,address,kind,time,source) VALUES(?,?,?,?,?)",(host,alias,"CNAME",timestamp(),"dnspython"))
                scanner.store.relate(host,alias,"dns-alias-unscoped","dnspython")
                scanner.store.observed(host,"cname",{"alias":alias,"authorization_transferred":False},"dnspython")
                if scanner.policy.host_allowed(alias):
                    try:
                        reserve()
                        await resolver.resolve(alias,"A",search=False,lifetime=scanner.config.budgets.timeout)
                    except dns.resolver.NXDOMAIN:
                        scanner.store.finding("dangling-dns-candidate",host,"CNAME points to an in-scope NXDOMAIN destination",{"alias":alias,"next_check":"Check service ownership manually; no resource claiming or takeover validation was attempted"},priority=60,confidence="low",reasons=["CNAME and current in-scope NXDOMAIN evidence; not a confirmed takeover"])
                    except dns.exception.DNSException as exc:
                        scanner.store.observed(alias,"dns-error",{"error":type(exc).__name__},"dnspython")
                else:
                    scanner.store.observed(host,"external-service-reference",{"alias":alias,"validation":"untested; out-of-scope destination not queried"},"dnspython")
            scanner.store.set_meta("cname:"+host,True)
        except dns.resolver.NXDOMAIN:
            scanner.store.observed(host,"dns-nxdomain",{"state":"unresolved","note":"Absence now; not proof of a claimable resource"},"dnspython")
            scanner.store.execute("UPDATE hosts SET state='unresolved' WHERE host=?",(host,))
        except dns.exception.DNSException as exc:
            failures.append(f"{host}: {type(exc).__name__}")
            scanner.store.observed(host,"dns-error",{"error":type(exc).__name__},"dnspython")
    for pattern in scanner.config.scope.hosts:
        if not pattern.startswith("*.") or scanner.config.scope.lab or scanner.store.meta("wildcard:"+pattern):
            continue
        addresses=[]
        probes=[]
        for _ in range(2):
            probe="reconmap-"+secrets.token_hex(10)+"."+pattern[2:]
            if not scanner.policy.host_allowed(probe):
                continue
            probes.append(probe)
            reserve()
            try:
                result=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(probe,443,type=socket.SOCK_STREAM),scanner.config.budgets.timeout)
                addresses.append({r[4][0] for r in result})
            except (OSError,TimeoutError):
                addresses.append(set())
        intersection=addresses[0]&addresses[1] if len(addresses)==2 else set()
        scanner.store.observed(pattern,"dns-wildcard-evidence",{"probes":probes,"addresses":[sorted(a) for a in addresses],"classification":"candidate wildcard" if intersection else "not demonstrated","note":"Two bounded random labels; retain observations"},"native-dns")
        scanner.store.set_meta("wildcard:"+pattern,True)
    scanner.store.stage("dns","partial" if failures else "completed","; ".join(failures) or "CNAME and explicit wildcard evidence bounded; literal/lab seeds use system DNS only")
