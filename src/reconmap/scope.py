from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import Scope, hostname, normalize_url


def host_matches(host: str, pattern: str) -> bool:
    return host.endswith("." + pattern[2:]) and host != pattern[2:] if pattern.startswith("*.") else host == pattern


def path_matches(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


class ScopePolicy:
    def __init__(self, config: Scope):
        self.config = config

    def host_allowed(self, host: str) -> bool:
        try:
            host = hostname(host)
        except ValueError:
            return False
        return any(host_matches(host, p) for p in self.config.hosts) and not any(host_matches(host, p) for p in self.config.exclude_hosts)

    def decision(self, url: str) -> tuple[bool, str]:
        try:
            u = urlsplit(normalize_url(url))
        except ValueError as exc:
            return False, str(exc)
        if not self.host_allowed(u.hostname):
            return False, "hostname outside scope"
        if u.scheme not in self.config.schemes or (u.port or (443 if u.scheme == "https" else 80)) not in self.config.ports:
            return False, "scheme or port outside scope"
        # Check raw and decoded paths to avoid ambiguity around encoded traversal/separators.
        path = u.path
        decoded = unquote(path)
        if "%" in decoded or "//" in decoded or any(c in decoded for c in "\\;?#") or any(ord(c) < 32 or ord(c) == 127 for c in decoded) or any(s in {".", ".."} for s in decoded.split("/")):
            return False, "ambiguous or traversing path"
        if not all(any(path_matches(p, s) for s in self.config.paths) for p in (path, decoded)):
            return False, "path outside scope"
        if any(path_matches(p, s) for p in (path, decoded) for s in self.config.exclude_paths):
            return False, "excluded path"
        try:
            if not self.ip_allowed(u.hostname):
                return False, "address outside network policy"
        except ValueError:
            pass  # DNS addresses are checked by the connection resolver.
        if re.search(r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|purchase|checkout|unsubscribe)(?:[/._-]|$)", decoded, re.I):
            return False, "non-crawl action"
        if any(k.lower() in {"action","do","command","op"} and v.lower() in {"logout","delete","remove","purchase","checkout","unsubscribe"} for k,v in parse_qsl(u.query)):
            return False, "non-crawl action query"
        return True, "allowed"

    def ip_allowed(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        # is_global alone includes multicast addresses on supported Python versions.
        if self.config.lab:
            return ip.is_loopback
        return ip.is_global and not any((ip.is_multicast, ip.is_reserved, ip.is_unspecified, ip.is_link_local, ip.is_loopback))
