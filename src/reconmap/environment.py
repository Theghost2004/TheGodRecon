"""Informational preflight only. Availability does not establish containment."""
import getpass
import os
import platform
import shutil
from pathlib import Path


def diagnostics(tools=None):
    capabilities = None
    seccomp = None
    if platform.system() == 'Linux':
        try:
            fields = dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
            capabilities = fields.get('CapEff','').strip()
            seccomp = fields.get('Seccomp','').strip()
        except OSError:
            pass
    try:
        user = getpass.getuser()
    except (OSError, KeyError):
        user = 'unavailable'
    return {'os':platform.system(), 'effective_uid':os.geteuid() if hasattr(os,'geteuid') else None,
        'user':user, 'linux_effective_capabilities_hex':capabilities, 'linux_seccomp_mode':seccomp,
        'sandbox_commands':{name:shutil.which(name) for name in ('bwrap','unshare','firejail')},
        'executable_permissions':{name: bool(info.path and os.access(info.path,os.X_OK)) for name,info in (tools or {}).items()},
        'compatible_tools':{name:info.compatible for name,info in (tools or {}).items()},
        'network_controls':{'native':'Pinned destination resolver, explicit scope/method/redirect controls and shared request ceilings',
            'external_active':'No verified cross-platform request containment; direct dnsx/httpx/Katana/Nuclei remain restricted'},
        'note':'Informational only: installed sandbox commands or Linux capabilities never authorize external network execution. No privilege elevation is performed.'}
