"""Campaign memory: exfiltration endpoints of packages the Meta models agree are malicious.

Attackers re-upload under new names after a takedown and reuse the same collector (a raw IP, a
webhook.site token, a tunnel subdomain). Only endpoints specific enough to name one attacker are kept;
`webhook.site` alone or `github.com` would match half of npm.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_URL = re.compile(r"""\bhttps?://[^\s"'`<>)\]}\\,;]+""", re.I)
# public resolvers and similar: malware mentions them too, but so does plenty of ordinary code
_SHARED_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
               "1.2.3.4", "4.3.2.1"}  # the last two: placeholder addresses in examples and tests
# collection and tunnel services: the endpoint is identified by a token in the path or a subdomain
_PATH_TOKEN_HOSTS = ("webhook.site", "requestbin.net", "pipedream.net", "discord.com", "discordapp.com", "hookbin.com")
_SUBDOMAIN_HOSTS = ("trycloudflare.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "oast.fun", "oast.pro", "oast.live",
                    "oast.site", "oast.online", "oast.me", "interact.sh", "burpcollaborator.net", "pipedream.net",
                    "requestbin.net", "loca.lt", "serveo.net", "m.pipedream.net")
# an identifier, not a word: path segments like "attachments" or "webhooks" are shared by everyone
_TOKEN = re.compile(r"(?=[A-Za-z_-]*[0-9])[A-Za-z0-9_-]{8,}")


def _public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_global and host not in _SHARED_IPS


def specific_iocs(text: str) -> set[str]:
    """Endpoints in `text` that identify one collector: URLs to a public IP, service URLs with a token, tunnel
    subdomains. Bare IPs outside URLs are ignored (version strings and resolver addresses look the same)."""
    out: set[str] = set()
    for m in _URL.finditer(text):
        try:
            parts = urlsplit(m.group(0))
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if _public_ip(host):
            out.add(host)
        elif host.endswith(_PATH_TOKEN_HOSTS):
            token = next((seg for seg in parts.path.split("/") if _TOKEN.fullmatch(seg)), None)
            if token:
                out.add(f"{host}/{token}")
        elif any(host.endswith("." + s) and len(host) > len(s) + 1 for s in _SUBDOMAIN_HOSTS):
            out.add(host)
    return out


def matches(text: str, known: dict[str, str]) -> list[tuple[str, str]]:
    """(ioc, source package) for every known endpoint found in `text`."""
    if not known:
        return []
    found = specific_iocs(text)
    return sorted((ioc, known[ioc]) for ioc in found if ioc in known)
