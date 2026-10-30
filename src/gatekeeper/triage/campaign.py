"""Campaign memory: exfiltration endpoints of packages the Meta models agree are malicious.

Attackers re-upload under new names after a takedown and reuse the same collector (a raw IP, a
webhook.site token, a tunnel subdomain). Only endpoints specific enough to name one attacker are kept;
`webhook.site` alone or `github.com` would match half of npm.
"""

from __future__ import annotations

import ipaddress
import json
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


def report_iocs(vuln: dict) -> set[str]:
    """Endpoints named in a public OSV malware report: the text, and its OpenSSF `iocs` block."""
    extra = vuln.get("database_specific") or {}
    found = specific_iocs(f"{vuln.get('details') or ''} {json.dumps(extra)}")
    ips = (extra.get("iocs") or {}).get("ips") or [] if isinstance(extra.get("iocs"), dict) else []
    return found | {ip for ip in ips if isinstance(ip, str) and _public_ip(ip)}


SHARED_ACCOUNTS = {"npm", "npm-support", "npmjs", "github-actions", "github actions", "gitlab-ci", "circleci"}


def account_names(doc: dict) -> set[str]:
    """npm accounts behind a package: whoever published a version, and the maintainers. `npm` itself takes
    over removed packages, so it never counts."""
    names = {(v.get("_npmUser") or {}).get("name") for v in (doc.get("versions") or {}).values() if isinstance(v, dict)}
    names |= {m.get("name") for m in doc.get("maintainers") or [] if isinstance(m, dict)}
    return {n for n in names if n and is_person(n)}


def is_person(account: str) -> bool:
    """False for the registry's own accounts and for trusted publishing, where `_npmUser` says "GitHub Actions" for
    every project on GitHub: remembering those would flag half of npm's automated releases."""
    return account not in SHARED_ACCOUNTS and " " not in account


# A throwaway campaign account has a handful of packages. Hundreds mean a real maintainer whose one
# package was hijacked: their other packages are no more suspect than anyone's.
SWEEP_MAX_PACKAGES = 60


def packages_of(client, account: str) -> list[str] | None:
    """All packages of an npm account, or None if it has too many to be a throwaway account."""
    r = client.get("https://registry.npmjs.org/-/v1/search",
                   params={"text": f"maintainer:{account}", "size": SWEEP_MAX_PACKAGES + 1})
    r.raise_for_status()
    names = [o["package"]["name"] for o in r.json().get("objects", [])]
    return None if len(names) > SWEEP_MAX_PACKAGES else names


def matches(text: str, known: dict[str, str]) -> list[tuple[str, str]]:
    """(ioc, source package) for every known endpoint found in `text`."""
    if not known:
        return []
    found = specific_iocs(text)
    return sorted((ioc, known[ioc]) for ioc in found if ioc in known)
