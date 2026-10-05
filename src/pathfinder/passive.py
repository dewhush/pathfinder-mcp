"""Passive recon tools — no packets hit the target from us.

Free public sources: CertSpotter CT log, HackerTarget, AlienVault OTX,
urlscan.io, Wayback Machine, direct DNS lookups. No API keys.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import httpx

WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=original&collapse=urlkey&limit={limit}"


def _clean_host(value: str) -> str:
    """Sources often return *.example.com or mail.example.com:443."""
    value = value.strip().lstrip("*.")
    return value.split(":")[0]


# ---- passive sources (no API key) -------------------------------------
# crt.sh dropped: rate-limits hard and stalls the whole tool. These cover
# the same CT/DNS surface in parallel and stay up.

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"


def _accepts_subdomain(host: str, domain: str, found: dict[str, None]) -> bool:
    return bool(host) and host.endswith(domain) and host not in found


def certspotter_subdomains(domain: str, timeout: float = 20.0) -> list[str]:
    """CertSpotter CT log — fast, generous free quota."""
    found: dict[str, None] = {}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                CERTSPOTTER_URL.format(domain=domain),
                headers={"User-Agent": "pathfinder-mcp/0.1"},
            )
            resp.raise_for_status()
            for entry in resp.json():
                for name in entry.get("dns_names") or []:
                    host = _clean_host(name)
                    if _accepts_subdomain(host, domain, found):
                        found[host] = None
    except (httpx.HTTPError, json.JSONDecodeError):
        pass
    return list(found)


def hackertarget_subdomains(domain: str, timeout: float = 20.0) -> list[str]:
    """HackerTarget hostsearch — plain text, no auth."""
    found: dict[str, None] = {}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                HACKERTARGET_URL.format(domain=domain),
                headers={"User-Agent": "pathfinder-mcp/0.1"},
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                host = _clean_host(line.split(",")[0])
                if _accepts_subdomain(host, domain, found):
                    found[host] = None
    except httpx.HTTPError:
        pass
    return list(found)


def otx_subdomains(domain: str, timeout: float = 20.0) -> list[str]:
    """AlienVault OTX passive DNS."""
    found: dict[str, None] = {}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                OTX_URL.format(domain=domain),
                headers={"User-Agent": "pathfinder-mcp/0.1"},
            )
            resp.raise_for_status()
            payload = resp.json()
            for entry in payload.get("passive_dns") or []:
                if entry.get("record_type") not in ("A", "AAAA", "CNAME"):
                    continue
                host = _clean_host(entry.get("hostname", ""))
                if _accepts_subdomain(host, domain, found):
                    found[host] = None
    except (httpx.HTTPError, json.JSONDecodeError):
        pass
    return list(found)


def urlscan_subdomains(domain: str, timeout: float = 20.0) -> list[str]:
    """urlscan.io search — subdomains seen in scans."""
    found: dict[str, None] = {}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                URLSCAN_SEARCH_URL.format(domain=domain),
                headers={"User-Agent": "pathfinder-mcp/0.1"},
            )
            resp.raise_for_status()
            for entry in resp.json().get("results") or []:
                page = entry.get("page") or {}
                host = _clean_host(page.get("domain", ""))
                if _accepts_subdomain(host, domain, found):
                    found[host] = None
    except (httpx.HTTPError, json.JSONDecodeError):
        pass
    return list(found)


def wayback_urls(host: str, limit: int = 500, timeout: float = 30.0) -> list[str]:
    """Historical URLs from the Wayback Machine for a host."""
    host = host.lstrip("*.")
    url = WAYBACK_URL.format(host=host, limit=limit)
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers={"User-Agent": "pathfinder-mcp/0.1"})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return []

    urls: dict[str, None] = {}
    for entry in data:
        if isinstance(entry, list) and entry:
            original = str(entry[0])
        elif isinstance(entry, dict):
            original = str(entry.get("original", ""))
        else:
            continue
        if original and original not in urls:
            urls[original] = None
    return list(urls)


def normalize_url(value: str, default_scheme: str = "https") -> str:
    """Ensure a bare host becomes a scheme://host URL."""
    value = value.strip()
    if not value:
        return value
    if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        return value
    return f"{default_scheme}://{value}"


def host_of(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except ValueError:
        return url
