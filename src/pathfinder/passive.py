"""Passive recon tools — no packets hit the target from us.

crt.sh certificate transparency, Wayback Machine, direct DNS lookups.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=original&collapse=urlkey&limit={limit}"


def _clean_host(value: str) -> str:
    """ crt.sh sometimes returns *.example.com or mail.example.com:443. """
    value = value.strip().lstrip("*.")
    return value.split(":")[0]


def crtsh_subdomains(domain: str, timeout: float = 30.0) -> list[str]:
    """Pull subdomains from the crt.sh certificate-transparency log."""
    url = CRTSH_URL.format(domain=domain)
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers={"User-Agent": "pathfinder-mcp/0.1"})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError):
        return []

    found: dict[str, None] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            raw = entry.get(field)
            if not raw:
                continue
            for line in str(raw).split("\n"):
                host = _clean_host(line)
                if host and host.endswith(domain) and host not in found:
                    found[host] = None
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
