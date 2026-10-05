"""WAF / CDN identification.

Two layers:
  1. header + body fingerprint rules (fast, no extra binary)
  2. origin-bypass check: does the host resolve *directly* to its origin IP?
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import dns.resolver

# ponytail: CDN/WAF egress ranges are a moving target; extend from the well-known
# published lists before relying on this for a production engagement.
WAF_RANGES: tuple[tuple[str, str], ...] = (
    # Cloudflare (subset of https://www.cloudflare.com/ips/)
    ("103.21.244.0/22", "cloudflare"),
    ("103.22.200.0/22", "cloudflare"),
    ("103.31.4.0/22", "cloudflare"),
    ("104.16.0.0/13", "cloudflare"),
    ("104.24.0.0/14", "cloudflare"),
    ("108.162.192.0/18", "cloudflare"),
    ("131.0.72.0/22", "cloudflare"),
    ("141.101.64.0/18", "cloudflare"),
    ("162.158.0.0/15", "cloudflare"),
    ("172.64.0.0/13", "cloudflare"),
    ("173.245.48.0/20", "cloudflare"),
    ("188.114.96.0/20", "cloudflare"),
    ("190.93.240.0/20", "cloudflare"),
    ("197.234.240.0/22", "cloudflare"),
    ("198.41.128.0/17", "cloudflare"),
    ("199.27.128.0/21", "cloudflare"),
    ("2606:4700::/32", "cloudflare"),
    ("2803:f800::/32", "cloudflare"),
    ("2c0f:f248::/32", "cloudflare"),
    ("2a06:98c0::/29", "cloudflare"),
    # Akamai
    ("23.32.0.0/11", "akamai"),
    ("23.64.0.0/14", "akamai"),
    ("72.246.0.0/13", "akamai"),
    ("92.122.0.0/15", "akamai"),
    ("95.100.0.0/13", "akamai"),
    ("184.24.0.0/13", "akamai"),
    # AWS CloudFront
    ("13.32.0.0/15", "aws-cloudfront"),
    ("13.34.0.0/15", "aws-cloudfront"),
    ("52.46.0.0/18", "aws-cloudfront"),
    ("52.84.0.0/15", "aws-cloudfront"),
    ("99.84.0.0/16", "aws-cloudfront"),
    ("108.138.0.0/15", "aws-cloudfront"),
    ("205.251.192.0/19", "aws-cloudfront"),
    ("205.251.224.0/22", "aws-cloudfront"),
    # Google Cloud / Firebase
    ("35.186.0.0/16", "gcp"),
    ("35.190.0.0/16", "gcp"),
    # Fastly
    ("151.101.0.0/16", "fastly"),
    ("199.232.0.0/16", "fastly"),
    # Sucuri
    ("192.124.249.0/24", "sucuri"),
    ("192.124.249.0/24", "sucuri"),
    # Imperva Incapsula
    ("45.60.0.0/16", "imperva"),
    ("45.223.0.0/16", "imperva"),
    ("199.83.0.0/16", "imperva"),
    ("107.154.0.0/16", "imperva"),
    ("193.30.0.0/16", "imperva"),
    ("45.60.0.0/16", "imperva"),
)

WAF_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("server", r"cloudflare", "cloudflare"),
    ("server", r"akamaighost", "akamai"),
    ("server", r"amazonelb|cloudfront", "aws-cloudfront"),
    ("server", r"sucuri", "sucuri"),
    ("server", r"imperva|incapsula", "imperva"),
    ("server", r"nginx", "nginx"),
    ("server", r"apache", "apache"),
    ("server", r"microsoft-iis", "iis"),
    ("cf-ray", r".", "cloudflare"),
    ("x-amz-cf-id", r".", "aws-cloudfront"),
    ("x-akamai-transformed", r".", "akamai"),
    ("x-sucuri-id", r".", "sucuri"),
    ("x-iinfo", r".", "imperva"),
    ("x-cdn", r"incapsula", "imperva"),
    ("set-cookie", r"incap_ses|visid_incap", "imperva"),
    ("via", r"1\.1 google|1\.1 cloudfront", "gcp"),
)

WAF_BODY_MARKERS: tuple[tuple[str, str], ...] = (
    (r"cf-error-details|attention required! \| cloudflare", "cloudflare"),
    (r"access denied - sucuri website firewall", "sucuri"),
    (r"incapsula incident", "imperva"),
    (r"akamai|reference\s*#\d+\.\d+[a-z0-9]+", "akamai"),
    (r"request blocked", "generic-waf"),
)


@dataclass
class WAFMatch:
    name: str
    evidence: str
    layer: str  # header | body | dns | cert


@dataclass
class WAFFingerprint:
    detected: list[WAFMatch] = field(default_factory=list)
    confidence: str = "none"

    def add(self, name: str, evidence: str, layer: str) -> None:
        if not any(m.name == name for m in self.detected):
            self.detected.append(WAFMatch(name, evidence, layer))

    def summarize(self) -> dict[str, Any]:
        names = [m.name for m in self.detected]
        if not names:
            return {"detected": False, "confidence": "none", "matches": []}
        # ponytail: heuristic; a DNS+header double signal is far more reliable
        # than a single header match, which is often a decoy or shared host.
        layers = {m.layer for m in self.detected}
        confidence = "high" if len(layers) >= 2 else ("medium" if layers == {"header"} else "low")
        return {
            "detected": True,
            "names": sorted(set(names)),
            "confidence": confidence,
            "matches": [m.__dict__ for m in self.detected],
        }


def fingerprint_headers(headers: dict[str, str]) -> WAFFingerprint:
    fp = WAFFingerprint()
    lowered = {k.lower(): v for k, v in headers.items()}
    for header, pattern, name in WAF_HEADERS:
        value = lowered.get(header)
        if value and re.search(pattern, value, re.IGNORECASE):
            fp.add(name, f"{header}: {value}", "header")
    return fp


def fingerprint_body(body: str) -> WAFFingerprint:
    fp = WAFFingerprint()
    if not body:
        return fp
    head = body[:4096].lower()
    for pattern, name in WAF_BODY_MARKERS:
        if re.search(pattern, head, re.IGNORECASE):
            fp.add(name, f"body marker /{pattern[:32]}/", "body")
    return fp


def _ipv6_normalize(addr: str) -> tuple[str, int]:
    """Return (normalized, prefix) so 2606:4700::/32 matches 2606:4700:0:1::2."""
    addr = addr.lower().strip()
    if addr.startswith("["):
        addr = addr[1 : addr.index("]")]
    if "::" in addr:
        # expand one `::`
        head, _, tail = addr.partition("::")
        head_groups = head.split(":") if head else []
        tail_groups = tail.split(":") if tail else []
        missing = 8 - len(head_groups) - len(tail_groups)
        expanded = head_groups + (["0"] * missing) + tail_groups
    else:
        expanded = addr.split(":")
    groups = [f"{int(g, 16):04x}" if g else "0000" for g in expanded]
    return ":".join(groups), 8


def in_range(ip: str, cidr: str) -> bool:
    """Minimal IPv4 + IPv6 CIDR containment check."""
    ip = ip.strip().rstrip(".")
    cidr = cidr.strip()
    if ":" in ip or ":" in cidr:
        try:
            net_addr, prefix = _ipv6_normalize(cidr.split("/")[0])
            ip_addr, _ = _ipv6_normalize(ip)
            width = int(cidr.split("/")[1]) if "/" in cidr else 128
        except ValueError:
            return False
        # compare on 16-bit groups
        net_groups = net_addr.split(":")
        ip_groups = ip_addr.split(":")
        if len(net_groups) != 8 or len(ip_groups) != 8:
            return False
        n = width // 16
        return net_groups[:n] == ip_groups[:n]

    if "/" not in cidr:
        return ip == cidr
    net, bits = cidr.split("/")
    bits = int(bits)
    if "." not in ip or "." not in net:
        return False
    try:
        ip_int = _ipv4_to_int(ip)
        net_int = _ipv4_to_int(net)
    except ValueError:
        return False
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return (ip_int & mask) == (net_int & mask)


def _ipv4_to_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(ip)
    octets = [int(p) for p in parts]
    if any(o < 0 or o > 255 for o in octets):
        raise ValueError(ip)
    return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]


def classify_ip(ip: str) -> str | None:
    """Return the WAF/CDN name whose range contains ip, else None."""
    for cidr, name in WAF_RANGES:
        if in_range(ip, cidr):
            return name
    return None


def resolve_a(host: str, timeout: float = 4.0) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(host, "A")
        return [r.to_text() for r in answers]
    except Exception:
        return []
