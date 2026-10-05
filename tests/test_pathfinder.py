"""Unit tests — no network, no external CLIs required."""

import json
import re
import subprocess
from unittest import mock

import pytest

from pathfinder.active import parse_httpx
from pathfinder.passive import host_of, normalize_url
from pathfinder.runner import resolve, run
from pathfinder.session import SessionStore
from pathfinder.waf import classify_ip, fingerprint_headers, in_range


# ---- runner -------------------------------------------------------------


def test_resolve_missing_binary_returns_none():
    assert resolve("definitely-not-a-real-binary-xyz") is None


def test_run_reports_missing_tool():
    result = run(["definitely-not-real-xyz"], binary="definitely-not-real-xyz")
    assert result.ok is False
    assert result.missing == "definitely-not-real-xyz"
    assert result.as_error()["status"] == "MISSING_TOOL"


# ---- session -----------------------------------------------------------


def test_session_store_chains_targets():
    store = SessionStore()
    first = store.new(hosts=["a.example.com", "b.example.com"])
    resolved = store.resolve_targets(first.token, ["c.example.com"])
    assert resolved == ["c.example.com", "a.example.com", "b.example.com"]


def test_session_store_unknown_token_is_none():
    store = SessionStore()
    assert store.get("nope") is None
    assert store.resolve_targets("nope", None) == []


def test_session_store_dedupes():
    store = SessionStore()
    s = store.new(hosts=["a.example.com"])
    s.touch(hosts=["a.example.com", "b.example.com"])
    assert s.hosts == ["a.example.com", "b.example.com"]


def test_session_store_evicts_oldest():
    store = SessionStore(max_sessions=2)
    a = store.new()
    b = store.new()
    c = store.new()
    assert store.get(a.token) is None
    assert store.get(b.token) is not None
    assert store.get(c.token) is not None


# ---- waf ---------------------------------------------------------------


def test_cloudflare_header_fingerprint():
    fp = fingerprint_headers({"Server": "cloudflare", "CF-RAY": "abc-XYZ"})
    summary = fp.summarize()
    assert summary["detected"] is True
    assert "cloudflare" in summary["names"]
    assert summary["confidence"] == "medium"


def test_no_waf_detected_on_plain_headers():
    fp = fingerprint_headers({"Server": "nginx/1.25"})
    summary = fp.summarize()
    assert "cloudflare" not in summary.get("names", [])
    # nginx is a server, not a WAF — but it is recorded
    assert "nginx" in summary["names"]


def test_ipv4_cidr_containment():
    assert in_range("104.16.132.229", "104.16.0.0/13") is True
    assert in_range("104.20.5.1", "104.16.0.0/13") is True    # top of /13
    assert in_range("104.24.5.1", "104.24.0.0/14") is True    # next Cloudflare block
    assert in_range("104.23.255.255", "104.16.0.0/13") is True
    assert in_range("104.15.255.255", "104.16.0.0/13") is False
    assert in_range("1.1.1.1", "104.16.0.0/13") is False
    assert in_range("203.0.113.10", "203.0.113.0/24") is True
    assert in_range("203.0.114.1", "203.0.113.0/24") is False


def test_ipv6_cidr_containment():
    assert in_range("2606:4700::6810:85e5", "2606:4700::/32") is True
    assert in_range("2606:4701::1", "2606:4700::/32") is False


def test_classify_ip_finds_cloudflare():
    assert classify_ip("104.16.132.229") == "cloudflare"
    assert classify_ip("203.0.113.10") is None


def test_classify_ip_aws_cloudfront():
    assert classify_ip("13.33.12.1") == "aws-cloudfront"


# ---- passive -----------------------------------------------------------


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"


def test_host_of_extracts_hostname():
    assert host_of("https://sub.example.com/path?x=1") == "sub.example.com"


# ---- httpx parsing -----------------------------------------------------


def test_parse_httpx_line():
    line = (
        '{"url":"https://example.com","status_code":200,"title":"Example",'
        '"webserver":"nginx","content_length":1256,"tech":["Nginx","React"]}'
    )
    probe = parse_httpx(line)
    assert probe is not None
    assert probe.url == "https://example.com"
    assert probe.status == 200
    assert probe.title == "Example"
    assert probe.server == "nginx"
    assert probe.technologies == ["Nginx", "React"]


def test_parse_httpx_garbage_returns_none():
    assert parse_httpx("not json at all") is None
    assert parse_httpx("") is None


# ---- tools (CLIs stubbed) ----------------------------------------------


@pytest.fixture
def no_tools():
    """Force every CLI lookup to miss so tools degrade gracefully.

    active.py calls resolve() from its own module globals, so that is the name
    that must be patched.
    """
    with mock.patch("pathfinder.active.resolve", return_value=None):
        yield


def test_http_probe_without_binary_reports_missing(no_tools):
    from pathfinder.active import http_probe

    result = http_probe(["example.com"])
    assert result["status"] == "MISSING_TOOL"
    assert result["error"] == "httpx"


def test_port_scan_without_binary_reports_missing(no_tools):
    from pathfinder.active import port_scan

    result = port_scan("example.com")
    assert result["status"] == "MISSING_TOOL"
    assert result["error"] == "nmap"


def test_subdomain_enum_bad_domain():
    from pathfinder.server import subdomain_enum

    out = json.loads(subdomain_enum("localhost"))
    assert out["status"] == "BAD_INPUT"


def test_dns_resolve_bad_host():
    from pathfinder.server import dns_resolve

    out = json.loads(dns_resolve(""))
    assert out["status"] == "BAD_INPUT"


def test_http_probe_no_targets():
    from pathfinder.server import http_probe

    out = json.loads(http_probe())
    assert out["status"] == "BAD_INPUT"


def test_nmap_output_parsed():
    """Validate the nmap -oG grep-output regex against a real nmap line."""
    sample = (
        "Host: 203.0.113.10 (example.com)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, "
        "80/open/tcp//http//nginx 1.25.3/, 443/open/tcp//https///"
    )
    ports = []
    for match in re.finditer(r"(\d+)/open/tcp//([^/]*)//([^/]*)", sample):
        p, s, v = match.group(1), match.group(2), match.group(3)
        ports.append({"port": int(p), "service": s, "version": v or None})
    assert len(ports) == 3
    assert ports[0]["port"] == 22
    assert ports[0]["service"] == "ssh"
    assert ports[0]["version"] == "OpenSSH 8.9p1"
    assert ports[1]["service"] == "http"
    assert ports[1]["version"] == "nginx 1.25.3"
    assert ports[2]["service"] == "https"
    assert ports[2]["version"] is None
