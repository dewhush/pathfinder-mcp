"""Pathfinder MCP server — exposes recon tools to LLM agents.

FastMCP: each @mcp.tool() becomes an MCP tool the client (Claude Code,
OpenCode, Codex, Hermes, ...) can call. Tools return plain JSON so the agent
can reason over the output and chain it via `from_token`.
"""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from .active import endpoint_discover, http_probe, nuclei_scan, port_scan
from .passive import (
    certspotter_subdomains,
    hackertarget_subdomains,
    host_of,
    normalize_url,
    otx_subdomains,
    urlscan_subdomains,
    wayback_urls,
)
from .runner import resolve
from .session import store
from .waf import classify_ip, fingerprint_body, fingerprint_headers, resolve_a

mcp = FastMCP("pathfinder")

ABOUT = """Pathfinder — offensive recon toolkit for LLM agents.

Wraps subfinder, httpx, nmap, ffuf and nuclei behind MCP tools so the agent
can plan and execute reconnaissance itself. Every tool returns structured
JSON; pass the returned `scan_token` into any other tool's `from_token`
argument to chain steps without re-stating targets.

Authorized use only. Run solely against infrastructure you own or are
explicitly authorized to test."""


@mcp.tool()
def subdomain_enum(domain: str, source: str = "all", from_token: str | None = None) -> str:
    """Passive subdomain enumeration for a domain.

    Args:
        domain: Root domain, e.g. "example.com".
        source: Which source(s) to query. Default "all" merges everything:
                certspotter (CT log), hackertarget (hostsearch),
                otx (AlienVault passive DNS), urlscan (scan archive),
                plus the local "subfinder" binary if installed.
                Any single name can be passed to use one source only.
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, scan_token, domain, hosts[], count, sources[]}
    """
    domain = (domain or "").strip().lstrip("*.@")
    if not domain or "." not in domain:
        return json.dumps({"status": "BAD_INPUT", "error": "domain required, e.g. example.com"})

    sources: list[str] = []
    hosts: dict[str, None] = {}

    # ponytail: crt.sh removed — rate-limits hard and stalls the whole tool.
    # These 4 free APIs cover the same CT/DNS surface in parallel.
    passive_sources = {
        "certspotter": certspotter_subdomains,
        "hackertarget": hackertarget_subdomains,
        "otx": otx_subdomains,
        "urlscan": urlscan_subdomains,
    }
    wanted = list(passive_sources) if source == "all" else ([source] if source in passive_sources else [])

    if wanted:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=len(wanted)) as pool:
            futures = {name: pool.submit(passive_sources[name], domain) for name in wanted}
            for name, future in futures.items():
                try:
                    for host in future.result():
                        hosts.setdefault(host, None)
                    sources.append(name)
                except Exception:
                    sources.append(f"{name}:error")

    if source in ("subfinder", "all") and resolve("subfinder"):
        from .runner import run

        result = run(
            ["subfinder", "-d", domain, "-silent", "-all", "-recursive"],
            timeout=300,
            binary="subfinder",
        )
        if result.ok:
            for line in result.stdout.splitlines():
                host = line.strip().lstrip("*.")
                if host and host.endswith(domain):
                    hosts.setdefault(host, None)
            sources.append("subfinder")
        else:
            sources.append("subfinder:failed")

    session = store.new(hosts=list(hosts), domain=domain, tool="subdomain_enum")
    return json.dumps(
        {
            "status": "OK",
            "scan_token": session.token,
            "domain": domain,
            "hosts": list(hosts),
            "count": len(hosts),
            "sources": sources,
        }
    )


@mcp.tool()
def dns_resolve(host: str, record_type: str = "A", from_token: str | None = None) -> str:
    """Resolve DNS records for a host.

    Args:
        host: Hostname, e.g. "example.com".
        record_type: A, AAAA, MX, TXT, NS, CNAME, or ALL.
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, scan_token, host, records[]}
    """
    import dns.resolver

    host = (host or "").strip()
    if not host:
        return json.dumps({"status": "BAD_INPUT", "error": "host required"})

    wanted = [r.strip().upper() for r in (record_type or "A").split(",") if r.strip()]
    if "ALL" in wanted:
        wanted = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

    records: list[dict[str, Any]] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    for rtype in wanted:
        try:
            answers = resolver.resolve(host, rtype)
        except Exception:
            continue
        for answer in answers:
            value = answer.to_text().strip('"')
            records.append({"type": rtype, "value": value})

    session = store.new(hosts=[host], records=records, tool="dns_resolve")
    return json.dumps(
        {
            "status": "OK",
            "scan_token": session.token,
            "host": host,
            "records": records,
            "count": len(records),
        }
    )


@mcp.tool()
def http_probe(hosts: list[str] | None = None, from_token: str | None = None) -> str:
    """Probe hosts for live HTTP(S) services.

    Args:
        hosts: List of hostnames/URLs. Required unless from_token is given.
        from_token: Reuse hosts discovered by an earlier call (e.g. subdomain_enum).

    Returns:
        JSON: {status, scan_token, live, probes[{url,status,title,server,technologies}], dead}
    """
    targets = store.resolve_targets(from_token, hosts)
    if not targets:
        return json.dumps(
            {"status": "BAD_INPUT", "error": "supply hosts or a from_token with hosts"}
        )

    result = http_probe(targets)
    if result.get("status") != "OK":
        return json.dumps(result)

    urls = [p.get("url") for p in result.get("probes", []) if p.get("url")]
    session = store.new(urls=urls, hosts=targets, tool="http_probe")
    payload = dict(result)
    payload["scan_token"] = session.token
    return json.dumps(payload)


@mcp.tool()
def tech_detect(url: str, from_token: str | None = None) -> str:
    """Fingerprint web technology behind a URL (httpx tech-detect).

    Args:
        url: Target URL, e.g. "https://example.com".
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, scan_token, url, technologies[], server, title}
    """
    url = normalize_url(url or "")
    if not url:
        return json.dumps({"status": "BAD_INPUT", "error": "url required"})

    result = http_probe([url])
    if result.get("status") != "OK" or not result.get("probes"):
        return json.dumps({"status": "NO_RESPONSE", "error": "target did not respond", "url": url})

    probe = result["probes"][0]
    session = store.new(urls=[url], tool="tech_detect")
    return json.dumps(
        {
            "status": "OK",
            "scan_token": session.token,
            "url": probe.get("url"),
            "technologies": probe.get("technologies", []),
            "server": probe.get("server"),
            "title": probe.get("title"),
            "status_code": probe.get("status"),
        }
    )


@mcp.tool()
def waf_detect(url: str, from_token: str | None = None) -> str:
    """Detect a WAF/CDN in front of a URL from headers and response body.

    Args:
        url: Target URL, e.g. "https://example.com".
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, url, detected, names[], confidence, matches[]}
    """
    import httpx

    url = normalize_url(url or "")
    if not url:
        return json.dumps({"status": "BAD_INPUT", "error": "url required"})

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True, verify=False) as client:
            resp = client.get(url, headers={"User-Agent": "Mozilla/5.0 (pathfinder-mcp)"})
    except httpx.HTTPError as exc:
        return json.dumps({"status": "NO_RESPONSE", "error": str(exc), "url": url})

    headers = {k: v for k, v in resp.headers.items()}
    body = resp.text or ""

    fp = fingerprint_headers(headers)
    for match in fingerprint_body(body).detected:
        fp.add(match.name, match.evidence, match.layer)

    return json.dumps(
        {
            "status": "OK",
            "url": str(resp.url),
            "status_code": resp.status_code,
            **fp.summarize(),
        }
    )


@mcp.tool()
def origin_bypass_check(host: str, from_token: str | None = None) -> str:
    """Check whether a WAF-protected host resolves directly to its origin IP.

    If the A record lands outside known WAF/CDN ranges, the origin is exposed
    and the WAF can be bypassed by hitting that IP with a spoofed Host header.

    Args:
        host: Hostname, e.g. "example.com".
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, host, verdict, ips[], waf, hint}
    """
    host = (host or "").strip()
    if not host:
        return json.dumps({"status": "BAD_INPUT", "error": "host required"})

    ips = resolve_a(host)
    if not ips:
        return json.dumps(
            {
                "status": "NO_DNS",
                "host": host,
                "error": "no A records resolved",
            }
        )

    classifications = {ip: classify_ip(ip) for ip in ips}
    exposed = [ip for ip, waf in classifications.items() if not waf]

    if not exposed:
        verdict = "WAF_PROTECTED"
        hint = (
            "All resolved IPs sit in known WAF/CDN ranges. Try DNS history "
            "(SecurityTrails/dnsdumpster), SPF/DMARC TXT records, or scan the "
            "host's own netblock for a matching service."
        )
    else:
        verdict = "ORIGIN_EXPOSED"
        hint = (
            "Origin IP resolves outside WAF ranges. Reach it directly with a "
            "spoofed Host header: `curl -H 'Host: "
            + host
            + "' https://<origin-ip>/ -k`"
        )

    session = store.new(hosts=[host], ips=ips, tool="origin_bypass_check")
    return json.dumps(
        {
            "status": "OK",
            "scan_token": session.token,
            "host": host,
            "verdict": verdict,
            "ips": ips,
            "classifications": classifications,
            "waf": next((w for w in classifications.values() if w), None),
            "hint": hint,
        }
    )


@mcp.tool()
def wayback_discover(host: str, limit: int = 500, from_token: str | None = None) -> str:
    """Pull historical URLs for a host from the Wayback Machine.

    Args:
        host: Hostname, e.g. "example.com".
        limit: Max URLs to return (default 500).
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, scan_token, host, urls[], count}
    """
    host = (host or "").strip()
    if not host:
        return json.dumps({"status": "BAD_INPUT", "error": "host required"})

    limit = max(1, min(int(limit or 500), 100000))
    urls = wayback_urls(host, limit=limit)

    session = store.new(urls=urls, hosts=[host], tool="wayback_discover")
    return json.dumps(
        {
            "status": "OK",
            "scan_token": session.token,
            "host": host,
            "urls": urls,
            "count": len(urls),
        }
    )


@mcp.tool()
def port_scan(host: str, top_ports: int = 1000, from_token: str | None = None) -> str:
    """nmap top-N port scan of a host.

    Args:
        host: Hostname or IP.
        top_ports: How many common ports to scan (default 1000).
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, host, open_ports[{port,service,version}], count}
    """
    host = (host or "").strip()
    if not host:
        return json.dumps({"status": "BAD_INPUT", "error": "host required"})

    result = port_scan(host, top_ports=top_ports)
    if result.get("status") == "OK":
        session = store.new(hosts=[host], ports=result.get("open_ports", []), tool="port_scan")
        result["scan_token"] = session.token
    return json.dumps(result)


@mcp.tool()
def endpoint_discover(
    url: str, wordlist: str = "raft-small", from_token: str | None = None
) -> str:
    """Fuzz common paths on a URL with ffuf.

    Args:
        url: Base URL, e.g. "https://example.com".
        wordlist: Named list (raft-small, raft-medium, raft-big, common,
                  seclists) or an absolute path to a wordlist file.
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, url, endpoints[{url,status,length,words,input}], count}
    """
    url = normalize_url(url or "")
    if not url:
        return json.dumps({"status": "BAD_INPUT", "error": "url required"})

    result = endpoint_discover(url, wordlist=wordlist)
    if result.get("status") == "OK":
        session = store.new(urls=[url], tool="endpoint_discover")
        result["scan_token"] = session.token
    return json.dumps(result)


@mcp.tool()
def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: list[str] | None = None,
    from_token: str | None = None,
) -> str:
    """Run nuclei templates against a target.

    Args:
        target: URL or host, e.g. "https://example.com".
        templates: Template dirs or IDs, e.g. ["cves", "exposures"].
        severity: Filter by severity, e.g. ["high", "critical"].
        from_token: Optional scan_token from an earlier call.

    Returns:
        JSON: {status, target, findings[{template,name,severity,matched,url}], count}
    """
    target = normalize_url(target or "")
    if not target:
        return json.dumps({"status": "BAD_INPUT", "error": "target required"})

    result = nuclei_scan(target, templates=templates, severity=severity)
    if result.get("status") == "OK":
        session = store.new(urls=[target], tool="nuclei_scan")
        result["scan_token"] = session.token
    return json.dumps(result)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
