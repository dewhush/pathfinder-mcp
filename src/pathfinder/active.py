"""Active recon tools — wrap projectdiscovery CLIs, nmap, ffuf.

Each wrapper resolves its binary and reports MISSING_TOOL on a partial install.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from .runner import resolve, run

WORDBUILDS: dict[str, str] = {
    "raft-small": "/usr/share/wordlists/raft/small.txt",
    "raft-medium": "/usr/share/wordlists/raft/medium.txt",
    "raft-big": "/usr/share/wordlists/raft/big.txt",
    "common": "/usr/share/wordlists/dirb/common.txt",
    "seclists": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
}


@dataclass
class ProbeResult:
    url: str
    status: int
    title: str
    server: str
    content_length: int = 0
    technologies: list[str] = field(default_factory=list)


def parse_httpx(line: str) -> ProbeResult | None:
    """httpx -json emits one JSON object per line."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return ProbeResult(
        url=str(obj.get("url", "")),
        status=int(obj.get("status_code", 0) or 0),
        title=str(obj.get("title", "") or ""),
        server=str(obj.get("webserver", obj.get("server", "")) or ""),
        content_length=int(obj.get("content_length", 0) or 0),
        technologies=[str(t) for t in (obj.get("tech", []) or []) if t],
    )


def http_probe(hosts: list[str], timeout: int = 300) -> dict[str, Any]:
    """Probe hosts for live HTTP(S) services via httpx."""
    if not resolve("httpx"):
        return {"status": "MISSING_TOOL", "error": "httpx", "hint": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}

    alive = [h for h in hosts if h]
    if not alive:
        return {"status": "NO_TARGETS", "error": "no hosts supplied"}

    cmd = [
        "httpx",
        "-json",
        "-silent",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-threads", "20",
        "-timeout", "10",
        "-rl", "150",
        "-no-color",
    ]
    result = run(cmd, timeout=timeout, stdin_data="\n".join(alive), binary=None)
    if result.missing:
        return result.as_error()

    probes: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        probe = parse_httpx(line)
        if probe and probe.url:
            probes.append(probe.__dict__)

    if result.stderr.strip() and not probes:
        return {
            "status": "ERROR",
            "error": result.stderr.strip()[:500],
            "returncode": result.returncode,
        }

    return {
        "status": "OK",
        "live": len(probes),
        "probes": probes,
        "dead": len(alive) - len(probes),
    }


def port_scan(host: str, top_ports: int = 1000, timeout: int = 600) -> dict[str, Any]:
    """nmap top-N port scan."""
    if not resolve("nmap"):
        return {"status": "MISSING_TOOL", "error": "nmap", "hint": "apt install nmap"}

    top_ports = max(10, min(int(top_ports or 1000), 65535))
    cmd = ["nmap", "-sS", "-Pn", "--top-ports", str(top_ports), "-T4", "--open", "-oG", "-", host]
    result = run(cmd, timeout=timeout, binary="nmap")
    if result.missing:
        return result.as_error()

    # nmap -oG format: 22/open/tcp//ssh//OpenSSH 8.9p1/
    ports: list[dict[str, Any]] = []
    for match in re.finditer(r"(\d+)/open/tcp//([^/]*)//([^/]*)", result.stdout):
        port_num, service, version = match.group(1), match.group(2), match.group(3)
        ports.append(
            {
                "port": int(port_num),
                "state": "open",
                "service": service,
                "version": version or None,
            }
        )

    if not ports:
        return {
            "status": "OK",
            "host": host,
            "open_ports": [],
            "note": "no open ports in top-%d" % top_ports,
        }

    return {"status": "OK", "host": host, "open_ports": ports, "count": len(ports)}


def endpoint_discover(
    url: str, wordlist: str = "raft-small", timeout: int = 600
) -> dict[str, Any]:
    """Fuzz common paths with ffuf."""
    if not resolve("ffuf"):
        return {"status": "MISSING_TOOL", "error": "ffuf", "hint": "apt install ffuf"}

    path = WORDBUILDS.get(wordlist)
    if not path:
        path = wordlist  # treat as absolute path
    if not shutil.which("test") and not _file_exists(path):
        return {"status": "MISSING_WORDLIST", "error": path}

    target = url.rstrip("/")
    cmd = [
        "ffuf",
        "-u", f"{target}/FUZZ",
        "-w", path,
        "-mc", "200,204,301,302,307,401,403,405,500",
        "-t", "40",
        "-timeout", "8",
        "-s",
        "-of", "json",
    ]
    result = run(cmd, timeout=timeout, binary="ffuf")
    if result.missing:
        return result.as_error()

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "OK", "url": url, "endpoints": [], "note": "no results"}

    endpoints: list[dict[str, Any]] = []
    for item in report.get("results", []):
        endpoints.append(
            {
                "url": item.get("url"),
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "input": item.get("input", {}).get("FUZZ"),
            }
        )

    return {"status": "OK", "url": url, "endpoints": endpoints, "count": len(endpoints)}


def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: list[str] | None = None,
    timeout: int = 900,
) -> dict[str, Any]:
    """Run nuclei templates against a target."""
    if not resolve("nuclei"):
        return {"status": "MISSING_TOOL", "error": "nuclei", "hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

    cmd = ["nuclei", "-json", "-silent", "-no-color", "-u", target]
    if templates:
        cmd.extend(["-t", ",".join(templates)])
    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    result = run(cmd, timeout=timeout, binary="nuclei")
    if result.missing:
        return result.as_error()

    findings: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            findings.append(
                {
                    "template": obj.get("template-id") or obj.get("templateID"),
                    "name": obj.get("info", {}).get("name") if isinstance(obj.get("info"), dict) else None,
                    "severity": obj.get("info", {}).get("severity") if isinstance(obj.get("info"), dict) else None,
                    "matched": obj.get("matched-at") or obj.get("matched"),
                    "url": obj.get("url") or target,
                    "type": obj.get("type"),
                    "extracted": obj.get("extracted-results"),
                }
            )

    return {
        "status": "OK",
        "target": target,
        "findings": findings,
        "count": len(findings),
        "note": "clean — no template matches" if not findings else None,
    }


def _file_exists(path: str) -> bool:
    import os

    return os.path.isfile(path)
