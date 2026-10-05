# pathfinder-mcp

> MCP server exposing offensive recon tooling to LLM agents — Claude Code, OpenCode, Codex, Hermes, any MCP client.

Pathfinder wraps the recon CLI tools security researchers already use (subfinder, httpx, nmap, ffuf, nuclei) into a single MCP server, so an LLM agent can plan and execute reconnaissance itself — not just tell you which commands to run.

- [x] Phase 1: passive subdomain enum, DNS, WAF detection, tech fingerprint, wayback discovery
- [x] Phase 2: active port scan, origin-bypass checks, nuclei templates
- [x] Phase 3: session state — the agent chains outputs across tools (`scan_result` tokens) instead of re-parsing raw text
- [ ] Phase 4: HTML/JSON report export, target diffing (today vs. yesterday)

## Quick start

```bash
git clone https://github.com/dewhush/pathfinder-mcp.git
cd pathfinder-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Requirements

Pathfinder wraps these CLIs. It degrades gracefully — a tool that can't find its binary reports `MISSING_TOOL` rather than crashing. Install the ones you want:

| Tool | Used by | Install |
| ---- | ------- | ------- |
| subfinder | `subdomain_enum` | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `http_probe`, `tech_detect`, `waf_detect` | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nmap | `port_scan` | `apt install nmap` |
| ffuf | `endpoint_discover` | `apt install ffuf` or `go install github.com/ffuf/ffuf/v2@latest` |
| nuclei | `nuclei_scan` | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

No external API keys required. Everything is local or free public APIs (crt.sh, Wayback).

## Connect to your agent

**Claude Code:**

```bash
claude mcp add pathfinder -- python -m pathfinder.server
```

**Hermes:**

```bash
hermes mcp add pathfinder --command "python -m pathfinder.server"
```

**OpenCode / Codex / other MCP clients:** add to your config:

```json
{
  "mcpServers": {
    "pathfinder": {
      "command": "python",
      "args": ["-m", "pathfinder.server"]
    }
  }
}
```

> Scope: Pathfinder is a tool-wrapper. You are responsible for running it only against infrastructure you own or are authorized to test.

## Tools

### Passive

**`subdomain_enum`** — passive subdomain enumeration (crt.sh + subfinder if present).

```
subdomain_enum(domain="example.com", source="all")
subdomain_enum(domain="example.com", source="crtsh")
```

**`dns_resolve`** — A / AAAA / MX / TXT / NS / CNAME records for a host.

```
dns_resolve(host="example.com", record_type="A")
```

**`tech_detect`** — web technology fingerprint via httpx.

```
tech_detect(url="https://example.com")
```

**`wayback_discover`** — historical URLs from the Wayback Machine for a host.

```
wayback_discover(host="example.com", limit=500)
```

### Active

**`http_probe`** — probe a list of hosts for live HTTP(S) services.

```
http_probe(hosts=["sub.example.com", "api.example.com"])
```

**`port_scan`** — nmap top-N ports on a host.

```
port_scan(host="example.com", top_ports=1000)
```

**`waf_detect`** — WAF/CDN identification from response headers, TLS cert, and WAF fingerprints (Cloudflare, Akamai, AWS, Sucuri, Imperva, Cloudfront).

```
waf_detect(url="https://example.com")
```

**`origin_bypass_check`** — check whether a WAF-protected host resolves directly to its origin IP, bypassing the WAF. Resolves the host, compares the IP against known WAF/CDN ranges, and reports `ORIGIN_EXPOSED` / `WAF_PROTECTED` / `UNKNOWN`.

```
origin_bypass_check(host="example.com")
```

This is the technique documented in [WAF origin bypass via direct IP access](docs/waf-origin-bypass.md). If a host reports `ORIGIN_EXPOSED`, the origin IP can be reached directly with a spoofed `Host` header:

```
curl -H "Host: example.com" https://<origin-ip>/
```

**`endpoint_discover`** — fuzz common paths with ffuf.

```
endpoint_discover(url="https://example.com", wordlist="raft-small")
```

Built-in wordlists: `raft-small` (default), `raft-medium`, `raft-big`, `common`, `seclists` (expects `/usr/share/seclists`). Use `wordlist="/abs/path"` for a custom file.

**`nuclei_scan`** — run nuclei templates against a target.

```
nuclei_scan(target="https://example.com", templates=["cves", "exposures"])
nuclei_scan(target="https://example.com", severity=["high", "critical"])
```

## Session chaining

Every tool returns structured JSON plus a `scan_token`. Pass it back into any other tool as `from_token` — Pathfinder resolves the token to the relevant hosts/URLs from the current session, so the agent chains steps without you re-typing targets:

```
1. subdomain_enum(domain="example.com")      → scan_token=abc123, 42 hosts
2. http_probe(from_token="abc123")           → scan_token=def456, 7 live
3. waf_detect(from_token="def456")           → 1 origin exposed
4. origin_bypass_check(from_token="def456")  → origin IP confirmed
```

Sessions are per-process and in-memory — nothing leaves the machine.

## Development

```bash
pip install -e ".[dev]"
pytest                       # unit tests, no network, all tools mocked
ruff check src tests
ruff format src tests
```

## License

MIT — [0xDew](https://github.com/dewhush). Authorized use only.
