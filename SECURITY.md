# Security Policy

## Scope of use

Pathfinder is offensive recon tooling. Run it **only against infrastructure
you own or are explicitly authorized to test**. Unauthorized scanning,
probing, or exploitation of third-party systems is out of scope and is not
condoned by this project.

## Supported versions

| Version | Supported |
| ------- | --------- |
| v0.1.x  | Yes       |
| < v0.1  | No        |

Only the latest release line receives security fixes.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Please report it privately via [GitHub Security Advisories / private
vulnerability reporting](https://github.com/dewhush/pathfinder-mcp/security/advisories/new)
for this repository. Include:

- a description of the vulnerability and its impact;
- steps to reproduce (commands, configuration, and versions used);
- the affected version or commit, if known.

## What happens next

1. The report is reviewed and confirmed.
2. A fix is prepared and released.
3. The advisory is published (with credit to the reporter, if they wish)
once the fix is available.

## Out of scope

- Vulnerabilities that require running Pathfinder against a target you do
  not own or are not authorized to test.
- Findings in third-party tools Pathfinder wraps (subfinder, httpx, nmap,
  ffuf, nuclei) — report those to the respective upstream projects.
- Reports based on automated scanner output without a demonstrated impact
  on Pathfinder itself.
