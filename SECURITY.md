# Security Policy

## Reporting a Vulnerability

This project is an offensive-security tool intended for authorized testing
only. If you discover a vulnerability in pathfinder-mcp itself (not in a
target you are authorized to test), please report it privately:

- Email: dewhush@users.noreply.github.com
- GitHub Security Advisories: https://github.com/dewhush/pathfinder-mcp/security/advisories

Do **not** open a public issue for security-sensitive findings.

## Scope

pathfinder-mcp ships recon tooling that executes third-party commands
(subfinder, httpx, nuclei, naabu, …) against user-supplied targets. It is
the operator's responsibility to ensure they have authorization before
running any tool against a target.

## Supported Versions

Only the latest release line receives security fixes.
