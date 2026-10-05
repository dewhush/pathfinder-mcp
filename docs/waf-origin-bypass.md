# WAF origin bypass via direct IP

If a site sits behind a Cloudflare/Akamai/AWS WAF, its real origin server is
still reachable — as long as you can learn its IP. Pathfinder's
`origin_bypass_check` tool automates the check.

## The idea

A WAF works by proxying traffic: DNS for `example.com` points at the WAF,
which forwards to the origin. Nothing stops a client from connecting directly
to the origin IP and simply *claiming* to be `example.com` via the
`Host` header. HTTP/1.1 virtual hosting trusts that header.

```
client -> DNS(example.com) -> 104.16.1.1 (Cloudflare) -> origin 203.0.113.10
client -----------------------------------------------> 203.0.113.10  Host: example.com
```

The second path skips the WAF entirely: no rate limiting, no WAF rules, no
bot challenge.

## Finding the origin

1. **Current DNS** — sometimes the A record is the origin and the WAF only
   covers `www`. `origin_bypass_check` resolves the host and compares every IP
   against known WAF/CDN ranges; anything outside them is reported as
   `ORIGIN_EXPOSED`.
2. **DNS history** — SecurityTrails, DNSDumpster, VirusTotal passive DNS.
   Look for an A record from before the site moved behind the WAF.
3. **SPF / DMARC TXT records** — mail servers usually live on the origin or
   in the same netblock. `dns_resolve` with `record_type="TXT, MX"` is a good
   first move.
4. **Subdomains** — `api.`, `dev.`, `staging.`, `mail.`, `direct.` often point
   straight at the origin and are rarely proxied. Chain `subdomain_enum` ->
   `origin_bypass_check` over each result.

## Exploiting it

```bash
curl -H "Host: example.com" https://203.0.113.10/ -k
curl -H "Host: example.com" http://203.0.113.10/ -k
```

`-k` because the origin's cert will not match the IP you connected to. Some
origins validate the Host header against an allowlist; try the bare domain,
`www.example.com`, and the origin's own hostname.

If TLS SNI matters:

```bash
curl -H "Host: example.com" --resolve example.com:443:203.0.113.10 https://example.com/ -k
```

## Pathfinder chain

```
1. subdomain_enum(domain="example.com")            -> 87 hosts, token=abc123
2. http_probe(from_token="abc123")                 -> 9 live,   token=def456
3. origin_bypass_check(host="dev.example.com")     -> ORIGIN_EXPOSED 203.0.113.10
4. nuclei_scan(target="https://203.0.113.10", templates=["cves", "exposures"])
```

## Defense

- Put the origin in a private subnet and publish only through the WAF.
- Restrict the origin's security group / firewall to the WAF's egress ranges
  only. This is the fix that actually works; Host-header checks are bypassable.
