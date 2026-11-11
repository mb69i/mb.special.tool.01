# scanner.py

A small async TCP port scanner with web and TLS checks. One file, Python 3.9+, no dependencies.

> Only scan hosts you own or have written permission to test.

## Usage

```
python scanner.py example.com                  # top 44 ports + web/TLS checks
python scanner.py https://example.com/         # a URL works too
python scanner.py 10.0.0.0/24 -p 22,80,443     # CIDR range, custom ports
python scanner.py host1 host2 -p all --json    # several hosts, all ports, JSON
```

| Option | Meaning |
|---|---|
| `-p` | `top` (default), `all`, or a list such as `22,80,8000-8100` |
| `-c` | parallel connections (default 300) |
| `-t` | connect timeout in seconds (default 1.0) |
| `--no-web` | skip the web and TLS checks |
| `--json` | machine-readable output |

## What it reports

- **Open ports**, with the service name and any banner the service sends.
- **Risky exposed services** such as Telnet, RDP, Redis, databases and the Docker API.
- **Web servers on any open port**, not just the usual ones. HTTPS and HTTP are detected automatically.
- **Security headers**, checked for sensible values and not just presence: CSP, HSTS,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options.
- **Cookies** set without `HttpOnly` or `Secure`.
- **TLS certificates**: not trusted, wrong host name, expired, or expiring within 30 days.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan finished, nothing flagged |
| 1 | findings: a risky exposed service, or a web or TLS issue |
| 2 | error or incomplete scan: bad arguments, a target that did not resolve, no route to a target, or ports that could not be tested |

## How the checks behave

- Every open port that stays silent on connect gets one plain HTTP request and, if needed, one TLS
  handshake. Ports whose service announces itself (SSH, FTP, SMTP and so on) are left alone, and raw
  printer ports 9100-9107 are never probed, because they print whatever they receive.
- Redirects are followed for up to 5 hops, on the same host only. The final page is the one judged.
  A redirect to another host is reported and not followed, so the scan stays on your target.
- With a host name target, the certificate must be valid for that name. With an IP target the name
  check is skipped, since it would always fail.
- Every address a host name resolves to is scanned. An address this machine cannot route to
  (for example IPv6 on an IPv4-only network) is reported as such instead of "0 open".
- Concurrency is lowered automatically to fit the system's open-file limit, and a port is never
  reported closed because the scanner itself ran out of sockets.

## Limits

- TCP connect scan only: no UDP, no SYN scan, no version or OS fingerprinting.
- Only open ports are listed. Closed and filtered ports are not told apart in the output.
- CIDR ranges are capped at 65,536 addresses.
- Header checks cover the response to one request per site. They are a quick review, not a full audit.

## Tests

```
python -m unittest -v
```

The TLS tests need the `openssl` command and are skipped without it.
