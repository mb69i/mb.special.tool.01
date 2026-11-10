#!/usr/bin/env python3
"""scanner.py - small async TCP port + web header scanner. Stdlib only, Python 3.9+.

    python scanner.py example.com                 # top ports + web checks
    python scanner.py 10.0.0.5 -p 1-1024,8080     # custom ports
    python scanner.py host1 host2 -p all --json   # many hosts, JSON out

Only scan hosts you own or have written permission to test.
"""
import argparse
import asyncio
import http.client
import json
import socket
import ssl
import sys
import time

TOP = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
       1433, 1521, 1883, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900,
       5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 15672, 27017]
HTTP = {80, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 15672}
HTTPS = {443, 8443}
RISK = {21: "FTP: plaintext passwords", 23: "Telnet: plaintext, disable it",
        135: "RPC exposed", 445: "SMB exposed", 1433: "MSSQL exposed",
        2375: "Docker API without TLS = remote root", 3306: "MySQL exposed",
        3389: "RDP exposed (brute-force target)", 5432: "Postgres exposed",
        5900: "VNC exposed", 6379: "Redis often has no auth", 9200: "Elasticsearch exposed",
        11211: "Memcached exposed", 27017: "MongoDB exposed"}
WANT = {"content-security-policy": "CSP", "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}


def svc(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "https" if port in HTTPS else "http" if port in HTTP else "?"


async def probe(ip, port, timeout):
    """TCP connect + short passive banner grab. Returns None if closed/filtered."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    banner = ""
    try:
        data = await asyncio.wait_for(r.read(128), 0.5)
        line = (data.decode("latin-1").strip().splitlines() or [""])[0]
        banner = "".join(c if c.isprintable() else "." for c in line)[:70]
    except (OSError, asyncio.TimeoutError):
        pass
    w.close()
    try:
        await w.wait_closed()
    except OSError:
        pass
    return {"port": port, "service": svc(port), "banner": banner, "risk": RISK.get(port, "")}


def web_check(host, port, tls):
    """One GET / (no redirects, no body). Flags missing security headers and weak cookies."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # scanner: accept self-signed
            c = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
        else:
            c = http.client.HTTPConnection(host, port, timeout=5)
        try:
            c.connect()
            ver = c.sock.version() if tls else ""
            c.request("GET", "/", headers={"User-Agent": "scanner.py", "Connection": "close"})
            r = c.getresponse()
            hdr = r.getheaders()
        finally:
            c.close()
    except (OSError, http.client.HTTPException) as e:
        return {"error": str(e)[:80]}
    h = {k.lower(): v for k, v in hdr}
    issues = []
    if not (300 <= r.status < 400 and not tls):  # plain-HTTP redirects: nothing to judge
        issues = [f"missing {n}" for k, n in WANT.items() if k not in h]
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            issues.append("missing X-Frame-Options")
        if tls and "strict-transport-security" not in h:
            issues.append("missing HSTS")
        if not tls:
            issues.append("served over plain HTTP")
        for k, v in hdr:
            if k.lower() == "set-cookie":
                attrs = {a.strip().lower() for a in v.split(";")[1:]}
                bad = [f for f, ok in (("HttpOnly", "httponly" in attrs),
                                       ("Secure", "secure" in attrs or not tls)) if not ok]
                if bad:
                    issues.append(f"cookie {v.split('=')[0]}: no {'/'.join(bad)}")
    return {"status": r.status, "server": h.get("server", ""), "powered_by": h.get("x-powered-by", ""),
            "location": h.get("location", ""), "tls": ver, "issues": issues}


async def run(target, a):
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        print(f"cannot resolve {target}", file=sys.stderr)
        return None
    ip, ports, found, done, t0 = infos[0][4][0], a.ports, [], 0, time.time()
    it = iter(ports)  # shared iterator: bounded memory, even for -p all

    async def worker():
        nonlocal done
        for p in it:
            r = await probe(ip, p, a.timeout)
            if r:
                found.append(r)
            done += 1
            if len(ports) > 2000 and done % 2000 == 0:
                print(f"  {done}/{len(ports)}", file=sys.stderr, flush=True)

    await asyncio.gather(*(worker() for _ in range(min(a.concurrency, len(ports)))))
    found.sort(key=lambda r: r["port"])
    if not a.no_web:
        webs = [r for r in found if r["port"] in HTTP | HTTPS]
        res = await asyncio.gather(*(asyncio.to_thread(web_check, target, r["port"], r["port"] in HTTPS)
                                     for r in webs))
        for r, w in zip(webs, res):
            r["web"] = w
    return {"target": target, "ip": ip, "scanned": len(ports),
            "seconds": round(time.time() - t0, 1), "open": found}


def show(d):
    print(f"\n== {d['target']} ({d['ip']}) | {d['scanned']} ports, {d['seconds']}s, {len(d['open'])} open ==")
    for r in d["open"]:
        print(f"{r['port']:<7}{r['service']:<13}{r['banner']}")
        if r["risk"]:
            print(f"       ! {r['risk']}")
        w = r.get("web")
        if not w:
            continue
        if "error" in w:
            print(f"       web error: {w['error']}")
            continue
        loc = "-> " + w["location"] if w["location"] else ""
        info = " ".join(x for x in (w["server"], w["powered_by"], w["tls"], loc) if x)
        print(f"       HTTP {w['status']} {info}".rstrip())
        for i in w["issues"]:
            print(f"       - {i}")


def ports_arg(s):
    try:
        if s == "top":
            return TOP
        if s == "all":
            return list(range(1, 65536))
        out = set()
        for part in s.split(","):
            lo, _, hi = part.partition("-")
            out.update(range(max(1, int(lo)), min(65535, int(hi or lo)) + 1))
        if not out:
            raise ValueError
        return sorted(out)
    except ValueError:
        raise argparse.ArgumentTypeError("use top, all, or e.g. 22,80,8000-8100")


def main():
    ap = argparse.ArgumentParser(description="Small async port + web header scanner. Authorized targets only.")
    ap.add_argument("targets", nargs="+", help="hostnames or IPs")
    ap.add_argument("-p", "--ports", type=ports_arg, default=TOP, help="top (default), all, or 22,80,8000-8100")
    ap.add_argument("-c", "--concurrency", type=int, default=300, help="parallel connects (default 300)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    ap.add_argument("--no-web", action="store_true", help="skip HTTP header checks")
    ap.add_argument("--json", action="store_true", help="JSON output")
    a = ap.parse_args()
    print("Scan only hosts you own or have written permission to test.", file=sys.stderr)

    async def go():
        out = []
        for t in a.targets:
            d = await run(t, a)
            if d:
                out.append(d)
        return out

    out = asyncio.run(go())
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        for d in out:
            show(d)


if __name__ == "__main__":
    main()
