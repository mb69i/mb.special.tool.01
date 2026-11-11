#!/usr/bin/env python3
"""scanner.py - small async TCP port scanner with web and TLS checks. Stdlib only, Python 3.9+.

    python scanner.py example.com                  # top ports + web/TLS checks
    python scanner.py https://example.com/         # a URL works too
    python scanner.py 10.0.0.0/24 -p 22,80,443     # CIDR range, custom ports
    python scanner.py host1 host2 -p all --json    # many hosts, JSON out

Exit codes: 0 nothing flagged, 1 findings, 2 error or incomplete scan.
Only scan hosts you own or have written permission to test.
"""
import argparse
import asyncio
import errno
import functools
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

TOP = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
       1433, 1521, 1883, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900,
       5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 15672, 27017]
RISK = {21: "FTP: plaintext passwords", 23: "Telnet: plaintext, disable it",
        135: "RPC exposed", 445: "SMB exposed", 1433: "MSSQL exposed",
        2375: "Docker API without TLS = remote root", 3306: "MySQL exposed",
        3389: "RDP exposed (brute-force target)", 5432: "Postgres exposed",
        5900: "VNC exposed", 6379: "Redis often has no auth", 9200: "Elasticsearch exposed",
        11211: "Memcached exposed", 27017: "MongoDB exposed"}
TLS_FIRST = {443, 8443}                    # try TLS before plain HTTP on these ports
WEB_HINT = TLS_FIRST | {80, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 15672}
NO_PROBE = set(range(9100, 9108))          # raw printer ports print whatever they are sent
REDIRECT = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 5
MAX_HOSTS = 65536                          # largest CIDR range accepted
SOON_DAYS = 30                             # warn when a certificate expires within this
HSTS_MIN = 180 * 86400
BUSY = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM}
NO_ROUTE = {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL}
REFERRER = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
UA = "scanner.py"


class TlsOnly(Exception):
    """The port completed a TLS handshake but does not speak HTTP. args: (version, cert issues)."""


# ---------------------------------------------------------------- port scan

def svc(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "https" if port in TLS_FIRST else "http" if port in WEB_HINT else "?"


def fd_budget(want):
    """Keep concurrency under the open-file limit, raising the limit first when allowed."""
    try:
        import resource
    except ImportError:                    # Windows has no such limit to manage
        return want
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return want
    need = want + 64
    if soft < need:
        goal = need if hard == resource.RLIM_INFINITY else min(need, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (goal, hard))
            soft = goal
        except (ValueError, OSError):
            pass
    return max(1, min(want, soft - min(64, soft // 2)))


async def probe(ip, port, timeout):
    """TCP connect + short passive banner grab.
    -> (state, record); state is open, closed, filtered, unreachable or error."""
    for attempt in range(6):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            break
        except (asyncio.TimeoutError, TimeoutError):
            return "filtered", None
        except OSError as e:
            if e.errno in BUSY:            # out of sockets: wait and retry, never call it closed
                await asyncio.sleep(0.2 * (attempt + 1))
            elif e.errno in NO_ROUTE:
                return "unreachable", None
            else:
                return "closed", None
    else:
        return "error", None
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
    return "open", {"port": port, "service": svc(port), "banner": banner, "risk": RISK.get(port, "")}


async def scan(addrs, conc, timeout):
    """Probe every (address, port) pair with a shared pool of workers."""
    total = sum(len(a["ports"]) for a in addrs)
    pairs = ((a, p) for a in addrs for p in a["ports"])   # lazy: bounded memory for big scans
    done = 0

    async def worker():
        nonlocal done
        for a, p in pairs:
            a.setdefault("t0", time.time())
            state, rec = await probe(a["ip"], p, timeout)
            if rec:
                a["open"].append(rec)
            else:
                a["n"][state] += 1
            a["t1"] = time.time()
            done += 1
            if total > 2000 and done % 2000 == 0:
                print(f"  {done}/{total}", file=sys.stderr, flush=True)

    await asyncio.gather(*(worker() for _ in range(max(1, min(conc, total)))))
    for a in addrs:
        a["open"].sort(key=lambda r: r["port"])


# ---------------------------------------------------------------- TLS

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=None)
def tls_context(verify, by_ip):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    elif by_ip:
        ctx.check_hostname = False         # scanned by IP: a name mismatch would always fire
    return ctx


def der_not_after(der):
    """Expiry time (epoch seconds) of a DER-encoded X.509 certificate, or None."""
    def tlv(i):                            # -> tag, value start, value end
        tag, n, i = der[i], der[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            n, i = int.from_bytes(der[i:i + k], "big"), i + k
        return tag, i, i + n

    try:
        _, start, _ = tlv(0)               # Certificate
        _, start, _ = tlv(start)           # tbsCertificate
        tag, _, end = tlv(start)
        if tag == 0xA0:                    # optional [0] version, then serialNumber
            _, _, end = tlv(end)
        _, _, end = tlv(end)               # signature algorithm
        _, _, end = tlv(end)               # issuer
        _, start, _ = tlv(end)             # validity
        _, _, end = tlv(start)             # notBefore
        tag, start, end = tlv(end)         # notAfter
        fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
        when = datetime.strptime(der[start:end].decode("ascii"), fmt)
        return when.replace(tzinfo=timezone.utc).timestamp()
    except (IndexError, ValueError):
        return None


def cert_issues(why, not_after, now):
    """why: verification error text or None. not_after: epoch seconds or None."""
    out = []
    expired = bool(why) and "expired" in why
    if why and not expired:
        out.append(f"certificate not trusted: {why.rstrip('.')}")
    left = None if not_after is None else not_after - now
    if expired or (left is not None and left < 0):
        ago = int(-left // 86400) if left is not None and left < 0 else 0
        out.append("certificate expired" + (f" {ago} day(s) ago" if ago else ""))
    elif left is not None and left < SOON_DAYS * 86400:
        days = int(left // 86400)
        out.append(f"certificate expires in {days} day(s)" if days else "certificate expires in less than a day")
    return out


def tls_open(host, ip, port):
    """TLS handshake that also checks the certificate. -> (socket, issues).
    Raises ssl.SSLError / OSError when the port does not speak TLS."""
    name = None if is_ip(host) else host
    raw = socket.create_connection((ip, port), timeout=4)
    try:
        s = tls_context(True, name is None).wrap_socket(raw, server_hostname=name)
        why = None
        try:
            not_after = ssl.cert_time_to_seconds(s.getpeercert()["notAfter"])
        except (KeyError, TypeError, ValueError):
            not_after = None
    except ssl.SSLCertVerificationError as e:
        raw.close()
        why = e.verify_message
        raw = socket.create_connection((ip, port), timeout=4)
        try:
            s = tls_context(False, False).wrap_socket(raw, server_hostname=name)
        except BaseException:
            raw.close()
            raise
        not_after = der_not_after(s.getpeercert(binary_form=True) or b"")
    except BaseException:
        raw.close()
        raise
    return s, cert_issues(why, not_after, time.time())


# ---------------------------------------------------------------- web

def csp_issues(csp):
    d = {}
    for part in csp.split(";"):
        toks = part.split()
        if toks:
            d.setdefault(toks[0].lower(), [t.lower() for t in toks[1:]])
    src = d.get("script-src", d.get("default-src"))
    if src is None:
        return ["CSP does not restrict scripts (no script-src or default-src)"]
    out = []
    pinned = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in src)
    if "'unsafe-inline'" in src and not pinned:    # browsers ignore it once a nonce or hash is set
        out.append("CSP allows inline scripts ('unsafe-inline')")
    if "'unsafe-eval'" in src:
        out.append("CSP allows eval ('unsafe-eval')")
    if any(t in ("*", "http:", "https:") for t in src) and "'strict-dynamic'" not in src:
        out.append("CSP allows scripts from any origin")
    return out


def judge(headers, tls):
    """Security findings for one final HTTP response. headers: list of (name, value)."""
    h = {k.lower(): v.strip() for k, v in headers}
    out = []
    csp = h.get("content-security-policy")
    out += ["missing CSP"] if csp is None else csp_issues(csp)

    v = h.get("x-content-type-options")
    if v is None:
        out.append("missing X-Content-Type-Options")
    elif v.lower() != "nosniff":
        out.append("X-Content-Type-Options is not nosniff")

    v = h.get("referrer-policy")
    if v is None:
        out.append("missing Referrer-Policy")
    else:
        ok = [t for t in (x.strip().lower() for x in v.split(",")) if t in REFERRER]
        if not ok:
            out.append("Referrer-Policy has no valid value")
        elif ok[-1] == "unsafe-url":
            out.append("Referrer-Policy is unsafe-url (leaks full URLs)")

    v = h.get("permissions-policy")
    if v is None:
        out.append("missing Permissions-Policy")
    elif not v:
        out.append("Permissions-Policy is empty")

    if "frame-ancestors" not in (csp or "").lower():
        v = h.get("x-frame-options")
        if v is None:
            out.append("missing X-Frame-Options")
        elif v.upper() not in ("DENY", "SAMEORIGIN"):
            out.append("X-Frame-Options is not DENY or SAMEORIGIN")

    if tls:
        v = h.get("strict-transport-security")
        if v is None:
            out.append("missing HSTS")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
            if not m:
                out.append("HSTS has no max-age")
            elif int(m.group(1)) == 0:
                out.append("HSTS is switched off (max-age=0)")
            elif int(m.group(1)) < HSTS_MIN:
                out.append(f"HSTS max-age is short ({int(m.group(1)) // 86400} days, use 180+)")
    else:
        out.append("served over plain HTTP")

    for k, v in headers:
        if k.lower() == "set-cookie":
            attrs = {x.strip().lower() for x in v.split(";")[1:]}
            bad = [f for f, ok in (("HttpOnly", "httponly" in attrs),
                                   ("Secure", "secure" in attrs or not tls)) if not ok]
            if bad:
                out.append(f"cookie {v.split('=')[0].strip()}: no {'/'.join(bad)}")
    return out


def make_url(tls, host, port, path):
    name = f"[{host}]" if ":" in host else host
    if port != (443 if tls else 80):
        name += f":{port}"
    return f"{'https' if tls else 'http'}://{name}{path}"


def request(host, ip, port, tls, path):
    """One GET on a fresh connection to ip:port, with Host/SNI set to host."""
    if tls:
        sock, certs = tls_open(host, ip, port)
        ver = sock.version() or "TLS"
    else:
        sock, certs, ver = socket.create_connection((ip, port), timeout=4), [], ""
    c = http.client.HTTPConnection(host, port)
    c.sock = sock
    try:
        c.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", make_url(tls, host, port, "").split("://", 1)[1])
        c.putheader("User-Agent", UA)
        c.putheader("Accept", "*/*")
        c.putheader("Connection", "close")
        c.endheaders()
        r = c.getresponse()
        return {"tls": tls, "ver": ver, "status": r.status, "headers": r.getheaders(), "certs": certs}
    except (OSError, http.client.HTTPException) as e:
        if tls:
            raise TlsOnly(ver, certs) from e
        raise
    finally:
        c.close()


def web_check(host, ip, port):
    """Find out whether an open port speaks HTTPS or HTTP, follow same-host redirects,
    and judge the final response. -> result dict, or None when the port is not a web service."""
    order = (True, False) if port in TLS_FIRST else (False, True)
    hop = fallback = err = None
    for tls in order:
        try:
            got = request(host, ip, port, tls, "/")
        except TlsOnly as e:
            return {"url": "", "status": None, "server": "", "powered_by": "", "tls": e.args[0],
                    "redirects": [], "note": "", "issues": e.args[1]}
        except (OSError, http.client.HTTPException) as e:
            err = e
            continue
        if not tls and got["status"] == 400 and not order[0]:
            fallback = got                 # a TLS port may answer plain HTTP with 400: try TLS too
            continue
        hop = got
        break
    hop = hop or fallback
    if hop is None:
        return {"error": str(err)[:80]} if port in WEB_HINT else None

    url = make_url(hop["tls"], host, port, "/")
    certs, chain, note, loop = list(hop["certs"]), [], "", False
    while hop["status"] in REDIRECT:
        loc = next((v for k, v in hop["headers"] if k.lower() == "location"), "")
        if not loc:
            break
        nxt = urlsplit(urljoin(url, loc))
        if nxt.scheme not in ("http", "https") or (nxt.hostname or "").lower() != host.lower():
            note = f"redirects to another host (not followed): {nxt.geturl()[:120]}"
            break
        target = nxt._replace(fragment="").geturl()
        if len(chain) >= MAX_REDIRECTS or target == url or target in chain:
            loop = True
            break
        tls = nxt.scheme == "https"
        try:
            got = request(host, ip, nxt.port or (443 if tls else 80), tls,
                          (nxt.path or "/") + ("?" + nxt.query if nxt.query else ""))
        except (OSError, http.client.HTTPException, TlsOnly, ValueError) as e:
            note = f"redirect to {target[:120]} failed: {str(e)[:60]}"
            break
        chain.append(url)
        url, hop = target, got
        certs += [c for c in got["certs"] if c not in certs]

    h = {k.lower(): v for k, v in hop["headers"]}
    issues = certs + ([] if hop["status"] in REDIRECT else judge(hop["headers"], hop["tls"]))
    if loop:
        issues.append("redirect loop")
    return {"url": url, "status": hop["status"], "server": h.get("server", ""),
            "powered_by": h.get("x-powered-by", ""), "tls": hop["ver"],
            "redirects": chain, "note": note, "issues": issues}


def final_port(w):
    u = urlsplit(w["url"])
    return u.port or (443 if u.scheme == "https" else 80)


def link_ports(e):
    """A port that only redirects to another checked port points there instead of repeating it."""
    own = {r["port"] for r in e["open"]
           if r.get("web") and r["web"].get("status") is not None and final_port(r["web"]) == r["port"]}
    for r in e["open"]:
        w = r.get("web")
        if w and w.get("status") is not None and w["redirects"]:
            if final_port(w) != r["port"] and final_port(w) in own:
                w["see_port"], w["issues"] = final_port(w), []


async def web_phase(addrs):
    def safe(host, ip, port):
        try:
            return web_check(host, ip, port)
        except Exception as e:             # one odd server must not sink the whole scan
            return {"error": f"{type(e).__name__}: {e}"[:80]}

    jobs = [(a, r) for a in addrs for r in a["open"]
            if r["port"] not in NO_PROBE and (not r["banner"] or r["banner"].startswith("HTTP/"))]
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=32) as pool:
        res = await asyncio.gather(*(loop.run_in_executor(pool, safe, a["host"], a["ip"], r["port"])
                                     for a, r in jobs))
    for (a, r), w in zip(jobs, res):
        if w:
            r["web"] = w
            if r["service"] == "?" and "error" not in w:
                r["service"] = "tls" if w["status"] is None else "https" if w["tls"] else "http"
    for a in addrs:
        link_ports(a)


# ---------------------------------------------------------------- targets, output

def parse_target(t):
    """-> (label, hosts, extra port or None, is_range). Raises ValueError."""
    if "://" in t:
        u = urlsplit(t)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"not a usable URL: {t}")
        return t, [u.hostname], u.port or (443 if u.scheme == "https" else 80), False
    if "/" in t:
        net = ipaddress.ip_network(t, strict=False)
        if net.num_addresses > MAX_HOSTS:
            raise ValueError(f"{t} holds {net.num_addresses} addresses, the limit is {MAX_HOSTS}")
        return t, [str(h) for h in net.hosts()] or [str(net.network_address)], None, True
    return t, [t], None, False


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


async def run(a):
    loop = asyncio.get_running_loop()
    addrs, groups, bad = [], [], []
    for label, hosts, extra, is_range in a.parsed:
        ports = sorted(set(a.ports) | ({extra} if extra else set()))
        group = {"label": label, "range": is_range, "addrs": []}
        for h in hosts:
            if is_ip(h):
                ips = [h]
            else:
                try:
                    infos = await loop.getaddrinfo(h, None, type=socket.SOCK_STREAM)
                except socket.gaierror:
                    print(f"cannot resolve {h}", file=sys.stderr)
                    bad.append(label)
                    continue
                ips = list(dict.fromkeys(i[4][0] for i in infos))   # every address, not just the first
            for ip in ips:
                e = {"target": label, "host": h, "ip": ip, "ports": ports, "open": [],
                     "n": dict.fromkeys(("closed", "filtered", "unreachable", "error"), 0)}
                group["addrs"].append(e)
                addrs.append(e)
        groups.append(group)
    await scan(addrs, a.conc, a.timeout)
    if not a.no_web:
        await web_phase(addrs)
    return groups, bad


def finish(e):
    """Internal entry -> public result."""
    return {"target": e["target"], "ip": e["ip"], "scanned": len(e["ports"]),
            "seconds": round(e.get("t1", 0) - e.get("t0", 0), 1), "open": e["open"],
            "untested": e["n"]["error"],
            "unreachable": bool(e["ports"]) and e["n"]["unreachable"] == len(e["ports"])}


def show(d):
    head = f"\n== {d['target']} ({d['ip']}) | "
    if d["unreachable"]:
        print(head + "no route to this address from here, not scanned ==")
        return
    extra = f", {d['untested']} untested" if d["untested"] else ""
    print(head + f"{d['scanned']} ports, {d['seconds']}s, {len(d['open'])} open{extra} ==")
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
        if w.get("see_port"):
            print(f"       redirects to {w['url']} (checked under port {w['see_port']})")
            continue
        if w["status"] is None:
            print(f"       {w['tls']} service, not HTTP")
        else:
            info = " ".join(x for x in (w["server"], w["powered_by"], w["tls"]) if x)
            line = f"       HTTP {w['status']} {info}".rstrip()
            if w["redirects"]:
                line += f"  after {len(w['redirects'])} redirect(s): {w['url']}"
            print(line)
        if w["note"]:
            print(f"       {w['note']}")
        for i in w["issues"]:
            print(f"       - {i}")


def main():
    ap = argparse.ArgumentParser(
        description="Small async port scanner with web and TLS checks. Authorized targets only.")
    ap.add_argument("targets", nargs="+", help="hostnames, IPs, URLs or CIDR ranges")
    ap.add_argument("-p", "--ports", type=ports_arg, default=TOP, help="top (default), all, or 22,80,8000-8100")
    ap.add_argument("-c", "--concurrency", type=int, default=300, help="parallel connects (default 300)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    ap.add_argument("--no-web", action="store_true", help="skip web and TLS checks")
    ap.add_argument("--json", action="store_true", help="JSON output")
    a = ap.parse_args()
    try:
        a.parsed = [parse_target(t) for t in a.targets]
    except ValueError as e:
        ap.error(str(e))
    a.conc = fd_budget(max(1, a.concurrency))
    if a.conc < a.concurrency:
        print(f"note: concurrency lowered to {a.conc} to fit this system's open-file limit", file=sys.stderr)
    print("Scan only hosts you own or have written permission to test.", file=sys.stderr)

    groups, bad = asyncio.run(run(a))
    out, errors = [], bool(bad)
    for g in groups:
        res = [finish(e) for e in g["addrs"]]
        out += res
        dead = sum(d["unreachable"] for d in res)
        errors = errors or any(d["untested"] for d in res) or (bool(res) and dead == len(res))
        if a.json:
            continue
        for d in res:
            if not g["range"] or d["open"] or d["untested"]:
                show(d)
        if g["range"]:
            live = sum(bool(d["open"]) for d in res)
            tail = f", {dead} with no route" if dead else ""
            print(f"\n== {g['label']} | {len(res)} addresses scanned, {live} with open ports{tail} ==")
    if a.json:
        print(json.dumps(out, indent=2))
    findings = any(r["risk"] or (r.get("web") or {}).get("issues") for d in out for r in d["open"])
    return 2 if errors else 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
