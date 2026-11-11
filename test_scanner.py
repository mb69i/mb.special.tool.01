"""Tests for scanner.py. Run with:  python -m unittest -v"""
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scanner  # noqa: E402

SCANNER = os.path.join(HERE, "scanner.py")
GOOD = [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"), ("Strict-Transport-Security", "max-age=31536000")]
WEAK = [("Strict-Transport-Security", "max-age=0"),
        ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
        ("X-Content-Type-Options", "banana"), ("Referrer-Policy", "unsafe-url"),
        ("Permissions-Policy", ""), ("X-Frame-Options", "ALLOWALL")]


def serve(routes, cert=None):
    """Start a local server. routes: path -> (status, headers). Returns its port."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers = routes.get(self.path, (404, []))
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    class Server(http.server.ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            pass                                # rejected handshakes are expected in these tests

    srv = Server(("127.0.0.1", 0), Handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*cert)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run(*args, **kw):
    p = subprocess.run([sys.executable, SCANNER, *map(str, args)], capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


def web_of(*args):
    """Scan with --json and return (exit code, web result of the first open port)."""
    code, out, err = run(*args, "--json")
    return code, json.loads(out)[0]["open"][0]["web"]


class HeaderTests(unittest.TestCase):
    def test_strong_headers_pass(self):
        self.assertEqual(scanner.judge(GOOD, True), [])

    def test_weak_values_are_flagged(self):
        found = " | ".join(scanner.judge(WEAK, True))
        for part in ("unsafe-inline", "unsafe-eval", "any origin", "not nosniff", "unsafe-url",
                     "Permissions-Policy is empty", "not DENY or SAMEORIGIN", "max-age=0"):
            self.assertIn(part, found)

    def test_missing_headers_and_plain_http(self):
        found = scanner.judge([], False)
        self.assertIn("missing CSP", found)
        self.assertIn("served over plain HTTP", found)
        self.assertNotIn("missing HSTS", found)

    def test_short_hsts_is_flagged(self):
        found = scanner.judge(GOOD[:4] + [("Strict-Transport-Security", "max-age=3600")], True)
        self.assertTrue(any("HSTS max-age is short" in f for f in found))

    def test_nonce_makes_unsafe_inline_harmless(self):
        self.assertEqual(scanner.csp_issues("script-src 'nonce-abc' 'unsafe-inline'"), [])

    def test_csp_without_script_rules(self):
        self.assertTrue(scanner.csp_issues("frame-ancestors 'none'"))

    def test_cookie_flags(self):
        found = scanner.judge(GOOD + [("Set-Cookie", "sid=1; Path=/")], True)
        self.assertEqual(found, ["cookie sid: no HttpOnly/Secure"])
        self.assertEqual(scanner.judge(GOOD + [("Set-Cookie", "sid=1; Secure; HttpOnly")], True), [])


class CertTests(unittest.TestCase):
    def test_issue_wording(self):
        now = 1_000_000_000
        day = 86400
        self.assertEqual(scanner.cert_issues(None, now + 400 * day, now), [])
        self.assertEqual(scanner.cert_issues(None, now + 10 * day + 5, now), ["certificate expires in 10 day(s)"])
        self.assertEqual(scanner.cert_issues(None, now - 3 * day - 5, now), ["certificate expired 3 day(s) ago"])
        self.assertEqual(scanner.cert_issues("certificate has expired", None, now), ["certificate expired"])
        self.assertEqual(scanner.cert_issues("self-signed certificate", now + 400 * day, now),
                         ["certificate not trusted: self-signed certificate"])

    def test_garbage_der_is_handled(self):
        self.assertIsNone(scanner.der_not_after(b""))
        self.assertIsNone(scanner.der_not_after(b"\x30\x03\x02\x01\x01"))


class TargetTests(unittest.TestCase):
    def test_url(self):
        self.assertEqual(scanner.parse_target("https://example.com/x")[1:], (["example.com"], 443, False))
        self.assertEqual(scanner.parse_target("http://example.com:8080")[2], 8080)
        with self.assertRaises(ValueError):
            scanner.parse_target("ftp://example.com")

    def test_cidr(self):
        label, hosts, port, is_range = scanner.parse_target("192.168.1.0/30")
        self.assertEqual((hosts, port, is_range), (["192.168.1.1", "192.168.1.2"], None, True))
        with self.assertRaises(ValueError):
            scanner.parse_target("10.0.0.0/8")

    def test_ports(self):
        self.assertEqual(scanner.ports_arg("22,80-82"), [22, 80, 81, 82])
        self.assertEqual(len(scanner.ports_arg("all")), 65535)


class LiveTests(unittest.TestCase):
    """End-to-end runs against servers on localhost."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert = None
        if shutil.which("openssl"):
            crt, key = os.path.join(cls.tmp, "c.pem"), os.path.join(cls.tmp, "k.pem")
            done = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                                   "-out", crt, "-days", "365", "-subj", "/CN=localhost"], capture_output=True)
            if done.returncode == 0:
                cls.cert = (crt, key)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_web_server_on_unusual_port_is_checked(self):
        code, web = web_of("127.0.0.1", "-p", serve({"/": (200, [])}))
        self.assertEqual((code, web["status"]), (1, 200))
        self.assertIn("missing CSP", web["issues"])

    def test_redirect_is_followed_and_final_page_judged(self):
        port = serve({"/": (302, [("Location", "/login")]), "/login": (200, GOOD)})
        code, web = web_of("127.0.0.1", "-p", port)
        self.assertEqual(web["status"], 200)
        self.assertEqual(len(web["redirects"]), 1)
        self.assertTrue(web["url"].endswith("/login"))
        self.assertEqual(web["issues"], ["served over plain HTTP"])

    def test_redirect_to_another_host_is_not_followed(self):
        code, web = web_of("127.0.0.1", "-p", serve({"/": (302, [("Location", "http://example.org/")])}))
        self.assertEqual((web["status"], web["issues"]), (302, []))
        self.assertIn("not followed", web["note"])

    def test_redirect_loop_is_reported(self):
        port = serve({"/": (302, [("Location", "/a")]), "/a": (302, [("Location", "/")])})
        code, web = web_of("127.0.0.1", "-p", port)
        self.assertIn("redirect loop", web["issues"])

    def test_self_signed_certificate_is_reported(self):
        if not self.cert:
            self.skipTest("openssl not available")
        code, web = web_of("127.0.0.1", "-p", serve({"/": (200, GOOD)}, self.cert))
        self.assertTrue(web["tls"].startswith("TLS"))
        self.assertEqual(len(web["issues"]), 1)
        self.assertIn("certificate not trusted", web["issues"][0])

    def test_expiry_is_read_from_the_certificate(self):
        if not self.cert:
            self.skipTest("openssl not available")
        end = subprocess.run(["openssl", "x509", "-in", self.cert[0], "-noout", "-enddate"],
                             capture_output=True, text=True).stdout.strip().split("=", 1)[1]
        with open(self.cert[0]) as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
        self.assertEqual(scanner.der_not_after(der), ssl.cert_time_to_seconds(end))

    def test_url_target(self):
        port = serve({"/": (200, [])})
        code, out, err = run(f"http://127.0.0.1:{port}/", "-p", closed_port(), "--json")
        self.assertEqual([r["port"] for r in json.loads(out)[0]["open"]], [port])

    def test_cidr_range(self):
        port = serve({"/": (200, [])})
        code, out, err = run("127.0.0.0/30", "-p", port, "--no-web", "--json")
        res = {d["ip"]: d for d in json.loads(out)}
        self.assertEqual(sorted(res), ["127.0.0.1", "127.0.0.2"])
        self.assertEqual([r["port"] for r in res["127.0.0.1"]["open"]], [port])

    def test_exit_codes(self):
        self.assertEqual(run("127.0.0.1", "-p", closed_port())[0], 0)
        self.assertEqual(run("127.0.0.1", "-p", serve({"/": (200, [])}))[0], 1)
        self.assertEqual(run("no-such-host.invalid", "-p", 80)[0], 2)

    def test_open_port_is_found_under_a_low_file_limit(self):
        try:
            import resource
        except ImportError:
            self.skipTest("no resource module on this platform")
        port = serve({"/": (200, [])})
        lo, hi = max(1, port - 1000), min(65535, port + 1000)
        code, out, err = run("127.0.0.1", "-p", f"{lo}-{hi}", "--no-web", "--json",
                             preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256)))
        self.assertIn("concurrency lowered", err)
        self.assertIn(port, [r["port"] for r in json.loads(out)[0]["open"]])


if __name__ == "__main__":
    unittest.main()
