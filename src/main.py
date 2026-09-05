#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthProxy — "holder" of an authenticated session for any CLI scanners.

Runs a local proxy (mitmproxy) that:
  * injects your cookies ONLY into requests to the target domain;
  * intercepts Set-Cookie and updates rotating cookies on the fly (mode 1);
  * keeps the session alive with background pings through itself;
  * on logout, either re-authenticates itself (mode 2, --login),
    or honestly asks you to paste a new cookie;
  * serves current cookies via HTTP (GET/PUT /cookies).

Usage:
  python3 authproxy.py --target https://site.com --cookie "A=...;B=..."

Then any tool can be directed through the proxy with a single option:
  katana  -proxy http://127.0.0.1:8888 ...
  nuclei  -proxy http://127.0.0.1:8888 ...
  sqlmap  --proxy=http://127.0.0.1:8888 ...
  dalfox  --proxy http://127.0.0.1:8888 ...
"""

import argparse
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

VERSION = "1.0.0"


# ============================================================
# Colors and banner (style preserved)
# ============================================================
class C:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


COLOR_ENABLED = True


def paint(text, color=C.GREEN, bold=False):
    if not COLOR_ENABLED:
        return text
    prefix = C.BOLD if bold else ""
    return f"{prefix}{color}{text}{C.END}"


BANNER = f"""
{C.CYAN}
  ░███    ░██ ░██████░███████   ░██     ░██   ░██████     ░██████    ░██████
  ░████   ░██   ░██  ░██   ░██  ░██     ░██  ░██   ░██   ░██   ░██  ░██   ░██
  ░██░██  ░██   ░██  ░██    ░██ ░██     ░██ ░██     ░██ ░██        ░██
  ░██ ░██ ░██   ░██  ░██    ░██ ░██████████ ░██     ░██ ░██  █████ ░██  █████
  ░██  ░██░██   ░██  ░██    ░██ ░██     ░██ ░██     ░██ ░██     ██ ░██     ██
  ░██   ░████   ░██  ░██   ░██  ░██     ░██  ░██   ░██   ░██  ░███  ░██  ░███
  ░██    ░███ ░██████░███████   ░██     ░██   ░██████     ░█████░█   ░█████░█

  Session-Aware Proxy for Security Scanners
  v{VERSION}
{C.END}
"""


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def print_banner():
    if COLOR_ENABLED:
        print(BANNER)
    else:
        print(_ANSI_RE.sub("", BANNER))


def ts():
    return time.strftime("%H:%M:%S")


def log(msg, color=None):
    if color is None:
        print(msg)
    else:
        print(paint(msg, color))


# ============================================================
# Pure helpers (testable without mitmproxy)
# ============================================================
def parse_cookie_string(s):
    """Parses a 'a=1; b=2' string into a dict."""
    cookies = {}
    if not s:
        return cookies
    s = s.strip().strip('"').strip("'")
    for part in s.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name:
            cookies[name] = value
    return cookies


def format_cookie_string(cookies):
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def parse_set_cookie(header):
    """From a Set-Cookie header returns (name, value) or (name, None) on deletion."""
    if not header:
        return None
    m = re.match(r"^\s*([^=;\s]+)\s*=\s*([^;]*)", header)
    if not m:
        return None
    name = m.group(1).strip()
    value = m.group(2).strip()
    deleted = re.search(
        r"(?i)(max-age\s*=\s*0\b|max-age\s*=\s*-\d+|expires\s*=\s*(thu,\s*)?01[- ]jan[- ]1970)",
        header,
    )
    if deleted:
        return (name, None)
    return (name, value)


def host_from_url(url):
    if "://" not in url:
        url = "https://" + url
    netloc = urlparse(url).netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if ":" in netloc:
        netloc = netloc.rsplit(":", 1)[0]
    return netloc.lower()


def host_matches(host, target, include_subdomains=False):
    host = (host or "").lower()
    target = (target or "").lower()
    if not target or not host:
        return False
    if include_subdomains:
        return host == target or host.endswith("." + target)
    return host == target


COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "httponly", "secure", "samesite", "comment"}


def extract_cookies_from_text(text):
    """Extracts cookies from login script output.

    Understands both a plain cookie string ('A=1;B=2') and verbose output
    with headers like 'Set-Cookie: PHPSESSID=abc; Path=/' (attributes
    Path/Domain/Expires/... are stripped).
    """
    cookies = {}
    if not text:
        return cookies
    text = text.strip()

    # Plain cookie string: one line, no colons.
    if "\n" not in text and ":" not in text:
        direct = parse_cookie_string(text)
        if direct:
            return direct

    # Otherwise, line by line look for name=value / Set-Cookie.
    for line in text.splitlines():
        if "=" not in line:
            continue
        # strip prefix like "Set-Cookie:"
        if ":" in line:
            before, _, after = line.partition(":")
            if "set-cookie" in before.lower():
                line = after
        for part in line.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip().strip('"').strip("'")
            value = value.strip().strip('"').strip("'")
            if name and name.lower() not in COOKIE_ATTRS:
                cookies[name] = value
    return cookies


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


# ============================================================
# mitmproxy addon (runs inside the mitmdump process)
# ============================================================
try:
    from mitmproxy import ctx  # noqa: F401

    HAS_MITMPROXY = True
except Exception:
    HAS_MITMPROXY = False


class AuthProxyAddon:
    """Cookie injection + Set-Cookie capture + logout detection + re-login."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.target_host = cfg.get("target_host", "")
        self.include_subdomains = bool(cfg.get("include_subdomains", False))
        self.cookies = dict(cfg.get("cookies", {}))
        self.login_cmd = cfg.get("login_cmd") or None
        self.logout_markers = [str(m).lower() for m in cfg.get("logout_markers", [])]
        self.logout_status = set(int(s) for s in cfg.get("logout_status", [401]))
        self.cookie_file = cfg.get("cookie_file")
        self.command_file = cfg.get("command_file")
        self.ua = cfg.get("user_agent") or None

        self.updates = 0
        self.logged_out = False
        self._lock = threading.Lock()
        self._last_relogin = 0.0
        self._stop = threading.Event()
        self._last_command_mtime = None
        self._write_state()
        threading.Thread(target=self._watch_commands, daemon=True).start()

    # ---------- lifecycle ----------
    def running(self):
        try:
            ctx.log.info(
                f"AuthProxy: {len(self.cookies)} cookie(s) for {self.target_host}"
            )
        except Exception:
            pass

    # ---------- request: inject cookies only to target domain ----------
    def request(self, flow):
        if not host_matches(flow.request.host, self.target_host, self.include_subdomains):
            return
        with self._lock:
            cookies = dict(self.cookies)
        if cookies:
            flow.request.headers["Cookie"] = format_cookie_string(cookies)
        if self.ua:
            flow.request.headers["User-Agent"] = self.ua

    # ---------- response: capture Set-Cookie and logout ----------
    def response(self, flow):
        if not host_matches(flow.request.host, self.target_host, self.include_subdomains):
            return

        changed = False
        for header in flow.response.headers.get_all("Set-Cookie"):
            parsed = parse_set_cookie(header)
            if not parsed:
                continue
            name, value = parsed
            with self._lock:
                if value is None:
                    if name in self.cookies:
                        del self.cookies[name]
                        changed = True
                elif name not in self.cookies or self.cookies[name] != value:
                    self.cookies[name] = value
                    changed = True
        if changed:
            with self._lock:
                self.updates += 1
            self._write_state()

        if self._is_logout(flow):
            self._on_logout()

    # ---------- logout detection ----------
    def _is_logout(self, flow):
        if flow.response.status_code in self.logout_status:
            return True
        if flow.response.status_code in (301, 302, 303, 307, 308):
            loc = (flow.response.headers.get("Location", "") or "").lower()
            if any(m in loc for m in self.logout_markers):
                return True
        return False

    def _on_logout(self):
        with self._lock:
            was = self.logged_out
            self.logged_out = True
        if not was:
            self._write_state()
            try:
                ctx.log.warn("AuthProxy: logout detected")
            except Exception:
                pass

        if self.login_cmd:
            now = time.time()
            if now - self._last_relogin > 60:  # cooldown; retry later on failure
                self._last_relogin = now
                self._relogin()

    def _relogin(self):
        try:
            ctx.log.info("AuthProxy: running login command...")
        except Exception:
            pass
        try:
            r = subprocess.run(
                self.login_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            out = (r.stdout or "").strip()
            new = extract_cookies_from_text(out)
            if new:
                with self._lock:
                    self.cookies = new
                    self.logged_out = False
                    self.updates += 1
                self._write_state()
                try:
                    ctx.log.info(f"AuthProxy: re-login OK ({len(new)} cookies)")
                except Exception:
                    pass
            else:
                try:
                    ctx.log.warn("AuthProxy: login command produced no cookies")
                except Exception:
                    pass
        except Exception as e:
            try:
                ctx.log.warn(f"AuthProxy: re-login failed: {e}")
            except Exception:
                pass

    # ---------- save state to file (for the main process) ----------
    def _write_state(self):
        if not self.cookie_file:
            return
        with self._lock:
            data = {
                "cookies": dict(self.cookies),
                "updates": self.updates,
                "logged_out": self.logged_out,
                "ts": time.time(),
            }
        try:
            write_json(self.cookie_file, data)
        except Exception:
            pass

    # ---------- background reading of external commands (PUT /cookies) ----------
    def _watch_commands(self):
        while not self._stop.is_set():
            try:
                if self.command_file and os.path.exists(self.command_file):
                    mtime = os.path.getmtime(self.command_file)
                    if mtime != self._last_command_mtime:
                        self._last_command_mtime = mtime
                        cmd = read_json(self.command_file)
                        if cmd and "cookies" in cmd:
                            with self._lock:
                                self.cookies = dict(cmd["cookies"])
                                self.logged_out = False
                                self.updates += 1
                            self._write_state()
                            try:
                                ctx.log.info("AuthProxy: cookies updated externally")
                            except Exception:
                                pass
            except Exception:
                pass
            time.sleep(1)


# If the file is loaded via mitmproxy -s — export the addon
_CONFIG = None
if "AUTHPROXY_CONFIG" in os.environ:
    _CONFIG = read_json(os.environ["AUTHPROXY_CONFIG"])

if _CONFIG is not None and HAS_MITMPROXY:
    addons = [AuthProxyAddon(_CONFIG)]  # noqa: F821
elif _CONFIG is not None and not HAS_MITMPROXY:
    addons = []  # noqa: F821


# ============================================================
# Control HTTP server (GET/PUT /cookies)
# ============================================================
class ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._send(200, json.dumps({"status": "ok", "name": "authproxy"}))
        elif self.path == "/cookies":
            state = self.server.read_state() or {}
            self._send(200, json.dumps(state.get("cookies", {}), ensure_ascii=False))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_PUT(self):
        if self.path == "/cookies":
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
            cookies = parse_cookie_string(body)
            if not cookies:
                self._send(400, json.dumps({"error": "no cookies parsed"}))
                return
            self.server.apply_cookies(cookies)
            self._send(200, json.dumps({"ok": True, "cookies": cookies}, ensure_ascii=False))
        else:
            self._send(404, json.dumps({"error": "not found"}))


# ============================================================
# Helper functions for the main process
# ============================================================
def port_open(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def find_mitmproxy_ca():
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.pem"),
        os.path.join(home, ".mitmproxy", "mitmproxy-ca.pem"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    # fallback: any *ca*.pem in ~/.mitmproxy
    d = os.path.join(home, ".mitmproxy")
    if os.path.isdir(d):
        for fname in sorted(os.listdir(d)):
            if "ca" in fname.lower() and fname.endswith(".pem"):
                return os.path.join(d, fname)
    return None


def install_ca_system(ca_path):
    if os.geteuid() != 0:
        log("   ⚠️ System installation requires root (sudo).", C.YELLOW)
        return False
    dst = "/usr/local/share/ca-certificates/mitmproxy-authproxy.crt"
    try:
        shutil.copy(ca_path, dst)
        subprocess.run(["update-ca-certificates"], check=False)
        log("   ✅ mitmproxy CA installed system-wide.", C.GREEN)
        return True
    except Exception as e:
        log(f"   ❌ Failed to install CA: {e}", C.RED)
        return False


# ============================================================
# Main CLI
# ============================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="AuthProxy — maintains an authenticated session for CLI scanners.",
        add_help=True,
    )
    p.add_argument("--target", help="Target URL (https://site.com)")
    p.add_argument("--cookie", help="Cookies: 'A=1;B=2'")
    p.add_argument(
        "--login",
        help="Re-login command on logout; its stdout should be a new cookie string 'A=1;B=2'",
    )
    p.add_argument("--keepalive", help="URL for background pings (default = target)")
    p.add_argument("--keepalive-interval", type=int, default=300, help="Ping interval in seconds (default 300)")
    p.add_argument("--port", type=int, default=8888, help="Proxy port (default 8888)")
    p.add_argument("--control-port", type=int, default=8890, help="Control API port (default 8890)")
    p.add_argument("--host", default="127.0.0.1", help="Address the proxy listens on (default 127.0.0.1)")
    p.add_argument("--include-subdomains", action="store_true", help="Inject cookies to subdomains as well")
    p.add_argument("--logout-status", default="401", help="HTTP status codes for logout detection (comma-separated, default 401)")
    p.add_argument("--logout-marker", default="login,auth,signin", help="Logout markers in Location header (comma-separated)")
    p.add_argument("--ua", help="Override User-Agent (by default don't touch)")
    p.add_argument("--install-ca", action="store_true", help="Install mitmproxy CA system-wide (requires root)")
    p.add_argument("--no-color", action="store_true", help="Disable colors")
    p.add_argument("--version", action="version", version=f"AuthProxy v{VERSION}")
    return p.parse_args()


def main():
    global COLOR_ENABLED
    args = parse_args()
    COLOR_ENABLED = not args.no_color
    print_banner()

    # --- target URL and cookies: flags or interactive ---
    target = args.target
    cookie_str = args.cookie

    interactive = sys.stdin.isatty()
    if not target:
        if not interactive:
            log("❌ --target not specified and interactive input is unavailable.", C.RED)
            sys.exit(1)
        target = input(paint("🌐 Target URL: ", C.CYAN)).strip()
    if not cookie_str:
        if not interactive:
            log("❌ --cookie not specified and interactive input is unavailable.", C.RED)
            sys.exit(1)
        cookie_str = input(paint("🔑 Cookie [A=1;B=2]: ", C.CYAN)).strip()

    if not target:
        log("❌ URL not set.", C.RED)
        sys.exit(1)
    if "://" not in target:
        target = "https://" + target

    cookies = parse_cookie_string(cookie_str)
    if not cookies:
        log("❌ Failed to parse cookies.", C.RED)
        sys.exit(1)
    target_host = host_from_url(target)

    if not HAS_MITMPROXY:
        log("❌ mitmproxy is not installed.", C.RED)
        log("   Install it: pip3 install mitmproxy", C.YELLOW)
        sys.exit(1)

    # --- working directory ---
    workdir = f"/tmp/authproxy-{os.getpid()}"
    os.makedirs(workdir, exist_ok=True)
    cookie_file = os.path.join(workdir, "cookies.json")
    command_file = os.path.join(workdir, "command.json")
    config_path = os.path.join(workdir, "config.json")

    logout_markers = [m.strip() for m in args.logout_marker.split(",") if m.strip()]
    logout_status = [int(s.strip()) for s in args.logout_status.split(",") if s.strip()]

    cfg = {
        "target_host": target_host,
        "include_subdomains": args.include_subdomains,
        "cookies": cookies,
        "login_cmd": args.login,
        "logout_markers": logout_markers,
        "logout_status": logout_status,
        "cookie_file": cookie_file,
        "command_file": command_file,
        "user_agent": args.ua,
    }
    write_json(config_path, cfg)

    # --- start mitmdump ---
    log(f"\n🔄 Starting proxy for {target_host} on port {args.port}...", C.CYAN)
    cmd = [
        shutil.which("mitmdump") or "mitmdump",
        "-s", os.path.abspath(__file__),
        "-q",
        "--listen-host", args.host,
        "--listen-port", str(args.port),
        "--ssl-insecure",
        "--set", "upstream_cert=false",
        "--set", "connection_strategy=lazy",
        "--set", "keep_host_header=true",
        "--no-http2",
        "--flow-detail", "0",
    ]
    env = {**os.environ, "AUTHPROXY_CONFIG": config_path, "PYTHONUNBUFFERED": "1"}
    try:
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log(f"❌ Failed to start mitmdump: {e}", C.RED)
        sys.exit(1)

    # --- wait for proxy readiness ---
    ready = False
    for _ in range(30):
        if proc.poll() is not None:
            break
        if port_open(args.port):
            ready = True
            break
        time.sleep(0.3)
    if not ready:
        log("❌ Proxy failed to start. Check if the port is free.", C.RED)
        proc.terminate()
        sys.exit(1)
    log(f"   ✅ Proxy running: http://127.0.0.1:{args.port}", C.GREEN)

    # --- CA / trust ---
    ca_path = None
    for _ in range(10):
        ca_path = find_mitmproxy_ca()
        if ca_path:
            break
        time.sleep(0.5)

    if args.install_ca and ca_path:
        install_ca_system(ca_path)
    elif ca_path:
        log(f"\n🔐 For HTTPS to work through the proxy, tools must trust mitmproxy's CA.", C.YELLOW)
        log(f"   CA: {ca_path}", C.DIM)
        log("   One-time (requires root):", C.YELLOW)
        log(f"     sudo cp {ca_path} /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates", C.DIM)
        log("   Or without root (for Go tools like katana/nuclei/dalfox):", C.YELLOW)
        log(f"     export SSL_CERT_FILE={ca_path}", C.DIM)

    # --- control server ---
    def read_state():
        return read_json(cookie_file)

    def apply_cookies(c):
        write_json(command_file, {"cookies": c})

    try:
        srv = ThreadingHTTPServer((args.host, args.control_port), ControlHandler)
        srv.read_state = read_state
        srv.apply_cookies = apply_cookies
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        control_ok = True
    except Exception as e:
        log(f"   ⚠️ Control API failed to start: {e}", C.YELLOW)
        control_ok = False

    # --- background pings (through the proxy, to catch cookie rotation) ---
    keepalive_url = args.keepalive or target
    keep_running = {"v": True}
    # Pings go to the local loopback of the process (independent of --host).
    local_proxy = f"http://127.0.0.1:{args.port}"
    # Address that the user points tools to.
    proxy_hint = f"http://127.0.0.1:{args.port}"
    control_hint = f"http://127.0.0.1:{args.control_port}"

    def keep_alive():
        handler = urllib.request.ProxyHandler({"http": local_proxy, "https": local_proxy})
        ctx_ssl = ssl._create_unverified_context()
        opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=ctx_ssl))
        while keep_running["v"]:
            time.sleep(args.keepalive_interval)
            try:
                opener.open(keepalive_url, timeout=10)
            except Exception:
                pass

    threading.Thread(target=keep_alive, daemon=True).start()
    log(f"   🔄 Keep-alive: pinging {keepalive_url} every {args.keepalive_interval // 60} min (through proxy)", C.DIM)

    # --- hints ---
    log("\n" + paint("=" * 62, C.CYAN))
    log(paint("💡 How to point tools through the proxy:", C.BOLD))
    log(paint("=" * 62, C.CYAN))
    for t in [
        f"katana  -proxy {proxy_hint} ...",
        f"nuclei  -proxy {proxy_hint} ...",
        f"sqlmap  --proxy={proxy_hint} ...",
        f"dalfox  --proxy {proxy_hint} ...",
        f"curl    --proxy {proxy_hint} ...",
    ]:
        log(f"   {t}", C.DIM)
    if control_ok:
        log("\n" + paint("🎛️  Cookie Management:", C.BOLD))
        log(f"   GET {control_hint}/cookies  — view current cookies", C.DIM)
        log(f"   PUT {control_hint}/cookies  (body: A=1;B=2)  — update cookies without restart", C.DIM)
    if args.host in ("0.0.0.0", "::"):
        log("\n   💡 Proxy is listening on all interfaces; for remote access replace 127.0.0.1 with the host IP.", C.DIM)
    log("\n" + paint("🛑 Press Ctrl+C to stop", C.DIM))

    # --- state monitoring ---
    last_updates = -1
    warned_logout = False
    last_notice = 0.0

    def on_interrupt(signum, frame):
        keep_running["v"] = False
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_interrupt)
    signal.signal(signal.SIGTERM, on_interrupt)

    try:
        while True:
            time.sleep(1)
            if proc.poll() is not None:
                log("\n⚠️ Proxy terminated unexpectedly.", C.YELLOW)
                break
            state = read_state()
            if not state:
                continue
            upd = state.get("updates", 0)
            if upd != last_updates:
                last_updates = upd
                now = time.time()
                if now - last_notice > 3:
                    last_notice = now
                    log(f"   🔄 [{ts()}] Cookie updated (total updates: {upd})", C.CYAN)
            if state.get("logged_out"):
                if not warned_logout:
                    warned_logout = True
                    if args.login:
                        log(f"\n🔴 [{ts()}] Logout! Attempting to re-login with --login...", C.RED)
                    else:
                        log(f"\n🔴 [{ts()}] Session expired! Please provide a new cookie:", C.RED)
                        if interactive:
                            new = input(paint("   🔑 New cookie [A=1;B=2]: ", C.YELLOW)).strip()
                            nc = parse_cookie_string(new)
                            if nc:
                                apply_cookies(nc)
                                log("   ✅ Cookie updated.", C.GREEN)
                        else:
                            log("   💡 Or update via PUT /cookies", C.YELLOW)
            elif warned_logout:
                warned_logout = False
    except KeyboardInterrupt:
        pass
    finally:
        keep_running["v"] = False
        log("\n⏹️  Stopping proxy...", C.YELLOW)
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass
        log("👋 Done.", C.GREEN)


if __name__ == "__main__":
    main()
