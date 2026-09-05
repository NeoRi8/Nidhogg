# AuthProxy (Nidhogg)

Keeps the authorized session alive for any CLI scanners. (`katana`, `nuclei`,
`sqlmap`, `dalfox`, `ffuf`, `httpx`, `curl` …). A local proxy based on mitmproxy that:

- attaches cookies **only** to requests destined for the target domain (does not leak the session to third-party domains);
- intercepts `Set-Cookie` headers and updates rotating cookies on the fly;
- keeps the session alive via background pings **routed through itself** (ensuring cookie rotation remains intact);
- upon logout, either automatically re-authenticates (`--login`) or prompts the user to provide a new cookie;
- exposes current cookies via HTTP: `GET/PUT /cookies`.

## Quick Start

### Option 1 — pip (recommended)
```bash
pip3 install --break-system-packages mitmproxy
python3 src/authproxy.py --target https://site.com --cookie "PHPSESSID=abc;TOKEN=xyz"
```

### Вариант 2 — Docker

```bash
docker build -t authproxy .
docker run --rm -it -p 8888:8888 -p 8890:8890 \
  -v ~/.mitmproxy:/root/.mitmproxy \
  authproxy --target https://site.com --cookie "PHPSESSID=abc;TOKEN=xyz" --host 0.0.0.0
```

> `-v ~/.mitmproxy:/root/.mitmproxy` places the mitmproxy CA directly into your `~/.mitmproxy/`
> directory on the host—this way, CA trust is set up once, without needing `docker cp`.

## Routing tools through a proxy

After starting the proxy, simply add the proxy flag to the tool:

| Tool | Flag |
|---|---|
| katana | `-proxy http://127.0.0.1:8888` |
| nuclei | `-proxy http://127.0.0.1:8888` |
| sqlmap | `--proxy=http://127.0.0.1:8888` |
| dalfox | `--proxy http://127.0.0.1:8888` |
| httpx | `-http-proxy http://127.0.0.1:8888` |
| ffuf | `-x http://127.0.0.1:8888` |
| curl | `--proxy http://127.0.0.1:8888` |

## Trusting the CA (required for HTTPS, one-time)

mitmproxy intercepts HTTPS and presents its own certificate. To prevent tools from complaining about `x509: certificate signed by unknown authority`:

```bash
# Option 1 — system-wide (requires root), covers all tools:
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates

# Option 2 — without root, for Go tools (katana/nuclei/dalfox):
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
```

Alternatively, run it with the `--install-ca` flag (as root) — Option 1 will execute automatically.

## Two operating modes

### Mode 1 — the cookie is updated via `Set-Cookie` (default)

No action is required: the proxy automatically captures new cookies from responses. Background pings
(`--keepalive`, defaulting to the target URL) prevent the session from expiring.

### Mode 2 — cookie updated via a separate request or re-login

Pass the `--login` argument—a command whose **stdout** returns a fresh cookie string.
Upon logout, the proxy will automatically execute this command and update the cookies.

```bash
python3 src/authproxy.py \
  --target https://site.com \
  --cookie "A=...;B=..." \
  --login 'python3 /opt/mylogin.py'    # prints "A=...;B=..."
```
## Cookie Management (HTTP)

```bash
curl http://127.0.0.1:8890/cookies                      # view
curl -X PUT -d "A=1;B=2" http://127.0.0.1:8890/cookies  # update without restarting
```

## Full List of Flags/Cookie Example/Acknowledgments

```bash
python3 src/authproxy.py --help

Cookie Example
┌─────────────────────────────────────────────────────────────┐
│ CMS/Framework     │ Cookie                                  │
├─────────────────────────────────────────────────────────────┤
│ 1C-Bitrix         │ PHPSESSID=...;BITRIX_SM_UIDH=...        │
│ WordPress         │ wordpress_logged_in_...;wordpress_sec_..│
│ Laravel           │ laravel_session=...                     │
│ Django            │ sessionid=...                           │
│ Node.js/Express   │ connect.sid=...                         │
│ Java/Spring       │ JSESSIONID=...                          │
│ Drupal            │ SESS...=...                             │
│ Magento           │ PHPSESSID=... admin=...                 │
└─────────────────────────────────────────────────────────────┘

Acknowledgments

    Built on top of mitmproxy — an amazing interactive HTTPS proxy.

    Thanks to the mitmproxy team for creating such a powerful and flexible tool.

    Inspired by the need to keep sessions alive during long security scans.

⭐ If you find this tool useful, consider giving it a star on GitHub!
