# =========================================================
# AuthProxy — authorized session storage for CLI scanners
# (proxy only; scanners remain on your host)
# =========================================================
FROM python:3.12-slim

# ca-certificates нужен для upstream TLS и флага --install-ca
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir mitmproxy

WORKDIR /app
COPY src/authproxy.py /app/authproxy.py

EXPOSE 8888 8890

ENTRYPOINT ["python3", "/app/authproxy.py"]
