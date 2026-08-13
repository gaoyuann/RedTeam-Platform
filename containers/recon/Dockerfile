FROM alpine:3.19

# ── Alpine packages ──────────────────────────────────────────────────────
RUN apk add --no-cache nmap nmap-scripts curl

# ── Go binaries (pre-downloaded to avoid slow GitHub downloads in Docker) ─
COPY binaries/gobuster /usr/local/bin/gobuster
COPY binaries/ffuf     /usr/local/bin/ffuf
COPY binaries/amass    /usr/local/bin/amass

# ── httpx (ProjectDiscovery) — small enough to download inline ──────────
RUN apk add --no-cache wget unzip && \
    cd /tmp && \
    wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.3/httpx_1.6.3_linux_amd64.zip && \
    unzip -o httpx_*.zip httpx -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/* && \
    apk del wget unzip

# ── whatweb (Ruby, from GitHub source) ──────────────────────────────────
RUN apk add --no-cache ruby ruby-bundler git make gcc musl-dev ruby-dev && \
    cd /opt && \
    git clone --depth 1 -b v0.6.4 https://github.com/urbanadventurer/WhatWeb.git whatweb && \
    cd whatweb && \
    bundle install --without mongo rchardet test development && \
    ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb && \
    apk del git make gcc musl-dev ruby-dev
