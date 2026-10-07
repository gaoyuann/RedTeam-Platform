FROM alpine:3.19

# ── Alpine packages ──────────────────────────────────────────────────────
RUN apk add --no-cache nmap nmap-scripts curl

# ── Go binaries (download during build) ─────────────────────────────────
# Set proxy for GitHub downloads (cleared after downloads)
ARG PROXY=http://drinkflower:zlt77776666@43.163.196.77:809
ENV http_proxy=${PROXY} https_proxy=${PROXY} HTTP_PROXY=${PROXY} HTTPS_PROXY=${PROXY}

RUN apk add --no-cache wget unzip && \
    cd /tmp && \
    wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_linux_amd64.zip && \
    unzip -o gobuster_linux_amd64.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/gobuster && \
    wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar xzf ffuf_*.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip && \
    unzip -o amass_*.zip -d /tmp/amass-extract/ && \
    mv /tmp/amass-extract/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/* && \
    apk del wget unzip

# ── httpx (ProjectDiscovery) ───────────────────────────────────────────
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

# ── Wordlists for gobuster/ffuf (code references /usr/share/wordlists/...) ──
# gobuster 等工具的字典文件。rt-recon 镜像此前只装二进制不装字典，
# 导致 gobuster 启动即失败（wordlist file does not exist）。
RUN apk add --no-cache wget && \
    mkdir -p /usr/share/wordlists/dirb /usr/share/wordlists/dirbuster /usr/share/wordlists/metasploit && \
    wget -q -O /usr/share/wordlists/dirb/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    wget -q -O /usr/share/wordlists/dirb/small.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt && \
    wget -q -O /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt && \
    wget -q -O /usr/share/wordlists/metasploit/unix_users.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt && \
    wget -q -O /usr/share/wordlists/metasploit/unix_passwords.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt && \
    apk del wget

# Clear proxy (not needed at runtime)
ENV http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY=
