FROM alpine:3.19

RUN apk add --no-cache nikto python3 py3-pip wget unzip && \
    pip3 install --no-cache-dir --break-system-packages sqlmap && \
    cd /tmp && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip nuclei_*.zip -d /usr/local/bin/ && \
    rm -rf /tmp/* && \
    apk del wget unzip
