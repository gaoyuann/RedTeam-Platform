FROM alpine:3.19

ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6

RUN apk add --no-cache nikto python3 py3-pip wget unzip && \
    pip3 install --no-cache-dir --break-system-packages sqlmap && \
    cd /tmp && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O nuclei.zip && \
    echo "${NUCLEI_SHA256}  nuclei.zip" | sha256sum -c - && \
    unzip nuclei.zip nuclei -d /usr/local/bin/ && \
    rm -rf /tmp/* && \
    apk del wget unzip
