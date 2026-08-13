FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages awscli && \
    pip3 install --no-cache-dir --break-system-packages cloudmapper || \
    echo "[WARN] cloudmapper not installed" && \
    pip3 install --no-cache-dir --break-system-packages pacu || \
    echo "[WARN] pacu not installed"

COPY scripts/ /opt/redteam/scripts/
