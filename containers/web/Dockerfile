FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages arjun requests

COPY web-brute.py /usr/local/bin/web-brute.py
RUN chmod +x /usr/local/bin/web-brute.py
