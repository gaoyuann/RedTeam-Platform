FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages responder mitm6 || \
    pip3 install --no-cache-dir --break-system-packages responder
