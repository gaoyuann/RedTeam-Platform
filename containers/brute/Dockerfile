FROM alpine:3.19

# hashcat needs OpenCL runtime, use community repo
RUN echo 'https://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories && \
    apk add --no-cache hydra john hashcat || \
    apk add --no-cache hydra john
