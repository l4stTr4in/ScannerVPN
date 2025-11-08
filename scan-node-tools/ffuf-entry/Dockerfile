# scan-node-tools/ffuf-entry/Dockerfile
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git && \
    go install github.com/ffuf/ffuf/v2@latest

FROM python:3.11-alpine

# Install packages for VPN support
RUN apk add --no-cache \
    ca-certificates \
    openvpn \
    curl \
    wget \
    iproute2 \
    iptables \
    procps && \
    update-ca-certificates

# Copy ffuf binary from builder
COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

# Install Python packages
RUN pip install --no-cache-dir \
    requests[socks]==2.32.3 \
    beautifulsoup4==4.12.3 \
    lxml==5.2.2

WORKDIR /app

# Copy application files
COPY ffuf_entry.py /app/ffuf_entry.py
COPY vpn_manager.py /app/vpn_manager.py

# Copy wordlists to workdir for easy access
COPY wordlists/ /app/

RUN adduser -D -u 10001 scanner && chown -R scanner /app
USER scanner

ENTRYPOINT ["python", "/app/ffuf_entry.py"]
