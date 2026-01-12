FROM registry.access.redhat.com/ubi9/ubi:9.7-1764794285 AS builder

WORKDIR /vector

COPY vector-*-unknown-linux-*.tar.gz ./
RUN tar -xvf vector-*-$(uname -m)-unknown-linux-*.tar.gz --strip-components=2

RUN mkdir -p /var/lib/vector

FROM registry.access.redhat.com/ubi9/ubi:latest

# Install dependencies for Vector and FIPS
RUN dnf install -y \
      openssl \
      openssl-devel \
      ca-certificates \
      tzdata \
      systemd \
      && dnf clean all

# Set environment for Rust to use system OpenSSL
ENV OPENSSL_FIPS=1
ENV OPENSSL_DIR=/usr
ENV OPENSSL_STATIC=0

# Copy from builder stage
COPY --from=builder /vector/bin/* /usr/bin/
COPY --from=builder /vector/config/README.md /etc/vector/README.md
COPY --from=builder /var/lib/vector /var/lib/vector

# Smoke test
RUN ["vector", "--version"]

USER root

ENTRYPOINT ["/usr/bin/vector"]
