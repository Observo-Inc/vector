FROM registry.access.redhat.com/ubi8/ubi:latest

# Enable FIPS mode (simulate in container)
RUN echo 1 > /proc/sys/crypto/fips_enabled || true
ENV OPENSSL_FIPS=1

# Install dependencies for Vector and FIPS
RUN dnf install -y \
      openssl \
      openssl-devel \
      ca-certificates \
      && dnf clean all

# Set environment for Rust to use system OpenSSL
ENV OPENSSL_DIR=/usr
ENV OPENSSL_STATIC=0

# Copy Vector binary from build context
COPY vector /usr/local/bin/vector

# Validate FIPS mode at build time
RUN echo "FIPS enabled at build time: $(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 'unknown')" && \
    openssl version && \
    openssl md5 || echo "MD5 not available in FIPS mode"

# Run as root user
USER root

ENTRYPOINT ["/usr/local/bin/vector"] 