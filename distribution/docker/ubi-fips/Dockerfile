FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

WORKDIR /dataplane

COPY vector-*-unknown-linux-*.tar.gz ./
RUN tar -xvf vector-*-$(uname -m)-unknown-linux-*.tar.gz --strip-components=2

# Rename vector binary to dataplane for consistency with site images
RUN mv /dataplane/bin/vector /dataplane/bin/dataplane

RUN mkdir -p /var/lib/dataplane

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
COPY --from=builder /dataplane/bin/* /usr/bin/
COPY --from=builder /dataplane/config/README.md /etc/dataplane/README.md
COPY --from=builder /var/lib/dataplane /var/lib/dataplane

# Smoke test
RUN ["dataplane", "--version"]

USER root

ENTRYPOINT ["/usr/bin/dataplane"]
