FROM artifactory.eng.sentinelone.tech/docker-release/common/ubuntu-base/ubuntu:2.0.75 AS builder

WORKDIR /vector

COPY vector-*-unknown-linux-*.tar.gz ./
RUN tar -xvf vector-*-$(uname -m)-unknown-linux-*.tar.gz --strip-components=2

RUN mkdir -p /var/lib/vector

FROM artifactory.eng.sentinelone.tech/docker-release/common/ubuntu-base/ubuntu:2.0.75

# Install dependencies for Vector and FIPS
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl \
      libssl-dev \
      ca-certificates \
      tzdata \
      systemd \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/*

# Set environment for Rust to use system OpenSSL
ENV OPENSSL_FIPS=1
ENV OPENSSL_DIR=/usr
ENV OPENSSL_STATIC=0
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf.fips
ENV OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules

# Copy from builder stage
COPY --from=builder /vector/bin/* /usr/bin/
COPY --from=builder /vector/config/README.md /etc/vector/README.md
COPY --from=builder /var/lib/vector /var/lib/vector

# Smoke test
RUN ["vector", "--version"]

USER root

ENTRYPOINT ["/usr/bin/vector"]
