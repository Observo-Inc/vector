FROM docker.io/debian:12.7-slim AS builder

WORKDIR /vector

COPY vector-*-unknown-linux-*.tar.gz ./
RUN tar -xvf vector-*-"$(uname -m)"-unknown-linux-*.tar.gz --strip-components=2

RUN mkdir -p /var/lib/vector

FROM docker.io/debian:12.7-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata systemd && rm -rf /var/lib/apt/lists/*

COPY --from=builder /vector/bin/* /usr/bin/
COPY --from=builder /vector/config/README.md /etc/vector/README.md
COPY --from=builder /var/lib/vector /var/lib/vector

# Smoke test
RUN ["vector", "--version"]

ENTRYPOINT ["/usr/bin/vector"]
