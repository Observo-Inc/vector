FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5

COPY scripts/cross/bootstrap-ubuntu.sh scripts/environment/install-protoc.sh /
RUN /bootstrap-ubuntu.sh && bash /install-protoc.sh

# Fix bindgen cross-compilation: add /usr/include as fallback for system headers (stddef.h, etc.)
# See: https://github.com/cross-rs/cross/issues/1389
ENV BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=/usr/aarch64-linux-gnu -idirafter/usr/include"
