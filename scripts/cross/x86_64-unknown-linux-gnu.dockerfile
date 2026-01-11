FROM ghcr.io/cross-rs/x86_64-unknown-linux-gnu:0.2.5

COPY scripts/cross/bootstrap-ubuntu.sh scripts/environment/install-protoc.sh /
RUN /bootstrap-ubuntu.sh && bash /install-protoc.sh

# Fix bindgen cross-compilation: install clang-9 for builtin headers (stddef.h)
# See: https://github.com/cross-rs/cross/issues/1389
RUN apt-get update && apt-get install -y clang-9
ENV BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_gnu="-I/usr/include -I/usr/lib/llvm-9/lib/clang/9.0.1/include"
