FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5

COPY scripts/cross/bootstrap-ubuntu.sh scripts/environment/install-protoc.sh /
RUN /bootstrap-ubuntu.sh && bash /install-protoc.sh

# Fix bindgen cross-compilation: install clang-9 for builtin headers (stddef.h)
# and set include paths for cross-compilation target
# See: https://github.com/cross-rs/cross/issues/1389
RUN apt-get update && apt-get install -y clang-9
ENV BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=/usr/aarch64-linux-gnu -I/usr/lib/llvm-9/lib/clang/9.0.1/include"

# krb5-src cross-compilation: skip configure tests that can't run when cross-compiling
ENV krb5_cv_attr_constructor_destructor=yes
ENV ac_cv_func_regcomp=yes
ENV ac_cv_printf_positional=yes
