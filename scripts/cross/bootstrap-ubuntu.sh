#!/bin/sh
set -o errexit

echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries

apt-get update
apt-get install -y \
  apt-transport-https \
  gnupg \
  wget

# we need LLVM >= 3.9 for onig_sys/bindgen

cat <<-EOF > /etc/apt/sources.list.d/llvm.list
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main
EOF

wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key| apt-key add -

apt-get update

# needed by onig_sys
apt-get install -y \
      libclang1-9 \
      llvm-9 \
      unzip

# Xenial ships OpenSSL 1.0.2g; openssl-sys requires >= 1.1.0.
# Pull libssl-dev 1.1.x from Ubuntu 18.04 Bionic security repo.
echo "deb http://security.ubuntu.com/ubuntu bionic-security main" > /etc/apt/sources.list.d/bionic-security.list
apt-get update
apt-get install -y libssl1.1 libssl-dev