#! /usr/bin/env bash
set -e -o verbose

rustup show # causes installation of version from rust-toolchain.toml
rustup default "$(rustup show active-toolchain | awk '{print $1;}')"
if [[ "$(cross --version | grep cross)" != "cross 0.2.5" ]] ; then
  rustup run stable cargo install cross --version 0.2.5 --force --locked
fi
if [[ "$(cargo-nextest --version)" != "cargo-nextest 0.9.47" ]] ; then
  rustup run stable cargo install cargo-nextest --version 0.9.47 --force --locked
fi
