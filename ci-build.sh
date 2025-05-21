#!/bin/sh

set -eux

#Discard all uncommited changes
git checkout -f

#Build LiTL
nproc="$(nproc)"
make BUILD_MUSL=1 no_cond_var -j "$nproc"

#Delete source files, keep only .so libraries and .sh scripts for use those libraries
if [ "${1:-}" = "delete_sources" ]; then
    find . -mindepth 1 ! -path "./.git/*" ! -name ".git" ! -name ".gitignore" ! -name ".clang-format" \
        ! -path "./lib/*" ! -name "lib" \
        ! -name "*.sh" \
        -exec rm -rf {} +
fi
