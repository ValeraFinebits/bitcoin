#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_payjoin
export CI_IMAGE_NAME_TAG="mirror.gcr.io/rust:1.85.1-bookworm"
export APT_LLVM_V="17"
export PACKAGES="clang-${APT_LLVM_V} llvm-${APT_LLVM_V} libboost-dev libsqlite3-dev"
export PAYJOIN=1
export GOAL="all"
export MAKEJOBS="-j4"
export CARGO_BUILD_JOBS=4
export RUN_FUNCTIONAL_TESTS=false
export BITCOIN_CONFIG="\
 -DCMAKE_BUILD_TYPE=Debug \
 -DCMAKE_C_COMPILER=clang \
 -DCMAKE_CXX_COMPILER=clang++ \
 -DENABLE_IPC=OFF \
 -DENABLE_PAYJOIN=ON \
"
