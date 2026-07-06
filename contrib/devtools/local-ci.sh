#!/usr/bin/env bash

# A simple script to run all .gitlab-ci.yml jobs locally. It is manually curated,
# so any changes to .gitlab-ci.yml may need corresponding adustments here.
#
# Run this inside the CI buildenv docker container. E.g., `cd` to your bitcoin-cash-node checkout then run:
# 
# docker run --rm -it -v "$PWD":/bchn -w /bchn bitcoincashnode/buildenv:debian-v6 bash -c contrib/devtools/local-ci.sh

export LC_ALL=C

header() { 
    charlen=$((${#1}+5))
    line="$(printf '=%.0s' $(seq 1 $charlen))"
    echo
    echo -e "\e[1;33m$line\e[0m"
    echo -e "\e[1;33mJob:\e[0m \e[1m$1\e[0m"
    echo -e "\e[1;33m$line\e[0m"
}

export TRAVIS=1
export PIP_CACHE_DIR=/bchn/.cache/pip
export CCACHE_BASEDIR=/bchn/
export CCACHE_DIR=/bchn/ccache
export CCACHE_COMPILERCHECK=content

. /opt/venv/bin/activate
cd /bchn || exit 1
mkdir -p build ccache
git config --global --add safe.directory /bchn
cd build || exit 1

# Limit ccache to 3 GB (from default 5 GB).
# 'ninja all check bench_bitcoin' produces ~2.1GB cache (Jan 2021)
ccache -M 3G

header "static-run-linters"
cmake -GNinja -DENABLE_MAN=OFF ..
ninja check-lint

header "build-win-64-depends"
cd /bchn/depends || exit 1
make build-win64 HOST=x86_64-w64-mingw32 NO_QT=1 JOBS="$(nproc)"

header "build-aarch64-depends"
make build-linux-aarch64 -j "$(nproc)"

header "build-debian"
cd /bchn/build || exit 1
cmake -GNinja .. -DENABLE_MAN=OFF -DDOC_ONLINE=ON
ninja

header "build-debian-tests"
# These 'needs:' statements are preserved in comments to help keep jobs in a logical order
# needs: ["build-debian"]
ninja test_bitcoin

header "test-debian-unittests"
# needs: ["build-debian-tests"]
./src/test/test_bitcoin --logger=HRF:JUNIT,message,junit_unit_tests.xml

header "test-debian-benchmarks"
# needs: ["build-debian"]
ninja bitcoin-bench
src/bench/bench_bitcoin -evals=1

header "test-debian-utils"
# needs: ["build-debian"]
ninja check-bitcoin-qt check-bitcoin-seeder check-bitcoin-util check-devtools check-leveldb check-rpcauth check-secp256k1 check-univalue

header "test-debian-functional"
# needs: ["build-debian"]
ninja check-functional

header "test-debian-functional-extended"
# needs: ["build-debian"]
ninja check-functional-extended

header "deploy-debian"
# needs: ["build-debian"]
ninja package

header "pages"
# needs: ["build-debian"]
ninja doc-html

header "build-debian-nowallet"
cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_WALLET=OFF
ninja

header "build-debian-nowallet-tests"
# needs: ["build-debian-nowallet"]
ninja test_bitcoin

header "build-debian-clang"
cmake -GNinja .. -DENABLE_MAN=OFF
ninja

header "build-debian-tests-clang"
# needs: ["build-debian-clang"]
ninja test_bitcoin

header "build-debian-makefiles"
cmake -G"Unix Makefiles" .. -DENABLE_MAN=OFF
make -j"$(nproc)"

header "build-debian-debug"
cmake -GNinja .. -DENABLE_MAN=OFF -DCMAKE_BUILD_TYPE=Debug
ninja

header "build-debian-debug-tests"
# needs: ["build-debian-debug"]
ninja test_bitcoin

header "build-debian-debug-clang"
cmake -GNinja .. -DENABLE_MAN=OFF -DCMAKE_BUILD_TYPE=Debug
ninja

header "build-debian-debug-clang-tests"
# needs: ["build-debian-debug-clang"
ninja test_bitcoin

header "build-win-64"
cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_QT=OFF -DBUILD_BITCOIN_SEEDER=OFF -DCMAKE_TOOLCHAIN_FILE=../cmake/platforms/Win64.cmake
ninja

header "build-aarch64"
cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_ZMQ=OFF -DCMAKE_TOOLCHAIN_FILE=../cmake/platforms/LinuxAArch64.cmake -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v qemu-aarch64-static)" -DEXCLUDE_FUNCTIONAL_TESTS=bchn-rpc-getblocktemplate-sigops
ninja

header "build-aarch64-tests"
# needs: ["build-aarch64"]
ninja test_bitcoin
