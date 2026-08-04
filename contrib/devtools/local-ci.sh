#!/usr/bin/env bash

# A simple script to run all .gitlab-ci.yml jobs locally. It is manually curated,
# so any changes to .gitlab-ci.yml may need corresponding adustments here.
#
# You can watch a summary of the pipeline progress in a second terminal with:
#
#   docker exec -it $(docker ps -ql) bash -c 'tail -n +1 -f $(ls /tmp/ci-results*)'

export LC_ALL=C
export TRAVIS=1
export CCACHE_BASEDIR=/bchn/
export CCACHE_DIR=/bchn/ccache
export CCACHE_COMPILERCHECK=content

docker_image=docker.io/bitcoincashnode/buildenv@sha256:f4ebe3d250eebbff0a78d078199ef58f161da3a1a2c5d0d2d0609898242ab9ce # debian-v7

PROJECT_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/../..
DOCKER=${DOCKER:-docker}

# Build a command line argument for docker, enabling interactive mode if stdin
# is a tty and enabling tty in docker if stdout is a tty.
export DOCKER_RUN_TTY=""
if [ -t 0 ] ; then export DOCKER_RUN_TTY="${DOCKER_RUN_TTY}i" ; fi
if [ -t 1 ] ; then export DOCKER_RUN_TTY="${DOCKER_RUN_TTY}t" ; fi
if [ -n "$DOCKER_RUN_TTY" ] ; then export DOCKER_RUN_TTY="-${DOCKER_RUN_TTY}" ; fi

# Only set color variables if stdout is a tty
if [ -t 1 ]; then
    red="\e[1;31m" green="\e[1;32m" yellow="\e[1;33m" bold="\e[1m" normal="\e[0m"
else
    red="" green="" yellow="" bold="" normal=""
fi

# Require that binfmt_misc is mounted, so that qemu can be used to run aarch64 binaries.
if [ ! -d /proc/sys/fs/binfmt_misc ]; then
    echo -e "${red}ERROR: binfmt_misc is not mounted${normal}"
    exit 1
fi

if [ "${INSIDE_DOCKER:-}" != "1" ]; then
    mounts=(-v "$PROJECT_ROOT:/bchn:ro")
    if [ -f "$PROJECT_ROOT/.git" ]; then
        repo=$(git -C "$PROJECT_ROOT" rev-parse --path-format=absolute --git-common-dir) || exit
        mounts+=(-v "$repo:$repo:ro")
    fi
    rw_dirs=("build" "buildFuzzer" "ccache" "depends" "src/bench")
    mkdir -p "${rw_dirs[@]/#/$PROJECT_ROOT/}"
    for rw_dir in "${rw_dirs[@]}"; do
        mounts+=(-v "$PROJECT_ROOT/$rw_dir:/bchn/$rw_dir")
    done
    cmd=("$DOCKER" run --rm "$DOCKER_RUN_TTY" \
        "${mounts[@]}" \
        -w /bchn \
        -e "INSIDE_DOCKER=1" \
        "$docker_image" \
        bash -c "/bchn/contrib/devtools/local-ci.sh" "$@")
    echo -e "Running: ${bold}${cmd[*]}${normal}"
    echo
    "${cmd[@]}"
    exit $?
fi

if [ -f /sys/fs/cgroup/pids.max ] && [ "$(cat /sys/fs/cgroup/pids.max)" -le 2048 ]; then
    echo -e "${red}WARNING: The container is running with a pids limit of $(cat /sys/fs/cgroup/pids.max), which may cause some tests to fail. Consider increasing the limit.${normal}"
fi

sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' /opt/venv/pyvenv.cfg
# shellcheck disable=SC1091
. /opt/venv/bin/activate
python -m pip freeze
git config --global --add safe.directory /bchn

# Limit ccache to 3 GB (from default 5 GB).
# 'ninja all check bench_bitcoin' produces ~2.1GB cache (Jan 2021)
ccache -M 3G

run_test() {
    job=$1
    job_num=$2
    num_jobs=$3


    # Print job header
    charlen=$((${#job}+${#job_num}+${#num_jobs}+7))
    line="$(printf '=%.0s' $(seq 1 $charlen))"
    echo
    echo -e "${yellow}$line"
    echo -e "${yellow}Job ${job_num}/${num_jobs}:${normal} ${bold}$1${normal}"
    echo -e "${yellow}$line${normal}"

    # Run job and record result
    printf "${yellow}Job ${job_num}/${num_jobs}:${normal} ${bold}%-42s${normal}" "$job:" >> "$results"
    $job
    exit_code=$?
    if [ "$exit_code" -eq 0 ]; then
        echo -e "${green}pass${normal}" | tee -a "$results"
    else
        echo -e "${red}FAIL${normal}" | tee -a "$results"
    fi
}

# Some helpers
clear_cmake() {
    rm -rf CMakeCache.txt CMakeFiles
}
debian-clang-env() {
    export CC="clang-18"
    export CXX="clang++-18"
}
test_bitcoin() {
    ./src/test/test_bitcoin --logger=HRF:JUNIT,message,junit_unit_tests.xml
}
bench_bitcoin() {
    ./src/bench/bench_bitcoin -evals=1
}

# Define CI jobs
static-run-linters() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja -DENABLE_MAN=OFF .. &&
    ninja check-lint
}
build-aarch64-depends() {
    cd /bchn/depends &&
    make build-linux-aarch64 -j "$(nproc)"
}
build-win-64-depends() {
    cd /bchn/depends &&
    make build-win64 HOST=x86_64-w64-mingw32 NO_QT=1 JOBS="$(nproc)"
}
build-debian() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DDOC_ONLINE=ON &&
    ninja
}
build-debian-tests() {
    # These 'needs:' statements are preserved in comments to help keep jobs in a logical order
    # needs: ["build-debian"]
    ninja test_bitcoin
}
test-debian-unittests() {
    # needs: ["build-debian-tests"]
    test_bitcoin
}
test-debian-benchmarks() {
    # needs: ["build-debian"]
    ninja bitcoin-bench &&
    bench_bitcoin
}
test-debian-utils() {
    # needs: ["build-debian"]
    ninja check-bitcoin-qt check-bitcoin-seeder check-bitcoin-util check-devtools check-leveldb check-rpcauth check-secp256k1 check-univalue
}
test-debian-functional-extended() {
    # needs: ["build-debian"]
    export TEST_RUNNER_EXTRA="--coverage" &&
    ninja check-functional-extended
}
deploy-debian() {
    # needs: ["build-debian"]
    ninja package
}
pages() {
    # needs: ["build-debian"]
    ninja doc-html
}
build-debian-nowallet() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_WALLET=OFF &&
    ninja
}
test-debian-nowallet-functional-extended() {
    # needs: ["build-debian-nowallet"]
    export TEST_RUNNER_EXTRA="--coverage" &&
    ninja -t restat &&
    ninja check-functional-longeronly
}
build-debian-nowallet-tests() {
    # needs: ["build-debian-nowallet"]
    ninja test_bitcoin
}
test-debian-nowallet-unittests() {
    # needs: ["build-debian-nowallet-tests"]
    test_bitcoin
}
build-debian-clang() {
    cd /bchn/build &&
    debian-clang-env &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF &&
    ninja
}
build-debian-tests-clang() {
    # needs: ["build-debian-clang"]
    debian-clang-env &&
    ninja test_bitcoin
}
test-debian-unittests-clang() {
    # needs: ["build-debian-tests-clang"]
    debian-clang-env &&
    test_bitcoin
}
test-debian-benchmarks-clang() {
    # needs: ["build-debian-clang"]
    debian-clang-env &&
    ninja -t restat &&
    ninja bitcoin-bench &&
    bench_bitcoin
}
test-debian-utils-clang() {
    # needs: ["build-debian-clang"]
    debian-clang-env &&
    ninja -t restat &&
    ninja check-bitcoin-qt check-bitcoin-seeder check-bitcoin-util check-devtools check-leveldb check-rpcauth check-secp256k1 check-univalue
}
build-debian-makefiles() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -G"Unix Makefiles" .. -DENABLE_MAN=OFF &&
    make -j"$(nproc)"
}
build-debian-debug() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DCMAKE_BUILD_TYPE=Debug &&
    ninja
}
build-debian-debug-tests() {
    # needs: ["build-debian-debug"]
    ninja test_bitcoin
}
test-debian-debug-unittests() {
    # needs: ["build-debian-debug-tests"]
    test_bitcoin
}
build-debian-debug-clang() {
    cd /bchn/build &&
    debian-clang-env &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DCMAKE_BUILD_TYPE=Debug &&
    ninja
}
build-debian-debug-clang-tests() {
    # needs: ["build-debian-debug-clang"
    debian-clang-env &&
    ninja test_bitcoin
}
test-debian-debug-clang-unittests() {
    # needs: ["build-debian-debug-clang-tests"]
    test_bitcoin
}
build-win-64() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_QT=OFF -DBUILD_BITCOIN_SEEDER=OFF -DCMAKE_TOOLCHAIN_FILE=../cmake/platforms/Win64.cmake &&
    ninja
}
build-aarch64() {
    cd /bchn/build &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DBUILD_BITCOIN_ZMQ=OFF -DCMAKE_TOOLCHAIN_FILE=../cmake/platforms/LinuxAArch64.cmake -DCMAKE_CROSSCOMPILING_EMULATOR="$(command -v qemu-aarch64-static)" -DEXCLUDE_FUNCTIONAL_TESTS=bchn-rpc-getblocktemplate-sigops &&
    ninja
}
build-aarch64-tests() {
    # needs: ["build-aarch64"]
    ninja test_bitcoin
}
test-aarch64-unittests() {
    # needs: ["build-aarch64-tests"]
    export QEMU_LD_PREFIX="/usr/aarch64-linux-gnu" &&
    $(command -v qemu-aarch64-static) ./src/test/test_bitcoin --logger=HRF:JUNIT,message,junit_unit_tests.xml
}
test-aarch64-functional() {
    # needs: ["build-aarch64"]
    ninja -t restat &&
    export QEMU_LD_PREFIX="/usr/aarch64-linux-gnu" &&
    export NON_TESTS="example_test|test_runner|combine_logs|create_cache" &&
    export LONG_TESTS="abc-p2p-compactblocks|abc-p2p-fullblocktest|feature_block|feature_dbcrash|feature_pruning|mining_getblocktemplate_longpoll|p2p_timeouts|wallet_backup" &&
    export EXCLUDED_TESTS="getblocktemplate_errors|getblocktemplate-timing" &&
    export UI_TESTS=`ls -1 ../test/functional/*.py | xargs -n 1 basename | grep ^ui | tr '\n' '|' | sed 's/|$//'` &&
    test/functional/test_runner.py `ls -1 ../test/functional/*.py | xargs -n 1 basename | egrep -v "($NON_TESTS|$LONG_TESTS|$EXCLUDED_TESTS|$UI_TESTS)"`
}
fuzz-libfuzzer() {
    cd /bchn/buildFuzzer &&
    debian-clang-env &&
    [ -d "qa-assets" ] || git clone --branch master --single-branch --depth=1 https://gitlab.com/bitcoin-cash-node/bchn-sw/qa-assets.git &&
    clear_cmake &&
    cmake -GNinja .. -DENABLE_MAN=OFF -DCCACHE=OFF -DENABLE_SANITIZERS="fuzzer;address" &&
    ninja bitcoin-fuzzers link-fuzz-test_runner.py &&
    ./test/fuzz/test_runner.py -l DEBUG ./qa-assets/fuzz_seed_corpus/
}
sanitizer-undefined() {
    cd /bchn/build &&
    export CC="clang-18" &&
    export CXX="clang++-18" &&
    export ASAN_OPTIONS="log_path=stdout" &&
    export LSAN_OPTIONS="log_path=stdout" &&
    export TSAN_OPTIONS="log_path=stdout" &&
    export UBSAN_OPTIONS="log_path=stdout" &&
    clear_cmake &&
    cmake -GNinja .. -DCCACHE=OFF -DCMAKE_BUILD_TYPE=Debug -DENABLE_CLANG_TIDY=OFF -DENABLE_MAN=OFF -DENABLE_SANITIZERS=undefined &&
    ninja test_bitcoin &&
    test_bitcoin &&
    ninja check-bitcoin-qt check-bitcoin-seeder check-bitcoin-util check-functional
}

# Run the jobs and gather results.
# You can enable/disable jobs by commenting out lines below.
# The indentation is a hint to illustrate job dependencies. For each active job, ensure that its ancestors in the tree are also enabled.
results=$(mktemp /tmp/ci-results.XXXXXX)
ci_jobs=(
    static-run-linters
    build-aarch64-depends
    build-win-64-depends
    build-debian
        build-debian-tests
            test-debian-unittests
        test-debian-benchmarks
        test-debian-utils
        test-debian-functional-extended
        deploy-debian
        pages
    build-debian-nowallet
        test-debian-nowallet-functional-extended
        build-debian-nowallet-tests
            test-debian-nowallet-unittests
    build-debian-clang
        build-debian-tests-clang
            test-debian-benchmarks-clang
        test-debian-utils-clang
        test-debian-unittests-clang
    build-debian-makefiles
    build-debian-debug
        build-debian-debug-tests
            test-debian-debug-unittests
    build-debian-debug-clang
        build-debian-debug-clang-tests
            test-debian-debug-clang-unittests
    build-win-64
    build-aarch64
        build-aarch64-tests
            test-aarch64-unittests
        test-aarch64-functional
    fuzz-libfuzzer
    sanitizer-undefined
)
num_jobs="${#ci_jobs[@]}"
job_num=1
for job in "${ci_jobs[@]}"; do
    run_test "$job" "$job_num" "$num_jobs"
    ((job_num++))
done

# Print results
echo
line=$(printf '=%.0s' $(seq 1 46))
echo -e "${bold}${line}\nResults\n${line}${normal}"
cat "$results"
rm "$results"
