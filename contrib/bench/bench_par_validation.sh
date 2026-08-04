#!/usr/bin/env bash
#
# This script is intended to support users in setting the best `-par` option on their system
#
# If you already have cloned and built the project,
# you can simply run the last three lines from your `build` directory
# Otherwise, if you're starting from a clean system
# (for example testing cloud server performance)
# uncomment the first lines before running.
#
# Usage: bash contrib/bench/bench_par_validation.sh

export LC_ALL=C

#sudo apt update
#sudo apt -y upgrade
#sudo apt-get -y install build-essential cmake git libboost-chrono-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev libevent-dev libminiupnpc-dev libssl-dev libzmq3-dev help2man ninja-build python3
#sudo apt-get -y install libdb-dev libdb++-dev
#git clone https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node.git
#cd bitcoin-cash-node
#git checkout v26.0.0 # Should you run into any errors, check out the latest release tag and try again

#mkdir build
#cd build

#cmake -GNinja .. -DBUILD_BITCOIN_WALLET=OFF -DBUILD_BITCOIN_QT=OFF -DCMAKE_BUILD_TYPE=Release
#ninja bench_bitcoin

num_cores=$(grep -c ^processor /proc/cpuinfo)
echo "Detected CPU: $(lscpu | grep "Model name")"
echo "$num_cores cores found on this CPU, running $num_cores tests. If this is incorrect, run the following suite manually."
for i in $(seq 1 "$num_cores"); do src/bench/bench_bitcoin -filter=CCheckQueue_RealBlock_32MB_NoCacheStore -par="$i"; done
for i in $(seq 1 "$num_cores"); do src/bench/bench_bitcoin -filter=CCheckQueue_RealBlock_32MB_WithCacheStore -par="$i"; done