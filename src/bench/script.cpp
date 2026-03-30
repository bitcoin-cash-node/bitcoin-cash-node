// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <random.h>
#include <script/script.h>
#include <script/standard.h>

#include <cassert>

// Create a CScript in a loop, one that is smaller than the prevector static capacity
static void ScriptAppendSmall(benchmark::State &state) {
    constexpr size_t expectedSize = 23u;
    static_assert(expectedSize <= CScript::static_capacity());
    // For this bench, we create a scriptPubKey corresponding to a random p2sh20 address
    uint160 randomHash{uint160::Uninitialized};
    GetRandBytes(randomHash.data(), randomHash.size());
    const CTxDestination dest{ScriptID{randomHash}};

    assert(IsValidDestination(dest));

    BENCHMARK_LOOP {
        const CScript scriptPubKey = GetScriptForDestination(dest);
        assert(scriptPubKey.size() == expectedSize);
    }
}

// Create a CScript in a loop, one that is larger than the prevector static capacity
static void ScriptAppendLarge(benchmark::State &state) {
    constexpr size_t expectedSize = 35u;
    static_assert(expectedSize > CScript::static_capacity());
    // For this bench, we create a scriptPubKey corresponding to a random p2sh32 address
    uint256 randomHash{uint256::Uninitialized};
    GetRandBytes(randomHash.data(), randomHash.size());
    const CTxDestination dest{ScriptID{randomHash}};

    assert(IsValidDestination(dest));

    BENCHMARK_LOOP {
        const CScript scriptPubKey = GetScriptForDestination(dest);
        assert(scriptPubKey.size() == expectedSize);
    }
}

BENCHMARK(ScriptAppendSmall, 8000 * 1000);
BENCHMARK(ScriptAppendLarge, 8000 * 1000);
