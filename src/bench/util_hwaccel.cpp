// Copyright (c) 2026-present The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <util/hwaccel.h>

#include <uint256.h>

#include <span>

// Naïve "IsAllZeros" check that just does a simple bytewise scan (should be slowest)
static bool IsAllZeros_NaiveImpl(const std::span<std::byte> &span) {
    for (auto b : span) {
        if (b != std::byte{0}) {
            return false;
        }
    }
    return true;
}

static void IsAllZeros_Naive(benchmark::State &state, const size_t size) {
    std::vector<std::byte> data(size, std::byte{0});
    benchmark::NoOptimize(data);

    BENCHMARK_LOOP {
        benchmark::NoOptimize(IsAllZeros_NaiveImpl(data));
    }
}

// Bench the SIMD-optimized implementation
static void IsAllZeros_SIMD(benchmark::State &state, const size_t size) {
    std::vector<std::byte> data(size, std::byte{0});
    benchmark::NoOptimize(data);

    BENCHMARK_LOOP {
        benchmark::NoOptimize(hwaccel::IsAllZeros(data));
    }
}

// Bench the internal "portable" implementation (no SIMD)
static void IsAllZeros_Portable(benchmark::State &state, const size_t size) {
    std::vector<std::byte> data(size, std::byte{0});
    benchmark::NoOptimize(data);

    BENCHMARK_LOOP {
        benchmark::NoOptimize(hwaccel::detail::IsAllZerosPortable(data));
    }
}

// Bench uint256::IsNull(), which ultimately calls hwaccel::IsAllZeros in non-consteval contexts
static void IsAllZeros_uint256_IsNull(benchmark::State &state) {
    uint256 u256;
    benchmark::NoOptimize(u256);

    BENCHMARK_LOOP {
        benchmark::NoOptimize(u256.IsNull());
    }
}

static void IsAllZeros_Naive_8(benchmark::State &state) { IsAllZeros_Naive(state, 8); }
static void IsAllZeros_Naive_16(benchmark::State &state) { IsAllZeros_Naive(state, 16); }
static void IsAllZeros_Naive_520(benchmark::State &state) { IsAllZeros_Naive(state, 520); }
static void IsAllZeros_Naive_10000(benchmark::State &state) { IsAllZeros_Naive(state, 10000); }

BENCHMARK(IsAllZeros_Naive_8, 100'000);
BENCHMARK(IsAllZeros_Naive_16, 100'000);
BENCHMARK(IsAllZeros_Naive_520, 100'000);
BENCHMARK(IsAllZeros_Naive_10000, 100'000);

static void IsAllZeros_SIMD_8(benchmark::State &state) { IsAllZeros_SIMD(state, 8); }
static void IsAllZeros_SIMD_16(benchmark::State &state) { IsAllZeros_SIMD(state, 16); }
static void IsAllZeros_SIMD_520(benchmark::State &state) { IsAllZeros_SIMD(state, 520); }
static void IsAllZeros_SIMD_10000(benchmark::State &state) { IsAllZeros_SIMD(state, 10000); }

BENCHMARK(IsAllZeros_SIMD_8, 100'000);
BENCHMARK(IsAllZeros_SIMD_16, 100'000);
BENCHMARK(IsAllZeros_SIMD_520, 100'000);
BENCHMARK(IsAllZeros_SIMD_10000, 100'000);

static void IsAllZeros_Portable_8(benchmark::State &state) { IsAllZeros_Portable(state, 8); }
static void IsAllZeros_Portable_16(benchmark::State &state) { IsAllZeros_Portable(state, 16); }
static void IsAllZeros_Portable_520(benchmark::State &state) { IsAllZeros_Portable(state, 520); }
static void IsAllZeros_Portable_10000(benchmark::State &state) { IsAllZeros_Portable(state, 10000); }

BENCHMARK(IsAllZeros_Portable_8, 100'000);
BENCHMARK(IsAllZeros_Portable_16, 100'000);
BENCHMARK(IsAllZeros_Portable_520, 100'000);
BENCHMARK(IsAllZeros_Portable_10000, 100'000);

BENCHMARK(IsAllZeros_uint256_IsNull, 100'000);
