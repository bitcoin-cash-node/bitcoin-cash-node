// Copyright (c) 2026-present The Bitcoin Cash Node developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

// Utility functions that may be hardware-accelerated via SIMD instructions (SSE2, AVX2, etc).
// All functions below fall back to portable versions if the machine we are on is unknown or has no SIMD instructions.
namespace hwaccel {

//! Returns true if the specified byte blob is empty or if it contains nothing but zeroes. False otherwise.
bool IsAllZeros(std::span<const std::byte> bytes) noexcept;

//! Convenience version of above for uint8_t
inline bool IsAllZeros(std::span<const uint8_t> bytes) noexcept { return IsAllZeros(std::as_bytes(bytes)); }

namespace detail {
//! Internal portable version of the above -- always uses plain portable C++ and no SIMD or other platform-specific
//! optimizations. Used by tests & benchmarks.
bool IsAllZerosPortable(const std::span<const std::byte> &bytes) noexcept;
} // namespace detail

} // namespace hwaccel
