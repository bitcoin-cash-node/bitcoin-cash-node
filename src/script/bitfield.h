// Copyright (c) 2019-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

enum class ScriptError;

/**
 * @brief DecodeBitfield - Helper class used by the script interpreter to decode multisig bitfield bytes.
 * @param vch - The bitfield bytes stack item. This stack item must be sized appropriately (`size` + 7 / 8).
 * @param size - The size of the bitfield, in bits. Must be <= 32.
 * @param bitfield - Out param, the bitfield decoded and packed into a single 32-bit machine word.
 * @param serror - Out param, the error (only set if return value is false).
 * @return `false` on error. If `true` is returned, then the `bitfield` out param is populated properly.
 */
bool DecodeBitfield(const std::vector<uint8_t> &vch, unsigned size, uint32_t &bitfield, ScriptError *serror);
