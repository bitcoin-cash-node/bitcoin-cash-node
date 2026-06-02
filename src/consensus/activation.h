// Copyright (c) 2018-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>

class CBlockIndex;

namespace Consensus {
struct Params;
}

/** Check if UAHF has activated. */
bool IsUAHFenabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev);

/** Check if DAA HF has activated. */
bool IsDAAEnabled(const Consensus::Params &params,
                  const CBlockIndex *pindexPrev);

/** Check if Nov 15, 2018 HF has activated using block height. */
bool IsMagneticAnomalyEnabled(const Consensus::Params &params, int32_t nHeight);
/** Check if Nov 15, 2018 HF has activated using previous block index. */
bool IsMagneticAnomalyEnabled(const Consensus::Params &params,
                              const CBlockIndex *pindexPrev);

/** Check if Nov 15th, 2019 protocol upgrade has activated. */
bool IsGravitonEnabled(const Consensus::Params &params,
                       const CBlockIndex *pindexPrev);

/** Check if May 15th, 2020 protocol upgrade has activated. */
bool IsPhononEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev);

/** Check if November 15th, 2020 protocol upgrade has activated. */
bool IsAxionEnabled(const Consensus::Params &params,
                    const CBlockIndex *pindexPrev);

/** Note: May 15th, 2021 protocol upgrade was relay-only, and has no on-chain rules.
 *  The function "IsTachyonEnabled" that used to live here has been removed. */

/**
 *  Global: If set, the user overrode the -upgrade9activationheight from the command-line or config file. Unit tests
 *  also may temporarily set this value. If this is not set, the *Upgrade9*() functions use hard-coded chain params for
 *  the activation height rather than this override.
 */
extern std::optional<int32_t> g_Upgrade9HeightOverride;

/** Check if May 15th, 2023 protocol upgrade has activated. */
bool IsUpgrade9EnabledForHeightPrev(const Consensus::Params &params, const int32_t nHeightPrev);
bool IsUpgrade9Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev);
/** Returns the height of the activation block. This is one less than the actual block for which the new rules apply. */
int32_t GetUpgrade9ActivationHeight(const Consensus::Params &params);

/**
 *  Global: If set, the user overrode the -upgrade10activationheight from the command-line or config file. Unit tests
 *  also may temporarily set this value. If this is not set, the *Upgrade10*() functions use hard-coded chain params for
 *  the activation height rather than this override.
 */
extern std::optional<int32_t> g_Upgrade10HeightOverride;

/** Check if May 15th, 2024 protocol upgrade has activated. */
bool IsUpgrade10Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev);
/** Returns the height of the activation block. This is one less than the actual block for which the new rules apply. */
int32_t GetUpgrade10ActivationHeight(const Consensus::Params &params);

/**
 *  Global: If set, the user overrode the -upgrade11activationheight from the command-line or config file. Unit tests
 *  also may temporarily set this value. If this is not set, the *Upgrade11*() functions use hard-coded chain params for
 *  the activation height rather than this override.
 */
extern std::optional<int32_t> g_Upgrade11HeightOverride;

/** Check if May 15th, 2025 protocol upgrade has activated. */
bool IsUpgrade11Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev);
/** Returns the height of the activation block. This is one less than the actual block for which the new rules apply. */
int32_t GetUpgrade11ActivationHeight(const Consensus::Params &params);

/**
 *  Global: If set, the user overrode the -upgrade12activationheight from the command-line or config file. Unit tests
 *  also may temporarily set this value. If this is not set, the *Upgrade12*() functions use hard-coded chain params for
 *  the activation height rather than this override.
 */
extern std::optional<int32_t> g_Upgrade12HeightOverride;

/** Check if May 15th, 2026 protocol upgrade has activated. */
bool IsUpgrade12Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev);
/** Returns the height of the activation block. This is one less than the actual block for which the new rules apply. */
int32_t GetUpgrade12ActivationHeight(const Consensus::Params &params);

/** Check if May 15th, 2027 protocol upgrade has activated. */
bool IsUpgrade2027Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev);
