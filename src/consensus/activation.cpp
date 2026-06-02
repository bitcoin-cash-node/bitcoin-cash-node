// Copyright (c) 2018-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/activation.h>

#include <chain.h>
#include <consensus/params.h>
#include <util/system.h>

static bool IsUAHFenabled(const Consensus::Params &params, int nHeight) {
    return nHeight >= params.uahfHeight;
}

bool IsUAHFenabled(const Consensus::Params &params,
                   const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUAHFenabled(params, pindexPrev->nHeight);
}

static bool IsDAAEnabled(const Consensus::Params &params, int nHeight) {
    return nHeight >= params.daaHeight;
}

bool IsDAAEnabled(const Consensus::Params &params,
                  const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsDAAEnabled(params, pindexPrev->nHeight);
}

bool IsMagneticAnomalyEnabled(const Consensus::Params &params,
                              int32_t nHeight) {
    return nHeight >= params.magneticAnomalyHeight;
}

bool IsMagneticAnomalyEnabled(const Consensus::Params &params,
                              const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsMagneticAnomalyEnabled(params, pindexPrev->nHeight);
}

static bool IsGravitonEnabled(const Consensus::Params &params,
                              int32_t nHeight) {
    return nHeight >= params.gravitonHeight;
}

bool IsGravitonEnabled(const Consensus::Params &params,
                       const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsGravitonEnabled(params, pindexPrev->nHeight);
}

static bool IsPhononEnabled(const Consensus::Params &params, int32_t nHeight) {
    return nHeight >= params.phononHeight;
}

bool IsPhononEnabled(const Consensus::Params &params,
                     const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsPhononEnabled(params, pindexPrev->nHeight);
}

bool IsAxionEnabled(const Consensus::Params &params,
                    const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    if (params.asertAnchorParams) {
        // This chain has a checkpointed anchor block, do simple height check
        return pindexPrev->nHeight >= params.asertAnchorParams->nHeight;
    }

    // Otherwise, do the MTP check
    return pindexPrev->GetMedianTimePast() >=
           gArgs.GetArg("-axionactivationtime", params.axionActivationTime);
}

// Upgrade 9
std::optional<int32_t> g_Upgrade9HeightOverride;

int32_t GetUpgrade9ActivationHeight(const Consensus::Params &params) {
    return g_Upgrade9HeightOverride.value_or(params.upgrade9Height);
}

bool IsUpgrade9EnabledForHeightPrev(const Consensus::Params &params, const int32_t nHeightPrev) {
    return nHeightPrev >= GetUpgrade9ActivationHeight(params);
}

bool IsUpgrade9Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUpgrade9EnabledForHeightPrev(params, pindexPrev->nHeight);
}

// Upgrade 10
std::optional<int32_t> g_Upgrade10HeightOverride;

int32_t GetUpgrade10ActivationHeight(const Consensus::Params &params) {
    return g_Upgrade10HeightOverride.value_or(params.upgrade10Height);
}

static bool IsUpgrade10EnabledForHeightPrev(const Consensus::Params &params, const int32_t nHeightPrev) {
    return nHeightPrev >= GetUpgrade10ActivationHeight(params);
}

bool IsUpgrade10Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUpgrade10EnabledForHeightPrev(params, pindexPrev->nHeight);
}

// Upgrade 11
std::optional<int32_t> g_Upgrade11HeightOverride;

int32_t GetUpgrade11ActivationHeight(const Consensus::Params &params) {
    return g_Upgrade11HeightOverride.value_or(params.upgrade11Height);
}

static bool IsUpgrade11EnabledForHeightPrev(const Consensus::Params &params, const int32_t nHeightPrev) {
    return nHeightPrev >= GetUpgrade11ActivationHeight(params);
}

bool IsUpgrade11Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUpgrade11EnabledForHeightPrev(params, pindexPrev->nHeight);
}

// Upgrade 12
std::optional<int32_t> g_Upgrade12HeightOverride;

int32_t GetUpgrade12ActivationHeight(const Consensus::Params &params) {
    return g_Upgrade12HeightOverride.value_or(params.upgrade12Height);
}

static bool IsUpgrade12EnabledForHeightPrev(const Consensus::Params &params, const int32_t nHeightPrev) {
    return nHeightPrev >= GetUpgrade12ActivationHeight(params);
}

bool IsUpgrade12Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUpgrade12EnabledForHeightPrev(params, pindexPrev->nHeight);
}

// Upgrade 2027
static bool IsUpgrade2027Enabled(const Consensus::Params &params, const int64_t nMedianTimePast) {
    return nMedianTimePast >= gArgs.GetArg("-upgrade2027activationtime", params.upgrade2027ActivationTime);
}

bool IsUpgrade2027Enabled(const Consensus::Params &params, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsUpgrade2027Enabled(params, pindexPrev->GetMedianTimePast());
}
