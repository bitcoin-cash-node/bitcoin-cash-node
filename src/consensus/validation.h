// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <dsproof/dspid.h>

#include <string>

class Config;

/** "reject" message codes */
inline constexpr uint8_t REJECT_MALFORMED = 0x01;
inline constexpr uint8_t REJECT_INVALID = 0x10;
inline constexpr uint8_t REJECT_OBSOLETE = 0x11;
inline constexpr uint8_t REJECT_DUPLICATE = 0x12;
inline constexpr uint8_t REJECT_NONSTANDARD = 0x40;
inline constexpr uint8_t REJECT_INSUFFICIENTFEE = 0x42;
inline constexpr uint8_t REJECT_CHECKPOINT = 0x43;

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   //!< everything ok
        MODE_INVALID, //!< network rule violation (DoS value may be set)
        MODE_ERROR,   //!< run-time error
    } mode = MODE_VALID;
    int nDoS = 0;
    std::string strRejectReason;
    unsigned int chRejectCode = 0;
    bool corruptionPossible = false;
    std::string strDebugMessage;

    //! Validation data related to DoubleSpendProof. The most common case is that *no* DSP exists. In order to minimize
    //! the memory & CPU footprint of the DSProof facility, we wrap this hash in a tiny object for the common case.
    DspIdPtr dspIdPtr;

public:
    CValidationState() = default;

    bool DoS(int level, bool ret = false, unsigned int chRejectCodeIn = 0,
             const std::string &strRejectReasonIn = "",
             bool corruptionIn = false,
             const std::string &strDebugMessageIn = "") {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        if (mode == MODE_ERROR) {
            return ret;
        }
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }

    bool Invalid(bool ret = false, unsigned int _chRejectCode = 0,
                 const std::string &_strRejectReason = "",
                 const std::string &_strDebugMessage = "") {
        return DoS(0, ret, _chRejectCode, _strRejectReason, false,
                   _strDebugMessage);
    }
    bool Error(const std::string &strRejectReasonIn) {
        if (mode == MODE_VALID) {
            strRejectReason = strRejectReasonIn;
        }

        mode = MODE_ERROR;
        return false;
    }

    bool IsValid() const { return mode == MODE_VALID; }
    bool IsInvalid() const { return mode == MODE_INVALID; }
    bool IsError() const { return mode == MODE_ERROR; }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }

    bool CorruptionPossible() const { return corruptionPossible; }
    void SetCorruptionPossible() { corruptionPossible = true; }
    unsigned int GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }

    // DoubleSpendProof getters and setters
    bool HasDspId() const { return bool(dspIdPtr); }
    DspId GetDspId() const { return dspIdPtr ? *dspIdPtr : DspId{}; }
    void SetDspId(const DspId &dspId) { dspIdPtr = dspId; }

    // Used by e.g. the testmempoolaccept RPC for the "reject-details" result key
    std::string ToString() const {
        if (IsValid()) {
            return "Valid";
        }

        if (!strDebugMessage.empty()) {
            return strRejectReason + ", " + strDebugMessage;
        }

        return strRejectReason;
    }
};

/// Class used to paramaterize operation of certain validation functions such as e.g. CheckBlock() in validation.h
class BlockValidationOptions {
    bool checkPoW;
    bool checkMerkleRoot;

public:
    // Do full validation by default
    BlockValidationOptions(bool _checkPow = true, bool _checkMerkleRoot = true)
        : checkPoW(_checkPow), checkMerkleRoot(_checkMerkleRoot) {}

    // Compatibility c'tor to keep old source working (config param unused but may be used again someday)
    BlockValidationOptions(const Config &config [[maybe_unused]], bool _checkPow = true, bool _checkMerkleRoot = true)
        : BlockValidationOptions(_checkPow, _checkMerkleRoot) {}

    BlockValidationOptions withCheckPoW(bool _checkPoW = true) const {
        BlockValidationOptions ret = *this;
        ret.checkPoW = _checkPoW;
        return ret;
    }

    BlockValidationOptions withCheckMerkleRoot(bool _checkMerkleRoot = true) const {
        BlockValidationOptions ret = *this;
        ret.checkMerkleRoot = _checkMerkleRoot;
        return ret;
    }

    bool shouldValidatePoW() const { return checkPoW; }
    bool shouldValidateMerkleRoot() const { return checkMerkleRoot; }
};
