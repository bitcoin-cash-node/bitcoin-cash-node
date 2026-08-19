// Copyright (c) 2017 Amaury SÉCHET
// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <feerate.h>
#include <policy/policy.h>
#include <util/noncopyable.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>

/** Default for -usecashaddr */
static constexpr bool DEFAULT_USE_CASHADDR = true;

class CChainParams;

class Config : public NonCopyable {
public:
    /** Convenience. Returns the consensus max block size as configured by Consensus::Params for the current chain.
        Note: If ABLA is enabled, this is the max block size floor for ABLA.
        Note2: May return the value (if any) set by SetBlockSizeOverride() (functional tests only). */
    virtual uint64_t GetDefaultConsensusBlockSize() const = 0;

    /** Functional tests only: corresponds to the hidden CLI arg: -forceblocksize */
    virtual bool SetBlockSizeOverride(std::optional<uint64_t> overrideBlockSize) = 0;

    /** Look-ahead "guess" for the max blocksize (actual blocksize limit is guaranteed to be <= this value for
        blocks within the block download window). This value gets updated by validation.cpp when the tip changes.
        Used by net code and some pre-checks on blocks to discard blocks that are definitely oversized. */
    virtual uint64_t GetMaxBlockSizeLookAheadGuess() const = 0;
    virtual void NotifyMaxBlockSizeLookAheadGuessChanged(uint64_t) const = 0;

    /** Set the largest block size this node will generate (mine) in bytes. */
    virtual void SetGeneratedBlockSizeBytes(uint64_t blockSize) = 0;
    /** Set the largest block size this node will generate (mine), in terms of
        percentage of the current block size as determined by ABLA.
        Returns false if `percent` is not in the range [0.0, 100.0]. */
    virtual bool SetGeneratedBlockSizePercent(double percent) = 0;
    /** Returns the maximum mined block size in bytes, which is always <= `currentMaxBlockSize`. */
    virtual uint64_t GetGeneratedBlockSize(uint64_t currentMaxBlockSize) const = 0;
    /** The maximum amount of RAM to be used in the mempool before TrimToSize is called. */
    virtual void SetMaxMemPoolSize(uint64_t maxMemPoolSize) = 0;
    virtual uint64_t GetMaxMemPoolSize() const = 0;
    virtual bool SetInvBroadcastRate(uint64_t rate) = 0;
    virtual uint64_t GetInvBroadcastRate() const = 0;
    virtual bool SetInvBroadcastInterval(uint64_t interval) = 0;
    virtual uint64_t GetInvBroadcastInterval() const = 0;
    virtual const CChainParams &GetChainParams() const = 0;
    virtual void SetCashAddrEncoding(bool) = 0;
    virtual bool UseCashAddrEncoding() const = 0;

    virtual void SetExcessUTXOCharge(Amount amt) = 0;
    virtual Amount GetExcessUTXOCharge() const = 0;

    virtual void SetRejectSubVersions(const std::set<std::string> &reject) = 0;
    virtual const std::set<std::string> & GetRejectSubVersions() const = 0;

    virtual void SetGBTCheckValidity(bool) = 0;
    virtual bool GetGBTCheckValidity() const = 0;

    virtual void SetAllowUnconnectedMining(bool) = 0;
    virtual bool GetAllowUnconnectedMining() const = 0;
};

class GlobalConfig final : public Config {
public:
    GlobalConfig();
    uint64_t GetDefaultConsensusBlockSize() const override;
    bool SetBlockSizeOverride(std::optional<uint64_t> blockSize) override;
    uint64_t GetMaxBlockSizeLookAheadGuess() const override;
    void NotifyMaxBlockSizeLookAheadGuessChanged(uint64_t) const override;
    void SetGeneratedBlockSizeBytes(uint64_t blockSize) override;
    bool SetGeneratedBlockSizePercent(double percent) override;
    uint64_t GetGeneratedBlockSize(uint64_t currentMaxBlockSize) const override;
    void SetMaxMemPoolSize(uint64_t maxMemPoolSize) override { nMaxMemPoolSize = maxMemPoolSize; }
    uint64_t GetMaxMemPoolSize() const override { return nMaxMemPoolSize; }
    //! Note: `rate` may not exceed MAX_INV_BROADCAST_RATE (1 million)
    bool SetInvBroadcastRate(uint64_t rate) override;
    uint64_t GetInvBroadcastRate() const override { return nInvBroadcastRate; }
    //! Note: `interval` may not exceed MAX_INV_BROADCAST_INTERVAL (1 million)
    bool SetInvBroadcastInterval(uint64_t interval) override;
    uint64_t GetInvBroadcastInterval() const override { return nInvBroadcastInterval; }
    const CChainParams &GetChainParams() const override;
    void SetCashAddrEncoding(bool) override;
    bool UseCashAddrEncoding() const override;

    void SetExcessUTXOCharge(Amount) override;
    Amount GetExcessUTXOCharge() const override;

    void SetRejectSubVersions(const std::set<std::string> &reject) override { rejectSubVersions = reject; }
    const std::set<std::string> & GetRejectSubVersions() const override { return rejectSubVersions; }

    void SetGBTCheckValidity(bool b) override { gbtCheckValidity = b; }
    bool GetGBTCheckValidity() const override { return gbtCheckValidity; }

    //! "Unconnected mining" (default false). If true, getblocktemplate[light] works even if not connected to any peers.
    void SetAllowUnconnectedMining(bool b) override { allowUnconnectedMining = b; }
    bool GetAllowUnconnectedMining() const override { return allowUnconnectedMining; }

private:
    bool useCashAddr;
    bool gbtCheckValidity;
    bool allowUnconnectedMining;
    Amount excessUTXOCharge;
    uint64_t nInvBroadcastRate;
    uint64_t nInvBroadcastInterval;

    /** Override for the blockSize for functional tests */
    std::optional<uint64_t> blockSizeOverride;

    /** The largest block size this node will generate. Stores either a size in bytes or a percentage (double). */
    std::variant<uint64_t, double> varGeneratedBlockSizeParam;

    /** The maximum amount of RAM to be used in the mempool before TrimToSize is called. */
    uint64_t nMaxMemPoolSize;

    std::set<std::string> rejectSubVersions;

    /** Temporarily set to mutable because consensus code only gets passed a `const Config &`, but it does need to
        modify this value as the chain tip is updated. */
    mutable std::atomic<uint64_t> nMaxBlockSizeWorstCaseGuess{0u};
};

// Dummy for subclassing in unittests
class DummyConfig : public Config {
public:
    DummyConfig();
    DummyConfig(const std::string &net);
    DummyConfig(std::unique_ptr<CChainParams> chainParamsIn);
    uint64_t GetDefaultConsensusBlockSize() const override { return 0; }
    bool SetBlockSizeOverride(std::optional<uint64_t>) override { return false; }
    uint64_t GetMaxBlockSizeLookAheadGuess() const override { return 0; }
    void NotifyMaxBlockSizeLookAheadGuessChanged(uint64_t) const override {}
    void SetGeneratedBlockSizeBytes(uint64_t) override {}
    bool SetGeneratedBlockSizePercent(double) override { return false; }
    uint64_t GetGeneratedBlockSize(uint64_t) const override { return 0; }
    void SetMaxMemPoolSize(uint64_t) override {}
    uint64_t GetMaxMemPoolSize() const override { return 0; }
    bool SetInvBroadcastRate(uint64_t) override { return false; }
    uint64_t GetInvBroadcastRate() const override { return 0; }
    bool SetInvBroadcastInterval(uint64_t) override { return false; }
    uint64_t GetInvBroadcastInterval() const override {return 0; }

    void SetChainParams(const std::string &net);
    const CChainParams &GetChainParams() const override { return *chainParams; }

    void SetCashAddrEncoding(bool) override {}
    bool UseCashAddrEncoding() const override { return false; }

    void SetExcessUTXOCharge(Amount) override {}
    Amount GetExcessUTXOCharge() const override { return Amount::zero(); }

    void SetRejectSubVersions(const std::set<std::string> &) override {}
    const std::set<std::string> & GetRejectSubVersions() const override {
        static const std::set<std::string> dummy;
        return dummy;
    }

    void SetGBTCheckValidity(bool) override {}
    bool GetGBTCheckValidity() const override { return false; }

    void SetAllowUnconnectedMining(bool) override {}
    bool GetAllowUnconnectedMining() const override { return false; }

private:
    std::unique_ptr<CChainParams> chainParams;
};

// Temporary woraround.
const Config &GetConfig();
Config &GetMutableConfig();
