// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <arith_uint256.h>
#include <blockstatus.h>
#include <blockvalidity.h>
#include <clientversion.h>
#include <consensus/abla.h>
#include <consensus/params.h>
#include <crypto/common.h> // for ReadLE64
#include <flatfile.h>
#include <primitives/block.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>

#include <atomic>
#include <ios>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * Maximum amount of time that a block timestamp is allowed to exceed the
 * current network-adjusted time before the block will be accepted.
 */
static constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/**
 * Timestamp window used as a grace period by code that compares external
 * timestamps (such as timestamps passed to RPCs, or wallet key creation times)
 * to block timestamps. This should be set at least as high as
 * MAX_FUTURE_BLOCK_TIME.
 */
static constexpr int64_t TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME;

/**
 * Maximum gap between node time and block time used
 * for the "Catching up..." mode in GUI.
 *
 * Ref: https://github.com/bitcoin/bitcoin/pull/1026
 */
static constexpr int64_t MAX_BLOCK_TIME_GAP = 90 * 60;

/**
 *  Mixin class that provides atomic, thread-safe access to an optional abla::State instance.
 *  Used by CBlockIndex and its subclasses to capture the abla state (if any) of a particular block.
 */
class AblaStateMixin {
    struct PackedState {
        bool engaged : 1;
        uint64_t blockSize : 63; ///< 2^63 is more than we will ever need, since consensus clamps at ~2^31
        uint64_t controlBlockSize;
        uint64_t elasticBufferSize;

        constexpr PackedState &clear() noexcept {
            engaged = false;
            blockSize = controlBlockSize = elasticBufferSize = 0;
            return *this;
        }

        std::optional<abla::State> unpack() const noexcept {
            std::optional<abla::State> ret;
            if (engaged) {
                ret.emplace() = abla::State::FromTuple({blockSize, controlBlockSize, elasticBufferSize});
            }
            return ret;
        }

        static PackedState pack(const std::optional<abla::State> &o) noexcept {
            PackedState r;
            if (o.has_value()) {
                r.engaged = true;
                const uint64_t blockSize = o->GetBlockSize();
                assert(0 == (blockSize >> 63) && "INTERNAL ERROR: blockSize has bit 64 set"); /* detect truncation */
                r.blockSize = blockSize;
                r.controlBlockSize = o->GetControlBlockSize();
                r.elasticBufferSize = o->GetElasticBufferSize();
            } else {
                r.clear();
            }
            return r;
        }
    };
    static_assert(std::is_trivially_default_constructible_v<PackedState> && std::is_trivially_copyable_v<PackedState>,
                  "Paranoia extra constraints for std::atomic to guarantee POD-ness");

    std::atomic<PackedState> atomicPacked;

public:
    AblaStateMixin() noexcept { atomicPacked.store(PackedState().clear(), std::memory_order_relaxed); }
    AblaStateMixin(const AblaStateMixin &o) noexcept {
        atomicPacked.store(o.atomicPacked.load(), std::memory_order_relaxed);
    }

    AblaStateMixin &operator=(const AblaStateMixin &) = delete;

    std::optional<abla::State> GetAblaStateOpt() const {
        return atomicPacked.load().unpack();
    }

    /// If `atomicPacked` is engaged, unpacks and returns the abla::State, otherwise returns the results of invoking
    /// `func()`. `func()` is only invoked if the packed state is not engaged.
    template <typename Func>
    abla::State GetAblaStateOr(Func &&func) const {
        if (const auto optState = GetAblaStateOpt()) {
            return *optState;
        }
        return func();
    }

    void SetAblaStateOpt(const std::optional<abla::State> &s) {
        atomicPacked.store(PackedState::pack(s));
    }
};

/**
 * The block chain is a tree shaped structure starting with the genesis block at
 * the root, with each block potentially having multiple candidates to be the
 * next block. A blockindex may have multiple pprev pointing to it, but at most
 * one of them can be part of the currently active branch.
 */
class CBlockIndex : public AblaStateMixin {
protected:
    //! Copy & assignment operators are protected for safety since this is a
    //! linked list node with pointers pointing to this instance and it would
    //! be unsafe to copy instances of CBlockIndex in client code.  This
    //! restriction prevents client code from building a chain and putting
    //! CBlockIndex into a vector *by value*, for example, which may get
    //! inadvertently resized (thus leading to a situation with dangling
    //! pointers).
    explicit CBlockIndex(const CBlockIndex &) = default;
    CBlockIndex &operator=(const CBlockIndex &) = delete;
    //! Move construction and move assignment are forbidden since nothing
    //! in this codebase uses these and it's safer not to allow it.
    CBlockIndex(CBlockIndex &&) = delete;
    CBlockIndex &operator=(CBlockIndex &&) = delete;

public:
    //! pointer to the hash of the block, if any. Memory is owned by external
    //! code that also owns this CBlockIndex. See: class CChanState in validation.cpp.
    const BlockHash *phashBlock = nullptr;

    //! pointer to the index of the predecessor of this block
    CBlockIndex *pprev = nullptr;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex *pskip = nullptr;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight = 0;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile = 0;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos = 0;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos = 0;

    //! (memory only) Total amount of work (expected number of hashes) in the
    //! chain up to and including this block
    arith_uint256 nChainWork = arith_uint256();

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied
    //! upon
    unsigned int nTx = 0;

    //! Verification status of this block. See enum BlockStatus
    BlockStatus nStatus = BlockStatus();

    //! (memory only) Number of transactions in the chain up to and including
    //! this block.
    //! This value will be non-zero only if and only if transactions for this
    //! block and all its parents are available.
    uint64_t nChainTx = 0;

    //! block header
    int32_t nVersion = 0;
    uint256 hashMerkleRoot = uint256();
    uint32_t nTime = 0; ///< Note: Do not modify nTime once it is set; doing so will make cachedMTP for subsequent blocks be incorrect.
    uint32_t nBits = 0;
    uint32_t nNonce = 0;

    //! (memory only) Sequential id assigned to distinguish order in which
    //! blocks are received.
    int32_t nSequenceId = 0;

    //! (memory only) block header metadata
    uint64_t nTimeReceived = 0;

    //! (memory only) Maximum nTime in the chain up to and including this block.
    unsigned int nTimeMax = 0;

private:
    //! (memory only) The cached medium time past value, lazily calculated the first time GetMedianTimePast() is called.
    //! Change this to 64-bit when changing nTime to be 64-bit in some future upgrade before the year ~2100 or so.
    mutable class CachedMTP {
        static constexpr uint32_t NoValue = 0xff'ff'ff'ffu;
        std::atomic_uint32_t val = NoValue;
    public:
        CachedMTP() = default;
        CachedMTP(const CachedMTP &o) : val(o.Get().value_or(NoValue)) {}

        std::optional<uint32_t> Get() const {
            if (const uint32_t ret = val.load(std::memory_order_acquire); ret != NoValue) { return ret; }
            return std::nullopt;
        }

        void Set(uint32_t v) { val.store(v, std::memory_order_release); }
        void Clear() { Set(NoValue); }
    } cachedMTP;

public:
    explicit CBlockIndex() = default;

    explicit CBlockIndex(const CBlockHeader &block) : CBlockIndex() {
        nVersion = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime = block.nTime;
        nTimeReceived = 0;
        nBits = block.nBits;
        nNonce = block.nNonce;
    }

    FlatFilePos GetBlockPos() const {
        FlatFilePos ret;
        if (nStatus.hasData()) {
            ret.nFile = nFile;
            ret.nPos = nDataPos;
        }
        return ret;
    }

    FlatFilePos GetUndoPos() const {
        FlatFilePos ret;
        if (nStatus.hasUndo()) {
            ret.nFile = nFile;
            ret.nPos = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const {
        CBlockHeader block;
        block.nVersion = nVersion;
        if (pprev) {
            block.hashPrevBlock = pprev->GetBlockHash();
        }
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block;
    }

    BlockHash GetBlockHash() const { return *phashBlock; }

    /**
     * Get the number of transaction in the chain so far.
     */
    uint64_t GetChainTxCount() const { return nChainTx; }

    /**
     * Check whether this block's and all previous blocks' transactions have
     * been downloaded (and stored to disk) at some point.
     *
     * Does not imply the transactions are consensus-valid (ConnectTip might
     * fail) Does not imply the transactions are still stored on disk.
     * (IsBlockPruned might return true)
     */
    bool HaveTxsDownloaded() const { return GetChainTxCount() != 0; }

    int64_t GetBlockTime() const { return int64_t(nTime); }

    int64_t GetBlockTimeMax() const { return int64_t(nTimeMax); }

    int64_t GetHeaderReceivedTime() const { return nTimeReceived; }

    int64_t GetReceivedTimeDiff() const {
        return GetHeaderReceivedTime() - GetBlockTime();
    }

    static constexpr size_t nMedianTimeSpan = 11;

private:
    uint32_t CalculateMedianTimePast() const {
        uint32_t pmedian[nMedianTimeSpan];
        uint32_t *pbegin = &pmedian[nMedianTimeSpan];
        uint32_t *pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex *pindex = this;
        for (size_t i = 0; i < nMedianTimeSpan && pindex; ++i, pindex = pindex->pprev) {
            *--pbegin = pindex->nTime;
        }

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin) / 2];
    }

public:
    int64_t GetMedianTimePast() const {
        std::optional<uint32_t> ret = cachedMTP.Get();
        if (!ret) {
            ret = CalculateMedianTimePast();
            cachedMTP.Set(*ret);
        }
        return static_cast<int64_t>(*ret);
    }

    bool HasCachedMTPValue() const { return cachedMTP.Get().has_value(); }
    void ClearCachedMTPValue() { cachedMTP.Clear(); }

    std::string ToString() const {
        return strprintf(
            "CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)", pprev,
            nHeight, hashMerkleRoot.ToString(), GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity
    //! level.
    bool IsValid(enum BlockValidity nUpTo = BlockValidity::TRANSACTIONS) const {
        return nStatus.isValid(nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockValidity nUpTo) {
        // Only validity flags allowed.
        if (nStatus.isInvalid()) {
            return false;
        }

        if (nStatus.getValidity() >= nUpTo) {
            return false;
        }

        nStatus = nStatus.withValidity(nUpTo);
        return true;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex *GetAncestor(int height);
    const CBlockIndex *GetAncestor(int height) const;
};

// ensure that the future code that may modify the CBlockIndex preserves type safety restriction on CBlockIndex
static_assert(!std::is_copy_constructible_v<CBlockIndex> && !std::is_move_constructible_v<CBlockIndex>
    && !std::is_copy_assignable_v<CBlockIndex> && !std::is_move_assignable_v<CBlockIndex>);

/**
 * Maintain a map of CBlockIndex for all known headers.
 */
struct BlockHasher {
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const BlockHash &hash) const {
        return ReadLE64(hash.begin());
    }
};

extern RecursiveMutex cs_main;
// Note that this codebase assumes CBlockIndex has stable pointers, which is the case with all std maps.
// If we ever change this to a container without stable pointers, then we must use a std::unique_ptr<CBlockIndex> as the
// mapped type here.
using BlockMap = std::unordered_map<BlockHash, CBlockIndex, BlockHasher>;
extern BlockMap &mapBlockIndex GUARDED_BY(cs_main);

inline CBlockIndex *LookupBlockIndex(const BlockHash &hash) {
    AssertLockHeld(cs_main);
    BlockMap::iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : &it->second;
}

arith_uint256 GetBlockProof(const CBlockIndex &block);

/**
 * Return the time it would take to redo the work difference between from and
 * to, assuming the current hashrate corresponds to the difficulty at tip, in
 * seconds.
 */
int64_t GetBlockProofEquivalentTime(const CBlockIndex &to,
                                    const CBlockIndex &from,
                                    const CBlockIndex &tip,
                                    const Consensus::Params &);
/**
 * Find the forking point between two chain tips.
 */
const CBlockIndex *LastCommonAncestor(const CBlockIndex *pa,
                                      const CBlockIndex *pb);

/**
 * Check if two block index are on the same fork.
 */
bool AreOnTheSameFork(const CBlockIndex *pa, const CBlockIndex *pb);

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex {
public:
    BlockHash hashPrev;

    CDiskBlockIndex() { hashPrev = BlockHash(); }

    explicit CDiskBlockIndex(const CBlockIndex *pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : BlockHash());
    }

    SERIALIZE_METHODS(CDiskBlockIndex, obj) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(VARINT_MODE(_nVersion, VarIntMode::NONNEGATIVE_SIGNED));
        }

        READWRITE(VARINT_MODE(obj.nHeight, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(obj.nStatus);
        READWRITE(VARINT(obj.nTx));
        if (obj.nStatus.hasData() || obj.nStatus.hasUndo()) {
            READWRITE(VARINT_MODE(obj.nFile, VarIntMode::NONNEGATIVE_SIGNED));
        }
        if (obj.nStatus.hasData()) {
            READWRITE(VARINT(obj.nDataPos));
        }
        if (obj.nStatus.hasUndo()) {
            READWRITE(VARINT(obj.nUndoPos));
        }

        // block header
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrev);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);

        // blocksize AA state data -- may be missing if older serialized data before CLIENT_VERSION_ABLA_BLOCKINDEX_DATA
        if (_nVersion >= CLIENT_VERSION_ABLA_BLOCKINDEX_DATA) {
            std::optional<abla::State> ablaStateOpt;
            SER_WRITE(obj, ablaStateOpt = obj.GetAblaStateOpt());
            try {
                READWRITE(ablaStateOpt);
            } catch (const std::ios_base::failure &e) {
                if (!ser_action.ForRead() || std::string_view{e.what()}.find("end of data") == std::string_view::npos) {
                    // if writing or if not end-of-data, bubble error out
                    throw;
                }
                // otherwise, tolerate end-of-data on reading; reset the optional
                ablaStateOpt.reset();
            }
            SER_READ(obj, obj.SetAblaStateOpt(ablaStateOpt));
        } else {
            // old serialized data, indicate missing data.
            SER_READ(obj, obj.SetAblaStateOpt(std::nullopt));
        }

        // clear the cachedMTP value (if any) when unserializing since it no longer would necessarily be correct
        SER_READ(obj, obj.ClearCachedMTPValue());
    }

    BlockHash GetBlockHash() const {
        CBlockHeader block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrev;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        return block.GetHash();
    }

    std::string ToString() const {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
                         GetBlockHash().ToString(), hashPrev.ToString());
        return str;
    }
};

/**
 * An in-memory indexed chain of blocks.
 */
class CChain {
private:
    std::vector<CBlockIndex *> vChain;

public:
    /**
     * Returns the index entry for the genesis block of this chain, or nullptr
     * if none.
     */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : nullptr;
    }

    /**
     * Returns the index entry for the tip of this chain, or nullptr if none.
     */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : nullptr;
    }

    /**
     * Returns the index entry at a particular height in this chain, or nullptr
     * if no such height exists.
     */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size()) {
            return nullptr;
        }
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const {
        return (*this)[pindex->nHeight] == pindex;
    }

    /**
     * Find the successor of a block in this chain, or nullptr if the given
     * index is not found or is the tip.
     */
    CBlockIndex *Next(const CBlockIndex *pindex) const {
        if (!Contains(pindex)) {
            return nullptr;
        }

        return (*this)[pindex->nHeight + 1];
    }

    /**
     * Return the maximal height in the chain. Is equal to chain.Tip() ?
     * chain.Tip()->nHeight : -1.
     */
    int Height() const { return vChain.size() - 1; }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /**
     * Return a CBlockLocator that refers to a block in this chain (by default
     * the tip).
     */
    CBlockLocator GetLocator(const CBlockIndex *pindex = nullptr) const;

    /**
     * Find the last common block between this chain and a block index entry.
     */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;

    /**
     * Find the earliest block with timestamp equal or greater than the given.
     */
    CBlockIndex *FindEarliestAtLeast(int64_t nTime) const;
};
