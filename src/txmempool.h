// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <coins.h>
#include <core_memusage.h>
#include <dsproof/dspid.h>
#include <indirectmap.h>
#include <primitives/transaction.h>
#include <random.h>
#include <span.h>
#include <sync.h>
#include <util/saltedhashers.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/signals2/signal.hpp>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

class CBlockIndex;
class Config;
class DoubleSpendProof;
class DoubleSpendProofStorage;


extern RecursiveMutex cs_main;

/**
 * Fake height value used in Coins to signify they are only in the memory
 * pool(since 0.8)
 */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

struct LockPoints {
    // Will be set to the blockchain height and median time past values that
    // would be necessary to satisfy all relative locktime constraints (BIP68)
    // of this tx given our view of block chain history
    int height;
    int64_t time;
    // As long as the current chain descends from the highest height block
    // containing one of the inputs used in the calculation, then the cached
    // values are still valid even after a reorg.
    CBlockIndex *maxInputBlock;

    LockPoints() : height(0), time(0), maxInputBlock(nullptr) {}
};

class CTxMemPool;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the corresponding transaction, as well as
 * data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 *
 * When a new entry is added to the mempool, we update the descendant state
 * (nCountWithDescendants, nSizeWithDescendants, and nModFeesWithDescendants)
 * for all ancestors of the newly added transaction.
 */

class CTxMemPoolEntry {
    //! Unique identifier -- used for topological sorting
    uint64_t entryId = 0;

    const CTransactionRef tx;
    //! Cached to avoid expensive parent-transaction lookups
    const Amount nFee;
    //! ... and avoid recomputing tx size
    const size_t nTxSize;
    //! ... and total memory usage
    const size_t nUsageSize;
    //! Local time when entering the mempool
    const int64_t nTime;
    //! keep track of transactions that spend a coinbase
    const bool spendsCoinbase;
    //! Total sigchecks
    const int64_t sigChecks;
    //! Used for determining the priority of the transaction for mining in a
    //! block
    Amount feeDelta;
    //! Track the height and time at which tx was final
    LockPoints lockPoints;

    //! If not nullptr, this entry has an associated DoubleSpendProof.
    //! We use a DspIdPtr here to use less memory than a direct DspId would
    //! in the common case of no proof for this entry, while still keeping this
    //! class copy constructible.
    DspIdPtr dspIdPtr;

public:
    CTxMemPoolEntry(const CTransactionRef &_tx, const Amount _nFee,
                    int64_t _nTime,
                    bool spendsCoinbase, int64_t _sigChecks, LockPoints lp);

    uint64_t GetEntryId() const { return entryId; }
    //! This should only be set exactly once by addUnchecked() before entry insertion into the mempool.
    //! In other words, it may not be mutated for an instance whose storage is in CTxMemPool::mapTx, otherwise mempool
    //! invariants will be violated.
    void SetEntryId(uint64_t eid) { entryId = eid; }

    const CTransaction &GetTx() const { return *this->tx; }
    CTransactionRef GetSharedTx() const { return this->tx; }
    Amount GetFee() const { return nFee; }
    size_t GetTxSize() const { return nTxSize; }
    size_t GetTxVirtualSize() const;

    int64_t GetTime() const { return nTime; }
    int64_t GetSigChecks() const { return sigChecks; }
    Amount GetModifiedFee() const { return nFee + feeDelta; }
    CFeeRate GetModifiedFeeRate() const { return CFeeRate(GetModifiedFee(), GetTxVirtualSize()); }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints &GetLockPoints() const { return lockPoints; }

    // Updates the fee delta used for mining priority score, and the
    // modified fees with descendants.
    void UpdateFeeDelta(Amount feeDelta);
    // Update the LockPoints after a reorg
    void UpdateLockPoints(const LockPoints &lp);

    bool GetSpendsCoinbase() const { return spendsCoinbase; }

    bool HasDsp() const { return dspIdPtr && !dspIdPtr->IsNull(); }
    //! @returns the dspId if this entry has a dsp or an IsNull() DspId if it does not
    const DspId & GetDspId() const {
        static const DspId staticNull;
        return dspIdPtr ? *dspIdPtr : staticNull;
    }
    void SetDspId(const DspId &dspId) { dspIdPtr = dspId; }
};

// --- Helpers for modifying CTxMemPool::mapTx, which is a boost multi_index.

struct update_fee_delta {
    explicit update_fee_delta(Amount _feeDelta) : feeDelta(_feeDelta) {}

    void operator()(CTxMemPoolEntry &e) { e.UpdateFeeDelta(feeDelta); }

private:
    Amount feeDelta;
};

struct update_lock_points {
    explicit update_lock_points(const LockPoints &_lp) : lp(_lp) {}

    void operator()(CTxMemPoolEntry &e) { e.UpdateLockPoints(lp); }

private:
    const LockPoints &lp;
};

// extracts a transaction id from CTxMemPoolEntry or CTransactionRef
struct mempoolentry_txid {
    typedef TxId result_type;
    result_type operator()(const CTxMemPoolEntry &entry) const {
        return entry.GetTx().GetId();
    }

    result_type operator()(const CTransactionRef &tx) const {
        return tx->GetId();
    }
};

// used by the entry_id index
struct CompareTxMemPoolEntryByEntryId {
    bool operator()(const CTxMemPoolEntry &a, const CTxMemPoolEntry &b) const {
        return a.GetEntryId() < b.GetEntryId();
    }
};

/** \class CompareTxMemPoolEntryByModifiedFeeRate
 *
 *  Sort by feerate of entry (modfee/vsize) in descending order.
 *  This is used by the block assembler (mining).
 */
struct CompareTxMemPoolEntryByModifiedFeeRate {
    bool operator()(const CTxMemPoolEntry &a, const CTxMemPoolEntry &b) const {
        const CFeeRate frA = a.GetModifiedFeeRate(), frB = b.GetModifiedFeeRate();
        if (frA == frB) {
            // Ties are broken by whichever is topologically earlier
            // (this helps mining code avoid some backtracking).
            return a.GetEntryId() < b.GetEntryId();
        }
        return frA > frB;
    }
};

// Multi_index tag names
struct modified_feerate {};
struct entry_id {};

/**
 * Information about a mempool transaction.
 */
struct TxMempoolInfo {
    /** The transaction itself */
    CTransactionRef tx;

    /** Time the transaction entered the mempool. */
    int64_t nTime{};

    /** Feerate of the transaction. */
    CFeeRate feeRate;

    /** The fee delta. */
    Amount nFeeDelta;

    /** The EntryId (mempool acceptance order), higher is later; for topological sort order */
    uint64_t entryId{};
};

/**
 * Reason why a transaction was removed from the mempool, this is passed to the
 * notification signal.
 */
enum class MemPoolRemovalReason {
    //! Manually removed or unknown reason
    UNKNOWN = 0,
    //! Expired from mempool
    EXPIRY,
    //! Removed in size limiting
    SIZELIMIT,
    //! Removed for reorganization
    REORG,
    //! Removed for block
    BLOCK,
    //! Removed for conflict with in-block transaction
    CONFLICT,
    //! Removed for replacement
    REPLACED
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain transactions that
 * may be included in the next block.
 *
 * Transactions are added when they are seen on the network (or created by the
 * local node), but not all transactions seen are added to the pool. For
 * example, the following new transactions will not be added to the mempool:
 * - a transaction which doesn't meet the minimum fee requirements.
 * - a new transaction that double-spends an input of a transaction already in
 * the pool.
 * - a non-standard transaction.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 3 criteria:
 * - transaction hash
 * - time in mempool
 * - entry id (this is a topological index)
 *
 * Note: the term "descendant" refers to in-mempool transactions that depend on
 * this one, while "ancestor" refers to in-mempool transactions that a given
 * transaction depends on.
 *
 * When a new transaction is added to the mempool, it has no in-mempool children
 * (because any such children would be an orphan). So in addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all in-mempool children to not include it as a parent
 *
 * These happen in UpdateForRemoveFromMempool(). (Note that when removing a
 * transaction along with its descendants, we must calculate that set of
 * transactions to be removed before doing the removal, or else the mempool can
 * be in an inconsistent state where it's impossible to walk the ancestors of a
 * transaction.)
 *
 * In the event of a reorg, the invariant that all newly-added tx's have no
 * in-mempool children must be maintained.  On top of this, we use a topological
 * index (GetEntryId).  As such, we always dump mempool tx's into a
 * disconnect pool on reorg, and simply add them one by one, along with tx's from
 * disconnected blocks, when the reorg is complete.
 *
 * Computational limits:
 *
 * Updating of all in-mempool ancestors does not occur anymore in this codebase
 * after the May 15th 2021 network upgrade.  As such, there is no bound on how
 * many in-mempool ancestors of a tx there may be.
 */
class CTxMemPool {
private:
    //! Value n means that n times in 2^32 we check.
    uint32_t nCheckFrequency GUARDED_BY(cs);
    //! Used by getblocktemplate to trigger CreateNewBlock() invocation
    unsigned int nTransactionsUpdated;

    //! sum of all mempool tx's sizes.
    size_t totalTxSize GUARDED_BY(cs);
    //! sum of all mempool tx fees
    Amount totalTxFee GUARDED_BY(cs);
    //! sum of dynamic memory usage of all the map elements (NOT the maps
    //! themselves)
    size_t cachedInnerUsage;

    mutable int64_t lastRollingFeeUpdate;
    mutable bool blockSinceLastRollingFeeBump;
    //! minimum fee to get into the pool, decreases exponentially
    mutable double rollingMinimumFeeRate;

    void trackPackageRemoved(const CFeeRate &rate) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool m_is_loaded GUARDED_BY(cs){false};

    //! Used by addUnchecked to generate ever-increasing CTxMemPoolEntry::entryId's
    uint64_t nextEntryId GUARDED_BY(cs) = 1;

public:
    // public only for testing
    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;

    using indexed_transaction_set = boost::multi_index_container<
        CTxMemPoolEntry, boost::multi_index::indexed_by<
                             // sorted by txid
                             boost::multi_index::hashed_unique<
                                 mempoolentry_txid, SaltedTxIdHasher>,
                             // sorted by fee rate
                             boost::multi_index::ordered_non_unique<
                                 boost::multi_index::tag<modified_feerate>,
                                 boost::multi_index::identity<CTxMemPoolEntry>,
                                 CompareTxMemPoolEntryByModifiedFeeRate>,
                            // sorted topologically (insertion order)
                            boost::multi_index::ordered_unique<
                                boost::multi_index::tag<entry_id>,
                                boost::multi_index::identity<CTxMemPoolEntry>,
                                CompareTxMemPoolEntryByEntryId>>>;

    /**
     * This mutex needs to be locked when accessing `mapTx` or other members
     * that are guarded by it.
     *
     * @par Consistency guarantees
     *
     * By design, it is guaranteed that:
     *
     * 1. Locking both `cs_main` and `mempool.cs` will give a view of mempool
     *    that is consistent with current chain tip (`::ChainActive()` and
     *    `pcoinsTip`) and is fully populated. Fully populated means that if the
     *    current active chain is missing transactions that were present in a
     *    previously active chain, all the missing transactions will have been
     *    re-added to the mempool and should be present if they meet size and
     *    consistency constraints.
     *
     * 2. Locking `mempool.cs` without `cs_main` will give a view of a mempool
     *    consistent with some chain that was active since `cs_main` was last
     *    locked, and that is fully populated as described above. It is ok for
     *    code that only needs to query or remove transactions from the mempool
     *    to lock just `mempool.cs` without `cs_main`.
     *
     * To provide these guarantees, it is necessary to lock both `cs_main` and
     * `mempool.cs` whenever adding transactions to the mempool and whenever
     * changing the chain tip. It's necessary to keep both mutexes locked until
     * the mempool is consistent with the new chain tip and fully populated.
     *
     * @par Consistency bug
     *
     * The second guarantee above is not currently enforced, but
     * https://github.com/bitcoin/bitcoin/pull/14193 will fix it. No known code
     * in bitcoin currently depends on second guarantee, but it is important to
     * fix for third party code that needs be able to frequently poll the
     * mempool without locking `cs_main` and without encountering missing
     * transactions during reorgs.
     */
    mutable RecursiveMutex cs;
    indexed_transaction_set mapTx GUARDED_BY(cs);

    using txiter = indexed_transaction_set::nth_index<0>::type::const_iterator;

    struct CompareIteratorByEntryId {
        bool operator()(const txiter &a, const txiter &b) const {
            return a->GetEntryId() < b->GetEntryId();
        }
    };
    using setEntries = std::set<txiter, CompareIteratorByEntryId>;

    const setEntries &GetMemPoolParents(txiter entry) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    const setEntries &GetMemPoolChildren(txiter entry) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Add a double-spend proof to an existing mempool entry.
     * Returns the CTransactionRef of the mempool entry we added it to.
     *
     * The returned CTransactionRef may be null if no mempool transaction was found
     * spending the supplied proof's outpoint, or if the mempool transaction that does
     * spend it already has a proof.
     *
     * The optional second argument is a mapTx iterator for the existing mempool entry
     * to update and associate with this proof.  This argument is a performance
     * optimization used by AcceptToMemoryPoolWorker, and it is not checked for sanity.
     */
    CTransactionRef addDoubleSpendProof(const DoubleSpendProof &proof, const std::optional<txiter> &iter = {});

    DoubleSpendProofStorage *doubleSpendProofStorage() const;

    // -- Query double spend proofs (used by RPC) --

    //! Result type for some of the dsp getters below
    using DspTxIdPair = std::pair<DoubleSpendProof, TxId>;
    //! All of the in-memory descendants of an in-memory tx associated with a double-spend proof, including the
    //! tx itself.
    using DspDescendants = std::set<TxId>;
    //! The in-memory ancestry path leading up to the double-spend, most recent tx first. The last txId in this vector
    //! is the double-spend itself. The first element in this vector is the TxId used for the query.
    //! Note that this is not the full ancestor set, but merely an ordered path leading from query tx -> dsp tx.
    using DspQueryPath = std::vector<TxId>;
    //! Result type for recursiveDSProofSearch
    using DspRecurseResult = std::pair<DoubleSpendProof, DspQueryPath>;

    //! list all known proofs, optionally also returning all known orphans (orphans have an .IsNull() TxId)
    //! @throws std::runtime_error on internal error
    std::vector<DspTxIdPair> listDoubleSpendProofs(bool includeOrphans = false) const;

    //! Lookup a proof by DspId. If the proof is an orphan, it will have an .IsNull() TxId
    //! @param dspId - The double-spend proof id to look up.
    //! @param descendants - If not nullptr, also populate the set with all the tx's that descend from the TxId
    //!     associated with the result (if there is a non-orphan result), including the result TxId itself.
    //! @throws may throw std::runtime_error on internal error
    std::optional<DspTxIdPair> getDoubleSpendProof(const DspId &dspId, DspDescendants *descendants = nullptr) const;
    //! Lookup a proof by TxId. Does not do a recursive search. For recursion, @see recursiveDSProofSearch.
    //! @param txId - The TxId for which to lookup the proof.
    //! @param descendants - If not nullptr, also populate the set with all the tx's that descend from the TxId
    //!     associated with the result, including the result TxId itself.
    //! @throws std::runtime_error on internal error
    std::optional<DoubleSpendProof> getDoubleSpendProof(const TxId &txId, DspDescendants *descendants = nullptr) const;
    //! Lookup a proof by the double spent COutPoint.
    //! @returns A valid optional if there is a hit. If the proof is an orphan, it will have an .IsNull() TxId.
    //!     If there are multiple orphan proofs for an output point, only the first one found will be returned.
    //!     If there exists a non-orphan proofs, it will be preferentially returned over any orphan(s) that may
    //!     also exist.
    //! @param outpoint - output point for which to search for a proof.
    //! @param descendants - If not nullptr, also populate the set with all the tx's that descend from the TxId
    //!     associated with the result (if there is a non-orphan result), including the result TxId itself.
    //! @throws std::runtime_error on internal error
    std::optional<DspTxIdPair> getDoubleSpendProof(const COutPoint &outpoint, DspDescendants *descendants = nullptr) const;

    //! Thrown by recursiveDSProofSearch below if the search exceeded 1,000 ancestors deep, or 20,000 ancestors total.
    struct RecursionLimitReached : std::runtime_error {
        using std::runtime_error::runtime_error;
        ~RecursionLimitReached();
    };
    //!
    //! Recrusive search for a double-spend proof for a TxId and all its in-mempool ancestors.
    //!
    //! @returns A valid optional if `txId` or any of its in-mempool ancestors have a dsproof. Note: The DspQueryPath
    //!     vector is ordered such that the children come before their parents (most recent first ordering). If
    //!     this function finds a result, then the first element of the DspQueryPath vector is always `txId`, and
    //!     the last element is the double-spent TxId. In-between elements (if any) are the unconfirmed tx chain
    //!     of ancestor tx's leading to the double-spent tx.
    //! @param descendants - If not nullptr, also populate the set with all the tx's that descend from the TxId
    //!     associated with the result, including the result TxId itself.
    //! @param score - If not nullptr, the search is performed differently; we scan until we reach a parent tx
    //!     that either has a proof or we cannot ever produce a proof for (not P2PKH). In that case we set score to
    //!     0.0 (no confidence), and we stop scanning. If no such parent exists and no proof is found for this or any
    //!     ancestor, we set score to 1.0 (high confidence). We also may set score to 0.25 (low confidence) if the
    //!     recursion depth is reached (in which case RecursionLimitReached is thrown), or if we hit an ancestor
    //!     that has a P2PKH input that is not signed with SIGHASH_ALL or is signed with SIGHASH_ANYONECANPAY.
    //!     We set score to -1.0 if txId is not found in the mempool.
    //! @throws std::runtime_error on internal error, or RecursionLimitReached if the search exceeded a depth of 1,000
    //!     ancestors deep, or 20,000 ancestors total.
    std::optional<DspRecurseResult> recursiveDSProofSearch(const TxId &txId, DspDescendants *descendants = nullptr,
                                                           double *score = nullptr) const;

private:
    //! Lookup a dsproof by TxId -- caller must hold cs.
    //! @returns a valid optional contaning the proof if such a proof exists for `txId`.
    //! @param desc - if non-nullptr, `*desc` will be set to contain all the in-memory descendants of `txId` (including
    //!     `txId` itself). This set is only populated when there is a successful result.
    //! @throws std::runtime_error on internal error
    std::optional<DoubleSpendProof> getDoubleSpendProof_common(const TxId &txId, DspDescendants *desc = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    //! Called by above function.
    //! @pre - `it` must be valid and point to an entry in mapTx
    std::optional<DoubleSpendProof> getDoubleSpendProof_common(txiter it, DspDescendants *desc = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    //! Helper function for getDoubleSpendProof_common and others
    DspDescendants getDspDescendantsForIter(txiter) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    struct TxLinks {
        setEntries parents;
        setEntries children;
    };

    using txlinksMap = std::map<txiter, TxLinks, CompareIteratorByEntryId>;
    txlinksMap mapLinks;

    void UpdateParent(txiter entry, txiter parent, bool add);
    void UpdateChild(txiter entry, txiter child, bool add);

public:
    indirectmap<COutPoint, const CTransaction *> mapNextTx GUARDED_BY(cs);
    std::map<TxId, Amount> mapDeltas;

    /**
     * Create a new CTxMemPool.
     */
    CTxMemPool();
    ~CTxMemPool();

    /**
     * If sanity-checking is turned on, check makes sure the pool is consistent
     * (does not contain two transactions that spend the same inputs, all inputs
     * are in the mapNextTx array). If sanity-checking is turned off, check does
     * nothing.
     */
    void check(const CCoinsViewCache *pcoins) const;
    void setSanityCheck(double dFrequency = 1.0) {
        LOCK(cs);
        nCheckFrequency = static_cast<uint32_t>(dFrequency * 4294967295.0);
    }
    double getSanityCheck() const {
        LOCK(cs);
        return static_cast<double>(nCheckFrequency) / 4294967295.0;
    }

    // addUnchecked must update state for all parents of a given transaction,
    // updating child links as necessary. Returns the EntryId (acceptance order) for this entry.
    uint64_t addUnchecked(CTxMemPoolEntry &&entry) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main);
    // This overload of addUnchecked is provided for convenience, but critical paths should use the above version.
    uint64_t addUnchecked(const CTxMemPoolEntry &entry) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main) {
        return addUnchecked(CTxMemPoolEntry{entry});
    }

    void removeRecursive(
        const CTransaction &tx,
        MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN);
    void removeConflicts(const CTransaction &tx) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void removeForBlock(const std::vector<CTransactionRef> &vtx);

    void clear(bool clearDspOrphans = true);
    // lock free
    void _clear(bool clearDspOrphans = true) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void queryHashes(std::vector<uint256> &vtxid) const;
    bool isSpent(const COutPoint &outpoint) const;
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a
     * block.
     */
    bool HasNoInputsOf(const CTransaction &tx) const;

    /** Affect CreateNewBlock prioritisation of transactions */
    void PrioritiseTransaction(const TxId &txid, const Amount nFeeDelta);
    void ApplyDelta(const TxId &txid, Amount &nFeeDelta) const;
    void ClearPrioritisation(const TxId &txid);

    /** Get the transaction in the pool that spends the same prevout */
    const CTransaction *GetConflictTx(const COutPoint &prevout) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /** Returns an iterator to the given txid, if found */
    std::optional<txiter> GetIter(const TxId &txid) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     *  Allow external code to iterate over a particular index. By default the `entry_id` index
     *  is returned (topological ordering).
     *
     *  Available index tags: `void` (for the untagged 0th txid index), `modified_feerate`, `entry_id`.
     */
    template <typename IndexTag = entry_id>
    const auto & GetIndex() const EXCLUSIVE_LOCKS_REQUIRED(cs) {
        if constexpr (std::is_same_v<IndexTag, void>) {
            return mapTx.get<0>();
        } else {
            return mapTx.get<IndexTag>();
        }
    }

    /**
     * Translate a set of txids into a set of pool iterators to avoid repeated
     * lookups.
     */
    setEntries GetIterSet(const std::set<TxId> &txids) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Remove a set of transactions from the mempool. If a transaction is in
     * this set, then all in-mempool descendants must also be in the set, unless
     * this transaction is being removed for being in a block.
     */
    void
    RemoveStaged(const setEntries &stage, MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN)
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Try to calculate all in-mempool ancestors of entry.
     *  (these are all calculated including the tx itself)
     * fSearchForParents = whether to search a tx's vin for in-mempool parents,
     * or look up parents from mapLinks. Must be true for entries not in the
     * mempool.
     */
    void CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors,
                                   bool fSearchForParents = true) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Populate setDescendants with all in-mempool descendants of hash.
     * Assumes that setDescendants includes all in-mempool descendants of
     * anything already in it.
     */
    void CalculateDescendants(txiter it, setEntries &setDescendants) const
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * The minimum fee to get into the mempool, which may itself not be enough
     * for larger-sized transactions. The incrementalRelayFee policy variable is
     * used to bound the time it takes the fee rate to go back down all the way
     * to 0. When the feerate would otherwise be half of this, it is set to 0
     * instead.
     */
    CFeeRate GetMinFee(size_t sizelimit) const;

    /**
     * Remove transactions from the mempool until its dynamic size is <=
     * sizelimit. pvNoSpendsRemaining, if set, will be populated with the list
     * of outpoints which are not in mempool which no longer have any spends in
     * this mempool.
     */
    void TrimToSize(size_t sizelimit,
                    std::vector<COutPoint> *pvNoSpendsRemaining = nullptr);

    /**
     * Expire all transaction (and their dependencies) in the mempool older than
     * time. Return the number of removed transactions.
     * If fast == true, then the algorithm will stop processing transactions when
     * the first one that is not older than time is found.
     */
    size_t Expire(int64_t time, bool fast = true);

    /**
     * Reduce the size of the mempool by expiring and then trimming the mempool.
     */
    void LimitSize(size_t limit, unsigned long age);

    /** @returns true if the mempool is fully loaded */
    bool IsLoaded() const;

    /** Sets the current loaded state */
    void SetIsLoaded(bool loaded);

    auto size() const {
        LOCK(cs);
        return mapTx.size();
    }

    auto GetTotalTxSize() const {
        LOCK(cs);
        return totalTxSize;
    }

    auto GetTotalFee() const {
        LOCK(cs);
        return totalTxFee;
    }

    bool exists(const TxId &txid) const {
        LOCK(cs);
        return mapTx.count(txid) != 0;
    }

    CTransactionRef get(const TxId &txid) const;
    TxMempoolInfo info(const TxId &txid) const;
    std::vector<TxMempoolInfo> infoAll() const;

    CFeeRate estimateFee() const;

    size_t DynamicMemoryUsage() const;

    boost::signals2::signal<void(CTransactionRef)> NotifyEntryAdded;
    boost::signals2::signal<void(CTransactionRef, MemPoolRemovalReason)>
        NotifyEntryRemoved;

private:
    /**
     * Update parents of `it` to add/remove it as a child transaction (updates mapLinks).
     */
    void UpdateParentsOf(bool add, txiter it)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    /**
     * For each transaction being removed, sever links between parents
     * and children in mapLinks
     */
    void UpdateForRemoveFromMempool(const setEntries &entriesToRemove)
        EXCLUSIVE_LOCKS_REQUIRED(cs);
    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(txiter entry) EXCLUSIVE_LOCKS_REQUIRED(cs);

    /**
     * Before calling removeUnchecked for a given transaction,
     * UpdateForRemoveFromMempool must be called on the entire (dependent) set
     * of transactions being removed at the same time. We use each
     * CTxMemPoolEntry's setMemPoolParents in order to walk ancestors of a given
     * transaction that is removed, so we can't remove intermediate transactions
     * in a chain before we've updated all the state for the removal.
     */
    void
    removeUnchecked(txiter entry,
                    MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN)
        EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::unique_ptr<DoubleSpendProofStorage> m_dspStorage;
};

/**
 * CCoinsView that brings transactions from a mempool into view.
 * It does not check for spendings by memory pool transactions.
 * Instead, it provides access to all Coins which are either unspent in the
 * base CCoinsView, or are outputs from any mempool transaction!
 * This allows transaction replacement to work as expected, as you want to
 * have all inputs "available" to check signatures, and any cycles in the
 * dependency graph are checked directly in AcceptToMemoryPool.
 * It also allows you to sign a double-spend directly in
 * signrawtransactionwithkey and signrawtransactionwithwallet,
 * as long as the conflicting transaction is not yet confirmed.
 */
class CCoinsViewMemPool : public CCoinsViewBacked {
protected:
    const CTxMemPool &mempool;

public:
    CCoinsViewMemPool(CCoinsView *baseIn, const CTxMemPool &mempoolIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
};

/**
 * DisconnectedBlockTransactions
 *
 * During the reorg, it's desirable to re-add previously confirmed transactions
 * to the mempool, so that anything not re-confirmed in the new chain is
 * available to be mined. However, it's more efficient to wait until the reorg
 * is complete and process all still-unconfirmed transactions at that time,
 * since we expect most confirmed transactions to (typically) still be
 * confirmed in the new chain, and re-accepting to the memory pool is expensive
 * (and therefore better to not do in the middle of reorg-processing).
 * Instead, store the disconnected transactions (in order!) as we go, remove any
 * that are included in blocks in the new chain, and then process the remaining
 * still-unconfirmed transactions at the end.
 *
 * It also enables efficient reprocessing of current mempool entries, useful
 * when (de)activating forks that result in in-mempool transactions becoming
 * invalid
 */
// multi_index tag names
struct txid_index {};
struct insertion_order {};

class DisconnectedBlockTransactions {
private:
    typedef boost::multi_index_container<
        CTransactionRef, boost::multi_index::indexed_by<
                             // hashed by txid
                             boost::multi_index::hashed_unique<
                                 boost::multi_index::tag<txid_index>,
                                 mempoolentry_txid, SaltedTxIdHasher>,
                             // sorted by order in the blockchain
                             boost::multi_index::sequenced<
                                 boost::multi_index::tag<insertion_order>>>>
        indexed_disconnected_transactions;

    indexed_disconnected_transactions queuedTx;
    uint64_t cachedInnerUsage = 0;
    uint64_t maxDynamicUsage{};

    struct TxInfo {
        const int64_t time;
        const Amount feeDelta;
        TxInfo(int64_t time_, Amount feeDelta_) noexcept
            : time(time_), feeDelta(feeDelta_) {}
    };

    using TxInfoMap = std::unordered_map<TxId, TxInfo, SaltedTxIdHasher>;
    TxInfoMap txInfo; ///< populated by importMempool(); the original tx entry times and feeDeltas

    void addTransaction(const CTransactionRef &tx) {
        if (queuedTx.insert(tx).second) {
            // Defensive programming; enforce class invariant for cachedInnerUsage: only increment on successul insert.
            cachedInnerUsage += RecursiveDynamicUsage(tx);
        }
    }

    /// @returns a pointer into the txInfo map if tx->GetId() exists in the map, or nullptr otherwise.
    /// Note that the returned pointer is only valid for as long as its underlying map node is valid.
    const TxInfo *getTxInfo(const CTransactionRef &tx) const;

public:
    /// @returns the default maximum number of bytes that this instance will use for DynamicMemoryUsage()
    /// before txs are culled from this instance. Right now this is max(640MB, maxMempoolSize) and
    /// it relies on the global Config object being valid and correctly configured.
    static uint64_t DefaultMaxDynamicUsage();

    /// Construct this instance, optionally specifying a custom max dynamic usage.
    explicit DisconnectedBlockTransactions(uint64_t maxDynamicUsageBytes = DefaultMaxDynamicUsage());

    // It's almost certainly a logic bug if we don't clear out queuedTx before
    // destruction, as we add to it while disconnecting blocks, and then we
    // need to re-process remaining transactions to ensure mempool consistency.
    // For now, assert() that we've emptied out this object on destruction.
    // This assert() can always be removed if the reorg-processing code were
    // to be refactored such that this assumption is no longer true (for
    // instance if there was some other way we cleaned up the mempool after a
    // reorg, besides draining this object).
    ~DisconnectedBlockTransactions() { assert(queuedTx.empty()); }

    // Estimate the overhead of queuedTx to be 6 pointers + an allocation, as
    // no exact formula for boost::multi_index_contained is implemented.
    size_t DynamicMemoryUsage() const {
        return memusage::MallocUsage(sizeof(CTransactionRef) +
                                     6 * sizeof(void *)) *
                   queuedTx.size() +
               memusage::DynamicUsage(txInfo) +
               cachedInnerUsage;
    }

    uint64_t GetMaxDynamicMemoryUsage() const { return maxDynamicUsage; }

    const indexed_disconnected_transactions &GetQueuedTx() const {
        return queuedTx;
    }

    // Import mempool entries in topological order into queuedTx and clear the
    // mempool. Caller should call updateMempoolForReorg to reprocess these
    // transactions
    void importMempool(CTxMemPool &pool);

    // Add entries for a block while reconstructing the topological ordering so
    // they can be added back to the mempool simply.
    void addForBlock(Span<const CTransactionRef> vtx, bool checkSanityForTests = false);

    // Identical to the above, but doesn't apply any dynamic memory usage limits.
    // Use this for one-offs when using this class as a topological sorter.
    void addNoLimit(Span<const CTransactionRef> vtx, bool checkSanityForTests = false);

    // Remove entries based on txid_index, and update memory usage.
    void removeForBlock(Span<const CTransactionRef> vtx) {
        // Short-circuit in the common case of a block being added to the tip
        if (queuedTx.empty()) {
            return;
        }
        for (auto const &tx : vtx) {
            auto it = queuedTx.find(tx->GetId());
            if (it != queuedTx.end()) {
                cachedInnerUsage -= RecursiveDynamicUsage(tx);
                queuedTx.erase(it);
                txInfo.erase(tx->GetId());
            }
        }
    }

    // Remove an entry by insertion_order index, and update memory usage.
    void removeEntry(indexed_disconnected_transactions::index<
                     insertion_order>::type::iterator entry) {
        cachedInnerUsage -= RecursiveDynamicUsage(*entry);
        txInfo.erase((*entry)->GetId());
        queuedTx.get<insertion_order>().erase(entry);
    }

    bool isEmpty() const { return queuedTx.empty(); }

    void clear() {
        cachedInnerUsage = 0;
        queuedTx.clear();
        txInfo.clear();
    }

    /**
     * Make mempool consistent after a reorg, by re-adding or recursively
     * erasing disconnected block transactions from the mempool, and also
     * removing any other transactions from the mempool that are no longer valid
     * given the new tip/height.
     *
     * Note: we assume that disconnectpool only contains transactions that are
     * NOT confirmed in the current chain nor already in the mempool (otherwise,
     * in-mempool descendants of such transactions would be removed).
     *
     * Passing fAddToMempool=false will skip trying to add the transactions
     * back, and instead just erase from the mempool as needed.
     */
    void updateMempoolForReorg(const Config &config, bool fAddToMempool);
};
