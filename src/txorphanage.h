// Copyright (c) 2021-2022 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/time.h>

#include <map>
#include <memory>
#include <set>

class FastRandomContext;

/** Expiration time for orphan transactions in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 * Not thread-safe. Requires external synchronization.
 */
class TxOrphanage {
public:
    TxOrphanage();
    ~TxOrphanage();

    /** Add a new orphan transaction */
    bool AddTx(const CTransactionRef &tx, NodeId peer);

    /** Check if we already have an orphan transaction (by txid only) */
    bool HaveTx(const TxId &txid) const;

    /** Extract a transaction from a peer's work set
     *  Returns nullptr if there are no transactions to work on.
     *  Otherwise returns the transaction reference, and removes
     *  it from the work set.
     */
    CTransactionRef GetTxToReconsider(NodeId peer);

    /** Erase an orphan by txid, returns 1 on success, 0 otherwise */
    size_t EraseTx(const TxId &txid);

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseForPeer(NodeId peer);

    /** Erase all orphans included in or invalidated by a new block */
    void EraseForBlock(const CBlock &block);

    /** Limit the orphanage to the given maximum */
    void LimitOrphans(size_t max_orphans);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction &tx);

    /** Does this peer have any work to do? */
    bool HaveTxToReconsider(NodeId peer) const;

    /** Get all children that spend from this tx and were received from nodeid. Sorted from most
     * recent to least recent. */
    std::vector<CTransactionRef> GetChildrenFromSamePeer(const CTransactionRef &parent, NodeId nodeid) const;

    /** Get all children that spend from this tx but were not received from nodeid. Also return which peer provided each tx. */
    std::vector<std::pair<CTransactionRef, NodeId>> GetChildrenFromDifferentPeer(const CTransactionRef &parent, NodeId nodeid) const;

    /** Return how many entries exist in the orphange */
    size_t Size() const {
        return m_orphans.size();
    }

    /** Allows providing orphan information externally */
    struct OrphanTxBase {
        CTransactionRef tx;
        NodeId fromPeer{};
        int64_t nTimeExpire{};

        OrphanTxBase() = default;
        explicit OrphanTxBase(const CTransactionRef &tx_, const NodeId fromPeer_ = 0, const int64_t nTimeExpire_ = 0)
            : tx{tx_}, fromPeer{fromPeer_}, nTimeExpire{nTimeExpire_} {}
    };

    std::vector<OrphanTxBase> GetOrphanTransactions() const;

protected:
    struct OrphanTx : OrphanTxBase {
        size_t list_pos{};

        OrphanTx(const CTransactionRef &tx_, const NodeId fromPeer_, const int64_t nTimeExpire_, const size_t list_pos_)
            : OrphanTxBase(tx_, fromPeer_, nTimeExpire_), list_pos{list_pos_} {}
    };

    using OrphanMap = std::map<TxId, OrphanTx>;

    /** Map from txid to orphan transaction record. Limited by -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    OrphanMap m_orphans;

    /** Which peer provided the orphans that need to be reconsidered */
    std::map<NodeId, std::set<TxId>> m_peer_work_set;

    struct IteratorComparator {
        bool operator()(const OrphanMap::iterator &a, const OrphanMap::iterator &b) const {
            return a->first < b->first;
        }
    };

    /** Index from the parents' COutPoint into the m_orphans. Used to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it;

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list;

    /** Timestamp for the next scheduled sweep of expired orphans */
    int64_t m_next_sweep = 0;

    // Used internally by LimitOrphans()
    std::unique_ptr<FastRandomContext> m_rng;
};
