// Copyright (c) 2021-2022 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <util/time.h>

#include <cassert>

TxOrphanage::TxOrphanage() : m_rng{std::make_unique<FastRandomContext>()} {}
TxOrphanage::~TxOrphanage() {}

bool TxOrphanage::AddTx(const CTransactionRef &tx, const NodeId peer) {
    const TxId &txid = tx->GetId();
    if (m_orphans.contains(txid)) {
        return false;
    }

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 100 orphans, each of which is at most 100,000 bytes big is
    // at most 10 megabytes of orphans and somewhat more byprev index (in the worst case):
    const size_t sz = tx->GetTotalSize();
    if (sz > MAX_STANDARD_TX_SIZE) {
        LogPrint(BCLog::MEMPOOL, "ignoring large orphan tx (size: %u, txid: %s)\n", sz, txid.ToString());
        return false;
    }

    auto ret = m_orphans.try_emplace(txid, tx, peer, GetTime() + ORPHAN_TX_EXPIRE_TIME, m_orphan_list.size());
    assert(ret.second);
    m_orphan_list.push_back(ret.first);
    for (const CTxIn &txin : tx->vin) {
        m_outpoint_to_orphan_it[txin.prevout].insert(ret.first);
    }

    LogPrint(BCLog::MEMPOOL, "stored orphan tx %s, size: %u (mapsz %u, outsz %u)\n",
             txid.ToString(), sz, m_orphans.size(), m_outpoint_to_orphan_it.size());
    return true;
}

size_t TxOrphanage::EraseTx(const TxId &txid) {
    const auto it = m_orphans.find(txid);
    if (it == m_orphans.end()) {
        return 0u;
    }
    for (const CTxIn &txin : it->second.tx->vin) {
        auto itPrev = m_outpoint_to_orphan_it.find(txin.prevout);
        if (itPrev == m_outpoint_to_orphan_it.end()) {
            continue;
        }
        itPrev->second.erase(it);
        if (itPrev->second.empty()) {
            m_outpoint_to_orphan_it.erase(itPrev); // `itPrev` invalidated here!
        }
    }

    const size_t old_pos = it->second.list_pos;
    assert(m_orphan_list[old_pos] == it);
    if (old_pos + 1u != m_orphan_list.size()) {
        // Unless we're deleting the last entry in m_orphan_list, move the last
        // entry to the position we're deleting.
        auto it_last = m_orphan_list.back();
        m_orphan_list[old_pos] = it_last;
        it_last->second.list_pos = old_pos;
    }
    // Time spent in orphanage = difference between current and entry time.
    // Entry time is equal to ORPHAN_TX_EXPIRE_TIME earlier than entry's expiry.
    LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s after %ds (mapsz %u, outsz %u)\n", txid.ToString(),
             GetTime() + ORPHAN_TX_EXPIRE_TIME - it->second.nTimeExpire,
             m_orphans.size() - 1u, m_outpoint_to_orphan_it.size());
    m_orphan_list.pop_back();

    m_orphans.erase(it); // `it` invalidated here!
    return 1u;
}

void TxOrphanage::EraseForPeer(const NodeId peer) {
    m_peer_work_set.erase(peer);

    size_t nErased = 0;
    auto iter = m_orphans.begin();
    while (iter != m_orphans.end()) {
        // Increment to avoid iterator becoming invalid after erasure
        const auto & [txid, orphan] = *iter++;
        if (orphan.fromPeer == peer) {
            nErased += EraseTx(txid);
        }
    }
    if (nErased > 0u) {
        LogPrint(BCLog::MEMPOOL, "Erased %u orphan transaction(s) from peer=%d\n", nErased, peer);
    }
}

void TxOrphanage::LimitOrphans(const size_t max_orphans) {
    size_t nEvicted = 0;
    const auto nNow = GetTime();
    if (m_next_sweep <= nNow) {
        // Sweep out expired orphan pool entries:
        size_t nErased = 0;
        auto nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        auto iter = m_orphans.begin();
        while (iter != m_orphans.end()) {
            auto maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                nErased += EraseTx(maybeErase->second.tx->GetId());
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        m_next_sweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (nErased > 0) {
            LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx due to expiration\n", nErased);
        }
    }
    while (m_orphans.size() > max_orphans) {
        // Evict a random orphan:
        size_t randompos = m_rng->randrange(m_orphan_list.size());
        EraseTx(m_orphan_list[randompos]->second.tx->GetId());
        ++nEvicted;
    }
    if (nEvicted > 0) {
        LogPrint(BCLog::MEMPOOL, "orphanage overflow, removed %u tx\n", nEvicted);
    }
}

void TxOrphanage::AddChildrenToWorkSet(const CTransaction &tx) {
    const TxId &txid = tx.GetId();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(txid, i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto &elem : it_by_prev->second) {
                // Get this source peer's work set, emplacing an empty set if it didn't exist
                // (note: if this peer wasn't still connected, we would have removed the orphan tx already)
                std::set<TxId> &orphan_work_set = m_peer_work_set[elem->second.fromPeer];
                // Add this tx to the work set
                const bool isnew = orphan_work_set.insert(elem->first).second;
                if (isnew) {
                    LogPrint(BCLog::MEMPOOL, "added %s to peer %d workset (setsz %d, nsets %d)\n",
                             txid.ToString(), elem->second.fromPeer, orphan_work_set.size(), m_peer_work_set.size());
                }
            }
        }
    }
}

bool TxOrphanage::HaveTx(const TxId &txid) const {
    return m_orphans.contains(txid);
}

CTransactionRef TxOrphanage::GetTxToReconsider(const NodeId peer) {
    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        auto &work_set = work_set_it->second;
        while (!work_set.empty()) {
            const TxId txid = *work_set.begin();
            work_set.erase(work_set.begin());

            const auto orphan_it = m_orphans.find(txid);
            if (orphan_it != m_orphans.end()) {
                return orphan_it->second.tx;
            }
        }
    }
    return nullptr;
}

bool TxOrphanage::HaveTxToReconsider(const NodeId peer) const {
    auto work_set_it = m_peer_work_set.find(peer);
    if (work_set_it != m_peer_work_set.end()) {
        const auto &work_set = work_set_it->second;
        return !work_set.empty();
    }
    return false;
}

void TxOrphanage::EraseForBlock(const CBlock& block) {
    std::vector<TxId> vOrphanErase;

    for (const CTransactionRef &ptx : block.vtx) {
        // Which orphan pool entries must we evict?
        for (const auto &txin : ptx->vin) {
            const auto itByPrev = m_outpoint_to_orphan_it.find(txin.prevout);
            if (itByPrev == m_outpoint_to_orphan_it.end()) {
                continue;
            }
            for (const OrphanMap::iterator &orphansIt : itByPrev->second) {
                const TxId &orphanTxId = orphansIt->first;
                vOrphanErase.push_back(orphanTxId);
            }
        }
    }

    // Erase orphan transactions included or precluded by this block
    if (vOrphanErase.size()) {
        size_t nErased = 0;
        for (const auto &orphanId : vOrphanErase) {
            nErased += EraseTx(orphanId);
        }
        LogPrint(BCLog::MEMPOOL, "Erased %d orphan transaction(s) included or conflicted by block\n", nErased);
    }
}

std::vector<CTransactionRef> TxOrphanage::GetChildrenFromSamePeer(const CTransactionRef &parent, const NodeId nodeid) const {
    // First construct a vector of iterators to ensure we do not return duplicates of the same tx
    // and so we can sort by nTimeExpire.
    std::vector<OrphanMap::iterator> iters;

    // For each output, get all entries spending this prevout, filtering for ones from the specified peer.
    for (size_t i = 0; i < parent->vout.size(); ++i) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(parent->GetId(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto &elem : it_by_prev->second) {
                if (elem->second.fromPeer == nodeid) {
                    iters.emplace_back(elem);
                }
            }
        }
    }

    // Sort so that more recent orphans (which expire later) come first.  Break ties based on txid, as nTimeExpire is
    // quantified in seconds and it is possible for orphans to have the same expiry.
    std::sort(iters.begin(), iters.end(), [](const auto &lhs, const auto &rhs) {
        if (lhs->second.nTimeExpire == rhs->second.nTimeExpire) {
            return lhs->first < rhs->first;
        } else {
            return lhs->second.nTimeExpire > rhs->second.nTimeExpire;
        }
    });
    // Erase duplicates
    iters.erase(std::unique(iters.begin(), iters.end()), iters.end());

    // Convert to a vector of CTransactionRef
    std::vector<CTransactionRef> children_found;
    children_found.reserve(iters.size());
    for (const auto &child_iter : iters) {
        children_found.emplace_back(child_iter->second.tx);
    }
    return children_found;
}

std::vector<std::pair<CTransactionRef, NodeId>> TxOrphanage::GetChildrenFromDifferentPeer(const CTransactionRef& parent,
                                                                                          const NodeId nodeid) const {
    // First construct vector of iterators to ensure we do not return duplicates of the same tx.
    std::vector<OrphanMap::iterator> iters;

    // For each output, get all entries spending this prevout, filtering for ones not from the specified peer.
    for (size_t i = 0; i < parent->vout.size(); ++i) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(parent->GetId(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto &elem : it_by_prev->second) {
                if (elem->second.fromPeer != nodeid) {
                    iters.emplace_back(elem);
                }
            }
        }
    }

    // Erase duplicates
    std::sort(iters.begin(), iters.end(), IteratorComparator());
    iters.erase(std::unique(iters.begin(), iters.end()), iters.end());

    // Convert iterators to pair<CTransactionRef, NodeId>
    std::vector<std::pair<CTransactionRef, NodeId>> children_found;
    children_found.reserve(iters.size());
    for (const auto &child_iter : iters) {
        children_found.emplace_back(child_iter->second.tx, child_iter->second.fromPeer);
    }
    return children_found;
}

std::vector<TxOrphanage::OrphanTxBase> TxOrphanage::GetOrphanTransactions() const {
    std::vector<OrphanTxBase> ret;
    ret.reserve(m_orphans.size());
    for (const auto & [_, orphanTx] : m_orphans) {
        ret.push_back(orphanTx);
    }
    return ret;
}
