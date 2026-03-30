// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>

#include <algorithm/contains.h>
#include <algorithm/erase_if.h>
#include <chain.h>
#include <chainparams.h> // for GetConsensus.
#include <clientversion.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <dsproof/dsproof.h>
#include <dsproof/storage.h>
#include <policy/fees.h>
#include <policy/mempool.h>
#include <policy/policy.h>
#include <reverse_iterator.h>
#include <streams.h>
#include <timedata.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>
#include <version.h>

#include <algorithm>
#include <deque>
#include <functional>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef &_tx, const Amount _nFee,
                                 int64_t _nTime,
                                 bool _spendsCoinbase, int64_t _sigChecks,
                                 LockPoints lp)
    : tx(_tx), nFee(_nFee), nTxSize(tx->GetTotalSize()),
      nUsageSize(RecursiveDynamicUsage(tx)), nTime(_nTime),
      spendsCoinbase(_spendsCoinbase),
      sigChecks(_sigChecks), lockPoints(lp) {

    feeDelta = Amount::zero();
}

size_t CTxMemPoolEntry::GetTxVirtualSize() const {
    return GetVirtualTransactionSize(nTxSize, sigChecks);
}

void CTxMemPoolEntry::UpdateFeeDelta(Amount newFeeDelta) {
    feeDelta = newFeeDelta;
}

void CTxMemPoolEntry::UpdateLockPoints(const LockPoints &lp) {
    lockPoints = lp;
}

void CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors,
                                           bool fSearchForParents /* = true */) const {
    setEntries parentHashes;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents) {
        // Get parents of this transaction that are in the mempool
        // GetMemPoolParents() is only valid for entries in the mempool, so we
        // iterate mapTx to find parents.
        for (const CTxIn &in : tx.vin) {
            std::optional<txiter> piter = GetIter(in.prevout.GetTxId());
            if (!piter) {
                continue;
            }
            parentHashes.insert(*piter);
        }
    } else {
        // If we're not searching for parents, we require this to be an entry in
        // the mempool already.
        txiter it = mapTx.iterator_to(entry);
        parentHashes = GetMemPoolParents(it);
    }

    while (!parentHashes.empty()) {
        txiter stageit = *parentHashes.begin();

        setAncestors.insert(stageit);
        parentHashes.erase(parentHashes.begin());

        const setEntries &setMemPoolParents = GetMemPoolParents(stageit);
        for (txiter phash : setMemPoolParents) {
            // If this is a new ancestor, add it.
            if (!algo::contains(setAncestors, phash)) {
                parentHashes.insert(phash);
            }
        }
    }
}

void CTxMemPool::UpdateParentsOf(bool add, txiter it) {
    // add or remove this tx as a child of each parent
    for (txiter piter : GetMemPoolParents(it)) {
        UpdateChild(piter, it, add);
    }
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it) {
    const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
    for (txiter updateIt : setMemPoolChildren) {
        UpdateParent(updateIt, it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove) {
    for (txiter removeIt : entriesToRemove) {
        // Note that UpdateParentsOf severs the child links that point to
        // removeIt in the mapLinks entries for the parents of removeIt.
        UpdateParentsOf(false, removeIt);
    }
    // After updating all the parent links, we can now sever the link between
    // each transaction being removed and any mempool children (ie, update
    // setMemPoolParents for each direct child of a transaction being removed).
    for (txiter removeIt : entriesToRemove) {
        UpdateChildrenForRemoval(removeIt);
    }
}

CTxMemPool::CTxMemPool()
    : nTransactionsUpdated(0),
      m_dspStorage(std::make_unique<DoubleSpendProofStorage>())
{
    // lock free clear
    _clear();

    // Sanity checks off by default for performance, because otherwise accepting
    // transactions becomes O(N^2) where N is the number of transactions in the
    // pool
    nCheckFrequency = 0;
}

CTxMemPool::~CTxMemPool() {}

bool CTxMemPool::isSpent(const COutPoint &outpoint) const {
    LOCK(cs);
    return algo::contains(mapNextTx, outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const {
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n) {
    LOCK(cs);
    nTransactionsUpdated += n;
}

uint64_t CTxMemPool::addUnchecked(CTxMemPoolEntry &&entry) {
    // get a guaranteed unique id (in case tests re-use the same object)
    entry.SetEntryId(nextEntryId++);

    // Update transaction for any feeDelta created by PrioritiseTransaction
    {
        Amount feeDelta = Amount::zero();
        ApplyDelta(entry.GetTx().GetId(), feeDelta);
        entry.UpdateFeeDelta(feeDelta);
    }

    NotifyEntryAdded(entry.GetSharedTx());

    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do all the appropriate checks.
    auto [newit, inserted] = mapTx.insert(entry);
    // Sanity check: It is a programming error if insertion fails (uniqueness invariants in mapTx are violated, etc)
    assert(inserted);
    // Sanity check: We should always end up inserting at the end of the entry_id index
    assert(&*mapTx.get<entry_id>().rbegin() == &*newit);

    mapLinks.try_emplace(newit);

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction &tx = newit->GetTx();
    std::set<TxId> setParentTransactions;
    for (const CTxIn &in : tx.vin) {
        mapNextTx.emplace(&in.prevout, &tx);
        setParentTransactions.insert(in.prevout.GetTxId());
    }
    // Don't bother worrying about child transactions of this one. It is
    // guaranteed that a new transaction arriving will not have any children,
    // because such children would be orphans.

    // Update ancestors with information about this tx
    for (const auto &pit : GetIterSet(setParentTransactions)) {
        UpdateParent(newit, pit, true);
    }
    UpdateParentsOf(true, newit);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    totalTxFee += entry.GetFee();
    return newit->GetEntryId();
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason) {
    NotifyEntryRemoved(it->GetSharedTx(), reason);
    if (it->HasDsp()) {
        // we put known dsproofs back into the orphan pool just in case there is
        // a reorg in the future and this deleted tx comes back.
        m_dspStorage->orphanExisting(it->GetDspId());
    }
    for (const CTxIn &txin : it->GetTx().vin) {
        mapNextTx.erase(txin.prevout);
    }

    totalTxSize -= it->GetTxSize();
    totalTxFee -= it->GetFee();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    if (const auto linksiter = mapLinks.find(it); linksiter != mapLinks.end()) {
        cachedInnerUsage -= memusage::DynamicUsage(linksiter->second.parents) +
                            memusage::DynamicUsage(linksiter->second.children);
        mapLinks.erase(linksiter);
    }
    mapTx.erase(it);
    nTransactionsUpdated++;
}

// Calculates descendants of entry that are not already in setDescendants, and
// adds to setDescendants. Assumes entryit is already a tx in the mempool and
// setMemPoolChildren is correct for tx and all descendants. Also assumes that
// if an entry is in setDescendants already, then all in-mempool descendants of
// it are already in setDescendants as well, so that we can save time by not
// iterating over those entries.
void CTxMemPool::CalculateDescendants(txiter entryit,
                                      setEntries &setDescendants) const {
    setEntries stage;
    if (!algo::contains(setDescendants, entryit)) {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have
    // either already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        txiter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(stage.begin());

        const setEntries &setChildren = GetMemPoolChildren(it);
        for (txiter childiter : setChildren) {
            if (!algo::contains(setDescendants, childiter)) {
                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx,
                                 MemPoolRemovalReason reason) {
    // Remove transaction from memory pool.
    LOCK(cs);
    setEntries txToRemove;
    txiter origit = mapTx.find(origTx.GetId());
    if (origit != mapTx.end()) {
        txToRemove.insert(origit);
    } else {
        // When recursively removing but origTx isn't in the mempool be sure to
        // remove any children that are in the pool. This can happen during
        // chain re-orgs if origTx isn't re-accepted into the mempool for any
        // reason.
        auto it = mapNextTx.lower_bound(COutPoint(origTx.GetId(), 0));
        while (it != mapNextTx.end() && it->first->GetTxId() == origTx.GetId()) {
            txiter nextit = mapTx.find(it->second->GetId());
            assert(nextit != mapTx.end());
            txToRemove.insert(nextit);
            ++it;
        }
    }

    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }

    RemoveStaged(setAllRemoves, reason);
}

void CTxMemPool::removeConflicts(const CTransaction &tx) {
    // Remove transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx) {
                ClearPrioritisation(txConflict.GetId());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner
 * fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef> &vtx) {
    LOCK(cs);

    if (mapTx.empty() && mapDeltas.empty()) {
        // fast-path for IBD and/or when mempool is empty; there is no need to
        // do any of the set-up work below which eats precious cycles.
        return;
    }

    DisconnectedBlockTransactions disconnectpool;
    disconnectpool.addNoLimit(vtx);

    // iterate in topological order (parents before children)
    for (const CTransactionRef &tx : reverse_iterate(disconnectpool.GetQueuedTx().get<insertion_order>())) {
        const txiter it = mapTx.find(tx->GetId());
        if (it != mapTx.end()) {
            setEntries stage;
            stage.insert(it);
            RemoveStaged(stage, MemPoolRemovalReason::BLOCK);
        } else {
            removeConflicts(*tx);
        }
    }
    // clear prioritisations (mapDeltas); optmized for the common case where
    // mapDeltas is empty or much smaller than block.vtx
    algo::erase_if(mapDeltas, [&disconnectpool](const auto &kv) {
        return algo::contains(disconnectpool.GetQueuedTx(), kv.first);
    });

    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;

    disconnectpool.clear();
}

void CTxMemPool::_clear(bool clearDspOrphans /*= true*/) {
    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    totalTxSize = 0;
    totalTxFee = Amount::zero();
    cachedInnerUsage = 0;
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = false;
    rollingMinimumFeeRate = 0;
    m_dspStorage->clear(clearDspOrphans);
    ++nTransactionsUpdated;
}

void CTxMemPool::clear(bool clearDspOrphans /*= true*/) {
    LOCK(cs);
    _clear(clearDspOrphans);
}

static void CheckInputsAndUpdateCoins(const CTransaction &tx,
                                      CCoinsViewCache &mempoolDuplicate,
                                      const int64_t spendheight) {
    CValidationState state;
    Amount txfee = Amount::zero();
    bool fCheckResult =
        tx.IsCoinBase() || Consensus::CheckTxInputs(tx, state, mempoolDuplicate,
                                                    spendheight, txfee);
    assert(fCheckResult);
    UpdateCoins(mempoolDuplicate, tx, std::numeric_limits<int>::max());
}

void CTxMemPool::check(const CCoinsViewCache *pcoins) const {
    LOCK(cs);
    if (nCheckFrequency == 0) {
        return;
    }

    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency) {
        return;
    }

    LogPrint(BCLog::MEMPOOL,
             "Checking mempool with %u transactions and %u inputs\n",
             (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    Amount checkFee = Amount::zero();
    uint64_t innerUsage = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache *>(pcoins));
    const int64_t spendheight = GetSpendHeight(mempoolDuplicate);

    std::list<const CTxMemPoolEntry *> waitingOnDependants;
    for (txiter it = mapTx.begin(); it != mapTx.end(); ++it) {
        checkTotal += it->GetTxSize();
        checkFee += it->GetFee();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction &tx = it->GetTx();
        auto linksiter = mapLinks.find(it);
        assert(linksiter != mapLinks.end());
        const TxLinks &links = linksiter->second;
        innerUsage += memusage::DynamicUsage(links.parents) +
                      memusage::DynamicUsage(links.children);
        bool fDependsWait = false;
        setEntries setParentCheck;
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available
            // coins, or other mempool tx's.
            txiter it2 = mapTx.find(txin.prevout.GetTxId());
            if (it2 != mapTx.end()) {
                const CTransaction &tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.GetN() &&
                       !tx2.vout[txin.prevout.GetN()].IsNull());
                fDependsWait = true;
                setParentCheck.insert(it2);
                // also check that parents have a topological ordering before their children
                assert(it2->GetEntryId() < it->GetEntryId());
            } else {
                assert(pcoins->HaveCoin(txin.prevout));
            }
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->first == &txin.prevout);
            assert(it3->second == &tx);
        }
        assert(setParentCheck == GetMemPoolParents(it));
        // Verify ancestor state is correct.
        setEntries setAncestors;
        CalculateMemPoolAncestors(*it, setAncestors);
        // all ancestors should have entryId < this tx's entryId
        for (const auto &ancestor : setAncestors)
            assert(ancestor->GetEntryId() < it->GetEntryId());

        // Check children against mapNextTx
        CTxMemPool::setEntries setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetId(), 0));
        for (; iter != mapNextTx.end() &&
               iter->first->GetTxId() == it->GetTx().GetId();
             ++iter) {
            txiter childit = mapTx.find(iter->second->GetId());
            // mapNextTx points to in-mempool transactions
            assert(childit != mapTx.end());
            setChildrenCheck.insert(childit);
        }
        assert(setChildrenCheck == GetMemPoolChildren(it));

        if (fDependsWait) {
            waitingOnDependants.push_back(&(*it));
        } else {
            CheckInputsAndUpdateCoins(tx, mempoolDuplicate, spendheight);
        }
    }

    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry *entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            CheckInputsAndUpdateCoins(entry->GetTx(), mempoolDuplicate,
                                      spendheight);
            stepsSinceLastRemove = 0;
        }
    }

    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        const TxId &txid = it->second->GetId();
        indexed_transaction_set::const_iterator it2 = mapTx.find(txid);
        const CTransaction &tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    assert(totalTxSize == checkTotal);
    assert(totalTxFee == checkFee);
    assert(innerUsage == cachedInnerUsage);
}

void CTxMemPool::queryHashes(std::vector<uint256> &vtxid) const {
    LOCK(cs);

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (const auto &entry : mapTx.get<entry_id>()) {
        vtxid.push_back(entry.GetTx().GetId());
    }
}

static TxMempoolInfo
GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(),
                         CFeeRate(it->GetFee(), it->GetTxSize()),
                         it->GetModifiedFee() - it->GetFee(),
                         it->GetEntryId()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const {
    LOCK(cs);

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());

    const auto & index = mapTx.get<entry_id>();
    for (auto it = index.begin(); it != index.end(); ++it) {
        ret.push_back(GetInfo(mapTx.project<0>(it)));
    }

    return ret;
}

CTransactionRef CTxMemPool::get(const TxId &txid) const {
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(txid);
    if (i == mapTx.end()) {
        return nullptr;
    }

    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const TxId &txid) const {
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(txid);
    if (i == mapTx.end()) {
        return TxMempoolInfo();
    }

    return GetInfo(i);
}

CFeeRate CTxMemPool::estimateFee() const {
    LOCK(cs);

    const Config &config = GetConfig();
    uint64_t maxMempoolSize = config.GetMaxMemPoolSize();
    // minerPolicy uses recent blocks to figure out a reasonable fee.  This
    // may disagree with the rollingMinimumFeerate under certain scenarios
    // where the mempool  increases rapidly, or blocks are being mined which
    // do not contain propagated transactions.
    return std::max(::minRelayTxFee, GetMinFee(maxMempoolSize));
}

void CTxMemPool::PrioritiseTransaction(const TxId &txid,
                                       const Amount nFeeDelta) {
    {
        LOCK(cs);
        Amount &delta = mapDeltas[txid];
        delta += nFeeDelta;
        txiter it = mapTx.find(txid);
        if (it != mapTx.end()) {
            mapTx.modify(it, update_fee_delta(delta));
            ++nTransactionsUpdated;
        }
    }
    LogPrintf("PrioritiseTransaction: %s fee += %s\n", txid.ToString(),
              FormatMoney(nFeeDelta));
}

void CTxMemPool::ApplyDelta(const TxId &txid, Amount &nFeeDelta) const {
    LOCK(cs);
    auto pos = mapDeltas.find(txid);
    if (pos == mapDeltas.end())
        return;
    nFeeDelta += pos->second;
}

void CTxMemPool::ClearPrioritisation(const TxId &txid) {
    LOCK(cs);
    mapDeltas.erase(txid);
}

const CTransaction *CTxMemPool::GetConflictTx(const COutPoint &prevout) const {
    const auto it = mapNextTx.find(prevout);
    return it == mapNextTx.end() ? nullptr : it->second;
}

std::optional<CTxMemPool::txiter>
CTxMemPool::GetIter(const TxId &txid) const {
    std::optional<CTxMemPool::txiter> ret;
    auto it = mapTx.find(txid);
    if (it != mapTx.end()) {
        ret.emplace(it);
    }
    return ret;
}

CTxMemPool::setEntries
CTxMemPool::GetIterSet(const std::set<TxId> &txids) const {
    CTxMemPool::setEntries ret;
    for (const auto &txid : txids) {
        const auto mi = GetIter(txid);
        if (mi) {
            ret.insert(*mi);
        }
    }
    return ret;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const {
    for (const CTxIn &in : tx.vin) {
        if (exists(in.prevout.GetTxId())) {
            return false;
        }
    }

    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView *baseIn,
                                     const CTxMemPool &mempoolIn)
    : CCoinsViewBacked(baseIn), mempool(mempoolIn) {}

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // If an entry in the mempool exists, always return that one, as it's
    // guaranteed to never conflict with the underlying cache, and it cannot
    // have pruned entries (as it contains full) transactions. First checking
    // the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.GetTxId());
    if (ptx) {
        if (outpoint.GetN() < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.GetN()], MEMPOOL_HEIGHT, false);
            return true;
        }
        return false;
    }
    return base->GetCoin(outpoint, coin);
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 9 pointers + an allocation, as no
    // exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) +
                                 9 * sizeof(void *)) *
               mapTx.size() +
           memusage::DynamicUsage(mapNextTx) +
           memusage::DynamicUsage(mapDeltas) +
           memusage::DynamicUsage(mapLinks) +
           cachedInnerUsage;
}

void CTxMemPool::RemoveStaged(const setEntries &stage, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage);
    for (txiter it : stage) {
        removeUnchecked(it, reason);
    }
}

size_t CTxMemPool::Expire(int64_t time, bool fast /* = true */) {
    LOCK(cs);

    setEntries stage;
    auto const& index = mapTx.get<entry_id>();
    for (auto it = index.begin(); it != index.end(); ++it) {
        if (it->GetTime() < time) {
            CalculateDescendants(mapTx.project<0>(it), stage);
        } else if (fast) {
            break;
        }
    }

    RemoveStaged(stage, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

void CTxMemPool::LimitSize(size_t limit, unsigned long age) {
    auto expired = Expire(GetTime() - age, /* fast */ true);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint &removed : vNoSpendsRemaining) {
        pcoinsTip->Uncache(removed);
    }
}

// NB: The pointer type is only used for template overload selection and never dereferenced so this is safe.
inline constexpr size_t setEntriesIncrementalUsage =
        memusage::IncrementalDynamicUsage(static_cast<CTxMemPool::setEntries *>(nullptr));

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add) {
    if (add && mapLinks[entry].children.insert(child).second) {
        cachedInnerUsage += setEntriesIncrementalUsage;
    } else if (!add && mapLinks[entry].children.erase(child)) {
        cachedInnerUsage -= setEntriesIncrementalUsage;
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add) {
    if (add && mapLinks[entry].parents.insert(parent).second) {
        cachedInnerUsage += setEntriesIncrementalUsage;
    } else if (!add && mapLinks[entry].parents.erase(parent)) {
        cachedInnerUsage -= setEntriesIncrementalUsage;
    }
}

const CTxMemPool::setEntries &
CTxMemPool::GetMemPoolParents(txiter entry) const {
    assert(entry != mapTx.end());
    auto it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.parents;
}

const CTxMemPool::setEntries &
CTxMemPool::GetMemPoolChildren(txiter entry) const {
    assert(entry != mapTx.end());
    auto it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

CTransactionRef CTxMemPool::addDoubleSpendProof(const DoubleSpendProof &proof, const std::optional<txiter> &optIter) {
    LOCK(cs);
    txiter iter;
    if (!optIter) {
        auto spendingTx = mapNextTx.find(proof.outPoint());
        if (spendingTx == mapNextTx.end()) {
            // Nothing spent this or tx disappeared in the meantime
            // -- proof no longer valid. Caller will accept the situation.
            return CTransactionRef();
        }
        iter = mapTx.find(spendingTx->second->GetId());
    } else
        iter = *optIter;

    if (iter->HasDsp())  {
        // A DSProof already exists for this tx, don't propagate new one.
        return CTransactionRef();
    }

    CTransactionRef ret{iter->GetSharedTx()};

    // Add to storage. If this was an orphan it will implicitly be flagged as a non-orphan
    m_dspStorage->add(proof);
    // Update mempool entry to save the dspId
    const auto &hash = proof.GetId();
    mapTx.modify(iter, [&hash](CTxMemPoolEntry &entry){ entry.SetDspId(hash); });
    return ret;
}

DoubleSpendProofStorage *CTxMemPool::doubleSpendProofStorage() const {
    return m_dspStorage.get();
}

//! list all known proofs, optionally also returning all known orphans (orphans have an .IsNull() TxId)
auto CTxMemPool::listDoubleSpendProofs(const bool includeOrphans) const -> std::vector<DspTxIdPair> {
    std::vector<DspTxIdPair> ret;
    LOCK(cs);
    auto proofs = m_dspStorage->getAll(includeOrphans);
    ret.reserve(proofs.size());
    for (auto & [proof, isOrphan] : proofs) {
        TxId txId;
        if (proof.isEmpty())
            throw std::runtime_error("Internal error: m_dspStorage returned an empty proof");
        if (isOrphan && !includeOrphans)
            throw std::runtime_error("Internal error: m_dspStorage returned orphans unexpectedly");
        if (!isOrphan) {
            // find the txId for this proof
            if (auto it = mapNextTx.find(proof.outPoint()); it != mapNextTx.end()) {
                txId = it->second->GetId();
                // Sanity check that actual CTxMemPoolEntry also has this DspId associated
                if (auto optiter = GetIter(txId); !optiter || (*optiter)->GetDspId() != proof.GetId()) {
                    // should never happen, indicates bug in code
                    throw std::runtime_error(strprintf("Unexpected state: DspId %s for COutPoint %s is not associated"
                                                       " with the expected txId %s!",
                                                       proof.GetId().ToString(), proof.outPoint().ToString(),
                                                       txId.ToString()));
                }
            } else {
                // should never happen, indicates bug in code
                throw std::runtime_error(strprintf("Unexpected state: DspId %s for COutPoint %s is missing its tx from"
                                                   " mempool, yet is not marked as an orphan!",
                                                   proof.GetId().ToString(), proof.outPoint().ToString()));
            }
        }
        ret.emplace_back(std::move(proof), std::move(txId) /* if orphan txId will be .IsNull() here */);
    }
    return ret;
}

//! Lookup a dsproof by dspId. If the proof is an orphan, it will have an .IsNull() TxId
auto CTxMemPool::getDoubleSpendProof(const DspId &dspId, DspDescendants *desc) const -> std::optional<DspTxIdPair> {
    std::optional<DspTxIdPair> ret;
    LOCK(cs);

    if (auto dsproof = m_dspStorage->lookup(dspId); dsproof.isEmpty()) {
        // not found, return nullopt
        return ret;
    } else {
        // found, populate ret
        ret.emplace(std::piecewise_construct, std::forward_as_tuple(std::move(dsproof)), std::forward_as_tuple());
    }
    // next, see if it's an orphan or not by looking up its COutPoint
    auto & [dsproof, txId] = *ret;
    if (auto it = mapNextTx.find(dsproof.outPoint()); it != mapNextTx.end()) {
        // Not an orphan, set txId
        txId = it->second->GetId();
        if (desc) {
            // caller supplied a descendants set they want populated, so populate it on this hit
            if (auto optIter = GetIter(txId))
                *desc = getDspDescendantsForIter(*optIter);
        }
    }
    return ret;
}

//! Lookup a dsproof by TxId.
auto CTxMemPool::getDoubleSpendProof(const TxId &txId, DspDescendants *desc) const -> std::optional<DoubleSpendProof> {
    LOCK(cs);
    return getDoubleSpendProof_common(txId, desc);
}

//! Helper (requires cs is held)
auto CTxMemPool::getDspDescendantsForIter(txiter it) const -> DspDescendants {
    DspDescendants ret;
    setEntries iters;
    CalculateDescendants(it, iters);
    for (const auto &iter : iters)
        ret.emplace(iter->GetTx().GetId());
    return ret;
}

auto CTxMemPool::getDoubleSpendProof_common(const TxId &txId, DspDescendants *desc) const -> std::optional<DoubleSpendProof> {
    std::optional<DoubleSpendProof> ret;
    if (auto it = mapTx.find(txId); it != mapTx.end()) {
        // txId found in mempool
        ret = getDoubleSpendProof_common(it, desc);
    }
    return ret;
}

auto CTxMemPool::getDoubleSpendProof_common(txiter it, DspDescendants *desc) const -> std::optional<DoubleSpendProof> {
    std::optional<DoubleSpendProof> ret;
    if (it->HasDsp()) {
        ret.emplace(m_dspStorage->lookup(it->GetDspId()));
        if (ret->isEmpty()) {
            // hash points to missing dsp from storage -- should never happen
            throw std::runtime_error(strprintf("Unexpected state: DspId %s for TxId %s missing from storage",
                                               it->GetDspId().ToString(), it->GetTx().GetId().ToString()));
        }
        if (desc) {
            // caller supplied a descendants set they want populated, so populate it on this hit
            *desc = getDspDescendantsForIter(it);
        }
    }
    return ret;
}


// for vtable
CTxMemPool::RecursionLimitReached::~RecursionLimitReached() {}

//! If txId or any of its in-mempool ancestors have a dsproof, then a valid optional will be returned.
auto CTxMemPool::recursiveDSProofSearch(const TxId &txId, DspDescendants *desc, double *score) const
-> std::optional<DspRecurseResult> {
    constexpr auto recursionMax = 1'000u, ancestorMax = 20'000u; // limit recursion and ancestor depth for this call
    std::optional<DspRecurseResult> ret;
    DspQueryPath path;
    std::optional<DoubleSpendProof> optProof;
    setEntries seenTxs; // to prevent recursion into tx's we've already searched

    // we must use a std::function because lambdas cannot see themselves
    std::function<void(txiter)> search = [&](txiter txit) EXCLUSIVE_LOCKS_REQUIRED(cs_main, cs) {
        path.push_back(txit->GetTx().GetId());

        if (path.size() > recursionMax || seenTxs.size() > ancestorMax) {
            if (score) *score = std::min(0.25, *score);
            // guard against excessively long mempool chains eating up resources
            throw RecursionLimitReached(strprintf("recursiveDSProofSearch: mempool depth limit exceeded (%d, %d)",
                                                  path.size(), seenTxs.size()));
        }

        // search this txId
        if ((optProof = getDoubleSpendProof_common(txit, desc))) {
            // dsp found for this txId. Setting `ret` ends any recursion
            ret.emplace(std::move(*optProof), std::move(path));
            if (score) *score = 0.0; // proof found, set score to 0
            return;
        }

        // caller wants a score -- we abort early in that case if we reach a tx that cannot have a proof (not p2pkh)
        if (score) {
            bool isProtected = false;
            const bool isPossible = DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(*this, txit->GetTx(),
                                                                                           &isProtected);
            if (!isPossible) {
                // proof not possible for this tx, stop searching
                *score = 0.0;
                return;
            }
            if (!isProtected) {
                // This txn is not protected because some inputs are not signed with SIGHASH_ALL or some are signed
                // with SIGHASH_ANYONECANPAY.
                *score = std::min(0.25, *score);
            }
        }

        // `txit` always refers to a mempool tx, in which case it may have unconfirmed parents,
        // so keep searching recursively; recurse for each parent (only if never seen).
        for (const auto &parent : GetMemPoolParents(txit)) {
            // if we have already searched this parent, skip
            if (!seenTxs.insert(parent).second)
                continue;

            // recurse; NB: this may modify `optProof`, `seenTxs`, `*score` and/or `ret`
            search(parent);

            if (ret || (score && *score < 0.001)) {
                // recursive search yielded an answer of some sort, return early
                return;
            }
        }

        // this recursive branch yielded no results (dead end), pop txId off stack
        path.pop_back();
    };

    LOCK2(cs_main, cs);

    if (txiter txit = mapTx.find(txId); txit != mapTx.end()) {
        if (score) *score = 1.0; // assume good until proven otherwise
        search(txit);
    } else if (score) {
        // confidence score is -1.0 for an unknown tx
        *score = -1.0;
    }

    return ret;
}

//! Lookup a dsproof by the double spent COutPoint.
auto CTxMemPool::getDoubleSpendProof(const COutPoint &outpoint, DspDescendants *desc) const -> std::optional<DspTxIdPair> {
    std::optional<DspTxIdPair> ret;
    LOCK(cs);

    if (auto it = mapNextTx.find(outpoint); it != mapNextTx.end()) {
        const auto &txId = it->second->GetId();
        auto it2 = mapTx.find(txId);
        assert(it2 != mapTx.end());
        if (it2->HasDsp()) {
            // mempool entry has a double-spend, get its proof from storage
            ret.emplace(m_dspStorage->lookup(it2->GetDspId()), txId);
            if (ret->first.isEmpty()) {
                // hash points to missing dsp from storage -- should never happen
                throw std::runtime_error(strprintf("Unexpected state: DspId %s for TxId %s missing from storage",
                                                   it2->GetDspId().ToString(), txId.ToString()));
            }
            if (desc) {
                // caller supplied a descendants set they want populated, so populate it on this hit
                if (auto optIter = GetIter(txId))
                    *desc = getDspDescendantsForIter(*optIter);
            }
        }
    } else {
        // outpoint not spent -- search for orphan proofs for this outpoint
        for (const auto & [dspId, ignored] : m_dspStorage->findOrphans(outpoint)) {
            ret.emplace(std::piecewise_construct,
                        std::forward_as_tuple(m_dspStorage->lookup(dspId)),
                        std::forward_as_tuple() /* default-constructed txid indicates orphan */);
            if (ret->first.isEmpty()) {
                // hash points to missing dsp from storage -- should never happen
                throw std::runtime_error(strprintf("Unexpected state: Orphan DspId %s missing actual proof in storage",
                                                   dspId.ToString()));
            }
            break; // iterate once; ranged for-loop was used so that we no-op if there are no orphans for outpoint
        }
    }

    return ret;
}


CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0) {
        return CFeeRate(int64_t(ceill(rollingMinimumFeeRate)) * SATOSHI);
    }

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4) {
            halflife /= 4;
        } else if (DynamicMemoryUsage() < sizelimit / 2) {
            halflife /= 2;
        }

        rollingMinimumFeeRate =
            rollingMinimumFeeRate /
            pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;
    }
    return CFeeRate(int64_t(ceill(rollingMinimumFeeRate)) * SATOSHI);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate &rate) {
    AssertLockHeld(cs);
    if ((rate.GetFeePerK() / SATOSHI) > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK() / SATOSHI;
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit,
                            std::vector<COutPoint> *pvNoSpendsRemaining) {
    LOCK(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(Amount::zero());
    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        auto it = mapTx.get<modified_feerate>().end();
        --it;

        // We set the new mempool min fee to the feerate of the removed transaction,
        // plus the "minimum reasonable fee rate" (ie some value under which we
        // consider txn to have 0 fee). This way, we don't allow txn to enter
        // mempool with feerate equal to txn which were removed with no block in
        // between.
        CFeeRate removed = it->GetModifiedFeeRate();
        removed += MEMPOOL_FULL_FEE_INCREMENT;

        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        setEntries stage;
        CalculateDescendants(mapTx.project<0>(it), stage);
        nTxnRemoved += stage.size();

        if (pvNoSpendsRemaining) {
            for (const txiter &iter : stage) {
                for (const CTxIn &txin : iter->GetTx().vin) {
                    if (!exists(txin.prevout.GetTxId())) {
                        pvNoSpendsRemaining->push_back(txin.prevout);
                    }
                }
            }
        }

        RemoveStaged(stage, MemPoolRemovalReason::SIZELIMIT);
    }

    if (maxFeeRateRemoved > CFeeRate(Amount::zero())) {
        LogPrint(BCLog::MEMPOOL,
                 "Removed %u txn, rolling minimum fee bumped to %s\n",
                 nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}

bool CTxMemPool::IsLoaded() const {
    LOCK(cs);
    return m_is_loaded;
}

void CTxMemPool::SetIsLoaded(bool loaded) {
    LOCK(cs);
    m_is_loaded = loaded;
}

DisconnectedBlockTransactions::DisconnectedBlockTransactions(uint64_t maxDynamicUsageBytes) {
    // ensure no infinite looping in addForBlock, etc
    maxDynamicUsage = std::max<uint64_t>(maxDynamicUsageBytes, DynamicMemoryUsage());
}

/* static */ uint64_t DisconnectedBlockTransactions::DefaultMaxDynamicUsage() {
    return std::max(20 * DEFAULT_CONSENSUS_BLOCK_SIZE, GetConfig().GetMaxMemPoolSize());
}

void DisconnectedBlockTransactions::addNoLimit(Span<const CTransactionRef> vtx, const bool checkSanity) {

    // Short-circuit out of here for trivial cases of empty vtx or blocks with only 1 coinbase
    if (vtx.empty()) {
        // no work to do
        return;
    } else if (vtx.size() == 1 && vtx.front()->IsCoinBase()) {
        // coinbase, just add it to the end (it has no parents, so it can get enqueued at the end).
        addTransaction(vtx.front());
        return;
    }

    struct Entry;
    using EntryMap = std::unordered_map<TxId, Entry, SaltedTxIdHasher>;
    using EntryWeakMap = std::unordered_map<TxId, Entry *, SaltedTxIdHasher>; // Entry * points to EntryMap entries
    struct Entry {
        CTransactionRef tx;
        EntryWeakMap parents, children;
        size_t in_degree = 0; ///< how many parents link to this child (DAG inbound edge "degree"; used by Kahn's algo)

        explicit Entry(const CTransactionRef &tx_) noexcept : tx(tx_) {}
    };

    EntryMap allTxns; // Store all the queued txns & block txns so we can quickly look them up by TxId
    allTxns.reserve(queuedTx.size() + vtx.size());
    // We ultimately want everything topologically sorted, including with respect to what's already in `queuedTx`;
    // so we need to process all the txns in `queuedTx` + `vtx` as a whole.
    for (const auto &tx : queuedTx) {
        allTxns.try_emplace(tx->GetId(), tx);
    }
    for (const auto &tx : vtx) {
        allTxns.try_emplace(tx->GetId(), tx);
    }

    // Temporarily clear queuedTx since we will need to re-add to it in total topological order.
    queuedTx.clear();
    cachedInnerUsage = 0u;

    auto linkParentAndChild = [](const TxId &parentTxid, Entry &parent, const TxId &childTxid, Entry &child) {
        // Assumption here: Pointers to mapped_values in an unordered_map remain valid for lifetime of the map entry.
        // This is guaranteed by the C++ standard.
        parent.children.try_emplace(childTxid, &child);
        if (child.parents.try_emplace(parentTxid, &parent).second)
            ++child.in_degree; // increment "in_degree" of child txn
    };

    // link parents and children (to create DAG, needed by Kahn's algorithm)
    for (auto & [txid, entry] : allTxns) {
        for (const auto &in : entry.tx->vin) {
            const auto &parentTxid = in.prevout.GetTxId();
            if (auto it = allTxns.find(parentTxid); it != allTxns.end()) {
                // has a parent in `allTxns`, link it
                linkParentAndChild(parentTxid, it->second, txid, entry);
            }
        }
    }

    // Do Kahn's algorithm
    std::vector<const Entry *> sorted; // ordered from parents -> children
    sorted.reserve(vtx.size());

    // 1. Add all nodes with in-degree 0 to a queue (these are txns with no in-block or in-pool ancestors)
    std::deque<Entry *> queue;
    for (auto & [txid, entry] : allTxns) {
        assert(entry.in_degree == entry.parents.size()); // initially "in_degree" should match parent size
        if (entry.in_degree == 0) {
            queue.push_back(&entry);
        }
    }

    // 2. Remove nodes from queue, decrement all of their children's in-degrees, add children with in-degree 0 to `sorted`
    while (!queue.empty()) {
        auto entry = queue.front();
        queue.pop_front();
        sorted.push_back(entry);
        for (const auto & [childTxid, child] : entry->children) {
            if (--child->in_degree == 0) {
                // seen all parents, add to queue
                queue.push_back(child);
            }
        }
    }

    // 3. Reverse insert `sorted` into `queuedTx` (which wants child -> parent ordering)
    for (const auto &entry : reverse_iterate(sorted)) {
        addTransaction(entry->tx);
    }

    // Sanity check (unit tests only)
    if (checkSanity) {
        CHECK_NONFATAL(allTxns.size() == queuedTx.size()); // allTxns and queuedTx should contain the same txns
        size_t expectedUsage = 0;
        for (const auto & [txid, entry] : allTxns) {
            CHECK_NONFATAL(entry.in_degree == 0); // if this is ever not true, we have cycles or a bug in the above code.
            CHECK_NONFATAL(queuedTx.find(txid) != queuedTx.end()); // verify they are the same set
            // tally usage
            expectedUsage += RecursiveDynamicUsage(entry.tx);
        }
        // Verify cachedInnerUsage invariant is maintained
        CHECK_NONFATAL(expectedUsage == cachedInnerUsage);
        // Verify all txns we got from the caller are now in queuedTx
        for (const auto &tx : vtx) {
            CHECK_NONFATAL(queuedTx.find(tx->GetId()) != queuedTx.end());
        }
        // Verify class invariant: when reverse iterating `queuedTx`, parents must come before children
        std::unordered_set<TxId, SaltedTxIdHasher> seen;
        for (const auto &tx : reverse_iterate(queuedTx.get<insertion_order>())) {
            for (const auto &in : tx->vin) {
                const auto &parentTxid = in.prevout.GetTxId();
                if (queuedTx.find(parentTxid) != queuedTx.end()) {
                    // If it lives in `queuedTx`, we should have already seen its parents!
                    if (seen.find(parentTxid) == seen.end()) {
                        CHECK_NONFATAL(!"Bug! `queuedTx` is not topologically sorted!");
                    }
                }
            }
            seen.insert(tx->GetId());
        }
    }
}

void DisconnectedBlockTransactions::addForBlock(Span<const CTransactionRef> vtx, const bool checkSanityForTests) {
    addNoLimit(vtx, checkSanityForTests);

    // Keep the size under control.
    while (DynamicMemoryUsage() > maxDynamicUsage) {
        // Drop the earliest entry, and remove its children from the
        // mempool.
        auto it = queuedTx.get<insertion_order>().begin();
        g_mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        removeEntry(it);
    }
}

void DisconnectedBlockTransactions::importMempool(CTxMemPool &pool) {
    // addForBlock's algorithm sorts a vector of transactions back into
    // topological order. We use it in a separate object to create a valid
    // ordering of all mempool transactions, which we then splice in front of
    // the current queuedTx. This results in a valid sequence of transactions to
    // be reprocessed in updateMempoolForReorg.

    // We create vtx in order of the entry_id index to facilitate for
    // addForBlocks (which iterates in reverse order), as vtx probably end in
    // the correct ordering for queuedTx.
    std::vector<CTransactionRef> vtx;
    {
        LOCK(pool.cs);
        vtx.reserve(pool.mapTx.size());
        txInfo.reserve(pool.mapTx.size());
        for (const CTxMemPoolEntry &e : pool.mapTx.get<entry_id>()) {
            vtx.push_back(e.GetSharedTx());
            // save entry time and feeDelta for use in updateMempoolForReorg()
            txInfo.try_emplace(e.GetTx().GetId(), e.GetTime(), e.GetModifiedFee() - e.GetFee());
            // notify all observers of this (possibly temporary) removal
            pool.NotifyEntryRemoved(e.GetSharedTx(), MemPoolRemovalReason::REORG);
        }
        pool.doubleSpendProofStorage()->orphanAll();
        pool.clear(/* clearDspOrphans = */ false);
    }

    // Use addNoLimit to sort the transactions and then splice them in front
    // of queuedTx
    DisconnectedBlockTransactions orderedTxnPool;
    orderedTxnPool.addNoLimit(vtx);
    cachedInnerUsage += orderedTxnPool.cachedInnerUsage;
    queuedTx.get<insertion_order>().splice(
        queuedTx.get<insertion_order>().begin(),
        orderedTxnPool.queuedTx.get<insertion_order>());

    // We limit memory usage because we can't know if more blocks will be
    // disconnected
    while (DynamicMemoryUsage() > maxDynamicUsage) {
        // Drop the earliest entry which, by definition, has no children
        removeEntry(queuedTx.get<insertion_order>().begin());
    }
}

auto DisconnectedBlockTransactions::getTxInfo(const CTransactionRef &tx) const -> const TxInfo * {
    if (auto it = txInfo.find(tx->GetId()); it != txInfo.end())
        return &it->second;
    return nullptr;
}

void DisconnectedBlockTransactions::updateMempoolForReorg(const Config &config,
                                                          bool fAddToMempool) {
    AssertLockHeld(cs_main);

    if (fAddToMempool) {
        // disconnectpool's insertion_order index sorts the entries from oldest to
        // newest, but the oldest entry will be the last tx from the latest mined
        // block that was disconnected.
        // Iterate disconnectpool in reverse, so that we add transactions back to
        // the mempool starting with the earliest transaction that had been
        // previously seen in a block.
        for (const CTransactionRef &tx : reverse_iterate(queuedTx.get<insertion_order>())) {
            if (tx->IsCoinBase())
                continue;
            // restore saved PrioritiseTransaction state and nAcceptTime
            const auto ptxInfo = getTxInfo(tx);
            bool hasFeeDelta = false;
            if (ptxInfo && ptxInfo->feeDelta != Amount::zero()) {
                // manipulate mapDeltas directly (faster than calling PrioritiseTransaction)
                LOCK(g_mempool.cs);
                g_mempool.mapDeltas[tx->GetId()] = ptxInfo->feeDelta;
                hasFeeDelta = true;
            }
            // ignore validation errors in resurrected transactions
            CValidationState stateDummy;
            bool ok = AcceptToMemoryPoolWithTime(config, g_mempool, stateDummy, tx,
                                                 nullptr /* pfMissingInputs */,
                                                 ptxInfo ? ptxInfo->time : GetTime() /* nAcceptTime */,
                                                 true /* bypass_limits */,
                                                 Amount::zero() /* nAbsurdFee */,
                                                 false /* test_accept */);
            if (!ok && hasFeeDelta) {
                // tx not accepted: undo mapDelta insertion from above
                LOCK(g_mempool.cs);
                g_mempool.mapDeltas.erase(tx->GetId());
            }
        }
    }

    queuedTx.clear();
    txInfo.clear();

    // Re-limit mempool size, in case we added any transactions
    g_mempool.LimitSize(config.GetMaxMemPoolSize(), gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}
