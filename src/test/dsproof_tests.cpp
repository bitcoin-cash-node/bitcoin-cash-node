// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/validation.h>
#include <dsproof/storage.h>
#include <policy/mempool.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/sighashtype.h>
#include <script/sign.h>
#include <streams.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <validation.h>
#include <version.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

using ByteVec = std::vector<uint8_t>;

// Mixin to ensure mempool is cleared
struct EnsureClearedMempoolMixin {
    ~EnsureClearedMempoolMixin() { LOCK(g_mempool.cs); g_mempool.clear(); }
};

// Mixin to ensure tokens are enabled for this test
struct Upgrade9ActivatedMixin {
    std::optional<int32_t> origUpgrade9ActivationOverride;

    Upgrade9ActivatedMixin() {
        origUpgrade9ActivationOverride = g_Upgrade9HeightOverride;
        g_Upgrade9HeightOverride = 0;
    }

    ~Upgrade9ActivatedMixin() {
        g_Upgrade9HeightOverride = origUpgrade9ActivationOverride;
    }
};


BOOST_FIXTURE_TEST_SUITE(dsproof_tests, BasicTestingSetup)

std::vector<DoubleSpendProof> makeDupeProofs(unsigned num, uint64_t fuzz = 0) {
    std::vector<DoubleSpendProof> ret;

    CDataStream stream(
        ParseHex("0100000001f1b76b251770f5d26334c41327ef54d52cba86f77f67e5fce35611d4dad729270000000"
                 "06441c70853c2bb31d8df457613cfcae7755bf1e1c558271804e2a82f86558c182cec731014ebdb70"
                 "9da6e642ed89042dbbd6faed1853ee6299393e46bb656a4c8dae4121035303d906d781995ba837f73"
                 "757e336446bbbc49e377cb95e98d86a64c6878898feffffff01bd4397964e0000001976a9140a373c"
                 "af0ab3c2b46cd05625b8d545c295b93d7a88acb4781500"),
        SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction inTx(deserialize, stream);
    if (fuzz) {
        TxId t = inTx.vin[0].prevout.GetTxId();
        auto N = inTx.vin[0].prevout.GetN();
        uint64_t begin;
        std::memcpy(&begin, t.begin(), std::min<size_t>(sizeof(begin), t.size()));
        begin ^= fuzz;
        std::memcpy(t.begin(), &begin, std::min<size_t>(sizeof(begin), t.size()));
        inTx.vin[0].prevout = COutPoint(t, N); // save fuzzed prevout
    }
    CTransaction tx1(inTx);
    ret.reserve(num);
    for (int i = 0; i < int(num); ++i) {
        CMutableTransaction mut(tx1);
        mut.vout[0].nValue -= (i+1) * SATOSHI;
        CTransaction tx2(mut);
        BOOST_CHECK(tx1.GetHash() != tx2.GetHash());
        ret.push_back( DoubleSpendProof::create(/* scriptFlags = */ 0, tx1, tx2, tx1.vin.at(0).prevout) );
        auto &proof = ret.back();
        BOOST_CHECK(!proof.isEmpty());
    }
    return ret;
}

std::vector<DoubleSpendProof> makeUniqueProofs(unsigned num) {
    std::vector<DoubleSpendProof> ret;
    ret.reserve(num);
    for (unsigned i = 0; i < num; ++i) {
        auto vec1 = makeDupeProofs(1, GetRand(std::numeric_limits<uint64_t>::max()));
        BOOST_CHECK(vec1.size() == 1);
        ret.emplace_back(std::move(vec1.front()));
    }
    return ret;
}

/// Test the COutPoint index of the m_proofs data structure:
/// Expected: that multiple proofs for the same COutPoint are possible and work.
BOOST_AUTO_TEST_CASE(dsproof_indexed_set_multiple_proofs_same_outpoint) {
    DoubleSpendProofStorage storage;
    constexpr unsigned NUM = 100;
    auto proofs = makeDupeProofs(NUM);
    BOOST_CHECK(proofs.size() == NUM);
    COutPoint prevout {proofs.front().outPoint()};
    std::set<DspId> ids;
    for (auto &proof: proofs) {
        auto before = ids.size();
        ids.insert(proof.GetId());
        BOOST_CHECK(ids.size() == before +1); // ensure new unique ID.
        storage.addOrphan(proof, ids.size());
    }
    // Check that we generated unique proofs for all the conflicts
    BOOST_CHECK(ids.size() == NUM);
    auto list = storage.findOrphans(prevout);
    // Check that all proofs for the one COutPoint in question are accounted for
    BOOST_CHECK(ids.size() == list.size());
    for (auto &pair : list) {
        // Check that the returned list contains the expected items
        BOOST_CHECK(ids.count(pair.first) == 1);
    }
}

// Test that claiming orphans works, as well as re-adding and removing
BOOST_AUTO_TEST_CASE(dsproof_claim_orphans_then_remove) {
    DoubleSpendProofStorage storage;
    BOOST_CHECK(storage.numOrphans() == 0);
    constexpr unsigned NUM = 100;
    auto proofs = makeUniqueProofs(NUM);
    BOOST_CHECK(proofs.size() == NUM);
    unsigned i = 0;
    for (auto &proof: proofs)
        storage.addOrphan(proof, ++i);
    BOOST_CHECK(storage.numOrphans() == NUM);
    BOOST_CHECK(storage.size() == NUM);

    i = 0;
    for (auto &proof: proofs) {
        storage.claimOrphan(proof.GetId());
        BOOST_CHECK(storage.numOrphans() == NUM - ++i);
    }
    BOOST_CHECK(storage.size() == NUM);
    BOOST_CHECK(storage.numOrphans() == 0);

    // re-add them as orphans again, size of container won't grow, they
    // just get re-categorized
    i = 0;
    for (auto &proof: proofs)
        storage.addOrphan(proof, ++i);
    BOOST_CHECK(storage.numOrphans() == NUM);
    BOOST_CHECK(storage.size() == NUM);

    // now remove
    for (auto &proof: proofs) {
        BOOST_CHECK(storage.exists(proof.GetId()));
        storage.remove(proof.GetId());
        BOOST_CHECK(!storage.exists(proof.GetId()));
    }
    BOOST_CHECK(storage.numOrphans() == 0);
    BOOST_CHECK(storage.size() == 0);

    // now remove already-removed
    for (auto &proof: proofs)
        storage.remove(proof.GetId());

    // nothing should have changed
    BOOST_CHECK(storage.numOrphans() == 0);
    BOOST_CHECK(storage.size() == 0);
}

// Test that orphan limits are respected
BOOST_AUTO_TEST_CASE(dsproof_orphans_limit) {
    DoubleSpendProofStorage storage;
    constexpr unsigned limit = 20;
    storage.setMaxOrphans(limit);
    BOOST_CHECK(storage.numOrphans() == 0);
    constexpr unsigned NUM = 200;

    auto proofs = makeDupeProofs(NUM, GetRand(std::numeric_limits<uint64_t>::max()));
    BOOST_CHECK(proofs.size() == NUM);
    COutPoint prevout {proofs.front().outPoint()};
    for (auto &proof : proofs) {
        storage.addOrphan(proof, 1);
    }

    // there is some fuzz factor when adding orphans, they may temporarily exceed limit, but no more than 25%
    BOOST_CHECK(storage.numOrphans() <= unsigned(limit * 1.25));
    BOOST_CHECK(storage.numOrphans() >= limit);
    BOOST_CHECK(storage.size() - storage.numOrphans() == 0);

    auto list = storage.findOrphans(prevout);
    BOOST_CHECK(list.size() == storage.numOrphans());
}

// Test correct functionality of the clear(false) versus clear(true) (DoubleSpendProofStorage)
BOOST_AUTO_TEST_CASE(dsproof_storage_clear) {
    DoubleSpendProofStorage storage;

    constexpr unsigned NUM = 200;

    auto proofs = makeUniqueProofs(NUM);

    for (const auto &proof : proofs) {
        storage.addOrphan(proof, 1);
    }

    // add 1 "non orphan"
    BOOST_CHECK(storage.add(makeUniqueProofs(1)[0]));
    BOOST_CHECK_EQUAL(storage.numOrphans(), NUM);
    BOOST_CHECK_EQUAL(storage.size(), NUM + 1);
    // clear only non-orphans
    storage.clear(/*clearOrphans =*/ false);
    BOOST_CHECK_EQUAL(storage.numOrphans(), NUM);
    BOOST_CHECK_EQUAL(storage.size(), NUM);
    // add 1 "non orphan" again
    BOOST_CHECK(storage.add(makeUniqueProofs(1)[0]));
    BOOST_CHECK_EQUAL(storage.numOrphans(), NUM);
    BOOST_CHECK_EQUAL(storage.size(), NUM + 1);
    // clear everything
    storage.clear(/*clearOrphans =*/ true);
    // everything should be gone now
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0);
    BOOST_CHECK_EQUAL(storage.size(), 0);
}

// Test that the periodic cleanup function works as expected, and reaps old orphans
BOOST_AUTO_TEST_CASE(dsproof_orphan_autocleaner) {
    DoubleSpendProofStorage storage;

    constexpr unsigned NUM = 200, SECS = 50, MAX_ORPHANS = NUM * 5;
    constexpr int64_t mockStart = 2'000'000, spacing = 2;

    storage.setSecondsToKeepOrphans(SECS);
    storage.setMaxOrphans(MAX_ORPHANS); // set maximum comfortably larger than we need

    auto proofs = makeUniqueProofs(NUM);

    SetMockTime(mockStart);

    int i = 0;
    using TimeMap = std::multimap<int64_t, DoubleSpendProof>;
    TimeMap map;
    for (const auto &proof : proofs) {
        // add them 2 seconds apart
        SetMockTime(mockStart + (i * spacing));
        storage.addOrphan(proof, ++i);
        map.emplace(GetTime(), proof);
    }
    BOOST_CHECK(storage.numOrphans() == NUM);
    BOOST_CHECK(map.size() == NUM);

    // this removes old orphans and only keep recent 50 secs worth
    storage.periodicCleanup();

    const size_t expected = (storage.secondsToKeepOrphans()+1) / spacing;
    BOOST_CHECK(expected != NUM);
    // test that we only kept the last 50 seconds worth of orphans (at 2 seconds apart = 25 orphans)
    BOOST_CHECK(storage.numOrphans() == expected);

    // make sure that what was deleted was what we expected -- only items that are >=50 seconds old
    // are deleted and itmes <50 seconds old were kept
    auto cutoff = GetTime() - storage.secondsToKeepOrphans();
    for (const auto &pair : map) {
        auto &time = pair.first;
        auto &proof = pair.second;
        const bool shouldExist = time > cutoff;
        BOOST_CHECK(shouldExist == storage.exists(proof.GetId()));
    }

    SetMockTime(0); // undo mocktime
}

static std::pair<bool, CValidationState> ToMemPool(const CMutableTransaction &tx, CTransactionRef *pref = nullptr)
EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CValidationState state;
    auto txref = MakeTransactionRef(tx);
    if (pref) *pref = txref;
    const bool b = AcceptToMemoryPool(GetConfig(), g_mempool, state, txref,
                                      nullptr /* pfMissingInputs */, true /* bypass_limits */,
                                      Amount::zero() /* nAbsurdFee */);
    return {b, std::move(state)};
}

struct EnsureClearedMempoolTestChain100Setup : TestChain100Setup, EnsureClearedMempoolMixin {};

/// Comprehensive test that adds real tx's to the mempool and double-spends them.
/// - Tests that the proofs are generated correctly when rejecting double-spends
/// - Tests orphans and claiming of orphans
BOOST_FIXTURE_TEST_CASE(dsproof_doublespend_mempool, EnsureClearedMempoolTestChain100Setup) {
    FlatSigningProvider provider;
    provider.keys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey;
    provider.pubkeys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey.GetPubKey();

    const CScript scriptPubKey = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    const size_t firstTxIdx = m_coinbase_txns.size();

    // we were given a blockchain that mines to a p2pk address --
    // check that txs that spend those cannot have dsproofs
    BOOST_CHECK(!m_coinbase_txns.empty());
    for (const auto & tx : m_coinbase_txns) {
        LOCK2(cs_main, g_mempool.cs);
        // belt-and-suspenders check that coinbase tx cannot have double spend proofs
        bool isProtected;
        BOOST_CHECK(!DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(g_mempool, *tx, &isProtected));
        BOOST_CHECK(!isProtected);
        CMutableTransaction spend;
        spend.nVersion = 1;
        spend.vin.resize(1);
        spend.vin[0].prevout = COutPoint(tx->GetId(), 0);
        spend.vout.resize(1);
        spend.vout[0].nValue = int64_t(GetRand(1'000)) * CENT;
        spend.vout[0].scriptPubKey = scriptPubKey;
        // Sign:
        const bool schnorr = InsecureRandBool();
        const auto ok = SignSignature(provider, *tx, spend, 0, SigHashType().withFork(),
                                      STANDARD_SCRIPT_VERIFY_FLAGS, {} /* context */, schnorr);
        BOOST_CHECK(ok);
        // Also a tx spending a p2pk cannot have a dsproof
        BOOST_CHECK(!DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(g_mempool, CTransaction{spend}, &isProtected));
        BOOST_CHECK(!isProtected);
    }

    // next, mine a bunch of blocks that send coinbase to p2pkh
    for (int i = 0; i < COINBASE_MATURITY*2 + 1; ++i) {
        const CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
        LOCK2(cs_main, g_mempool.cs);
        // belt-and-suspenders check that coinbase tx cannot have double spend proofs
        bool isProtected;
        BOOST_CHECK(!DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(g_mempool, *m_coinbase_txns.back(), &isProtected));
        BOOST_CHECK(!isProtected);
    }

    // Some code-paths below need locks held
    LOCK2(cs_main, g_mempool.cs);
    BOOST_CHECK(DoubleSpendProof::IsEnabled()); // default state should be enabled
    g_mempool.clear(); // ensure mempool is clean
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);


    // Create 100 double-spend pairs of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2 * COINBASE_MATURITY);
    auto const context = std::nullopt;
    for (size_t i = 0; i < spends.size(); ++i) {
        const auto &cbTxRef = m_coinbase_txns.at(firstTxIdx + i/2);
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout = COutPoint(cbTxRef->GetId(), 0);
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = int64_t(1+i) * CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;

        // Sign:
        const bool schnorr = InsecureRandBool();
        const auto ok = SignSignature(provider, *cbTxRef, spends[i], 0, SigHashType().withFork(),
                                      STANDARD_SCRIPT_VERIFY_FLAGS, context, schnorr);
        BOOST_CHECK(ok);
    }

    std::map<DspId, TxId> dspIdTxIdMap;
    std::vector<DoubleSpendProof> proofs;

    for (size_t i = 0; i+1 < spends.size(); i += 2) {
        const auto txNum = i / 2;
        const auto &cbTxRef = m_coinbase_txns.at(firstTxIdx + txNum);
        BOOST_CHECK_EQUAL(g_mempool.size(), txNum);

        const auto &spend1 = spends[i], &spend2 = spends[i+1];
        // Add first tx to mempool
        {
            auto [ok, state] = ToMemPool(spend1);
            BOOST_CHECK(ok);
            BOOST_CHECK(state.IsValid());
            // p2pkh can have dsproof
            bool isProtected;
            BOOST_CHECK(DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(g_mempool, CTransaction(spend1), &isProtected));
            BOOST_CHECK(isProtected);
        }
        // Add second tx to mempool, check that it is rejected and that the dsproof generated is what we expect
        {
            auto [ok, state] = ToMemPool(spend2);
            BOOST_CHECK(!ok);
            BOOST_CHECK(!state.IsValid());
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-mempool-conflict");
            BOOST_CHECK(state.HasDspId());
            auto dsproof = DoubleSpendProof::create(/* scriptFlags = */ 0, CTransaction{spend2}, CTransaction{spend1},
                                                    spend1.vin[0].prevout, &cbTxRef->vout[0]);
            BOOST_CHECK(!dsproof.isEmpty());
            auto val = dsproof.validate(g_mempool, {});
            BOOST_CHECK_EQUAL(val, DoubleSpendProof::Validity::Valid);
            BOOST_CHECK_EQUAL(dsproof.GetId(), state.GetDspId());
            BOOST_CHECK(!state.GetDspId().IsNull());

            // Ensure mempool entry has the proper hash as well
            auto optIter = g_mempool.GetIter(spend1.GetId());
            BOOST_CHECK(optIter);
            if (optIter) {
                const auto & entry = *(*optIter);
                BOOST_CHECK(entry.HasDsp());
                BOOST_CHECK(entry.GetDspId() == dsproof.GetId());
                dspIdTxIdMap[dsproof.GetId()] = spend1.GetId(); // save txid
            }

            // test higher-level mempool access methods
            auto optPair = g_mempool.getDoubleSpendProof(dsproof.GetId());
            auto optProof = g_mempool.getDoubleSpendProof(spend1.GetId());
            auto optPair2 = g_mempool.getDoubleSpendProof(dsproof.outPoint());
            BOOST_CHECK(bool(optPair));
            BOOST_CHECK(bool(optPair2));
            BOOST_CHECK(bool(optProof));
            BOOST_CHECK(*optPair == *optPair2);
            BOOST_CHECK(!optPair->second.IsNull());
            BOOST_CHECK(optPair->first == *optProof);
            BOOST_CHECK(dsproof == *optProof);
            BOOST_CHECK(optPair->second == dspIdTxIdMap[dsproof.GetId()]); // we expect the proof to be associated with this txid

            proofs.emplace_back(std::move(dsproof));
        }

        BOOST_CHECK_EQUAL(g_mempool.size(), txNum + 1); // mempool should have grown by 1
    }

    const auto sortById = [](const DoubleSpendProof &a, const DoubleSpendProof &b) {
        return a.GetId() < b.GetId();
    };
    {
        // check listDoubleSpendProofs call returns what we expect
        std::vector<DoubleSpendProof> proofs2;
        for (const auto & [dsproof, txid] : g_mempool.listDoubleSpendProofs(true)) {
            BOOST_CHECK(!txid.IsNull()); // we expect none of these to be orphans
            BOOST_CHECK(!dsproof.isEmpty()); // we expect all proofs to not be empty
            BOOST_CHECK(txid == dspIdTxIdMap[dsproof.GetId()]); // we expect the proof to be associated with this txid
            proofs2.push_back(dsproof); // save
        }
        std::sort(proofs2.begin(), proofs2.end(), sortById);
        auto proofsCpy = proofs;
        std::sort(proofsCpy.begin(), proofsCpy.end(), sortById);

        BOOST_CHECK(proofs2 == proofsCpy);
    }

    g_mempool.clear();
    BOOST_CHECK_EQUAL(g_mempool.size(), 0u);
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);


    // ---
    // NEXT, do OPRHAN check -- ensure adding orphan, then adding tx, ends up claiming the orphan
    // ---

    // Add all the proofs as orphans
    auto *storage = g_mempool.doubleSpendProofStorage();
    NodeId nid = 0;
    for (const auto & proof : proofs) {
        storage->addOrphan(proof, ++nid);
    }

    {
        // check listDoubleSpendProofs call returns what we expect
        std::vector<DoubleSpendProof> proofs2;
        for (const auto & [dsproof, txid] : g_mempool.listDoubleSpendProofs(true)) {
            BOOST_CHECK(txid.IsNull()); // we expect all of these to be orphans
            proofs2.push_back(dsproof); // save
            BOOST_CHECK(!dsproof.isEmpty()); // we expect all proofs to not be empty
        }
        std::sort(proofs2.begin(), proofs2.end(), sortById);
        auto proofsCpy = proofs;
        std::sort(proofsCpy.begin(), proofsCpy.end(), sortById);

        BOOST_CHECK(proofs2 == proofsCpy);
    }

    // test finding the getDoubleSpendProof* calls for an orphan
    for (const auto & proof : proofs) {
        auto optPair = g_mempool.getDoubleSpendProof(proof.GetId()); // should be found, null txid
        auto optPair2 = g_mempool.getDoubleSpendProof(proof.outPoint()); // should be found, null txid
        auto optProof = g_mempool.getDoubleSpendProof(dspIdTxIdMap[proof.GetId()]); // should be not found
        BOOST_CHECK(bool(optPair));
        BOOST_CHECK(bool(optPair2));
        BOOST_CHECK(!optProof);
        BOOST_CHECK(*optPair == *optPair2);
        BOOST_CHECK(optPair->second.IsNull());
        BOOST_CHECK(optPair->first == proof);
    }

    BOOST_CHECK_EQUAL(storage->numOrphans(), std::min(proofs.size(), storage->maxOrphans()));
    BOOST_CHECK(storage->numOrphans() > 0);

    // Next, add all the spends again -- these should implicitly claim the orphans
    size_t okCt = 0, nokCt = 0;
    for (const auto &spend : spends) {
        const auto nOrphans = storage->numOrphans();
        auto [ok, state] = ToMemPool(spend);
        if (!ok) {
            // not added (was dupe)
            ++nokCt;
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-mempool-conflict");
        } else {
            // added, but should have claimed orphan(s)
            ++okCt;
            BOOST_CHECK_EQUAL(storage->numOrphans(), nOrphans-1);

            // check that getDoubleSpendProof() overloads now return pairs with !txId.IsNull()
            auto optPair = g_mempool.getDoubleSpendProof(spend.vin[0].prevout); // should be found, valid txid
            BOOST_CHECK(bool(optPair));
            BOOST_CHECK(!optPair->second.IsNull());
            auto optPair2 = g_mempool.getDoubleSpendProof(optPair->first.GetId()); // find by dspId
            BOOST_CHECK(bool(optPair2));
            BOOST_CHECK(*optPair == *optPair2);
            BOOST_CHECK(optPair->second == dspIdTxIdMap[optPair->first.GetId()]); // txid should be what we expect
            // check find by txId
            auto optProof = g_mempool.getDoubleSpendProof(dspIdTxIdMap[optPair->first.GetId()]);
            BOOST_CHECK(bool(optProof));
            BOOST_CHECK(*optProof == optPair->first);
        }
    }
    BOOST_CHECK(okCt > 0);
    BOOST_CHECK(nokCt > 0);
    BOOST_CHECK_EQUAL(okCt + nokCt, spends.size());

    // ensure all orphans are gone now
    BOOST_CHECK_EQUAL(storage->numOrphans(), 0u);

    // listDoubleSpendProofs should not contain any orphans either
    for (const auto & [dsproof, txid] : g_mempool.listDoubleSpendProofs(true)) {
        BOOST_CHECK(!txid.IsNull());
    }

    // storage should still have the proofs though for tx's that have proofs
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), nokCt);


    // finally, clear the mempool
    g_mempool.clear();
    BOOST_CHECK_EQUAL(g_mempool.size(), 0u);
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);
}

/// Comprehensive test that adds real tx's to the mempool and double-spends them,
/// and also makes the double-spent tx's a chain of unconfirmed children. This
/// tests the CTxMemPool::recursiveDSProofSearch facility.
BOOST_FIXTURE_TEST_CASE(dsproof_recursive_search_mempool, EnsureClearedMempoolTestChain100Setup) {
    FlatSigningProvider provider;
    provider.keys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey;
    provider.pubkeys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey.GetPubKey();

    const CScript scriptPubKey = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    const size_t firstTxIdx = m_coinbase_txns.size();

    for (int i = 0; i < COINBASE_MATURITY*2 + 1; ++i) {
        const CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
    }

    // Some code-paths below need locks held
    LOCK2(cs_main, g_mempool.cs);
    BOOST_CHECK(DoubleSpendProof::IsEnabled()); // default state should be enabled
    g_mempool.clear(); // ensure mempool is clean
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);

    // Create 5 double-spend pairs of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2 * 5 /* 5 pairs */);
    auto const context = std::nullopt;
    for (size_t i = 0; i < spends.size(); ++i) {
        const auto &cbTxRef = m_coinbase_txns.at(firstTxIdx + i/2);
        spends[i].nVersion = 1;
        spends[i].vin.resize(1);
        spends[i].vin[0].prevout = COutPoint(cbTxRef->GetId(), 0);
        spends[i].vout.resize(2);
        // ensure spends are unique amounts (thus unique txid)
        spends[i].vout[0].nValue = cbTxRef->GetValueOut() - int64_t(i+1) * CENT;
        spends[i].vout[0].scriptPubKey = scriptPubKey;
        spends[i].vout[1].nValue = cbTxRef->GetValueOut() - spends[i].vout[0].nValue;
        spends[i].vout[1].scriptPubKey = scriptPubKey;

        // Sign:
        const bool schnorr = InsecureRandBool();
        const auto ok = SignSignature(provider, *cbTxRef, spends[i], 0, SigHashType().withFork(),
                                      STANDARD_SCRIPT_VERIFY_FLAGS, context, schnorr);
        BOOST_CHECK(ok);
    }
    size_t nokCt = 0, okCt = 0;
    std::vector<CTransactionRef> dblSpendRoots;

    for (const auto &spend : spends) {
        CTransactionRef tx;
        auto [ok, state] = ToMemPool(spend, &tx);
        if (!ok) {
            // not added (was dupe)
            ++nokCt;
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-mempool-conflict");
        } else {
            // added, but should have claimed orphan(s)
            ++okCt;
            dblSpendRoots.push_back(std::move(tx));
        }
    }
    BOOST_CHECK(okCt > 0);
    BOOST_CHECK(nokCt > 0);
    BOOST_CHECK(g_mempool.size() == dblSpendRoots.size());
    BOOST_CHECK(g_mempool.listDoubleSpendProofs().size() == dblSpendRoots.size());

    std::map<TxId, DoubleSpendProof> txIdDspMap;
    for (const auto & [proof, txid] : g_mempool.listDoubleSpendProofs()) {
        txIdDspMap[txid] = proof;
    }

    constexpr size_t txChainLen = 500; // build chains of length 500
    std::map<TxId, std::list<CTransactionRef>> dblSpendChildren;
    for (const auto &ds : dblSpendRoots) {
        // for each root dbl spend, create a chain of txChainLen child tx's
        CTransactionRef parent = ds;
        auto & l = dblSpendChildren[parent->GetId()];
        for (size_t i = 0; i < txChainLen; ++i) {
            CMutableTransaction tx;
            tx.nVersion = 1;
            tx.vin.resize(parent->vout.size());
            for (size_t n = 0; n < parent->vout.size(); ++n)
                tx.vin[n].prevout = COutPoint(parent->GetId(), n);
            tx.vout.resize(2);
            const Amount prevValueOut = parent->GetValueOut();
            tx.vout[0].nValue =  prevValueOut / 2;
            tx.vout[0].scriptPubKey = scriptPubKey;
            tx.vout[1].nValue = prevValueOut  / 2;
            tx.vout[1].scriptPubKey = scriptPubKey;

            // Sign:
            for (size_t n = 0; n < tx.vin.size(); ++n) {
                const bool schnorr = InsecureRandBool();
                const auto ok = SignSignature(provider, *parent, tx, n, SigHashType().withFork(),
                                              STANDARD_SCRIPT_VERIFY_FLAGS, context, schnorr);
                BOOST_CHECK(ok);
            }
            l.emplace_back();
            CTransactionRef &txRef = l.back();
            auto [ok2, state] = ToMemPool(tx, &txRef);
            BOOST_CHECK(ok2);
            if (!ok2) {
                BOOST_WARN_MESSAGE(ok2, state.GetRejectReason());
                // to avoid error spam
                return;
            }
            parent = txRef;
        }
    }
    BOOST_CHECK(dblSpendRoots.size() > 0);
    BOOST_CHECK(g_mempool.size() == dblSpendRoots.size() + dblSpendRoots.size() * txChainLen);

    // Now, check that the recursive search returns what we expect in its "ancestry" vector
    for (const auto & [txid, l] : dblSpendChildren) {
        std::vector<TxId> expectedTxids;
        expectedTxids.reserve(l.size() + 1);
        for (const auto &tx : l)
            expectedTxids.insert(expectedTxids.begin(), tx->GetId());
        expectedTxids.push_back(txid);

        for (auto it = expectedTxids.begin(), end = expectedTxids.end(); it != end; ++it) {
            const auto optResult = g_mempool.recursiveDSProofSearch(*it);
            BOOST_CHECK(bool(optResult));
            if (!optResult) continue;
            auto & [proof, ancestry] = *optResult;
            const std::vector<TxId> expected(it, end);
            BOOST_CHECK(expected == ancestry); // ensure ancestry chain of tx's matches what we expect
            BOOST_CHECK(!proof.isEmpty());
            BOOST_CHECK(proof.validate(g_mempool) == DoubleSpendProof::Validity::Valid);
            BOOST_CHECK(!ancestry.empty());
            BOOST_CHECK(txIdDspMap[ancestry.back()] == proof); // ensure proof matches what we expect
        }
    }

    g_mempool.clear();
    BOOST_CHECK_EQUAL(g_mempool.size(), 0u);
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);
}

// Like EnsureClearedMempoolTestChain100Setup, but ensures tokens are enabled
struct Upgrade9TestChain100Setup : Upgrade9ActivatedMixin, EnsureClearedMempoolTestChain100Setup {};

/// Test that a txn input with a CashToken in it does correctly produce a proof.
BOOST_FIXTURE_TEST_CASE(dsproof_with_cashtokens, Upgrade9TestChain100Setup) {
    FlatSigningProvider provider;
    provider.keys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey;
    provider.pubkeys[coinbaseKey.GetPubKey().GetID()] = coinbaseKey.GetPubKey();

    const CScript scriptPubKey = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    const size_t firstTxIdx = m_coinbase_txns.size();

    for (int i = 0; i < COINBASE_MATURITY*2 + 1; ++i) {
        const CBlock b = CreateAndProcessBlock({}, scriptPubKey);
        m_coinbase_txns.push_back(b.vtx[0]);
    }

    // Some code-paths below need locks held
    LOCK2(cs_main, g_mempool.cs);
    BOOST_CHECK(DoubleSpendProof::IsEnabled()); // default state should be enabled
    // tokens should also be enabled
    BOOST_CHECK(IsUpgrade9Enabled(::GetConfig().GetChainParams().GetConsensus(), ::ChainActive().Tip()));
    g_mempool.clear(); // ensure mempool is clean
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);
    const uint32_t scriptFlags = GetMemPoolScriptFlags(::GetConfig().GetChainParams().GetConsensus(),
                                                       ::ChainActive().Tip());

    // Create 5 new token categories, 1 fungle and 1 nft-only for each
    std::vector<CMutableTransaction> tokenGenesisTxns;
    auto const context = std::nullopt;
    tokenGenesisTxns.resize(5);
    for (size_t i = 0; i < tokenGenesisTxns.size(); ++i) {
        const auto &txFrom = m_coinbase_txns.at(firstTxIdx + i);
        auto & txTo = tokenGenesisTxns[i];
        const token::Id tokenId{txFrom->GetId()};
        txTo.nVersion = 1;
        txTo.vin.resize(1);
        txTo.vin[0].prevout = COutPoint(txFrom->GetId(), 0);
        txTo.vout.resize(2);

        // output 0- has fungible-only tokens
        auto *output = &txTo.vout[0];
        //   ensure spends are unique amounts (thus unique txid)
        output->nValue = txFrom->GetValueOut() - int64_t(i+1) * CENT;
        output->scriptPubKey = scriptPubKey;
        //   create a pure fungible token with 2^(24 + i) amount.
        output->tokenDataPtr.emplace(tokenId, token::SafeAmount::fromInt(0x1000000LL << i).value());

        // output 1 - has immutable NFT only
        output = &txTo.vout[1];
        output->nValue = txFrom->GetValueOut() - txTo.vout[0].nValue;
        output->scriptPubKey = scriptPubKey;
        //   create an NFT token with 0 amount.
        token::NFTCommitment commitmentData;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, commitmentData, 0);
        SerializeToVector(vw, InsecureRand256(), COMPACTSIZE(GetRand(65536))); // random hash and an int into commitment
        BOOST_CHECK_GT(commitmentData.size(), uint256::size());
        txTo.vout[1].tokenDataPtr.emplace(tokenId, token::SafeAmount::fromInt(0).value(), commitmentData, true /* hasNFT */);

        // Sign all inputs, randomly toggling between ECDSA and Schnorr
        for (size_t inputNum = 0; inputNum < txTo.vin.size(); ++inputNum) {
            const bool schnorr = InsecureRandBool();
            const auto ok = SignSignature(provider, *txFrom, txTo, inputNum, SigHashType().withFork(),
                                          scriptFlags, context, schnorr);
            BOOST_CHECK(ok);
        }
    }

    // put all the token genesis txns into mempool
    for (const auto &mtx : tokenGenesisTxns) {
        CTransactionRef tx;
        auto [ok, state] = ToMemPool(mtx, &tx);
        BOOST_CHECK_MESSAGE(ok, strprintf("ok was: %i, state was: %s", int(ok), state.GetRejectReason()));
    }

    BOOST_CHECK_EQUAL(g_mempool.size(), tokenGenesisTxns.size());
    BOOST_CHECK_EQUAL(g_mempool.listDoubleSpendProofs().size(), 0u);

    // Create double-spend pairs of the above token-genesis txns:
    std::vector<CMutableTransaction> spends;
    size_t nExpectedDbleSpends = 0;
    for (const auto &mtxFrom : tokenGenesisTxns) {
        const auto txFrom = MakeTransactionRef(mtxFrom);
        for (size_t txFromOutput = 0; txFromOutput < txFrom->vout.size(); ++txFromOutput) {
            ++nExpectedDbleSpends;
            for (size_t i = 0; i < 2; ++i) {
                const CTxOut &out = txFrom->vout.at(txFromOutput);
                // ensure spends are unique amounts (thus unique txid)
                const Amount value = int64_t((out.nValue / SATOSHI) - int64_t(txFromOutput+i+1)) * SATOSHI;
                auto &txTo = spends.emplace_back();
                txTo.nVersion = 1;
                txTo.vin.resize(1);
                txTo.vin[0].prevout = COutPoint(txFrom->GetId(), txFromOutput);

                txTo.vout.resize(2);
                txTo.vout[0].nValue = value / 2;
                txTo.vout[0].scriptPubKey = out.scriptPubKey;

                // pass the token data along...
                auto & ptok = txTo.vout[0].tokenDataPtr = out.tokenDataPtr;
                BOOST_CHECK(ptok && ptok.get() != out.tokenDataPtr.get());
                if (ptok->HasNFT()) {
                    BOOST_CHECK(ptok->HasCommitmentLength() && !ptok->HasAmount());
                } else {
                    BOOST_CHECK(ptok->IsFungibleOnly() && !ptok->HasCommitmentLength() && ptok->HasAmount());
                    ptok->SetAmount(ptok->GetAmount().safeSub(i+1).value()); // burn 1+ fungible by subtracting from token amount
                    BOOST_CHECK(ptok->HasAmount());
                    BOOST_CHECK(ptok->GetAmount() < out.tokenDataPtr->GetAmount());
                }

                txTo.vout[1].nValue = value / 2;
                txTo.vout[1].scriptPubKey = out.scriptPubKey;
                BOOST_CHECK( ! txTo.vout[1].tokenDataPtr);

                // Sign all inputs
                for (size_t inputNum = 0; inputNum < txTo.vin.size(); ++inputNum) {
                    const bool schnorr = InsecureRandBool();
                    const auto ok = SignSignature(provider, *txFrom, txTo, inputNum, SigHashType().withFork(),
                                                  scriptFlags, context, schnorr);
                    BOOST_CHECK(ok);
                }
            }
        }
    }
    BOOST_CHECK_GT(nExpectedDbleSpends, 0);

    // Send the above double-spends to mempool
    std::vector<CTransactionRef> dblSpendRoots, rejected;

    for (const auto &spend : spends) {
        CTransactionRef tx;
        auto [ok, state] = ToMemPool(spend, &tx);
        if (!ok) {
            // not added (was dupe)
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-mempool-conflict");
            rejected.push_back(MakeTransactionRef(spend));
        } else {
            // added
            dblSpendRoots.push_back(std::move(tx));
        }
    }
    BOOST_CHECK_EQUAL(dblSpendRoots.size(), nExpectedDbleSpends);
    BOOST_CHECK_EQUAL(dblSpendRoots.size(), spends.size()/2u);
    BOOST_CHECK_EQUAL(g_mempool.size(), dblSpendRoots.size() + tokenGenesisTxns.size());
    const auto &proofs = g_mempool.listDoubleSpendProofs();
    BOOST_CHECK_EQUAL(proofs.size(), dblSpendRoots.size());

    for (const auto &[proof, txid] : proofs) {
        // basic sanity checks
        BOOST_CHECK(g_mempool.exists(txid));
        // none of the proofs should be for a txn we don't have!
        BOOST_CHECK(std::none_of(rejected.begin(), rejected.end(), [t = txid](const auto &ptx){
            return ptx->GetId() == t;
        }));
        // paranoia: just ensure we can validate our own proof!
        BOOST_CHECK(proof.validate(g_mempool) == DoubleSpendProof::Validity::Valid);
    }

    g_mempool.clear();
    BOOST_CHECK_EQUAL(g_mempool.size(), 0u);
    BOOST_CHECK_EQUAL(g_mempool.doubleSpendProofStorage()->size(), 0u);
}


BOOST_AUTO_TEST_SUITE_END()
