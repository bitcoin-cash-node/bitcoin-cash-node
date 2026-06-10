// Copyright (c) 2011-2022 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <keystore.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/sign.h>
#include <test/setup_common.h>
#include <txorphanage.h>

#include <algorithm>
#include <cassert>
#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(orphanage_tests, TestingSetup)

class TxOrphanageTest : public TxOrphanage {
public:
    TxOrphanageTest() = default;

    CTransactionRef RandomOrphan() {
        assert(!m_orphans.empty());
        assert(m_rng);
        auto it = m_orphans.lower_bound(TxId{m_rng->rand256()});
        if (it == m_orphans.end()) {
            it = m_orphans.begin();
        }
        return it->second.tx;
    }

    FastRandomContext &Reseed(const uint256 &seed) { return *m_rng = FastRandomContext(seed); }

    FastRandomContext &ReseedDeterministic() { return *m_rng = FastRandomContext(true); }

    void CheckOutpointToOrphanSanity() {
        const auto &m = m_orphans;
        const auto &mp = m_outpoint_to_orphan_it;

        // every entry in mp must be a valid iterator in m, and there must be no empty sets in mp
        for (const auto & [outpt, set] : mp) {
            BOOST_CHECK(!set.empty());
            for (const auto &it : set) {
                const auto mit = m.find(it->first);
                BOOST_REQUIRE(mit != m.end()); // must exist
                BOOST_CHECK(it == mit); // must be the same iterator in m
                BOOST_CHECK(it->first == it->second.tx->GetId()); // check that the txid is the same (paranoia)
            }
        }

        // every tx in m must have an entry in mp for each of its CTxIns
        auto &m_nonconst = m_orphans; // we need a non-const iterator for below
        for (auto it = m_nonconst.begin(); it != m_nonconst.end(); ++it) {
            const auto & [txid, orphantx] = *it;
            for (const auto &txin : orphantx.tx->vin) {
                const auto it2 = mp.find(txin.prevout);
                BOOST_REQUIRE(it2 != mp.end());
                // sanity check the other way -- entry must exist in set, and it must be this iterator
                BOOST_CHECK(it2->second.count(it) == 1); // count here only works with non-const `it`
            }
        }
    }
};

static void MakeNewKeyWithFastRandomContext(CKey &key, FastRandomContext &rand_ctx) {
    std::vector<uint8_t> keydata;
    keydata = rand_ctx.randbytes(32);
    key.Set(keydata.data(), keydata.data() + keydata.size(), /*fCompressedIn=*/true);
    assert(key.IsValid());
}

// Creates a transaction with 2 outputs. Spends all outpoints. If outpoints is empty, spends a random one.
static CTransactionRef MakeTransactionSpending(const std::vector<COutPoint> &outpoints, FastRandomContext &det_rand) {
    CKey key;
    MakeNewKeyWithFastRandomContext(key, det_rand);
    CMutableTransaction tx;
    // If no outpoints are given, create a random one.
    if (outpoints.empty()) {
        tx.vin.emplace_back(TxId{det_rand.rand256()}, 0);
    } else {
        for (const auto &outpoint : outpoints) {
            tx.vin.emplace_back(outpoint);
            tx.vin.back().scriptSig << OP_TRUE;
        }
    }
    tx.vout.resize(2);
    tx.vout[0].nValue = CENT;
    tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
    tx.vout[1].nValue = 3 * CENT;
    tx.vout[1].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
    return MakeTransactionRef(tx);
}

// Make another (not necessarily valid) tx with different txid
static CTransactionRef MakeMutation(const CTransactionRef &ptx) {
    CMutableTransaction tx(*ptx);
    tx.vin.at(0).scriptSig << OP_TRUE;
    CTransactionRef mutated_tx = MakeTransactionRef(tx);
    assert(ptx->GetId() != mutated_tx->GetId());
    return mutated_tx;
}

static bool EqualTxns(const std::set<CTransactionRef> &set_txns, const std::vector<CTransactionRef> &vec_txns) {
    if (vec_txns.size() != set_txns.size()) return false;
    for (const auto &tx : vec_txns) {
        if (!set_txns.contains(tx)) return false;
    }
    return true;
}
static bool EqualTxns(const std::set<CTransactionRef> &set_txns,
                      const std::vector<std::pair<CTransactionRef, NodeId>> &vec_txns) {
    if (vec_txns.size() != set_txns.size()) return false;
    for (const auto & [tx, nodeid] : vec_txns) {
        if (!set_txns.contains(tx)) return false;
    }
    return true;
}

BOOST_AUTO_TEST_CASE(DoS_mapOrphans) {
    // This test had non-deterministic coverage due to
    // randomly selected seeds.
    // This seed is chosen so that all branches of the function
    // ecdsa_signature_parse_der_lax are executed during this test.
    // Specifically branches that run only when an ECDSA
    // signature's R and S values have leading zeros.
    TxOrphanageTest orphanage;
    auto &rng = orphanage.Reseed(uint256S("21"));

    CKey key;
    MakeNewKeyWithFastRandomContext(key, rng);
    CBasicKeyStore keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // Freeze time for length of test
    const auto now = GetTime();
    SetMockTime(now);

    // 50 orphan transactions:
    for (size_t i = 0; i < 50; ++i) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(TxId{rng.rand256()}, 0);
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1 * CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

        orphanage.AddTx(MakeTransactionRef(tx), i);
    }

    orphanage.CheckOutpointToOrphanSanity();

    // ... and 50 that depend on other orphans:
    for (size_t i = 0; i < 50; ++i) {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(txPrev->GetId(), 0);
        tx.vout.resize(1);
        tx.vout[0].nValue = 1 * CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        SignatureData empty;
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SigHashType().withFork(), STANDARD_SCRIPT_VERIFY_FLAGS, std::nullopt));

        orphanage.AddTx(MakeTransactionRef(tx), i);
    }

    orphanage.CheckOutpointToOrphanSanity();

    // This really-big orphan should be ignored:
    for (size_t i = 0; i < 10; ++i) {
        CTransactionRef txPrev = orphanage.RandomOrphan();

        CMutableTransaction tx;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1 * CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        tx.vin.resize(2777);
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            tx.vin[j].prevout = COutPoint(txPrev->GetId(), j);
        }
        SignatureData empty;
        BOOST_CHECK(SignSignature(keystore, *txPrev, tx, 0, SigHashType().withFork(), STANDARD_SCRIPT_VERIFY_FLAGS, std::nullopt));
        // Reuse same signature for other inputs
        // (they don't have to be valid for this test)
        for (size_t j = 1; j < tx.vin.size(); ++j)
            tx.vin[j].scriptSig = tx.vin[0].scriptSig;

        BOOST_CHECK(!orphanage.AddTx(MakeTransactionRef(tx), i));
    }

    size_t expected_num_orphans = orphanage.Size();

    // Non-existent peer; nothing should be deleted
    orphanage.EraseForPeer(/*peer=*/-1);
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_num_orphans);

    // Each of first three peers stored
    // two transactions each.
    for (NodeId i = 0; i < 3; ++i) {
        orphanage.EraseForPeer(i);
        expected_num_orphans -= 2;
        BOOST_CHECK(orphanage.Size() == expected_num_orphans);
        orphanage.CheckOutpointToOrphanSanity();
    }

    // Test LimitOrphanTxSize() function, nothing should timeout:
    orphanage.ReseedDeterministic();
    orphanage.LimitOrphans(/*max_orphans=*/expected_num_orphans);
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_num_orphans);
    orphanage.CheckOutpointToOrphanSanity();
    expected_num_orphans -= 1;
    orphanage.LimitOrphans(/*max_orphans=*/expected_num_orphans);
    BOOST_CHECK_EQUAL(orphanage.Size(), expected_num_orphans);
    orphanage.CheckOutpointToOrphanSanity();
    assert(expected_num_orphans > 40);
    orphanage.LimitOrphans(40);
    BOOST_CHECK_EQUAL(orphanage.Size(), 40);
    orphanage.CheckOutpointToOrphanSanity();
    orphanage.LimitOrphans(10);
    BOOST_CHECK_EQUAL(orphanage.Size(), 10);
    orphanage.CheckOutpointToOrphanSanity();
    orphanage.LimitOrphans(0);
    BOOST_CHECK_EQUAL(orphanage.Size(), 0);
    orphanage.CheckOutpointToOrphanSanity();

    // Add one more orphan, check timeout logic
    auto timeout_tx = MakeTransactionSpending(/*outpoints=*/{}, rng);
    orphanage.AddTx(timeout_tx, 0);
    orphanage.LimitOrphans(1);
    BOOST_CHECK_EQUAL(orphanage.Size(), 1);
    orphanage.CheckOutpointToOrphanSanity();

    // One second shy of expiration
    SetMockTime(now + ORPHAN_TX_EXPIRE_TIME - 1);
    orphanage.LimitOrphans(1);
    BOOST_CHECK_EQUAL(orphanage.Size(), 1);
    orphanage.CheckOutpointToOrphanSanity();

    // Jump one more second, orphan should be timed out on limiting
    SetMockTime(now + ORPHAN_TX_EXPIRE_TIME);
    BOOST_CHECK_EQUAL(orphanage.Size(), 1);
    orphanage.LimitOrphans(1);
    BOOST_CHECK_EQUAL(orphanage.Size(), 0);
    orphanage.CheckOutpointToOrphanSanity();
}

BOOST_AUTO_TEST_CASE(conflicting_tx) {
    TxOrphanageTest orphanage;
    auto &det_rand = orphanage.ReseedDeterministic();
    NodeId peer{0};

    std::vector<COutPoint> empty_outpoints;
    auto parent = MakeTransactionSpending(empty_outpoints, det_rand);

    // Create children to go into orphanage.
    auto child_normal = MakeTransactionSpending({{parent->GetId(), 0}}, det_rand);
    auto child_mutated = MakeMutation(child_normal);

    const auto &normal_txid = child_normal->GetId();
    const auto &mutated_txid = child_mutated->GetId();
    BOOST_CHECK(normal_txid != mutated_txid);

    BOOST_CHECK(orphanage.AddTx(child_normal, peer));
    // EraseTx fails as transaction by this txid doesn't exist.
    BOOST_CHECK_EQUAL(orphanage.EraseTx(mutated_txid), 0);
    BOOST_CHECK(orphanage.HaveTx(normal_txid));
    BOOST_CHECK(!orphanage.HaveTx(mutated_txid));
    orphanage.CheckOutpointToOrphanSanity();

    // Must succeed. Both transactions should be present in orphanage.
    BOOST_CHECK(orphanage.AddTx(child_mutated, peer));
    BOOST_CHECK(orphanage.HaveTx(normal_txid));
    BOOST_CHECK(orphanage.HaveTx(mutated_txid));
    orphanage.CheckOutpointToOrphanSanity();

    // Outpoints map should track all entries: check that both are returned as children of the parent.
    std::set<CTransactionRef> expected_children{child_normal, child_mutated};
    BOOST_CHECK(EqualTxns(expected_children, orphanage.GetChildrenFromSamePeer(parent, peer)));

    // Erase by txid: mutated first
    BOOST_CHECK_EQUAL(orphanage.EraseTx(mutated_txid), 1);
    BOOST_CHECK(orphanage.HaveTx(normal_txid));
    BOOST_CHECK(!orphanage.HaveTx(mutated_txid));
    orphanage.CheckOutpointToOrphanSanity();

    BOOST_CHECK_EQUAL(orphanage.EraseTx(normal_txid), 1);
    BOOST_CHECK(!orphanage.HaveTx(normal_txid));
    BOOST_CHECK(!orphanage.HaveTx(mutated_txid));
    orphanage.CheckOutpointToOrphanSanity();
}

BOOST_AUTO_TEST_CASE(get_children) {
    FastRandomContext det_rand{true};
    std::vector<COutPoint> empty_outpoints;

    auto parent1 = MakeTransactionSpending(empty_outpoints, det_rand);
    auto parent2 = MakeTransactionSpending(empty_outpoints, det_rand);

    // Make sure these parents have different txids otherwise this test won't make sense.
    while (parent1->GetHash() == parent2->GetHash()) {
        parent2 = MakeTransactionSpending(empty_outpoints, det_rand);
    }

    // Create children to go into orphanage.
    auto child_p1n0 = MakeTransactionSpending({{parent1->GetId(), 0}}, det_rand);
    auto child_p2n1 = MakeTransactionSpending({{parent2->GetId(), 1}}, det_rand);
    // Spends the same tx twice. Should not cause duplicates.
    auto child_p1n0_p1n1 = MakeTransactionSpending({{parent1->GetId(), 0}, {parent1->GetId(), 1}}, det_rand);
    // Spends the same outpoint as previous tx. Should still be returned; don't assume outpoints are unique.
    auto child_p1n0_p2n0 = MakeTransactionSpending({{parent1->GetId(), 0}, {parent2->GetId(), 0}}, det_rand);

    const NodeId node1{1};
    const NodeId node2{2};

    // All orphans provided by node1
    {
        TxOrphanage orphanage;
        BOOST_CHECK(orphanage.AddTx(child_p1n0, node1));
        BOOST_CHECK(orphanage.AddTx(child_p2n1, node1));
        BOOST_CHECK(orphanage.AddTx(child_p1n0_p1n1, node1));
        BOOST_CHECK(orphanage.AddTx(child_p1n0_p2n0, node1));

        std::set<CTransactionRef> expected_parent1_children{child_p1n0, child_p1n0_p2n0, child_p1n0_p1n1};
        std::set<CTransactionRef> expected_parent2_children{child_p2n1, child_p1n0_p2n0};

        BOOST_CHECK(EqualTxns(expected_parent1_children, orphanage.GetChildrenFromSamePeer(parent1, node1)));
        BOOST_CHECK(EqualTxns(expected_parent2_children, orphanage.GetChildrenFromSamePeer(parent2, node1)));

        BOOST_CHECK(EqualTxns(expected_parent1_children, orphanage.GetChildrenFromDifferentPeer(parent1, node2)));
        BOOST_CHECK(EqualTxns(expected_parent2_children, orphanage.GetChildrenFromDifferentPeer(parent2, node2)));

        // The peer must match
        BOOST_CHECK(orphanage.GetChildrenFromSamePeer(parent1, node2).empty());
        BOOST_CHECK(orphanage.GetChildrenFromSamePeer(parent2, node2).empty());

        // There shouldn't be any children of this tx in the orphanage
        BOOST_CHECK(orphanage.GetChildrenFromSamePeer(child_p1n0_p2n0, node1).empty());
        BOOST_CHECK(orphanage.GetChildrenFromSamePeer(child_p1n0_p2n0, node2).empty());
        BOOST_CHECK(orphanage.GetChildrenFromDifferentPeer(child_p1n0_p2n0, node1).empty());
        BOOST_CHECK(orphanage.GetChildrenFromDifferentPeer(child_p1n0_p2n0, node2).empty());
    }

    // Orphans provided by node1 and node2
    {
        TxOrphanage orphanage;
        BOOST_CHECK(orphanage.AddTx(child_p1n0, node1));
        BOOST_CHECK(orphanage.AddTx(child_p2n1, node1));
        BOOST_CHECK(orphanage.AddTx(child_p1n0_p1n1, node2));
        BOOST_CHECK(orphanage.AddTx(child_p1n0_p2n0, node2));

        // +----------------+---------------+----------------------------------+
        // |                | sender=node1  |           sender=node2           |
        // +----------------+---------------+----------------------------------+
        // | spends parent1 | child_p1n0    | child_p1n0_p1n1, child_p1n0_p2n0 |
        // | spends parent2 | child_p2n1    | child_p1n0_p2n0                  |
        // +----------------+---------------+----------------------------------+

        // Children of parent1 from node1:
        {
            std::set<CTransactionRef> expected_parent1_node1{child_p1n0};

            BOOST_CHECK(EqualTxns(expected_parent1_node1, orphanage.GetChildrenFromSamePeer(parent1, node1)));
            BOOST_CHECK(EqualTxns(expected_parent1_node1, orphanage.GetChildrenFromDifferentPeer(parent1, node2)));
        }

        // Children of parent2 from node1:
        {
            std::set<CTransactionRef> expected_parent2_node1{child_p2n1};

            BOOST_CHECK(EqualTxns(expected_parent2_node1, orphanage.GetChildrenFromSamePeer(parent2, node1)));
            BOOST_CHECK(EqualTxns(expected_parent2_node1, orphanage.GetChildrenFromDifferentPeer(parent2, node2)));
        }

        // Children of parent1 from node2:
        {
            std::set<CTransactionRef> expected_parent1_node2{child_p1n0_p1n1, child_p1n0_p2n0};

            BOOST_CHECK(EqualTxns(expected_parent1_node2, orphanage.GetChildrenFromSamePeer(parent1, node2)));
            BOOST_CHECK(EqualTxns(expected_parent1_node2, orphanage.GetChildrenFromDifferentPeer(parent1, node1)));
        }

        // Children of parent2 from node2:
        {
            std::set<CTransactionRef> expected_parent2_node2{child_p1n0_p2n0};

            BOOST_CHECK(EqualTxns(expected_parent2_node2, orphanage.GetChildrenFromSamePeer(parent2, node2)));
            BOOST_CHECK(EqualTxns(expected_parent2_node2, orphanage.GetChildrenFromDifferentPeer(parent2, node1)));
        }
    }
}

static CTransactionRef MakeTxSized(const size_t sizeRequired) {
    CMutableTransaction mtx;
    CTransactionRef tx;
    mtx.vin.resize(1);
    size_t size;
    while ((size = (tx = MakeTransactionRef(mtx))->GetTotalSize()) < sizeRequired) {
        if (mtx.vout.empty() || mtx.vout.back().scriptPubKey.size() != 1) {
            // push an empty OP_RETURN
            mtx.vout.emplace_back(Amount::zero(), CScript() << OP_RETURN);
        } else if (size_t n2add = std::min<size_t>(sizeRequired - size, 254); n2add > 0) {
            // extend the empty OP_RETURN with some OP_NOP opcodes
            auto &spk = mtx.vout.back().scriptPubKey;
            spk.reserve(spk.size() + n2add);
            while (n2add--) {
                spk << OP_NOP;
            }
        }
    }
    return tx;
}

BOOST_AUTO_TEST_CASE(too_large_orphan_tx) {
    TxOrphanage orphanage;

    // check that txs larger than MAX_STANDARD_TX_SIZE are not added to the orphanage
    auto tx = MakeTxSized(MAX_STANDARD_TX_SIZE + 1);
    BOOST_REQUIRE_GT(tx->GetTotalSize(), MAX_STANDARD_TX_SIZE);
    BOOST_CHECK(!orphanage.AddTx(tx, 0));

    tx = MakeTxSized(MAX_STANDARD_TX_SIZE);
    BOOST_CHECK_LE(tx->GetTotalSize(), MAX_STANDARD_TX_SIZE);
    BOOST_CHECK(orphanage.AddTx(tx, 0));
}

BOOST_AUTO_TEST_SUITE_END()
