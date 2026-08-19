// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/standard.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <memory>
#include <string_view>
#include <optional>

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);

static BlockAssembler AssemblerForTest(const Config &config, const CTxMemPool &mempool) {
    BlockAssembler::Options options;
    options.blockMinFeeRate = blockMinFeeRate;
    return BlockAssembler(config, mempool, options);
}

static struct {
    uint8_t extranonce;
    uint32_t nonce;
} blockinfo[] = {
    {4, 0xa4a3e223}, {2, 0x15c32f9e}, {1, 0x0375b547}, {1, 0x7004a8a5},
    {2, 0xce440296}, {2, 0x52cfe198}, {1, 0x77a72cd0}, {2, 0xbb5d6f84},
    {2, 0x83f30c2c}, {1, 0x48a73d5b}, {1, 0xef7dcd01}, {2, 0x6809c6c4},
    {2, 0x0883ab3c}, {1, 0x087bbbe2}, {2, 0x2104a814}, {2, 0xdffb6daa},
    {1, 0xee8a0a08}, {2, 0xba4237c1}, {1, 0xa70349dc}, {1, 0x344722bb},
    {3, 0xd6294733}, {2, 0xec9f5c94}, {2, 0xca2fbc28}, {1, 0x6ba4f406},
    {2, 0x015d4532}, {1, 0x6e119b7c}, {2, 0x43e8f314}, {2, 0x27962f38},
    {2, 0xb571b51b}, {2, 0xb36bee23}, {2, 0xd17924a8}, {2, 0x6bc212d9},
    {1, 0x630d4948}, {2, 0x9a4c4ebb}, {2, 0x554be537}, {1, 0xd63ddfc7},
    {2, 0xa10acc11}, {1, 0x759a8363}, {2, 0xfb73090d}, {1, 0xe82c6a34},
    {1, 0xe33e92d7}, {3, 0x658ef5cb}, {2, 0xba32ff22}, {5, 0x0227a10c},
    {1, 0xa9a70155}, {5, 0xd096d809}, {1, 0x37176174}, {1, 0x830b8d0f},
    {1, 0xc6e3910e}, {2, 0x823f3ca8}, {1, 0x99850849}, {1, 0x7521fb81},
    {1, 0xaacaabab}, {1, 0xd645a2eb}, {5, 0x7aea1781}, {5, 0x9d6e4b78},
    {1, 0x4ce90fd8}, {1, 0xabdc832d}, {6, 0x4a34f32a}, {2, 0xf2524c1c},
    {2, 0x1bbeb08a}, {1, 0xad47f480}, {1, 0x9f026aeb}, {1, 0x15a95049},
    {2, 0xd1cb95b2}, {2, 0xf84bbda5}, {1, 0x0fa62cd1}, {1, 0xe05f9169},
    {1, 0x78d194a9}, {5, 0x3e38147b}, {5, 0x737ba0d4}, {1, 0x63378e10},
    {1, 0x6d5f91cf}, {2, 0x88612eb8}, {2, 0xe9639484}, {1, 0xb7fabc9d},
    {2, 0x19b01592}, {1, 0x5a90dd31}, {2, 0x5bd7e028}, {2, 0x94d00323},
    {1, 0xa9b9c01a}, {1, 0x3a40de61}, {1, 0x56e7eec7}, {5, 0x859f7ef6},
    {1, 0xfd8e5630}, {1, 0x2b0c9f7f}, {1, 0xba700e26}, {1, 0x7170a408},
    {1, 0x70de86a8}, {1, 0x74d64cd5}, {1, 0x49e738a1}, {2, 0x6910b602},
    {0, 0x643c565f}, {1, 0x54264b3f}, {2, 0x97ea6396}, {2, 0x55174459},
    {2, 0x03e8779a}, {1, 0x98f34d8f}, {1, 0xc07b2b07}, {1, 0xdfe29668},
    {1, 0x3141c7c1}, {1, 0xb3b595f4}, {1, 0x735abf08}, {5, 0x623bfbce},
    {2, 0xd351e722}, {1, 0xf4ca48c9}, {1, 0x5b19c670}, {1, 0xa164bf0e},
    {2, 0xbbbeb305}, {2, 0xfe1c810a},
};

using CBlockIndexPtr = std::unique_ptr<CBlockIndex>;

static CBlockIndexPtr CreateBlockIndex(int nHeight) {
    CBlockIndexPtr index(new CBlockIndex);
    index->nHeight = nHeight;
    index->pprev = ::ChainActive().Tip();
    return index;
}

static bool TestSequenceLocks(const CTransaction &tx, int flags)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    LOCK(::g_mempool.cs);
    return CheckSequenceLocks(::g_mempool, tx, flags);
}

// Test suite for feerate transaction selection.
// Implemented as an additional function, rather than a separate test case, to
// allow reusing the blockchain created in CreateNewBlock_validity.
static void TestPackageSelection(const Config &config,
                                 const CScript &scriptPubKey,
                                 const std::vector<CTransactionRef> &txFirst)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main, ::g_mempool.cs) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected before a higher fee
    // transaction when the high-fee tx has a low fee parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = int64_t(5000000000LL - 1000) * SATOSHI;
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(1000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(true)
                               .FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = int64_t(5000000000LL - 10000) * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(10000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(true)
                               .FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = int64_t(5000000000LL - 1000 - 50000) * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(50000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(false)
                               .FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey);


    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == mediumFeeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == parentTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == highFeeTxId);

    // Test that a tranactions with ancestor below the block min tx fee doesn't get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = int64_t(5000000000LL - 1000 - 50000) * SATOSHI;
    TxId freeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(Amount::zero()).FromTx(tx));

    // Add a child transaction with high fee.
    Amount feeToUse = 50000 * SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue =
        int64_t(5000000000LL - 1000 - 50000) * SATOSHI - feeToUse;
    TxId highFeeDecendantTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate =
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey);

    // Verify that the free tx and its high fee descendant tx didn't get selected.
    for (const auto &txn : pblocktemplate->block.vtx) {
        BOOST_CHECK(txn->GetId() != freeTxId);
        BOOST_CHECK(txn->GetId() != highFeeDecendantTxId);
    }
}

// Coinbase scriptSig has to contain the /ABLA/ string
BOOST_AUTO_TEST_CASE(CheckCoinbase_ABLA) {
    GlobalConfig config;

    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;

    const CBlockIndex *pindexMinedTip;
    std::unique_ptr<CBlockTemplate> pblocktemplate =
        BlockAssembler(config, g_mempool).CreateNewBlock(scriptPubKey, 0, true, &pindexMinedTip);

    CBlock *pblock = &pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(pblock, pindexMinedTip, config, extraNonce);
    unsigned int nHeight = pindexMinedTip->nHeight + 1;

    constexpr std::string_view cbmsg{"/ABLA/"};
    std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig ==
                ((CScript() << ScriptInt::fromIntUnchecked(nHeight) << CScriptNum::fromIntUnchecked(extraNonce) << vec) +
                 COINBASE_FLAGS));
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity) {
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    CMutableTransaction tx;
    CScript script;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11 * SATOSHI;

    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 100 blocks :)
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (size_t i = 0; i < sizeof(blockinfo) / sizeof(*blockinfo); ++i) {
        // pointer for convenience.
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            pblock->nVersion = 1;
            const CBlockIndex * const tip = ::ChainActive().Tip();
            assert(tip != nullptr);
            pblock->nTime = tip->GetMedianTimePast() + 1;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            txCoinbase.vin[0].scriptSig = CScript();
            txCoinbase.vin[0].scriptSig.push_back(blockinfo[i].extranonce);
            txCoinbase.vin[0].scriptSig.push_back(::ChainActive().Height());
            txCoinbase.vout.resize(1);
            txCoinbase.vout[0].scriptPubKey = CScript();
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0) {
                baseheight = ::ChainActive().Height();
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(pblock->vtx[0]);
            }
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->nNonce = blockinfo[i].nonce;
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(ProcessNewBlock(config, shared_pblock, true, nullptr));
        pblock->hashPrevBlock = pblock->GetHash();
    }

    LOCK(cs_main);
    LOCK(::g_mempool.cs);

    // Just to make sure we can still make simple blocks.
    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    const Amount BLOCKSUBSIDY = 50 * COIN;
    const Amount LOWFEE = CENT;
    const Amount HIGHFEE = COIN;
    const Amount HIGHERFEE = 4 * COIN;

    // block size > limit
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<uint8_t> vchData(520);
    for (unsigned int i = 0; i < 18; ++i) {
        tx.vin[0].scriptSig << vchData << OP_DROP;
    }

    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY;
    for (unsigned int i = 0; i < 128; ++i) {
        tx.vout[0].nValue -= LOWFEE;
        const TxId txid = tx.GetId();
        // Only first tx spends coinbase.
        bool spendsCoinbase = i == 0;
        g_mempool.addUnchecked(entry.Fee(LOWFEE)
                                   .Time(GetTime())
                                   .SpendsCoinbase(spendsCoinbase)
                                   .FromTx(tx));
        tx.vin[0].prevout = COutPoint(txid, 0);
    }

    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    g_mempool.clear();

    // Orphan in mempool, template creation fails.
    g_mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    g_mempool.clear();

    // Child with higher priority than parent.
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    TxId txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout = COutPoint(txFirst[0]->GetId(), 0);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    g_mempool.clear();

    // Coinbase in mempool, template creation fails.
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = Amount::zero();
    txid = tx.GetId();
    // Give it a fee so it'll get mined.
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-tx-coinbase
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-tx-coinbase"));
    g_mempool.clear();

    // Double spend txn pair in mempool, template creation fails.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));
    g_mempool.clear();

    // Subsidy changing.
    int nHeight = ::ChainActive().Height();
    // Create an actual 209999-long block chain (without valid blocks).
    while (::ChainActive().Tip()->nHeight < 209999) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (::ChainActive().Tip()->nHeight < 210000) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }

    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = BLOCKSUBSIDY - LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(ScriptID(script, false /* no p2sh_32 */));
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript()
                          << std::vector<uint8_t>(script.begin(), script.end());
    tx.vout[0].nValue -= LOWFEE;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw blk-bad-inputs
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("blk-bad-inputs"));
    g_mempool.clear();

    // Delete the dummy blocks again.
    while (::ChainActive().Tip()->nHeight > nHeight) {
        CBlockIndex *del = ::ChainActive().Tip();
        ::ChainActive().SetTip(del->pprev);
        pcoinsTip->SetBestBlock(del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);
    uint32_t flags = LOCKTIME_VERIFY_SEQUENCE | LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // Relative height locked.
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    // Only 1 transaction.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    // txFirst[0] is the 2nd block
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight + 1;
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    const Consensus::Params &params = chainparams.GetConsensus();

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    // Sequence locks pass on 2nd block.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, &prevheights,
                      *CreateBlockIndex(::ChainActive().Tip()->nHeight + 2)));

    // Relative time locked.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    // txFirst[1] is the 3rd block.
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
                          (((::ChainActive().Tip()->GetMedianTimePast() + 1 -
                             ::ChainActive()[1]->GetMedianTimePast()) >>
                            CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
                           1);
    prevheights[0] = baseheight + 2;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    for (size_t i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        // Trick the MedianTimePast.
        CBlockIndex * const pindex = ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i);
        pindex->nTime += 512;
        pindex->ClearCachedMTPValue();
    }
    // Sequence locks pass 512 seconds later.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, &prevheights,
                      *CreateBlockIndex(::ChainActive().Tip()->nHeight + 1)));
    for (size_t i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        // Undo tricked MTP.
        CBlockIndex * const pindex = ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i);
        pindex->nTime -= 512;
        pindex->ClearCachedMTPValue();
    }

    // Absolute height locked.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = ::ChainActive().Tip()->nHeight + 1;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes on 2nd block.
        CValidationState state;
        int64_t nMedianTimePast = ::ChainActive().Tip()->GetMedianTimePast();
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 2,
            nMedianTimePast, nMedianTimePast));
    }

    // Absolute time locked.
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 0);
    tx.nLockTime = ::ChainActive().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes 1 second later.
        CValidationState state;
        int64_t nMedianTimePast =
            ::ChainActive().Tip()->GetMedianTimePast() + 1;
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 1,
            nMedianTimePast, nMedianTimePast));
    }

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout = COutPoint(txid, 0);
    prevheights[0] = ::ChainActive().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    pblocktemplate =
        AssemblerForTest(config, g_mempool).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

    // None of the of the absolute height/time locked tx should have made it
    // into the template because we still check IsFinalTx in CreateNewBlock, but
    // relative locked txs will if inconsistently added to g_mempool. For now
    // these will still generate a valid template until BIP68 soft fork.
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3UL);
    // However if we advance height by 1 and time by 512, all of them should be
    // mined.
    for (size_t i = 0; i < CBlockIndex::nMedianTimeSpan; ++i) {
        // Trick the MedianTimePast.
        CBlockIndex * const pindex = ::ChainActive().Tip()->GetAncestor(::ChainActive().Tip()->nHeight - i);
        pindex->nTime += 512;
        pindex->ClearCachedMTPValue();
    }
    ::ChainActive().Tip()->nHeight++;
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate = AssemblerForTest(config, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);

    ::ChainActive().Tip()->nHeight--;
    SetMockTime(0);
    g_mempool.clear();

    TestPackageSelection(config, scriptPubKey, txFirst);

    fCheckpointsEnabled = true;
}

static void CallCreateNewBlockOnceToFullyInit(BlockAssembler &ba) {
    ba.CreateNewBlock(CScript() << OP_TRUE, 1e-3);
}

static void CheckBlockMaxSize(Config &config, uint64_t size, uint64_t expected) {
    config.SetGeneratedBlockSizeBytes(size);

    BlockAssembler ba(config, g_mempool);
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), 0); // freshly-constructed class always has 0 here
    CallCreateNewBlockOnceToFullyInit(ba); // must call CreateNewBlock() to have `config` options "take effect"
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), expected);
}

static void CheckBlockMaxSizePercent(Config &config, std::optional<double> optPercent, uint64_t expected) {
    if (optPercent) {
        BOOST_CHECK(config.SetGeneratedBlockSizePercent(*optPercent));
    }

    BlockAssembler ba(config, g_mempool);
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), 0); // freshly-constructed class always has 0 here
    CallCreateNewBlockOnceToFullyInit(ba); // must call CreateNewBlock() to have `config` options "take effect"
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), expected);
}

BOOST_AUTO_TEST_CASE(BlockAssembler_construction) {
    GlobalConfig config;

    // check that generated block size can never exceed default max block size
    {
        const auto defbs = config.GetDefaultConsensusBlockSize();
        BOOST_CHECK_LE(config.GetGeneratedBlockSize(defbs), defbs);
        const size_t prevVal = config.GetGeneratedBlockSize(defbs),
                     largerVal = defbs + 100;
        BOOST_CHECK_NE(prevVal, largerVal); // ensure not equal for thoroughness
        // try and set generated block size beyond the conf. max block size (should fail)
        config.SetGeneratedBlockSizeBytes(largerVal);
        // check that we really did not raise the value until we actually grow the maxBlockSize
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(defbs), prevVal);
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(defbs + 1), prevVal + 1);
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(defbs + 2), prevVal + 2);
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(largerVal), largerVal);
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(largerVal + 1), largerVal);
        // reset back
        config.SetGeneratedBlockSizeBytes(prevVal);
        // check bad percentages
        BOOST_CHECK(!config.SetGeneratedBlockSizePercent(101.0));
        BOOST_CHECK(!config.SetGeneratedBlockSizePercent(100.1));
        BOOST_CHECK(!config.SetGeneratedBlockSizePercent(-0.001));
        // check that the failure really did not set the value
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(defbs), prevVal);
    }

    // We are working on a fake chain and need to protect ourselves.
    LOCK(cs_main);

    // Test around low values
    CheckBlockMaxSize(config, 0, 1000);
    CheckBlockMaxSize(config, 1000, 1000);
    CheckBlockMaxSize(config, 1001, 1001);
    CheckBlockMaxSize(config, 12345, 12345);

    // Test around one megabyte
    CheckBlockMaxSize(config, ONE_MEGABYTE - 1001, ONE_MEGABYTE - 1001);
    CheckBlockMaxSize(config, ONE_MEGABYTE - 1000, ONE_MEGABYTE - 1000);
    CheckBlockMaxSize(config, ONE_MEGABYTE - 999, ONE_MEGABYTE - 999);
    CheckBlockMaxSize(config, ONE_MEGABYTE, ONE_MEGABYTE);

    // Now we can test the default max block size.
    CheckBlockMaxSize(config, DEFAULT_CONSENSUS_BLOCK_SIZE - 1001, DEFAULT_CONSENSUS_BLOCK_SIZE - 1001);
    CheckBlockMaxSize(config, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, DEFAULT_CONSENSUS_BLOCK_SIZE - 998, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, DEFAULT_CONSENSUS_BLOCK_SIZE - 999, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, DEFAULT_CONSENSUS_BLOCK_SIZE, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000);

    // Test percent mode
    CheckBlockMaxSizePercent(config, 100.0, DEFAULT_CONSENSUS_BLOCK_SIZE - 1000);
    CheckBlockMaxSizePercent(config, 50.0, DEFAULT_CONSENSUS_BLOCK_SIZE / 2);
    CheckBlockMaxSizePercent(config, 10.0, DEFAULT_CONSENSUS_BLOCK_SIZE / 10);
    CheckBlockMaxSizePercent(config, 1.0, DEFAULT_CONSENSUS_BLOCK_SIZE / 100);
    CheckBlockMaxSizePercent(config, 0.25, DEFAULT_CONSENSUS_BLOCK_SIZE / 400);
    CheckBlockMaxSizePercent(config, 25.0, DEFAULT_CONSENSUS_BLOCK_SIZE / 4);

    // NB: If the generated block size parameter is not specified, the config object just defaults it to the default max
    // block size. But in that case the BlockAssembler ends up unconditionally reserving 1000 bytes of space for the
    // coinbase tx.
    constexpr size_t hardCodedCoinbaseReserved = 1000;
    {
        GlobalConfig freshConfig;
        BlockAssembler ba(freshConfig, g_mempool);
        BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), 0);
        CallCreateNewBlockOnceToFullyInit(ba);
        auto defbs = freshConfig.GetDefaultConsensusBlockSize();
        BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), defbs - hardCodedCoinbaseReserved);
    }
}

BOOST_AUTO_TEST_CASE(TestCBlockTemplateEntry) {
    CTransactionRef txRef = MakeTransactionRef();
    CBlockTemplateEntry txEntry(txRef, 1 * SATOSHI, 10);
    BOOST_CHECK_MESSAGE(txEntry.tx == txRef, "Transactions did not match");
    BOOST_CHECK_EQUAL(txEntry.fees, 1 * SATOSHI);
    BOOST_CHECK_EQUAL(txEntry.sigChecks, 10);
}

BOOST_AUTO_TEST_SUITE_END()
