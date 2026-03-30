// Copyright (c) 2021-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <bench/bench.h>
#include <config.h>
#include <consensus/validation.h>
#include <miner.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/standard.h>
#include <test/setup_common.h>
#include <test/util.h>
#include <txmempool.h>
#include <util/system.h>
#include <validation.h>

#include <list>
#include <queue>
#include <vector>

/// This file contains benchmarks focusing on chained transactions in the
/// mempool.

static const CScript REDEEM_SCRIPT = CScript()
    << OP_DROP << OP_TRUE;

static const CScript SCRIPT_PUB_KEY = GetScriptForDestination(ScriptID(REDEEM_SCRIPT, false /* p2sh_20 */));

static const CScript SCRIPT_SIG = CScript()
    << std::vector<uint8_t>(100, 0xff)
    << ByteView(REDEEM_SCRIPT);

/// Mine new utxos
static std::vector<CTxIn> createUTXOs(const Config& config, size_t n) {
    std::vector<CTxIn> utxos;
    utxos.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        utxos.emplace_back(MineBlock(config, SCRIPT_PUB_KEY));
    }

    for (size_t i = 0; i < COINBASE_MATURITY + 1; ++i) {
        MineBlock(config, SCRIPT_PUB_KEY);
    }

    return utxos;
}

/// Create a transaction spending a coinbase utxo
static CTransactionRef toTx(const Config&, CTxIn txin) {
    CMutableTransaction tx;
    tx.vin.emplace_back(txin);
    tx.vin.back().scriptSig = SCRIPT_SIG;
    tx.vout.emplace_back(25 * COIN - 1337 * SATOSHI, SCRIPT_PUB_KEY);
    return MakeTransactionRef(tx);
}

/// Creates a chain of transactions with 1-input-1-output.
static std::vector<CTransactionRef> oneInOneOutChain(const Config& config,
                                                     CTxIn utxo,
                                                     const size_t chainLength)
{
    auto firstTx = toTx(config, std::move(utxo));

    // Build the chain
    std::vector<CTransactionRef> chain = { firstTx };
    chain.reserve(chainLength);
    while (chain.size() < chainLength) {
        const COutPoint parent(chain.back()->GetId(), 0);
        const Amount inAmount(chain.back()->vout[0].nValue);
        CMutableTransaction tx;
        tx.vin.emplace_back(CTxIn(parent, SCRIPT_SIG));
        tx.vout.emplace_back(inAmount - 1337 * SATOSHI, SCRIPT_PUB_KEY);
        chain.emplace_back(MakeTransactionRef(tx));
    }
    assert(chain.size() == chainLength);
    return chain;
}


/// Creates a tree of transactions with 2-inputs-1-output. It has similar properties
/// to a complete binary-tree, where the last transaction is the "top" of the tree.
static std::vector<CTransactionRef> twoInOneOutTree(const Config& config,
                                                    const size_t treeDepth)
{
    /// Total number of txs is the sum of nodes at each depth of a binary tree.
    size_t txs = 0;
    for (size_t i = 0; i <= treeDepth; ++i) {
        txs += std::pow(2, i);
    }
    const size_t leafs = std::pow(2, treeDepth);

    std::vector<CTransactionRef> chain;
    chain.reserve(txs);

    std::queue<CTransactionRef> queue;
    for (auto txin : createUTXOs(config, leafs)) {
        auto tx = toTx(config, std::move(txin));
        queue.push(tx);
        chain.emplace_back(tx);
    }

    while (true) {
        CMutableTransaction tx;

        const CTransactionRef txin1 = queue.front();
        queue.pop();
        const CTransactionRef txin2 = queue.front();
        queue.pop();

        const Amount inAmount = txin1->vout[0].nValue + txin2->vout[0].nValue;

        tx.vin.emplace_back(CTxIn(COutPoint(txin1->GetId(), 0), SCRIPT_SIG));
        tx.vin.emplace_back(CTxIn(COutPoint(txin2->GetId(), 0), SCRIPT_SIG));
        tx.vout.emplace_back(inAmount - 1337 * SATOSHI, SCRIPT_PUB_KEY);

        CTransactionRef txref = MakeTransactionRef(tx);
        chain.push_back(txref);
        if (queue.empty()) {
            break;
        }
        queue.emplace(txref);
    }
    assert(chain.size() == txs);
    return chain;
}


/// Run benchmark on AcceptToMemoryPool
static void benchATMP(const Config& config,
                     benchmark::State& state,
                     const std::vector<CTransactionRef> chainedTxs)
{
    const Amount absurdFee(Amount::zero());

    LOCK(::cs_main);
    assert(g_mempool.size() == 0);
    BENCHMARK_LOOP {
        for (const auto& tx : chainedTxs) {
            CValidationState vstate;
            bool ok = AcceptToMemoryPool(
                    config, g_mempool, vstate, tx,
                    nullptr /* pfMissingInputs */,
                    false /* bypass_limits */,
                    absurdFee);
            assert(ok);
        }
        g_mempool.clear();
    }
}


/// Run benchmark that reorganizes blocks with one-input-one-output transaction
/// chains in them.
///
/// If 'includeMempoolTxRemoval' is set, the benchmark will include the time
/// it takes to remove the transactions of re-connected blocks from the mempool.
static void benchReorg(const Config& config,
                       benchmark::State& state,
                       size_t reorgDepth,
                       size_t chainSizePerBlock,
                       bool includeMempoolTxRemoval)
{
    std::vector<std::vector<CTransactionRef>> chains;
    for (auto &utxo : createUTXOs(config, reorgDepth)) {
        chains.emplace_back(oneInOneOutChain(config, std::move(utxo), chainSizePerBlock));
    }

    // Current tip will be last valid block.
    CBlockIndex *tipBeforeInvalidate = ::ChainActive().Tip();
    assert(tipBeforeInvalidate != nullptr);

    CBlockIndex *blockToInvalidate = nullptr;

    assert(g_mempool.size() == 0);

    // Build blocks
    TestMemPoolEntryHelper entry;
    entry.nFee = 1337 * SATOSHI;
    for (const auto& chain : chains) {
        {
            entry.spendsCoinbase = true;
            LOCK2(cs_main, g_mempool.cs);
            for (const auto& tx : chain) {
                g_mempool.addUnchecked(entry.FromTx(tx));
                // Setting spendCoinbase to false here assumes it's a chain
                // of 1-in-1-out transaction chain.
                entry.spendsCoinbase = false;
            }
        }
        assert(g_mempool.size() == chain.size());
        MineBlock(config, SCRIPT_PUB_KEY);
        assert(g_mempool.size() == 0);

        assert(ChainActive().Tip()->nTx == chain.size() + 1 /* coinbase */);

        if (blockToInvalidate == nullptr) {
            blockToInvalidate = ::ChainActive().Tip();
        }
    }
    CBlockIndex* mostWorkTip  = ::ChainActive().Tip();

    BENCHMARK_LOOP {
        CValidationState vstate;

        // Disconnect blocks with long transaction chains
        InvalidateBlock(config, vstate, blockToInvalidate);
        assert(vstate.IsValid());

        ActivateBestChain(config, vstate);
        assert(vstate.IsValid());
        assert(::ChainActive().Tip() == tipBeforeInvalidate);

        // Transactions should be stuffed back into the mempool.
        assert(g_mempool.size() == reorgDepth * chainSizePerBlock);

        if (!includeMempoolTxRemoval) {
            // As of writing this test, removing transactions from mempool
            // during re-connect takes significant amount of time, so we allow
            // to test both with and without this process.
            g_mempool.clear();
        }

        // Reconnect block
        {
            LOCK(cs_main);
            ResetBlockFailureFlags(blockToInvalidate);
        }

        ActivateBestChain(config, vstate);
        assert(vstate.IsValid());
        assert(::ChainActive().Tip() == mostWorkTip);
        assert(g_mempool.size() == 0);
    }
}

static void benchGenerateNewBlock(const Config& config,
                                  benchmark::State& state,
                                  const std::vector<std::vector<CTransactionRef>>& chains)
{
    TestMemPoolEntryHelper entry;
    entry.nFee = 1337 * SATOSHI;

    CTxMemPool mempool;

    // Fill mempool
    size_t txCount = 0;
    for (const auto& chain : chains) {
        entry.spendsCoinbase = true;
        LOCK2(cs_main, mempool.cs);
        for (const auto& tx : chain) {
            mempool.addUnchecked(entry.FromTx(tx));
            // Setting spendCoinbase to false here assumes it's a chain
            // of 1-in-1-out transaction chain.
            entry.spendsCoinbase = false;
            ++txCount;
        }
    }
    assert(mempool.size() == txCount);

    const CScript dummy = CScript() << OP_TRUE;
    BENCHMARK_LOOP {
        auto blocktemplate = BlockAssembler(config, mempool).CreateNewBlock(dummy);
        assert(blocktemplate);
        // +1 for coinbase
        assert(blocktemplate->block.vtx.size() == txCount + 1);
    }

}

static void benchEviction(const Config&,
                          benchmark::State& state,
                          const std::vector<std::vector<CTransactionRef>>& chains, bool revFee = true)
{
    std::list<CTxMemPool> pools;

    // Note: in order to isolate how long eviction takes (as opposed to add + eviction),
    // we are forced to pre-create all the pools we will be needing up front.

    for (uint64_t i = 0; i < state.m_num_iters; ++i) {
        pools.emplace_back();
        CTxMemPool &pool = pools.back();
        TestMemPoolEntryHelper entry;
        // Fill mempool
        size_t txCount = 0;
        entry.nFee = 1337 * SATOSHI;
        // add in order of decreasing fee if revFee, increasing otherwise
        const Amount feeBump = revFee ? int64_t(-1) * SATOSHI : int64_t(1) * SATOSHI;
        for (const auto &chain : chains) {
            entry.spendsCoinbase = true;
            if (revFee)
                entry.nFee += int64_t(chain.size()) * SATOSHI;
            LOCK2(cs_main, pool.cs);
            for (const auto &tx : chain) {
                pool.addUnchecked(entry.FromTx(tx));
                entry.nFee += feeBump;
                // Setting spendCoinbase to false here assumes it's a chain
                // of 1-in-1-out transaction chain.
                entry.spendsCoinbase = false;
                ++txCount;
            }
            if (revFee)
                entry.nFee += int64_t(chain.size()) * SATOSHI;
        }
        assert(pool.size() == txCount);
    }

    auto it = pools.begin();

    BENCHMARK_LOOP {
        assert(it != pools.end());
        auto & pool = *it++;
        LOCK2(cs_main, pool.cs);
        while (auto prevSize = pool.size()) {
            pool.TrimToSize(pool.DynamicMemoryUsage() * 99 / 100);
            assert(pool.size() < prevSize);
        }
    }

}

/// Tests a chain of 50 1-input-1-output transactions.
static void MempoolAcceptance50ChainedTxs(benchmark::State& state) {
    const Config &config = GetConfig();
    const std::vector<CTransactionRef> chainedTxs
        = oneInOneOutChain(config, createUTXOs(config, 1).back(), 50);
    benchATMP(config, state, chainedTxs);
}

/// Tests a chain of 500 1-input-1-output transactions.
static void MempoolAcceptance500ChainedTxs(benchmark::State& state) {
    const Config &config = GetConfig();
    const std::vector<CTransactionRef> chainedTxs
        = oneInOneOutChain(config, createUTXOs(config, 1).back(), 500);
    benchATMP(config, state, chainedTxs);
}

/// Test a tree of 63 2-inputs-1-output transactions
static void MempoolAcceptance63TxTree(benchmark::State& state) {
    const Config &config = GetConfig();
    const std::vector<CTransactionRef> chainedTxs = twoInOneOutTree(config, 5);
    assert(chainedTxs.size() == 63);
    benchATMP(config, state, chainedTxs);
}

/// Test a tree of 511 2-inputs-1-output transactions
static void MempoolAcceptance511TxTree(benchmark::State& state) {
    const Config &config = GetConfig();
    const std::vector<CTransactionRef> chainedTxs = twoInOneOutTree(config, 8);
    assert(chainedTxs.size() == 511);
    benchATMP(config, state, chainedTxs);
}


/// Try to reorg a chain of depth 10 where each block has a 50 tx 1-input-1-output chain.
static void Reorg10BlocksWith50TxChain(benchmark::State& state) {
    const Config &config = GetConfig();
    benchReorg(config, state, 10, 50, true);
}

/// Try to reorg a chain of depth 10 where each block has a 500 tx 1-input-1-output chain.
static void Reorg10BlocksWith500TxChain(benchmark::State& state) {
    const Config &config = GetConfig();
    benchReorg(config, state, 10, 500, true);
}

/// Try to reorg a chain of depth 10 where each block has a 50 tx 1-input-1-output chain,
/// skipping the process of removing transactions from the mempool during re-connect.
static void Reorg10BlocksWith50TxChainSkipMempool(benchmark::State& state) {
    const Config &config = GetConfig();
    benchReorg(config, state, 10, 50, false);
}

/// Try to reorg a chain of depth 10 where each block has a 500 tx 1-input-1-output chain,
/// skipping the process of removing transactions from the mempool during re-connect.
static void Reorg10BlocksWith500TxChainSkipMempool(benchmark::State& state) {
    const Config &config = GetConfig();
    benchReorg(config, state, 10, 500, false);
}


/// Generate a block with 50 1-input-1-output transactions
static void GenerateBlock50ChainedTxs(benchmark::State& state) {
    const Config& config = GetConfig();
    const CTxIn utxo = createUTXOs(config, 1).back();
    benchGenerateNewBlock(config, state, { oneInOneOutChain(config, utxo, 50) });
}

/// Generate a block with 500 1-input-1-output transactions
static void GenerateBlock500ChainedTxs(benchmark::State& state) {
    const Config& config = GetConfig();
    const CTxIn utxo = createUTXOs(config, 1).back();
    benchGenerateNewBlock(config, state, { oneInOneOutChain(config, utxo, 500) });
}


/// Fill a mempool then evict 2000 x 50 1-input-1-output transactions, CTxMemPool version, in order of increasing fee
static void EvictChained50Tx(benchmark::State& state) {
    const Config& config = GetConfig();
    // create 2000 chains of 50 1-in-1-out each
    std::vector<std::vector<CTransactionRef>> chains;
    constexpr int NChains = 2000;
    const auto utxos = createUTXOs(config, NChains);
    for (int i = 0; i < NChains; ++i) {
        chains.push_back( oneInOneOutChain(config, utxos[i], 50) );
    }
    benchEviction(config, state, chains, false);
}

/// Fill a mempool then evict 2000 x 50 1-input-1-output transactions, CTxMemPool version, in order of decreasing fee
static void EvictChained50TxRev(benchmark::State& state) {
    const Config& config = GetConfig();
    // create 2000 chains of 50 1-in-1-out each
    std::vector<std::vector<CTransactionRef>> chains;
    constexpr int NChains = 2000;
    const auto utxos = createUTXOs(config, NChains);
    for (int i = 0; i < NChains; ++i) {
        chains.push_back( oneInOneOutChain(config, utxos[i], 50) );
    }
    benchEviction(config, state, chains, true);
}


BENCHMARK(MempoolAcceptance50ChainedTxs, 600);
BENCHMARK(MempoolAcceptance500ChainedTxs, 6);
BENCHMARK(MempoolAcceptance63TxTree, 800);
BENCHMARK(MempoolAcceptance511TxTree, 80);

BENCHMARK(Reorg10BlocksWith50TxChain, 10);
BENCHMARK(Reorg10BlocksWith500TxChain, 1);
BENCHMARK(Reorg10BlocksWith50TxChainSkipMempool, 25);
BENCHMARK(Reorg10BlocksWith500TxChainSkipMempool, 1);

BENCHMARK(GenerateBlock50ChainedTxs, 3000);
BENCHMARK(GenerateBlock500ChainedTxs, 300);

BENCHMARK(EvictChained50Tx, 2);
BENCHMARK(EvictChained50TxRev, 2);
