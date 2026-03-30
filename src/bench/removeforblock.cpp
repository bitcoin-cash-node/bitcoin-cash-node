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
#include <util/defer.h>
#include <util/system.h>
#include <validation.h>

#include <cassert>
#include <list>
#include <utility>
#include <vector>

/// This file contains benchmarks focusing on removeForBlock in CTxMemPool

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

static void benchRemoveForBlock(const Config& config, benchmark::State& state,
                                const size_t nTx, const unsigned blockMB, const bool allowUnconfChains) {
    assert(nTx > 0 && blockMB > 0);

    // save initial state
    const auto origBlockMinTxFee = gArgs.GetArg("-blockmintxfee", "");
    gArgs.ForceSetArg("-blockmintxfee", "0");

    // undo above on scope end
    const Defer d([&origBlockMinTxFee] {
        gArgs.ForceSetArg("-blockmintxfee", origBlockMinTxFee);
        g_mempool.clear();
    });

    const auto utsIn = createUTXOs(config, 1);
    assert(utsIn.size() == 1);
    std::vector<CTxIn> utxos;
    using TxInAmtPair = std::pair<CTxIn, Amount>;
    using TxInAmtList = std::list<TxInAmtPair>;
    TxInAmtList ins;
    ins.emplace_back(utsIn.back(), 50 * COIN);

    auto SpendTxInToMempool = [&config](const CTxIn &txIn, const Amount val, const size_t fanoutSize,
                                        const bool unchecked = false) -> TxInAmtList {
        TxInAmtList ret;
        assert(fanoutSize > 0);
        CMutableTransaction tx;
        tx.vin.push_back(txIn);
        tx.vin.back().scriptSig = SCRIPT_SIG;
        while (tx.vout.size() < fanoutSize) {
            tx.vout.emplace_back(int64_t((val / SATOSHI) / fanoutSize) * SATOSHI, SCRIPT_PUB_KEY);
        }
        const CTransactionRef rtx = MakeTransactionRef(tx);
        const auto &txId = rtx->GetId();
        unsigned outN = 0;
        for (const auto &out : rtx->vout) {
            ret.emplace_back(CTxIn(txId, outN++), out.nValue);
        }
        LOCK(cs_main);
        if (unchecked) {
            LOCK(g_mempool.cs);
            g_mempool.addUnchecked(TestMemPoolEntryHelper{}.FromTx(rtx));
        } else {
            CValidationState vstate;
            bool missingInputs{};
            const bool ok = AcceptToMemoryPool(config, g_mempool, vstate, rtx, &missingInputs, true, Amount::zero());
            assert(ok && vstate.IsValid());
        }
        return ret;
    };

    while (ins.size() < nTx) {
        const auto [txIn, val] = ins.front();
        ins.pop_front();
        auto inList = SpendTxInToMempool(txIn, val, 100 /* fanoutSize */);
        // add the utxos we just generated to the input list at the end
        ins.splice(ins.end(), inList);
    }

    if (!allowUnconfChains) {
        // next, mine a block to commit the above chained tx's, then use the ins again as 1-to-1 tx's into the mempool
        LogPrint(BCLog::MEMPOOL, "(%s 1) mempool size: %i\n", __func__, g_mempool.size());
        MineBlock(config, SCRIPT_PUB_KEY);
        LogPrint(BCLog::MEMPOOL, "(%s 2) mempool size: %i\n", __func__,  g_mempool.size());
    }

    for (const auto & [txIn, val] : ins) {
        SpendTxInToMempool(txIn, val, 1 /* fanoutSize */, true /* unchecked */);
    }
    ins.clear(); // we don't need these inputs anymore

    assert(g_mempool.size() >= nTx);

    LogPrint(BCLog::MEMPOOL, "(%s 3) mempool size: %i\n",  __func__, g_mempool.size());

    BlockAssembler::Options opts;
    opts.blockMinFeeRate = CFeeRate{Amount::zero()};
    opts.nConsensusCurrentBlockSizeLimit = config.GetConfiguredMaxBlockSize();
    opts.nMaxGeneratedBlockSize = blockMB * ONE_MEGABYTE;
    const auto pblktemplate = BlockAssembler{config, ::g_mempool, opts}.CreateNewBlock(SCRIPT_PUB_KEY);
    const auto &block = pblktemplate->block;

    std::list<CTxMemPool> pools;

    // Note: in order to isolate how long removeForBlock takes, we are
    // forced to pre-create all the pools we will be needing up front,
    // copying the entries from g_mempool into them.
    for (uint64_t i = 0; i < state.m_num_iters + 1; ++i) {
        LOCK2(cs_main, g_mempool.cs);
        const auto &index = g_mempool.mapTx.get<entry_id>(); // iterate by entry id
        pools.emplace_back();
        auto &pool = pools.back();
        for (auto it = index.begin(); it != index.end(); ++it) {
            LOCK(pool.cs);
            pool.addUnchecked(*it);
        }
        assert(pool.size() == g_mempool.size());
    }

    auto it = pools.begin();

    BENCHMARK_LOOP {
        assert(it != pools.end());
        auto &pool = *it++;
        pool.removeForBlock(block.vtx);
    }
}

/// Fill a mempool with 450k txs, then repeatedly test removeForBlock with a 32MB block of ~170k small-sized txs
static void RemoveForBlock32MB(benchmark::State& state) {
    const Config& config = GetConfig();
    benchRemoveForBlock(config, state, 450'000, 32, false);
}

/// Fill a mempool with 450k txs, then repeatedly test removeForBlock with an 8MB block of ~43k small-sized txs
static void RemoveForBlock8MB(benchmark::State& state) {
    const Config& config = GetConfig();
    benchRemoveForBlock(config, state, 450'000, 8, false);
}

/// Fill a mempool with ~450k txs, then repeatedly test removeForBlock with a 32MB block of ~93k mixed-sized txs,
/// leaving some unconfirmed chains in mempool too so that the parentSet for some txs is larger
static void RemoveForBlock32MB_UnconfChains(benchmark::State& state) {
    const Config& config = GetConfig();
    benchRemoveForBlock(config, state, 450'000, 32, true);
}

/// Fill a mempool with 450k txs, then repeatedly test removeForBlock with an 8MB block of ~8k mixed-sized txs,
/// leaving some unconfirmed chains in mempool too so that the parentSet for some txs is larger
static void RemoveForBlock8MB_UnconfChains(benchmark::State& state) {
    const Config& config = GetConfig();
    benchRemoveForBlock(config, state, 450'000, 8, true);
}

BENCHMARK(RemoveForBlock32MB, 1);
BENCHMARK(RemoveForBlock8MB, 1);
BENCHMARK(RemoveForBlock32MB_UnconfChains, 1);
BENCHMARK(RemoveForBlock8MB_UnconfChains, 1);
