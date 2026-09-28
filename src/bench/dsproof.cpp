// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <coins.h>
#include <dsproof/dsproof.h>
#include <key.h>
#include <primitives/transaction.h>
#include <random.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/sighashtype.h>
#include <script/sign.h>
#include <script/standard.h>

#include <limits>
#include <optional>
#include <vector>

static void DoubleSpendProofCreate(benchmark::State &state) {
    CKey privKey, privKey2, privKey3;
    privKey.MakeNewKey(true);
    privKey2.MakeNewKey(true);
    privKey3.MakeNewKey(true);

    CMutableTransaction tx1, tx2;

    // make 2 huge tx's spending different fake inputs
    const uint64_t n_inputs = 3000;
    for (uint64_t i = 0; i < (n_inputs - 1); ++i) {
        tx1.vin.emplace_back(COutPoint{TxId(GetRandHash()), uint32_t(GetRand(n_inputs))});
        tx2.vin.emplace_back(COutPoint{TxId(GetRandHash()), uint32_t(GetRand(n_inputs))});
    }

    // make sure they spend a common input at the very end
    const COutPoint dupe{TxId(GetRandHash()), uint32_t(GetRand(n_inputs))};
    tx1.vin.emplace_back(dupe);
    tx2.vin.emplace_back(tx1.vin.back());

    tx1.vout.emplace_back(3 * COIN, GetScriptForDestination(privKey2.GetPubKey().GetID()));
    tx2.vout.emplace_back(2 * COIN, GetScriptForDestination(privKey3.GetPubKey().GetID()));

    std::optional<CTxOut> commonTxOut;

    // Sign transactions properly
    const SigHashType sigHashType = SigHashType().withFork();
    constexpr bool signSchnorr = true; /* we always just sign schnorr for this bench */
    FlatSigningProvider keyStore;
    keyStore.pubkeys.emplace(privKey.GetPubKey().GetID(), privKey.GetPubKey());
    keyStore.keys.emplace(privKey.GetPubKey().GetID(), privKey);
    for (auto *ptx : {&tx1, &tx2}) {
        auto &tx = *ptx;
        size_t i = 0;
        for (auto & txin : tx.vin) {
            const Coin coin(CTxOut{1 * COIN, GetScriptForDestination(privKey.GetPubKey().GetID())}, 123, false);

            // no "real" script execution context is necessary for dsproofs (P2PKH only)
            const ScriptExecutionContext limited_context{unsigned(i), coin.GetTxOut(), tx};

            SignatureData sigdata = DataFromTransaction(limited_context, STANDARD_SCRIPT_VERIFY_FLAGS);

            ProduceSignature(keyStore,
                             TransactionSignatureCreator(limited_context, sigHashType, signSchnorr),
                             coin.GetTxOut().scriptPubKey, sigdata, STANDARD_SCRIPT_VERIFY_FLAGS);
            UpdateInput(txin, sigdata);
            ++i;
            if (i == tx.vin.size() && !commonTxOut)
                commonTxOut = coin.GetTxOut();
        }
    }
    assert(bool(commonTxOut));

    const CTransaction ctx1{tx1}, ctx2{tx2};

    BENCHMARK_LOOP {
        auto proof = DoubleSpendProof::create(0, ctx1, ctx2, dupe, &*commonTxOut);
        assert(!proof.isEmpty());
    }
}

BENCHMARK(DoubleSpendProofCreate, 490);
