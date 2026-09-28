// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <chainparams.h>
#include <config.h>
#include <interfaces/chain.h>
#include <wallet/wallet.h>

#include <functional>

static void TopUpKeyPoolShared(benchmark::State &state, std::function<void(CWallet&)> setup) {
    SelectParams(CBaseChainParams::REGTEST);

    auto chain = interfaces::MakeChain();
    CWallet wallet(GetConfig(), *chain, WalletLocation(), WalletDatabase::CreateDummy());

    setup(wallet);

    LOCK(wallet.cs_wallet);

    BENCHMARK_LOOP {
        wallet.TopUpKeyPool(wallet.GetKeyPoolSize() + 10);
    }
}

static void TopUpKeyPoolHD(benchmark::State &state) {
    TopUpKeyPoolShared(state, [](CWallet& wallet) {
        auto master_pub_key = wallet.GenerateNewSeed();
        wallet.SetHDSeed(master_pub_key);
    });
}

BENCHMARK(TopUpKeyPoolHD, 25);

static void TopUpKeyPool(benchmark::State &state) {
    TopUpKeyPoolShared(state, [](CWallet& wallet) { });
}

BENCHMARK(TopUpKeyPool, 50);
