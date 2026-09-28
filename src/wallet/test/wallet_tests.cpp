// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <key.h>
#include <key_io.h>
#include <keystore.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <rpc/server.h>
#include <script/sign.h>
#include <util/defer.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcdump.h>
#include <wallet/wallet.h>

#include <test/setup_common.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

static void AddKey(CWallet &wallet, const CKey &key) {
    LOCK(wallet.cs_wallet);
    wallet.AddKeyPubKey(key, key.GetPubKey());
}

// Note: when backporting PR14957, see PR15321 and ensure both LockAnnotations
// are in place.
BOOST_FIXTURE_TEST_CASE(rescan, TestChain100Setup) {
    auto chain = interfaces::MakeChain();

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex *oldTip = ::ChainActive().Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex *newTip = ::ChainActive().Tip();

    LockAnnotation lock(::cs_main);
    auto locked_chain = chain->lock();

    // Verify ScanForWalletTransactions accommodates a null start block.
    {
        CWallet wallet(GetConfig(), *chain, WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            BlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.failed_block.IsNull());
        BOOST_CHECK(result.stop_block.IsNull());
        BOOST_CHECK(!result.stop_height);
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), Amount::zero());
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(GetConfig(), *chain, WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.stop_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.stop_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), 100 * COIN);
    }

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions only picks transactions in the new block
    // file.
    {
        CWallet wallet(GetConfig(), *chain, WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.failed_block, oldTip->GetBlockHash());
        BOOST_CHECK_EQUAL(result.stop_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.stop_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), 50 * COIN);
    }

    // Prune the remaining block file.
    PruneOneBlockFile(newTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({newTip->GetBlockPos().nFile});

    // Verify ScanForWalletTransactions scans no blocks.
    {
        CWallet wallet(GetConfig(), *chain, WalletLocation(),
                       WalletDatabase::CreateDummy());
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(&wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(
            oldTip->GetBlockHash(), BlockHash(), reserver, false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK_EQUAL(result.failed_block, newTip->GetBlockHash());
        BOOST_CHECK(result.stop_block.IsNull());
        BOOST_CHECK(!result.stop_height);
        BOOST_CHECK_EQUAL(wallet.GetImmatureBalance(), Amount::zero());
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup) {
    auto chain = interfaces::MakeChain();

    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex *oldTip = ::ChainActive().Tip();
    GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE;
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex *newTip = ::ChainActive().Tip();

    LockAnnotation lock(::cs_main);
    auto locked_chain = chain->lock();

    // Prune the older block file.
    PruneOneBlockFile(oldTip->GetBlockPos().nFile);
    UnlinkPrunedFiles({oldTip->GetBlockPos().nFile});

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(
            GetConfig(), *chain, WalletLocation(), WalletDatabase::CreateDummy());
        AddWallet(wallet);
        UniValue::Array keys;
        UniValue::Object key;
        key.emplace_back("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.emplace_back("timestamp", 0);
        key.emplace_back("internal", true);
        keys.emplace_back(std::move(key));
        BOOST_CHECK(key.empty());
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.emplace_back("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.emplace_back("timestamp", newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.emplace_back("internal", true);
        keys.emplace_back(std::move(key));
        JSONRPCRequest request;
        request.params.setArray();
        request.params.get_array().emplace_back(std::move(keys));

        UniValue response = importmulti(GetConfig(), request);
        BOOST_CHECK_EQUAL(
            UniValue::stringify(response),
            strprintf("[{\"success\":false,\"error\":{\"code\":-1,\"message\":"
                      "\"Rescan failed for key with creation timestamp %d. "
                      "There was an error reading a block from time %d, which "
                      "is after or within %d seconds of key creation, and "
                      "could contain transactions pertaining to the key. As a "
                      "result, transactions and coins using this key may not "
                      "appear in the wallet. This error could be caused by "
                      "pruning or data corruption (see bitcoind log for "
                      "details) and could be dealt with by downloading and "
                      "rescanning the relevant blocks (see -reindex and "
                      "-rescan options).\"}},{\"success\":true}]",
                      0, oldTip->GetBlockTimeMax(), TIMESTAMP_WINDOW));
        RemoveWallet(wallet);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup) {
    auto chain = interfaces::MakeChain();

    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = ::ChainActive().Tip()->GetBlockTimeMax() + 5;
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()))
            .vtx[0]);

    auto locked_chain = chain->lock();

    std::string backup_file =
        (SetDataDir("importwallet_rescan") / "wallet.backup").string();

    // Import key into wallet and call dumpwallet to create backup file.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(
            GetConfig(), *chain, WalletLocation(), WalletDatabase::CreateDummy());
        LOCK(wallet->cs_wallet);
        wallet->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime =
            KEY_TIME;
        wallet->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

        JSONRPCRequest request;
        request.params.setArray().emplace_back(backup_file);
        AddWallet(wallet);
        ::dumpwallet(GetConfig(), request);
        RemoveWallet(wallet);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(
            GetConfig(), *chain, WalletLocation(), WalletDatabase::CreateDummy());

        JSONRPCRequest request;
        request.params.setArray().emplace_back(backup_file);
        AddWallet(wallet);
        ::importwallet(GetConfig(), request);
        RemoveWallet(wallet);

        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 3U);
        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
            bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetId());
            bool expected = i >= 100;
            BOOST_CHECK_EQUAL(found, expected);
        }
    }

    SetMockTime(0);
}

// Verify that dumpwallet without a wallet loaded throws the correct RPC error.
BOOST_AUTO_TEST_CASE(no_wallet) {
    try {
        std::string backup_file = (SetDataDir("no_wallet") / "wallet.backup").string();
        JSONRPCRequest request;
        request.params.setArray().emplace_back(backup_file);
        ::dumpwallet(GetConfig(), request);
        BOOST_CHECK(false); // should never be reached because we expect the above to always throw
    } catch (const JSONRPCError &error) {
        BOOST_CHECK_EQUAL(error.code, RPC_METHOD_NOT_FOUND);
        BOOST_CHECK_EQUAL(error.message, "Method not found (wallet method is disabled because no wallet is loaded)");
    }
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup) {
    auto chain = interfaces::MakeChain();
    CWallet wallet(GetConfig(), *chain, WalletLocation(),
                   WalletDatabase::CreateDummy());
    CWalletTx wtx(&wallet, m_coinbase_txns.back());
    auto locked_chain = chain->lock();
    LOCK(wallet.cs_wallet);
    wtx.hashBlock = ::ChainActive().Tip()->GetBlockHash();
    wtx.nIndex = 0;

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), Amount::zero());

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    wallet.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
    BOOST_CHECK_EQUAL(wtx.GetImmatureCredit(*locked_chain), 50 * COIN);
}

static int64_t AddTx(CWallet &wallet, uint32_t lockTime, int64_t mockTime,
                     int64_t blockTime) {
    CMutableTransaction tx;
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex *block = nullptr;
    if (blockTime > 0) {
        LockAnnotation lock(::cs_main);
        auto locked_chain = wallet.chain().lock();
        auto inserted =
            mapBlockIndex.try_emplace(BlockHash(GetRandHash()));
        assert(inserted.second);
        const BlockHash &hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
    }

    CWalletTx wtx(&wallet, MakeTransactionRef(tx));
    if (block) {
        wtx.SetMerkleBranch(block->GetBlockHash(), 0);
    }
    {
        LOCK(cs_main);
        wallet.AddToWallet(wtx);
    }
    LOCK(wallet.cs_wallet);
    return wallet.mapWallet.at(wtx.GetId()).nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart) {
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(m_wallet, 5, 50, 600), 300);

    // Reset mock time for other tests.
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(LoadReceiveRequests) {
    CTxDestination dest = CKeyID();
    LOCK(m_wallet.cs_wallet);
    m_wallet.AddDestData(dest, "misc", "val_misc");
    m_wallet.AddDestData(dest, "rr0", "val_rr0");
    m_wallet.AddDestData(dest, "rr1", "val_rr1");

    auto values = m_wallet.GetDestValues("rr");
    BOOST_CHECK_EQUAL(values.size(), 2U);
    BOOST_CHECK_EQUAL(values[0], "val_rr0");
    BOOST_CHECK_EQUAL(values[1], "val_rr1");
}

class ListCoinsTestingSetup : public TestChain100Setup {
public:
    ListCoinsTestingSetup() {
        CreateAndProcessBlock({},
                              GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = std::make_unique<CWallet>(GetConfig(), *m_chain, WalletLocation(),
                                           WalletDatabase::CreateMock());
        bool firstRun;
        wallet->LoadWallet(firstRun);
        AddKey(*wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet.get());
        reserver.reserve();
        CWallet::ScanResult result = wallet->ScanForWalletTransactions(
            ::ChainActive().Genesis()->GetBlockHash(), BlockHash(), reserver,
            false /* update */);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK_EQUAL(result.stop_block,
                          ::ChainActive().Tip()->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.stop_height, ::ChainActive().Height());
        BOOST_CHECK(result.failed_block.IsNull());
    }

    ~ListCoinsTestingSetup() { wallet.reset(); }

    CWalletTx &AddTx(CRecipient recipient, CoinSelectionHint coinsel = CoinSelectionHint::Default,
                     int *changePosInOut = nullptr, const CCoinControl & coinControl = {}) {
        return AddTx(std::vector<CRecipient>{{recipient}}, coinsel, changePosInOut, coinControl);
    }

    CWalletTx &AddTx(const std::vector<CRecipient> &recipients,
                     CoinSelectionHint coinsel = CoinSelectionHint::Default,
                     int *changePosInOut = nullptr, const CCoinControl &coinControl = {}) {
        CTransactionRef tx;
        CReserveKey reservekey(wallet.get());
        Amount fee;
        int tmp_changePos = -1;
        int &changePos = changePosInOut ? *changePosInOut : tmp_changePos;
        std::string error;
        BOOST_CHECK_EQUAL(CreateTransactionResult::CT_OK,
                          wallet->CreateTransaction(
                              *m_locked_chain, recipients, tx, reservekey, fee,
                              changePos, error, coinControl, true, coinsel));

        // The anti-fee-sniping feature should set the lock time equal to the block height.
        BOOST_CHECK_EQUAL(::ChainActive().Height(), tx->nLockTime);

        CValidationState state;
        BOOST_CHECK(
            wallet->CommitTransaction(tx, {}, {}, reservekey, nullptr, state));
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx =
                CMutableTransaction(*wallet->mapWallet.at(tx->GetId()).tx);
        }
        const auto block = CreateAndProcessBlock({CMutableTransaction(blocktx)},
                                                 GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        {
            LOCK(cs_main);
            BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());
        }
        LOCK(wallet->cs_wallet);
        auto it = wallet->mapWallet.find(tx->GetId());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.SetMerkleBranch(::ChainActive().Tip()->GetBlockHash(), 1);

        return it->second;
    }

    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    // Temporary. Removed in upcoming lock cleanup
    std::unique_ptr<interfaces::Chain::Lock> m_locked_chain =
        m_chain->assumeLocked();
    std::unique_ptr<CWallet> wallet;
};

BOOST_FIXTURE_TEST_CASE(ListCoins, ListCoinsTestingSetup) {
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<CKeyID>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 1U);

    // Check initial balance from one mature coinbase transaction.
    BOOST_CHECK_EQUAL(50 * COIN, wallet->GetAvailableBalance());

    // Check that wallet->GetBalance returns the same thing
    BOOST_CHECK_EQUAL(50 * COIN, wallet->GetBalance());

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{GetScriptForRawPubKey({}), 1 * COIN, {},
                     false /* subtract fee */});
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<CKeyID>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*m_locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 2U);
    }
    for (const auto &group : list) {
        for (const auto &coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(COutPoint(coin.tx->GetId(), coin.i));
        }
    }
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<COutput> available;
        wallet->AvailableCoins(*m_locked_chain, available);
        BOOST_CHECK_EQUAL(available.size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        list = wallet->ListCoins(*m_locked_chain);
    }
    BOOST_CHECK_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<CKeyID>(list.begin()->first).ToString(),
                      coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(FastTransaction, ListCoinsTestingSetup) {
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    for (uint8_t i=0; i<2; i++) {
        CoinSelectionHint coinsel(static_cast<CoinSelectionHint>(i));

        BOOST_CHECK(wallet->GetBalance() == 50 * COIN);

        // Each AddTx call will spend some coins then mine a block, adding another 50 coins
        AddTx(CRecipient{GetScriptForRawPubKey({}),   1 * COIN, {}, true /* subtract fee */}, coinsel);
        BOOST_CHECK(wallet->GetBalance() == 99 * COIN);
        AddTx(CRecipient{GetScriptForRawPubKey({}),   1 * COIN, {}, true /* subtract fee */}, coinsel);
        BOOST_CHECK(wallet->GetBalance() == 148 * COIN);
        AddTx(CRecipient{GetScriptForRawPubKey({}),  51 * COIN, {}, true /* subtract fee */}, coinsel);
        BOOST_CHECK(wallet->GetBalance() == 147 * COIN);
        AddTx(CRecipient{GetScriptForRawPubKey({}), 147 * COIN, {}, true /* subtract fee */}, coinsel);

        BOOST_CHECK(wallet->GetBalance() == 50 * COIN);
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_error_on_invalid_coinselection_hint, ListCoinsTestingSetup) {
    CTransactionRef tx;
    CReserveKey reservekey(wallet.get());
    Amount fee;
    int changePos = -1;
    std::string error;
    CCoinControl dummy;
    CRecipient recipient{GetScriptForRawPubKey({}), 1 * COIN, {}, true};

    BOOST_CHECK_EQUAL(CreateTransactionResult::CT_INVALID_PARAMETER,
            wallet->CreateTransaction(
                *m_locked_chain, {recipient}, tx, reservekey, fee,
                changePos, error, dummy, true,
                CoinSelectionHint::Invalid));
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup) {
    auto chain = interfaces::MakeChain();
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(
        GetConfig(), *chain, WalletLocation(), WalletDatabase::CreateDummy());
    wallet->SetMinVersion(FEATURE_LATEST);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    BOOST_CHECK(!wallet->TopUpKeyPool(1000));
    CPubKey pubkey;
    BOOST_CHECK(!wallet->GetKeyFromPool(pubkey, false));
}

// Explicit calculation which is used to test the wallet constant
static size_t CalculateP2PKHInputSize(bool use_max_sig, bool use_schnorr) {
    // Generate ephemeral valid pubkey
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    CKeyID key_hash = pubkey.GetID();

    // Create script to enter into keystore. Key hash can't be 0...
    CScript script = GetScriptForDestination(key_hash);

    // Add script to key store and key to watchonly
    CBasicKeyStore keystore;
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;
    const auto &creator = use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR
                                      : (use_schnorr ? DUMMY_SCHNORR_SIGNATURE_CREATOR
                                                     : DUMMY_SIGNATURE_CREATOR);
    if (!ProduceSignature(keystore, creator, script, sig_data, 0 /* scriptFlags: unused by dummy class, 0 ok here */)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return static_cast<size_t>(GetVirtualTransactionInputSize(tx_in, 1, nBytesPerSigCheck));
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup) {
    BOOST_CHECK_EQUAL(CalculateP2PKHInputSize(false, false), DUMMY_P2PKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateP2PKHInputSize(true, false), DUMMY_P2PKH_INPUT_SIZE_MAX);
    BOOST_CHECK_EQUAL(CalculateP2PKHInputSize(true, true), DUMMY_P2PKH_INPUT_SIZE_MAX);
    BOOST_CHECK_EQUAL(CalculateP2PKHInputSize(false, true), DUMMY_P2PKH_INPUT_SIZE_SCHNORR);
}

// Sign a P2PKH input for real and measure it, so the dummy constants are
// anchored to an actual signature rather than only to the dummy creators.
static size_t RealP2PKHInputSize(bool sign_schnorr) {
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const CScript script = GetScriptForDestination(pubkey.GetID());

    CBasicKeyStore keystore;
    keystore.AddKeyPubKey(key, pubkey);

    // A transaction spending one P2PKH output of our own.
    const CTxOut prev_out(1 * COIN, script);
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vout[0].nValue = prev_out.nValue - 1000 * SATOSHI;
    tx.vout[0].scriptPubKey = script;

    BOOST_REQUIRE(SignSignature(keystore, script, tx, 0, prev_out, SigHashType().withFork(),
                                STANDARD_SCRIPT_VERIFY_FLAGS, {}, sign_schnorr));
    return static_cast<size_t>(GetVirtualTransactionInputSize(tx.vin[0], 1, nBytesPerSigCheck));
}

BOOST_FIXTURE_TEST_CASE(real_input_size_test, TestChain100Setup) {
    // The constants must bound what we really produce, not just what the dummy
    // creators produce; otherwise a matching error in both goes unnoticed.
    BOOST_CHECK_EQUAL(RealP2PKHInputSize(/* sign_schnorr= */ true), DUMMY_P2PKH_INPUT_SIZE_SCHNORR);
    size_t max_ecdsa = 0;
    for (size_t i = 0; i < 64u; ++i) {
        const size_t sz = RealP2PKHInputSize(/* sign_schnorr= */ false);
        // Note that: 1 in 64 times ECDSA signatures will be 70 bytes and not 71, thus sz will be 146 and not 147
        BOOST_CHECK_LE(sz, DUMMY_P2PKH_INPUT_SIZE);
        max_ecdsa = std::max(max_ecdsa, sz);
    }
    // After 64 iterations above the probability is essentially 1.0 that we have seen max_ecdsa == 147,
    // or more precisely: P(all 64 samples short) is about 2^-384
    BOOST_CHECK_EQUAL(max_ecdsa, DUMMY_P2PKH_INPUT_SIZE);
}

// CalculateP2PKHInputSize above re-implements DummySignInput's creator choice,
// so it cannot notice that choice regressing. Drive the wallet's own path.
BOOST_FIXTURE_TEST_CASE(dummy_input_size_honors_use_max_sig_test, TestChain100Setup) {
    const Defer d = [wasSchnorr = GetConfig().IsSignSchnorr()] {
        // Restore whatever the global setting was prior to this test
        GetMutableConfig().SetSignSchnorr(wasSchnorr);
    };
    auto chain = interfaces::MakeChain();
    auto wallet = std::make_shared<CWallet>(GetConfig(), *chain, WalletLocation(),
                                            WalletDatabase::CreateDummy());
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddKeyPubKey(key, pubkey));
    }
    const CTxOut txout(1 * COIN, GetScriptForDestination(pubkey.GetID()));

    const bool origSignSchnorr = GetConfig().IsSignSchnorr();
    Defer restore([&origSignSchnorr] { GetMutableConfig().SetSignSchnorr(origSignSchnorr); });

    // use_max_sig means an external party signs this input, so the estimate must
    // assume the largest signature they can produce, whatever we would sign with.
    GetMutableConfig().SetSignSchnorr(true);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(txout, wallet.get(), /* use_max_sig= */ true),
                      int(DUMMY_P2PKH_INPUT_SIZE_MAX));
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(txout, wallet.get(), /* use_max_sig= */ false),
                      int(DUMMY_P2PKH_INPUT_SIZE_SCHNORR));

    GetMutableConfig().SetSignSchnorr(false);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(txout, wallet.get(), /* use_max_sig= */ true),
                      int(DUMMY_P2PKH_INPUT_SIZE_MAX));
    // If use_max_sig is false in non-Schnorr context, we assume a grinded-down input size (147) bytes,
    // as we ourselves would sign in ECDSA mode.
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(txout, wallet.get(), /* use_max_sig= */ false),
                      int(DUMMY_P2PKH_INPUT_SIZE));
}

struct Upgrade9NotActivatedTestingSetup : ListCoinsTestingSetup {
    std::optional<int32_t> origUpgrade9Override;

    Upgrade9NotActivatedTestingSetup() : ListCoinsTestingSetup() {
        origUpgrade9Override = g_Upgrade9HeightOverride;
        g_Upgrade9HeightOverride = std::numeric_limits<int32_t>::max();
        LOCK(cs_main);
        // Ensure upgrade 9 (tokens) is not active for next block and mempool
        BOOST_CHECK(!IsUpgrade9Enabled(::GetConfig().GetChainParams().GetConsensus(), ::ChainActive().Tip()));
    }
    ~Upgrade9NotActivatedTestingSetup() {
        g_Upgrade9HeightOverride = origUpgrade9Override;
    }
};

BOOST_FIXTURE_TEST_CASE(wallet_bip69, Upgrade9NotActivatedTestingSetup) {
    // Note: The entire point of this test is to *just* test tx sorting with/without bip69 enabled when token data is
    // present/absent, and as such we didn't bother creating consensus-respecting CashToken txns for this test (which
    // is why this test requires upgrade9 be disabled).
    Defer d([]{
        // undo forceSetArg
        gArgs.ClearArg("-usebip69");
    });
    constexpr size_t N_KEYS = 4;
    std::array<CKey, N_KEYS> privKeys;
    std::array<CPubKey, N_KEYS> pubKeys;
    std::array<CScript, N_KEYS> scriptPubKeys;

    // generate random keys
    for (size_t i = 0; i < N_KEYS; ++i) {
        auto &pub = pubKeys[i];
        auto &priv = privKeys[i];
        auto &spk = scriptPubKeys[i];
        priv.MakeNewKey(false);
        pub = priv.GetPubKey();
        spk = GetScriptForDestination(pub.GetID()); // P2PKH
        BOOST_CHECK(pub.IsFullyValid());
        CTxDestination dest;
        BOOST_CHECK(ExtractDestination(spk, dest, 0 /* no p2sh_32 */));
        BOOST_CHECK(dest == CTxDestination(pub.GetID()));
    }

    // Ensure we have a bunch of small coins
    {
        const auto myScriptPubKey = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
        std::vector<CRecipient> toMe(100, CRecipient{myScriptPubKey, 1000 * CASH, {}, false});
        for (int i = 0; i < 3; ++i) {
            for (auto &r: toMe) r.nAmount += 10 * SATOSHI; // make subsequent iterations have slightly larger coins
            AddTx(toMe);
        }
    }

    BOOST_CHECK(wallet->GetBalance() > 50 * COIN);
    {
        // count the number of coins we have
        LOCK2(cs_main, wallet->cs_wallet);
        size_t nCoins = 0;
        for (const auto &[dest, vouts] : wallet->ListCoins(*m_locked_chain)) {
            nCoins += vouts.size();
        }
        // we should have a bunch of coins to really exercise this test
        BOOST_CHECK(nCoins >= 100);
    }

    token::OutputData tok1(token::Id{uint256S("00112233445577001122334455770011223344557700112233445577")},
                           token::SafeAmount::fromIntUnchecked(1234),
                           token::NFTCommitment{5u, uint8_t{3}}, true, true, true),
                      tok2(token::Id{uint256S("00112233445577001122334455770011223344557700112233445578")},
                           token::SafeAmount::fromIntUnchecked(1235),
                           token::NFTCommitment{5u, uint8_t{3}}, true, false, false);


    std::vector<CRecipient> recipients{{
        {scriptPubKeys[1], 3040 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[2], 3040 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[3], 8001 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[2], 1234 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[1], 1234 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[3], 1234 * CASH, {}, false /* subtract fee */},
        {scriptPubKeys[3], 1234 * CASH, token::OutputDataPtr{tok1}, false /* subtract fee */},
        {scriptPubKeys[3], 1234 * CASH, token::OutputDataPtr{tok2}, false /* subtract fee */},
        {scriptPubKeys[0], 234 * CASH, {}, false /* subtract fee */},
        // These funny scriptPubKeys here are to ensure we catch bad sorts that use the incorrect prevector::operator<
        // instead of the correct lexicographical ordering.
        {CScript() << opcodetype(FIRST_UNDEFINED_OP_VALUE-1),
                        234 * CASH, {}, false /* subtract fee */},
        {CScript() << opcodetype(FIRST_UNDEFINED_OP_VALUE-2) << opcodetype(FIRST_UNDEFINED_OP_VALUE-2),
                        234 * CASH, {}, false /* subtract fee */},
    }};

    const auto IsTxSorted = [](const CTransactionRef &tx) {
        // check outputs are sorted ascending according to: nValue, scriptPubKey, tokenDataPtr
        for (size_t i = 1; i < tx->vout.size(); ++i) {
            auto &a = tx->vout[i-1], &b = tx->vout[i];
            if (a.nValue > b.nValue) {
                return false;
            } else if (a.nValue == b.nValue) {
                if (a.scriptPubKey == b.scriptPubKey) {
                    if (!((a.tokenDataPtr < b.tokenDataPtr) || a.tokenDataPtr == b.tokenDataPtr)) {
                        return false;
                    }
                } else if (!std::lexicographical_compare(a.scriptPubKey.begin(), a.scriptPubKey.end(),
                                                         b.scriptPubKey.begin(), b.scriptPubKey.end())) {
                    return false;
                }
            }
            BOOST_TEST_MESSAGE(strprintf("%s < %s", a.ToString(), b.ToString()));
        }
        // check inputs are sorted ascending accorting to COutpoint::operator<
        for (size_t i = 1; i < tx->vin.size(); ++i) {
            auto &a = tx->vin[i-1].prevout, &b = tx->vin[i].prevout;
            if (!(a < b || a == b)) {
                return false;
            }
        }

        return true;
    };

    const auto AllRecipientsPresent = [](const std::vector<CRecipient> &rs, const CTransactionRef &tx) {
        struct RecipientSort {
            bool operator()(const CRecipient &a, const CRecipient &b) const noexcept {
                if (a.nAmount == b.nAmount) {
                    if (a.scriptPubKey == b.scriptPubKey) {
                        return a.tokenDataPtr < b.tokenDataPtr;
                    }
                    return a.scriptPubKey < b.scriptPubKey;
                }
                return a.nAmount < b.nAmount;
            }
        };
        std::set<CRecipient, RecipientSort> needed{rs.begin(), rs.end()}, seen;
        const size_t nNeeded = needed.size();
        BOOST_CHECK_EQUAL(nNeeded, rs.size());

        for (const auto &out : tx->vout) {
            const CRecipient r{out.scriptPubKey, out.nValue, out.tokenDataPtr, false};
            if (needed.count(r) && !seen.count(r)) {
                needed.erase(r);
                seen.insert(r);
            }
        }

        return needed.empty() && seen.size() == nNeeded;
    };

    const auto HasChangeAndOnlyChangeIsMine = [this](int changePos, const CTransactionRef &tx) {
          if (changePos < 0 || size_t(changePos) >= tx->vout.size())
              return false;
          for (size_t i = 0; i < tx->vout.size(); ++i) {
              const auto ismine = wallet->IsMine(tx->vout[i]);
              if (i == size_t(changePos)) {
                  // change pos
                  if ((ismine & ISMINE_SPENDABLE) != ISMINE_SPENDABLE) {
                    return false;
                  }
              } else {
                  // other
                  if (ismine != ISMINE_NO) {
                      return false;
                  }
              }
          }
          return true;
    };

    {
        // 1. Create tx with BIP69 enabled.
        //    Postconditions to be met: tx is sorted and change pos is correct.
        gArgs.ForceSetArg("-usebip69", "1");
        CTransactionRef tx;
        int changePos = -1;

        tx = AddTx(recipients, CoinSelectionHint::Default, &changePos).tx;

        BOOST_CHECK(tx->vin.size() > 1); // ensure we had a bunch of inputs in the txn
        BOOST_CHECK(IsTxSorted(tx));
        BOOST_CHECK(changePos != -1); // there should definitely be change
        BOOST_CHECK(AllRecipientsPresent(recipients, tx)); // all recipients should have gotten the exact amounts
        BOOST_CHECK(HasChangeAndOnlyChangeIsMine(changePos, tx));
    }

    {
        // 2. Create tx with BIP69 enabled, but with a hard-coded change pos.
        //    Postconditions: tx is NOT sorted and change pos is what we requested
        //                    (BIP69 is not applied when caller requests a specific change pos).
        gArgs.ForceSetArg("-usebip69", "1");
        CTransactionRef tx;
        int changePos = 2; // request change position 2

        tx = AddTx(recipients, CoinSelectionHint::Default, &changePos).tx;

        BOOST_CHECK(tx->vin.size() > 1); // ensure we had a bunch of inputs in the txn
        BOOST_CHECK( ! IsTxSorted(tx));
        BOOST_CHECK(changePos == 2); // there should definitely be change, where we said it should be.
        BOOST_CHECK(AllRecipientsPresent(recipients, tx)); // all recipients should have gotten the exact amounts
        BOOST_CHECK(HasChangeAndOnlyChangeIsMine(changePos, tx));
    }

    {
        // 3. Create tx with BIP69 disabled.
        //    Postconditions: tx is NOT sorted.
        gArgs.ForceSetArg("-usebip69", "0");
        CTransactionRef tx;
        int changePos = -1; // no specific change position requested

        tx = AddTx(recipients, CoinSelectionHint::Default, &changePos).tx;

        BOOST_CHECK(tx->vin.size() > 1); // ensure we had a bunch of inputs in the txn
        BOOST_CHECK( ! IsTxSorted(tx));
        BOOST_CHECK(changePos != -1); // there should definitely be change
        BOOST_CHECK(AllRecipientsPresent(recipients, tx)); // all recipients should have gotten the exact amounts
        BOOST_CHECK(HasChangeAndOnlyChangeIsMine(changePos, tx));
    }

    {
        // 4. Create a tx with BIP69 enabled but don't sign it.
        //    Postcondition: BIP69 should NOT be enabled when not signing.
        gArgs.ForceSetArg("-usebip69", "1");
        CTransactionRef tx;
        CReserveKey reservekey(wallet.get());
        Amount fee;
        int changePos = -1;
        std::string error;
        CCoinControl dummy;
        const auto res = wallet->CreateTransaction(*m_locked_chain, recipients, tx, reservekey, fee,
                                                   changePos, error, dummy, false /* don't sign */);
        BOOST_CHECK_EQUAL(res, CreateTransactionResult::CT_OK);
        BOOST_CHECK(tx->vin.size() > 1); // ensure we had a bunch of inputs in the txn
        BOOST_CHECK( ! IsTxSorted(tx));
        BOOST_CHECK(changePos != -1); // there should definitely be change
        BOOST_CHECK(AllRecipientsPresent(recipients, tx)); // all recipients should have gotten the exact amounts
        BOOST_CHECK(HasChangeAndOnlyChangeIsMine(changePos, tx));
    }
}

struct Upgrade9ActivatedTestingSetup : ListCoinsTestingSetup {
    std::optional<int32_t> origUpgrade9Override;
    Upgrade9ActivatedTestingSetup() : ListCoinsTestingSetup() {
        origUpgrade9Override = g_Upgrade9HeightOverride;
        g_Upgrade9HeightOverride = 0;
        LOCK(cs_main);
        // Ensure upgrade 9 (tokens) is active for next block and mempool
        BOOST_CHECK(IsUpgrade9Enabled(::GetConfig().GetChainParams().GetConsensus(), ::ChainActive().Tip()));
    }
    ~Upgrade9ActivatedTestingSetup() {
        g_Upgrade9HeightOverride = origUpgrade9Override;
    }
};

/// Test basic support in wallet for processing tokens (requires upgrade9 to work correctly)
BOOST_FIXTURE_TEST_CASE(wallet_tokens, Upgrade9ActivatedTestingSetup) {
    CCoinControl allIncludingTokens;
    allIncludingTokens.m_allow_tokens = true;

    auto GetTokenGenesisCoins = [&]{
        std::vector<COutput> tokenGenesisCandidateCoins;
        LOCK2(cs_main, wallet->cs_wallet);
        const uint32_t scriptFlags = ::GetMemPoolScriptFlags(::GetConfig().GetChainParams().GetConsensus(),
                                                             ::ChainActive().Tip());
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(*m_locked_chain, vCoins, true, &allIncludingTokens);
        for (const auto &out : vCoins) {
            if (out.i == 0) {
                const auto txout = out.GetInputCoin().txout;
                CTxDestination dest;
                ExtractDestination(txout.scriptPubKey, dest, scriptFlags);
                BOOST_TEST_MESSAGE(strprintf("Found potential genesis coin in wallet: %s paying to: %s, CTxOut: %s",
                                             out.GetInputCoin().outpoint.ToString(),
                                             EncodeDestination(dest, ::GetConfig()),
                                             txout.ToString()));
                tokenGenesisCandidateCoins.push_back(out);
            }
        }
        return tokenGenesisCandidateCoins;
    };

    auto GetTokenCoins = [&]{
        std::vector<COutput> ret;
        CCoinControl tokensOnly;
        tokensOnly.m_allow_tokens = true;
        tokensOnly.m_tokens_only = true;
        LOCK2(cs_main, wallet->cs_wallet);
        const uint32_t scriptFlags = ::GetMemPoolScriptFlags(::GetConfig().GetChainParams().GetConsensus(),
                                                             ::ChainActive().Tip());
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(*m_locked_chain, vCoins, true, &tokensOnly);
        for (const auto &out : vCoins) {
            const auto txout = out.GetInputCoin().txout;
            if (txout.tokenDataPtr) {
                CTxDestination dest;
                ExtractDestination(txout.scriptPubKey, dest, scriptFlags);
                BOOST_TEST_MESSAGE(strprintf("Found token-containing coin in wallet: %s paying to: %s, CTxOut: %s",
                                             out.GetInputCoin().outpoint.ToString(),
                                             EncodeDestination(dest, ::GetConfig()),
                                             txout.ToString()));
                ret.push_back(out);
            }
        }
        return ret;
    };

    auto GenesisTokenToWallet = [&]{
        auto tokenGenesisCandidateCoins = GetTokenGenesisCoins();
        BOOST_CHECK( ! tokenGenesisCandidateCoins.empty());

        CCoinControl ctl;
        ctl.fAllowOtherInputs = false;
        const auto inputCoin = tokenGenesisCandidateCoins.front().GetInputCoin();
        ctl.Select(inputCoin.outpoint);
        const token::Id tokenId{inputCoin.outpoint.GetTxId()};
        token::OutputDataPtr tokenData{tokenId, token::SafeAmount::fromIntUnchecked(12345),
                                       token::NFTCommitment(5u, uint8_t(0x1c)), true /* hasNFT */};
        const auto spk = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
        const CRecipient toMe{spk, 100 * CASH, tokenData, false};

        AddTx(toMe, CoinSelectionHint::Default, nullptr, ctl);
        return tokenId;
    };

    auto SendTokenToSelf = [&](const COutput &output) {
          CCoinControl ctl;
          ctl.fAllowOtherInputs = false;
          ctl.m_allow_tokens = true;
          ctl.m_tokens_only = true;
          ctl.Select(output.GetInputCoin().outpoint);

          const auto txout = output.GetInputCoin().txout;
          const CRecipient toMe{txout.scriptPubKey, txout.nValue, txout.tokenDataPtr, true /* subtract fee */};

          AddTx(toMe, CoinSelectionHint::Default, nullptr, ctl);
    };

    BOOST_CHECK_MESSAGE(GetTokenCoins().empty(), "Wallet should start out with no tokens");

    // Create a new token, consuming a coin that has output index 0 to do so.
    const auto tokenId = GenesisTokenToWallet();

    // Now query that we have 1 token in the wallet after genesis above
    auto tokenCoins = GetTokenCoins();
    BOOST_CHECK_MESSAGE(GetTokenCoins().size() == 1, "Wallet should now have 1 token coin in it");
    CTxOut txout = tokenCoins.front().GetInputCoin().txout;
    const COutPoint token1OutPt = tokenCoins.front().GetInputCoin().outpoint;
    BOOST_CHECK_MESSAGE(txout.tokenDataPtr && txout.tokenDataPtr->GetId() == tokenId,
                        "The single token should be the one we expect");

    // Now send the token to self again
    SendTokenToSelf(tokenCoins.front());
    tokenCoins = GetTokenCoins();
    BOOST_CHECK_MESSAGE(GetTokenCoins().size() == 1, "Wallet should still have 1 token coin in it");
    const COutPoint token2OutPt = tokenCoins.front().GetInputCoin().outpoint;
    BOOST_CHECK_MESSAGE(token1OutPt != token2OutPt, "The wallet's token was moved to the new output");

    // Check that the default "AvailableCoins" should always omit tokens
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(*m_locked_chain, vCoins);
        BOOST_CHECK_MESSAGE( ! vCoins.empty(), "Available coins should not be empty for below test to work");
        BOOST_CHECK_MESSAGE(std::none_of(vCoins.begin(), vCoins.end(),
                                         [](const auto &coin) { return bool(coin.GetInputCoin().txout.tokenDataPtr); }),
                            "Default coin selection should always skip coins with tokens on them");
    }

    // Check that sending all of the balance to an external address doesn't burn tokens
    const auto balanceBefore = wallet->GetAvailableBalance();
    BOOST_TEST_MESSAGE(strprintf("Wallet available balance: %s", balanceBefore.ToString()));
    CScript extScriptPubKey;
    {
        CKey extPrivKey;
        CPubKey extPubKey;
        extPrivKey.MakeNewKey(false);
        extPubKey = extPrivKey.GetPubKey();
        BOOST_CHECK(extPubKey.IsFullyValid());
        extScriptPubKey = GetScriptForDestination(extPubKey.GetID()); // P2PKH
    }

    const CRecipient toExt{extScriptPubKey, balanceBefore, {}, true /* subtract fees from amount */};
    AddTx(toExt); // send all non-token coins to external address

    const auto balanceAfter = wallet->GetAvailableBalance();
    BOOST_CHECK_MESSAGE(balanceBefore != balanceAfter && balanceAfter == 50 * COIN,
                        "Our ending balance should be just 50 BCH (newly matured coinbase from mining).");
    BOOST_CHECK_MESSAGE(GetTokenCoins().size() == 1, "Ensure that after sending all, we still have the token coin");
    const auto balancePlusTokens = wallet->GetAvailableBalance(&allIncludingTokens);
    BOOST_CHECK_MESSAGE(balancePlusTokens == balanceAfter + tokenCoins.front().GetInputCoin().txout.nValue,
                        "Extra balance check (listing all coins + token coins) should be what we expect");
}

BOOST_AUTO_TEST_SUITE_END()
