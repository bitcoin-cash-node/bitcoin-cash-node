// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2019-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <config.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/setup_common.h>
#include <txmempool.h>
#include <validation.h>
#include <consensus/tx_check.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup) {
    CScript scriptPubKey = CScript() << coinbaseKey.GetPubKey()
                                     << OP_CHECKSIG;
    CMutableTransaction coinbaseTx;

    coinbaseTx.nVersion = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    CValidationState state;

    LOCK(cs_main);

    unsigned int initialPoolSize = g_mempool.size();

    BOOST_CHECK_EQUAL(false,
                      AcceptToMemoryPool(GetConfig(), g_mempool, state,
                                         MakeTransactionRef(coinbaseTx),
                                         nullptr /* pfMissingInputs */,
                                         true /* bypass_limits */,
                                         Amount::zero() /* nAbsurdFee */));

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(g_mempool.size(), initialPoolSize);

    // Check that the validation state reflects the unsuccesful attempt.
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-tx-coinbase");

    int nDoS;
    BOOST_CHECK_EQUAL(state.IsInvalid(nDoS), true);
    BOOST_CHECK_EQUAL(nDoS, 100);
}

/**
 * Ensure that transactions with duplicate inputs are appropriately rejected regardless of the length of vin
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_dup_txin, TestChain100Setup) {
    CScript scriptPubKey = CScript() << coinbaseKey.GetPubKey() << OP_CHECKSIG;

    CMutableTransaction tx;
    for (size_t vinSize = 2; vinSize < 2000; vinSize < 20 ? vinSize++ : vinSize *= 2) {
      tx.nVersion = 1;
      tx.vin.resize(vinSize);
      tx.vout.resize(1);
      tx.vout[0].nValue = 400 * SATOSHI;
      tx.vout[0].scriptPubKey = scriptPubKey;
      for (size_t i=0; i<vinSize; i++) {
        tx.vin[i].prevout = COutPoint(TxId(InsecureRand256()), 0);
      }
      BOOST_CHECK(!CTransaction(tx).IsCoinBase());

      CValidationState state1;
      BOOST_CHECK(CheckRegularTransaction(CTransaction(tx), state1));

      size_t i = InsecureRandRange(vinSize);
      size_t j = InsecureRandRange(vinSize-1);
      if (j >= i) j++;
      tx.vin[j] = tx.vin[i];
      BOOST_CHECK(!CheckRegularTransaction(CTransaction(tx), state1));
      BOOST_CHECK_EQUAL(state1.GetRejectReason(), "bad-txns-inputs-duplicate");


      CValidationState state2;
      LOCK(cs_main);
      unsigned int initialPoolSize = g_mempool.size();

      BOOST_CHECK_EQUAL(false, AcceptToMemoryPool(GetConfig(), g_mempool, state2,
                                                  MakeTransactionRef(tx),
                                                  nullptr /* pfMissingInputs */,
                                                  true /* bypass_limits */,
                                                  Amount::zero() /* nAbsurdFee */));

      // Check that the transaction hasn't been added to mempool.
      BOOST_CHECK_EQUAL(g_mempool.size(), initialPoolSize);

      // Check that the validation state reflects the unsuccesful attempt.
      BOOST_CHECK(state2.IsInvalid());
      BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-txns-inputs-duplicate");

      int nDoS;
      BOOST_CHECK_EQUAL(state2.IsInvalid(nDoS), true);
      BOOST_CHECK_EQUAL(nDoS, 100);
    }
}

BOOST_AUTO_TEST_SUITE_END()
