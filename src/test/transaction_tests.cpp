// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h> // For CChainParams
#include <checkqueue.h>
#include <clientversion.h>
#include <coins.h>
#include <config.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_execution_context.h>
#include <script/sign.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

#include <test/data/tx_invalid.json.h>
#include <test/data/tx_valid.json.h>
#include <test/jsonutil.h>
#include <test/scriptflags.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <map>
#include <string>

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

static COutPoint buildOutPoint(const UniValue::Array &vinput) {
    TxId txid;
    txid.SetHex(vinput.at(0).get_str());
    return COutPoint(txid, vinput.at(1).get_int());
}

BOOST_AUTO_TEST_CASE(tx_valid) {
    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue::Array tests = read_json(
        std::string(json_tests::tx_valid,
                    json_tests::tx_valid + sizeof(json_tests::tx_valid)));

    ScriptError err;
    for (const UniValue& test : tests) {
        std::string strTest = UniValue::stringify(test);
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            CCoinsView dummy;
            CCoinsViewCache coins(&dummy);
            const UniValue::Array& inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue::Array& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint = buildOutPoint(vinput);
                const auto& scriptPubKey = mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                Amount amount = Amount::zero();
                if (vinput.size() >= 4) {
                    amount = mapprevOutValues[outpoint] = vinput[3].get_int64() * SATOSHI;
                }
                coins.AddCoin(outpoint, Coin(CTxOut(amount, scriptPubKey), 1, false), false);
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK,
                               PROTOCOL_VERSION);
            CTransaction tx(deserialize, stream);

            CValidationState state;
            BOOST_CHECK_MESSAGE(tx.IsCoinBase()
                                    ? CheckCoinbase(tx, state)
                                    : CheckRegularTransaction(tx, state),
                                strTest);
            BOOST_CHECK(state.IsValid());

            // Check that CheckCoinbase reject non-coinbase transactions and
            // vice versa.
            BOOST_CHECK_MESSAGE(!(tx.IsCoinBase()
                                      ? CheckRegularTransaction(tx, state)
                                      : CheckCoinbase(tx, state)),
                                strTest);
            BOOST_CHECK(state.IsInvalid());

            // Build native introspection contexts just in case the test has flags that enable this feature
            const auto contexts = ScriptExecutionContext::createForAllInputs(tx, coins);

            PrecomputedTransactionData txdata;
            for (size_t i = 0; i < tx.vin.size(); i++) {
                if (!txdata.populated) txdata.PopulateFromContext(contexts.at(i));
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount = Amount::zero();
                if (mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout],
                                                 verify_flags, TransactionSignatureChecker(contexts[i], txdata), &err),
                                    strTest);
                BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid) {
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2],
    // ...],"], serializedTransaction, verifyFlags
    // ... where all scripts are stringified scripts.
    //
    // verifyFlags is a comma separated list of script verification flags to
    // apply, or "NONE"
    UniValue tests = read_json(
        std::string(json_tests::tx_invalid,
                    json_tests::tx_invalid + sizeof(json_tests::tx_invalid)));

    // Initialize to ScriptError::OK. The tests expect err to be changed to a
    // value other than ScriptError::OK.
    ScriptError err = ScriptError::OK;
    for (size_t idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = UniValue::stringify(test);
        if (test[0].isArray()) {
            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
            std::map<COutPoint, Amount> mapprevOutValues;
            CCoinsView dummy;
            CCoinsViewCache coins(&dummy);
            const UniValue::Array& inputs = test[0].get_array();
            bool fValid = true;
            for (size_t inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
                const UniValue &input = inputs[inpIdx];
                if (!input.isArray()) {
                    fValid = false;
                    break;
                }
                const UniValue::Array& vinput = input.get_array();
                if (vinput.size() < 3 || vinput.size() > 4) {
                    fValid = false;
                    break;
                }
                COutPoint outpoint = buildOutPoint(vinput);
                const auto& scriptPubKey = mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
                Amount amount = Amount::zero();
                if (vinput.size() >= 4) {
                    amount = mapprevOutValues[outpoint] = vinput[3].get_int64() * SATOSHI;
                }
                coins.AddCoin(outpoint, Coin(CTxOut(amount, scriptPubKey), 1, false), false);
            }
            if (!fValid) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK,
                               PROTOCOL_VERSION);
            CTransaction tx(deserialize, stream);

            CValidationState state;
            fValid = CheckRegularTransaction(tx, state) && state.IsValid();

            // Build native introspection contexts just in case the test has flags that enable this feature
            const auto contexts = ScriptExecutionContext::createForAllInputs(tx, coins);

            PrecomputedTransactionData txdata;
            for (size_t i = 0; i < tx.vin.size() && fValid; i++) {
                if (!txdata.populated) txdata.PopulateFromContext(contexts.at(i));
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout)) {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                Amount amount = Amount::zero();
                if (0 != mapprevOutValues.count(tx.vin[i].prevout)) {
                    amount = mapprevOutValues[tx.vin[i].prevout];
                }

                uint32_t verify_flags = ParseScriptFlags(test[2].get_str());
                fValid = VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout], verify_flags,
                                      TransactionSignatureChecker(contexts[i], txdata), &err);
            }
            BOOST_CHECK_MESSAGE(!fValid, strTest);
            BOOST_CHECK_MESSAGE(err != ScriptError::OK, ScriptErrorString(err));
        }
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests) {
    // Random real transaction
    // (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    uint8_t ch[] = {
        0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65,
        0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8,
        0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74,
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00,
        0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77,
        0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f,
        0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2,
        0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e,
        0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4,
        0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2,
        0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a,
        0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34,
        0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97,
        0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b,
        0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f,
        0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00,
        0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef,
        0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39,
        0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93,
        0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43,
        0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> vch(ch, ch + sizeof(ch) - 1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CMutableTransaction tx;
    stream >> tx;
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckRegularTransaction(CTransaction(tx), state) &&
                            state.IsValid(),
                        "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckRegularTransaction(CTransaction(tx), state) ||
                            !state.IsValid(),
                        "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CMutableTransaction>
SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsViewCache &coinsRet) {
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++) {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11 * CENT;
    dummyTransactions[0].vout[0].scriptPubKey
        << key[0].GetPubKey() << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50 * CENT;
    dummyTransactions[0].vout[1].scriptPubKey
        << key[1].GetPubKey() << OP_CHECKSIG;
    AddCoins(coinsRet, CTransaction(dummyTransactions[0]), 0);

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21 * CENT;
    dummyTransactions[1].vout[0].scriptPubKey =
        GetScriptForDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22 * CENT;
    dummyTransactions[1].vout[1].scriptPubKey =
        GetScriptForDestination(key[3].GetPubKey().GetID());
    AddCoins(coinsRet, CTransaction(dummyTransactions[1]), 0);

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get) {
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout = COutPoint(dummyTransactions[0].GetId(), 1);
    t1.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t1.vin[1].prevout = COutPoint(dummyTransactions[1].GetId(), 0);
    t1.vin[1].scriptSig << std::vector<uint8_t>(65, 0) << std::vector<uint8_t>(33, 4);
    t1.vin[2].prevout = COutPoint(dummyTransactions[1].GetId(), 1);
    t1.vin[2].scriptSig << std::vector<uint8_t>(65, 0) << std::vector<uint8_t>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(CTransaction(t1), coins, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK_EQUAL(coins.GetValueIn(CTransaction(t1)), (50 + 21 + 22) * CENT);
}

static void CreateCreditAndSpend(const CKeyStore &keystore,
                                 const CScript &outscript,
                                 CTransactionRef &output,
                                 CMutableTransaction &input,
                                 bool success = true) {
    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout = COutPoint();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = SATOSHI;
    outputm.vout[0].scriptPubKey = outscript;
    CDataStream ssout(SER_NETWORK, PROTOCOL_VERSION);
    ssout << outputm;
    ssout >> output;
    BOOST_CHECK_EQUAL(output->vin.size(), 1UL);
    BOOST_CHECK(output->vin[0] == outputm.vin[0]);
    BOOST_CHECK_EQUAL(output->vout.size(), 1UL);
    BOOST_CHECK(output->vout[0] == outputm.vout[0]);

    CMutableTransaction inputm;
    inputm.nVersion = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout = COutPoint(output->GetId(), 0);
    inputm.vout.resize(1);
    inputm.vout[0].nValue = SATOSHI;
    inputm.vout[0].scriptPubKey = CScript();

    auto const context = std::nullopt;
    bool ret = SignSignature(keystore, *output, inputm, 0, SigHashType().withFork(), STANDARD_SCRIPT_VERIFY_FLAGS,
                             context);

    BOOST_CHECK_EQUAL(ret, success);
    CDataStream ssin(SER_NETWORK, PROTOCOL_VERSION);
    ssin << inputm;
    ssin >> input;
    BOOST_CHECK_EQUAL(input.vin.size(), 1UL);
    BOOST_CHECK(input.vin[0] == inputm.vin[0]);
    BOOST_CHECK_EQUAL(input.vout.size(), 1UL);
    BOOST_CHECK(input.vout[0] == inputm.vout[0]);
}

static
void CheckWithFlag(const CTransactionRef &output, const CMutableTransaction &input, int flags, bool success) {
    ScriptError error;
    CTransaction inputi(input);

    // build script execution context for `inputi`
    BOOST_CHECK(inputi.vin.size() == output->vout.size());
    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    for (size_t i = 0; i < inputi.vin.size(); ++i) {
        coins.AddCoin(inputi.vin[i].prevout, Coin(output->vout.at(i), 1, false), false);
    }
    const auto contexts = ScriptExecutionContext::createForAllInputs(inputi, coins);
    for (const auto& c : contexts) {
        // Ensure we have all coins
        BOOST_CHECK(!c.coin().IsSpent());
    }

    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey,
        flags | SCRIPT_ENABLE_SIGHASH_FORKID,
        TransactionSignatureChecker(contexts[0]),
        &error);
    BOOST_CHECK_EQUAL(ret, success);
}

static CScript PushAll(const StackT &values) {
    CScript result;
    for (const StackItem &v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v.vec();
        }
    }
    return result;
}

static
void ReplaceRedeemScript(CScript &script, const CScript &redeemScript) {
    StackT stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    BOOST_CHECK(stack.size() > 0);
    stack.back().mutableVec() = StackVec(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_transaction) {
    CKey key;
    key.MakeNewKey(false);
    CBasicKeyStore keystore;
    BOOST_CHECK(keystore.AddKeyPubKey(key, key.GetPubKey()));
    CScript scriptPubKey = CScript()
                           << key.GetPubKey() << OP_CHECKSIG;

    std::vector<SigHashType> sigHashes;
    sigHashes.emplace_back(SIGHASH_NONE | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_SINGLE | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_ALL | SIGHASH_FORKID);
    sigHashes.emplace_back(SIGHASH_NONE | SIGHASH_FORKID |
                           SIGHASH_ANYONECANPAY);
    sigHashes.emplace_back(SIGHASH_SINGLE | SIGHASH_FORKID |
                           SIGHASH_ANYONECANPAY);
    sigHashes.emplace_back(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);

    CMutableTransaction mtx;
    mtx.nVersion = 1;

    // create a big transaction of 4500 inputs signed by the same key.
    const static size_t OUTPUT_COUNT = 4500;
    mtx.vout.reserve(OUTPUT_COUNT);
    mtx.vin.reserve(OUTPUT_COUNT);

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);

    constexpr Amount inOutAmt = 1000 * SATOSHI;

    for (size_t ij = 0; ij < OUTPUT_COUNT; ij++) {
        size_t i = mtx.vin.size();
        TxId prevId(uint256S("0000000000000000000000000000000000000000000000000"
                             "000000000000100"));
        const COutPoint outpoint(prevId, i);

        mtx.vin.emplace_back(outpoint, CScript());
        coins.AddCoin(outpoint, Coin(CTxOut(inOutAmt, scriptPubKey), 1, false), false);

        mtx.vout.emplace_back(inOutAmt, CScript() << OP_1);
    }

    auto contexts = ScriptExecutionContext::createForAllInputs(mtx, coins);

    // sign all inputs
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, CTxOut{inOutAmt, scriptPubKey},
                                        sigHashes.at(i % sigHashes.size()), STANDARD_SCRIPT_VERIFY_FLAGS,
                                        contexts.at(i));
        BOOST_CHECK_MESSAGE(hashSigned, "Failed to sign test transaction");
    }

    CTransaction tx(mtx);
    contexts = ScriptExecutionContext::createForAllInputs(tx, coins); // generate contexts for this constant tx
    for (const auto& inp : tx.vin) {
        // ensure all coins present
        BOOST_CHECK(coins.HaveCoin(inp.prevout));
    }

    // check all inputs concurrently, with the cache
    PrecomputedTransactionData txdata;
    CCheckQueue<CScriptCheck> scriptcheckqueue(128);
    CCheckQueueControl<CScriptCheck> control(&scriptcheckqueue);

    scriptcheckqueue.StartWorkerThreads(20);

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (!txdata.populated) txdata.PopulateFromContext(contexts.at(i));
        std::vector<CScriptCheck> vChecks;
        vChecks.emplace_back(contexts.at(i), STANDARD_SCRIPT_VERIFY_FLAGS, false, txdata);
        control.Add(vChecks);
    }

    bool controlCheck = control.Wait();
    BOOST_CHECK(controlCheck);

    scriptcheckqueue.StopWorkerThreads();
}

SignatureData CombineSignatures(const CMutableTransaction &input1,
                                const CMutableTransaction &input2,
                                const CTransactionRef tx, ScriptExecutionContextOpt context = {}) {
    SignatureData sigdata;
    sigdata = DataFromTransaction(ScriptExecutionContext{0, tx->vout[0], input1}, STANDARD_SCRIPT_VERIFY_FLAGS);
    sigdata.MergeSignatureData(DataFromTransaction(ScriptExecutionContext{0, tx->vout[0], input2},
                                                   STANDARD_SCRIPT_VERIFY_FLAGS));

    ProduceSignature(
        DUMMY_SIGNING_PROVIDER,
        TransactionSignatureCreator(context.value_or(ScriptExecutionContext{0, tx->vout[0], input1})),
        tx->vout[0].scriptPubKey, sigdata, STANDARD_SCRIPT_VERIFY_FLAGS);
    return sigdata;
}

BOOST_AUTO_TEST_CASE(test_witness) {
    CBasicKeyStore keystore, keystore2;
    CKey key1, key2, key3, key1L, key2L;
    CPubKey pubkey1, pubkey2, pubkey3, pubkey1L, pubkey2L;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);
    key1L.MakeNewKey(false);
    key2L.MakeNewKey(false);
    pubkey1 = key1.GetPubKey();
    pubkey2 = key2.GetPubKey();
    pubkey3 = key3.GetPubKey();
    pubkey1L = key1L.GetPubKey();
    pubkey2L = key2L.GetPubKey();
    BOOST_CHECK(keystore.AddKeyPubKey(key1, pubkey1));
    BOOST_CHECK(keystore.AddKeyPubKey(key2, pubkey2));
    BOOST_CHECK(keystore.AddKeyPubKey(key1L, pubkey1L));
    BOOST_CHECK(keystore.AddKeyPubKey(key2L, pubkey2L));
    CScript scriptPubkey1, scriptPubkey2, scriptPubkey1L, scriptPubkey2L,
        scriptMulti;
    scriptPubkey1 << pubkey1 << OP_CHECKSIG;
    scriptPubkey2 << pubkey2 << OP_CHECKSIG;
    scriptPubkey1L << pubkey1L << OP_CHECKSIG;
    scriptPubkey2L << pubkey2L << OP_CHECKSIG;
    std::vector<CPubKey> oneandthree;
    oneandthree.push_back(pubkey1);
    oneandthree.push_back(pubkey3);
    scriptMulti = GetScriptForMultisig(2, oneandthree);
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey1L, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore.AddCScript(scriptPubkey2L, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore.AddCScript(scriptMulti, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore2.AddCScript(scriptMulti, false /*=p2sh_20*/, false /* legacy vm limits */));
    BOOST_CHECK(keystore2.AddKeyPubKey(key3, pubkey3));

    CTransactionRef output1, output2;
    CMutableTransaction input1, input2;

    // Normal pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-compressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptID(scriptPubkey1, false /*=p2sh_20*/)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptID(scriptPubkey2, false /*=p2sh_20*/)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore, scriptPubkey1L, output1, input1);
    CreateCreditAndSpend(keystore, scriptPubkey2L, output2, input2);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, false);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // P2SH pay-to-uncompressed-pubkey.
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptID(scriptPubkey1L, false /*=p2sh_20*/)),
                         output1, input1);
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptID(scriptPubkey2L, false /*=p2sh_20*/)),
                         output2, input2);
    ReplaceRedeemScript(input2.vin[0].scriptSig, scriptPubkey1L);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
    CheckWithFlag(output1, input2, 0, true);
    CheckWithFlag(output1, input2, SCRIPT_VERIFY_P2SH, false);
    CheckWithFlag(output1, input2, STANDARD_SCRIPT_VERIFY_FLAGS, false);

    // Normal 2-of-2 multisig
    CreateCreditAndSpend(keystore, scriptMulti, output1, input1, false);
    CheckWithFlag(output1, input1, 0, false);
    CreateCreditAndSpend(keystore2, scriptMulti, output2, input2, false);
    CheckWithFlag(output2, input2, 0, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);

    // P2SH 2-of-2 multisig
    CreateCreditAndSpend(keystore,
                         GetScriptForDestination(ScriptID(scriptMulti, false /*=p2sh_20*/)),
                         output1, input1, false);
    CheckWithFlag(output1, input1, 0, true);
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, false);
    CreateCreditAndSpend(keystore2,
                         GetScriptForDestination(ScriptID(scriptMulti, false /*=p2sh_20*/)),
                         output2, input2, false);
    CheckWithFlag(output2, input2, 0, true);
    CheckWithFlag(output2, input2, SCRIPT_VERIFY_P2SH, false);
    BOOST_CHECK(*output1 == *output2);
    UpdateInput(input1.vin[0], CombineSignatures(input1, input2, output1));
    CheckWithFlag(output1, input1, SCRIPT_VERIFY_P2SH, true);
    CheckWithFlag(output1, input1, STANDARD_SCRIPT_VERIFY_FLAGS, true);
}

BOOST_AUTO_TEST_CASE(test_IsStandard) {
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32 & ~SCRIPT_ENABLE_TOKENS;

    LOCK(cs_main);
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions =
        SetupDummyInputs(keystore, coins);

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout = COutPoint(dummyTransactions[0].GetId(), 1);
    t.vin[0].scriptSig << std::vector<uint8_t>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90 * CENT;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Check dust with default relay fee:
    Amount nDustThreshold = 3 * 182 * dustRelayFee.GetFeePerK() / 1000;
    BOOST_CHECK_EQUAL(nDustThreshold, 546 * SATOSHI);
    // dust:
    t.vout[0].nValue = nDustThreshold - SATOSHI;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));
    // not dust:
    t.vout[0].nValue = nDustThreshold;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Check dust with odd relay fee to verify rounding:
    // nDustThreshold = 182 * 1234 / 1000 * 3
    dustRelayFee = CFeeRate(1234 * SATOSHI);
    // dust:
    t.vout[0].nValue = (672 - 1) * SATOSHI;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));
    // not dust:
    t.vout[0].nValue = 672 * SATOSHI;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
    dustRelayFee = CFeeRate(DUST_RELAY_TX_FEE);

    t.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // Test P2SH_32 is non-standard pre-activation, and standard post-activation
    CTxOut &txout = t.vout[0];
    txout.scriptPubKey = GetScriptForDestination(ScriptID(txout.scriptPubKey, true /* p2sh_32 */));
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags | SCRIPT_ENABLE_P2SH_32));

    // Test token-containing output is non-standard pre-activation and standard post-activation
    txout.scriptPubKey = GetScriptForDestination(ScriptID(CScript() << OP_1, false /* p2sh_20 */));
    BOOST_CHECK(!txout.tokenDataPtr);
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
    txout.tokenDataPtr.emplace(token::Id{}, *token::SafeAmount::fromInt(1));
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags | SCRIPT_ENABLE_TOKENS));
    txout.tokenDataPtr.reset();

    // MAX_OP_RETURN_RELAY-byte TX_NULL_DATA (standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("646578784062697477617463682e636f2092c558ed52c56d"
                              "8dd14ca76226bc936a84820d898443873eb03d8854b21fa3"
                              "952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                              "3afb2ab8");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA (non-standard)
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("646578784062697477617463682e636f2092c558ed52c56d"
                              "8dd14ca76226bc936a84820d898443873eb03d8854b21fa3"
                              "952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                              "3afb2ab800");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // MAX_OP_RETURN_RELAY-byte TX_NULL_DATA in multiple outputs (standard after May 2021 Network Upgrade)
    t.vout.resize(3);
    t.vout[1].nValue = Amount::zero();
    t.vout[2].nValue = Amount::zero();
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("646578784062697477617463682e636f2092c558ed52c56d");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("8dd14ca76226bc936a84820d898443873eb03d8854b21fa3");
    t.vout[2].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size() + t.vout[2].scriptPubKey.size());
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // MAX_OP_RETURN_RELAY+1-byte TX_NULL_DATA in multiple outputs (non-standard)
    t.vout[2].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("952b99a2981873e74509281730d78a21786d34a38bd1ebab"
                              "822fad42278f7f4420db6ab1fd2b6826148d4f73bb41ec2d"
                              "40a6d5793d66e17074a0c56a8a7df21062308f483dd6e38d"
                              "53609d350038df0a1b2a9ac8332016e0b904f66880dd0108"
                              "81c4e8074cce8e4ad6c77cb3460e01bf0e7e811b5f945f83"
                              "732ba6677520a893d75d9a966cb8f85dc301656b1635c631"
                              "f5d00d4adf73f2dd112ca75cf19754651909becfbe65aed1"
                              "3a");
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY + 1, t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size() + t.vout[2].scriptPubKey.size());
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    /**
     * Check when a custom value is used for -datacarriersize .
     */
    const auto nMaxDatacarrierBytesOrig = nMaxDatacarrierBytes;
    nMaxDatacarrierBytes = 90;

    // Max user provided payload size is standard
    t.vout.resize(1);
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e64657878");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size(), 90);
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Max user provided payload size + 1 is non-standard
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548"
                              "271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e6465787800");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size(), 91);
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // Max user provided payload size in multiple outputs is standard
    // after the May 2021 Network Upgrade.
    t.vout.resize(2);
    t.vout[1].nValue = Amount::zero();
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e646578");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size(), 90);
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Max user provided payload size + 1 in multiple outputs is non-standard
    // even after the May 2021 Network Upgrade.
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
                              "b649f6bc3f4cef3877696e64657878");
    BOOST_CHECK_EQUAL(t.vout[0].scriptPubKey.size() + t.vout[1].scriptPubKey.size(), 91);
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // Verify -datacarriersize=0 rejects even the smallest possible OP_RETURN payload.
    nMaxDatacarrierBytes = 0;
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // Clear custom configuration.
    nMaxDatacarrierBytes = nMaxDatacarrierBytesOrig;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN << ParseHex("00") << ParseHex("01");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED
                                       << ScriptInt::fromIntUnchecked(-1)
                                       << ScriptInt::fromIntUnchecked(0)
                                       << ParseHex("01")
                                       << ScriptInt::fromIntUnchecked(2)
                                       << ScriptInt::fromIntUnchecked(3)
                                       << ScriptInt::fromIntUnchecked(4)
                                       << ScriptInt::fromIntUnchecked(5)
                                       << ScriptInt::fromIntUnchecked(6)
                                       << ScriptInt::fromIntUnchecked(7)
                                       << ScriptInt::fromIntUnchecked(8)
                                       << ScriptInt::fromIntUnchecked(9)
                                       << ScriptInt::fromIntUnchecked(10)
                                       << ScriptInt::fromIntUnchecked(11)
                                       << ScriptInt::fromIntUnchecked(12)
                                       << ScriptInt::fromIntUnchecked(13)
                                       << ScriptInt::fromIntUnchecked(14)
                                       << ScriptInt::fromIntUnchecked(15)
                                       << ScriptInt::fromIntUnchecked(16);
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
    t.vout[0].scriptPubKey = CScript()
                             << OP_RETURN
                             << ScriptInt::fromIntUnchecked(0)
                             << ParseHex("01")
                             << ScriptInt::fromIntUnchecked(2)
                             << ParseHex("fffffffffffffffffffffffffffffffffffff"
                                         "fffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    // TX_NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Only one TX_NULL_DATA permitted in all cases,
    // until the May 2021 Network Upgrade.
    t.vout.resize(2);
    t.vout[1].nValue = Amount::zero();
    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    t.vout[0].scriptPubKey =
        CScript() << OP_RETURN
                  << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));

    // Every OP_RETURN output script without data pushes is one byte long,
    // so the maximum number of outputs will be nMaxDatacarrierBytes.
    t.vout.resize(nMaxDatacarrierBytes + 1);
    for (auto& out : t.vout) {
        out.nValue = Amount::zero();
        out.scriptPubKey = CScript() << OP_RETURN;
    }
    BOOST_CHECK(!IsStandardTx(CTransaction(t), reason, flags));

    t.vout.pop_back();
    BOOST_CHECK(IsStandardTx(CTransaction(t), reason, flags));
}

BOOST_AUTO_TEST_CASE(txsize_activation_test) {
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();
    // ContextualCheckTransaction expects nHeight of next block and MTP for previous block.
    // But the hard-coded chain params are for previous block, hence why we increment the height here.
    const int32_t magneticAnomalyActivationHeight = params.magneticAnomalyHeight + 1;
    const int32_t upgrade9ActivationHeight = params.upgrade9Height + 1;
    BOOST_CHECK_LT(magneticAnomalyActivationHeight, upgrade9ActivationHeight);
    const int64_t unusedMTP = 0;

    // A minimally-sized transction.
    const auto &minTx = CTransaction::null;
    BOOST_CHECK(::GetSerializeSize(minTx) < MIN_TX_SIZE_MAGNETIC_ANOMALY);
    CValidationState state;

    BOOST_CHECK(ContextualCheckTransaction(
        params, minTx, state, magneticAnomalyActivationHeight - 1, 5678, unusedMTP));
    BOOST_CHECK(!ContextualCheckTransaction(
        params, minTx, state, magneticAnomalyActivationHeight, 5678, unusedMTP));
    BOOST_CHECK_EQUAL(state.GetRejectCode(), REJECT_INVALID);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-undersize");

    // A tx that is 65 bytes
    const CTransaction smallTx = []{
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vout.resize(1);
        const auto txSize = ::GetSerializeSize(tx);
        BOOST_REQUIRE_LE(txSize, MIN_TX_SIZE_UPGRADE9);
        tx.vin[0].scriptSig.resize(MIN_TX_SIZE_UPGRADE9 - txSize);
        return CTransaction{tx};
    }();
    BOOST_CHECK_EQUAL(::GetSerializeSize(smallTx), MIN_TX_SIZE_UPGRADE9);
    BOOST_CHECK_LT(::GetSerializeSize(smallTx), MIN_TX_SIZE_MAGNETIC_ANOMALY);
    state = CValidationState{};
    BOOST_CHECK(!ContextualCheckTransaction(
        params, smallTx, state, upgrade9ActivationHeight - 1, 5678, unusedMTP));
    BOOST_CHECK_EQUAL(state.GetRejectCode(), REJECT_INVALID);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-undersize");
    BOOST_CHECK(ContextualCheckTransaction(
        params, smallTx, state, upgrade9ActivationHeight, 5678, unusedMTP));
}

BOOST_FIXTURE_TEST_CASE(checktxinput_test, TestChain100Setup) {
    CScript const p2pk_scriptPubKey = CScript() << coinbaseKey.GetPubKey() << OP_CHECKSIG;
    CScript const p2sh_scriptPubKey = GetScriptForDestination(ScriptID(p2pk_scriptPubKey, false /*=p2sh_20*/));

    CMutableTransaction funding_tx_1;
    CScript noppyScriptPubKey;
    {
        funding_tx_1.nVersion = 1;
        funding_tx_1.vin.resize(1);
        funding_tx_1.vin[0].prevout = COutPoint(m_coinbase_txns[0]->GetId(), 0);
        funding_tx_1.vout.resize(1);
        funding_tx_1.vout[0].nValue = 50 * COIN;

        noppyScriptPubKey << OP_IF << OP_NOP10 << OP_ENDIF << OP_1;
        funding_tx_1.vout[0].scriptPubKey = noppyScriptPubKey;
        std::vector<uint8_t> fundingVchSig;
        const ScriptExecutionContext limited_context{0, m_coinbase_txns[0]->vout[0], funding_tx_1};
        uint256 fundingSigHash = SignatureHash(p2pk_scriptPubKey, limited_context, SigHashType().withFork(),
                                               nullptr, STANDARD_SCRIPT_VERIFY_FLAGS).signatureHash;
        BOOST_CHECK(coinbaseKey.SignECDSA(fundingSigHash, fundingVchSig));
        fundingVchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
        funding_tx_1.vin[0].scriptSig << fundingVchSig;
    }

    // Spend the funding transaction by mining it into a block
    {
        CBlock block = CreateAndProcessBlock({funding_tx_1}, p2pk_scriptPubKey);
        BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());
        BOOST_CHECK(pcoinsTip->GetBestBlock() == block.GetHash());
    }

    CMutableTransaction funding_tx_2;
    {
        funding_tx_2.nVersion = 1;
        funding_tx_2.vin.resize(1);
        funding_tx_2.vin[0].prevout = COutPoint(m_coinbase_txns[1]->GetId(), 0);
        funding_tx_2.vout.resize(1);
        funding_tx_2.vout[0].nValue = 50 * COIN;

        noppyScriptPubKey << OP_IF << OP_NOP10 << OP_ENDIF << OP_1;
        funding_tx_2.vout[0].scriptPubKey = noppyScriptPubKey;
        std::vector<uint8_t> fundingVchSig;
        const ScriptExecutionContext limited_context{0, m_coinbase_txns[0]->vout[0], funding_tx_2};
        uint256 fundingSigHash = SignatureHash(p2pk_scriptPubKey, limited_context, SigHashType().withFork(), nullptr,
                                               STANDARD_SCRIPT_VERIFY_FLAGS).signatureHash;
        BOOST_CHECK(coinbaseKey.SignECDSA(fundingSigHash, fundingVchSig));
        fundingVchSig.push_back(uint8_t(SIGHASH_ALL | SIGHASH_FORKID));
        funding_tx_2.vin[0].scriptSig << fundingVchSig;
    }

    {
        CMutableTransaction spend_tx;
        spend_tx.nVersion = 1;
        spend_tx.vin.resize(2);
        spend_tx.vin[0].prevout = COutPoint(funding_tx_1.GetId(), 0);
        spend_tx.vin[0].scriptSig << OP_1;
        spend_tx.vin[1].prevout = COutPoint(funding_tx_2.GetId(), 0);
        spend_tx.vin[1].scriptSig << OP_1;
        spend_tx.vout.resize(2);
        spend_tx.vout[0].nValue = 11 * CENT;
        spend_tx.vout[0].scriptPubKey = p2sh_scriptPubKey;
        spend_tx.vout[1].nValue = 11 * CENT;
        spend_tx.vout[1].scriptPubKey = p2sh_scriptPubKey;

        CTransaction const tx(spend_tx);
        CValidationState state;
        Amount txfee;

        CTxOut txout;
        txout.scriptPubKey = p2pk_scriptPubKey;
        txout.nValue = Amount::zero();
        pcoinsTip->AddCoin(spend_tx.vin[1].prevout, Coin(txout, 1, false), true);

        BOOST_CHECK(Consensus::CheckTxInputs(tx, state, pcoinsTip.get(), 0, txfee));

        pcoinsTip->SpendCoin(spend_tx.vin[1].prevout);
        BOOST_CHECK( ! Consensus::CheckTxInputs(tx, state, pcoinsTip.get(), 0, txfee));
    }
}

BOOST_AUTO_TEST_CASE(COutPoint_ToString) {
    BOOST_CHECK_EQUAL(COutPoint{}.ToString(), "COutPoint(0000000000, 4294967295)");
    BOOST_CHECK_EQUAL(COutPoint(TxId(uint256(std::vector<uint8_t>{1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0})), 0).ToString(), "COutPoint(0001000100, 0)");
}

BOOST_AUTO_TEST_CASE(CTxIn_ToString) {
    CTxIn txin;
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0000000000, 4294967295), coinbase )");

    txin.nSequence = 0;
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0000000000, 4294967295), coinbase , nSequence=0)");

    txin.prevout = COutPoint{TxId{uint256{std::vector<uint8_t>{1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0}}}, 0};
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0001000100, 0), scriptSig=, nSequence=0)");

    txin.nSequence = CTxIn::SEQUENCE_FINAL;
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0001000100, 0), scriptSig=)");

    std::vector<uint8_t> script_data{ParseHex("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac")};
    txin.scriptSig = CScript{script_data.begin(), script_data.end()};
    txin.prevout = COutPoint{};
    txin.nSequence = 0;
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0000000000, 4294967295), coinbase 76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac, nSequence=0)");

    txin.prevout = COutPoint{TxId{uint256{std::vector<uint8_t>{1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0}}}, 0};
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0001000100, 0), scriptSig=76a9141234567890abcdefa1, nSequence=0)");

    txin.nSequence = CTxIn::SEQUENCE_FINAL;
    BOOST_CHECK_EQUAL(txin.ToString(), "CTxIn(COutPoint(0001000100, 0), scriptSig=76a9141234567890abcdefa1)");
}

BOOST_AUTO_TEST_CASE(CTxOut_ToString) {
    CTxOut txout;

    //BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=-0.00000001, scriptPubKey=)");
    // test fails with current implementation ("0.-0000001")

    std::vector<uint8_t> script_data{ParseHex("76a9141234567890abcdefa1a2a3a4a5a6a7a8a9a0aaab88ac")};
    txout.scriptPubKey = CScript{script_data.begin(), script_data.end()};

    txout.nValue = Amount::zero();
    BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=0.00000000, scriptPubKey=76a9141234567890abcdefa1a2a3a4)");

    txout.nValue = 123'456'000 * SATOSHI;
    BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=1.23456000, scriptPubKey=76a9141234567890abcdefa1a2a3a4)");

    txout.nValue = 1230 * COIN;
    BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=1230.00000000, scriptPubKey=76a9141234567890abcdefa1a2a3a4)");

    txout.nValue = -123'456'000 * SATOSHI;
    //BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=-1.23456000, scriptPubKey=76a9141234567890abcdefa1a2a3a4)");
    // test fails with current implementation ("-1.-23456000")

    txout.nValue = -1230 * COIN;
    BOOST_CHECK_EQUAL(txout.ToString(), "CTxOut(nValue=-1230.00000000, scriptPubKey=76a9141234567890abcdefa1a2a3a4)");
}

BOOST_AUTO_TEST_CASE(CTransaction_ToString) {
    const std::vector<uint8_t> txBytes = ParseHex(
        "01000000012232249686666ec07808f294e7b139953ecf775e3070c86e3e911b4813ee50e3010000006b483045022100e498300237c45b"
        "90f76bd5b43c8ee2f34dffc9357554fe034f4baa9a85e048dd02202f770fffc15936e37bed2a6c4927db4080f9c9d94748099775f78e77"
        "e07e098c412102574c8811c6e5435f0773a588495271c7d74b687cc374b95a3a330d45c9a7d0d7ffffffff02c58b8b1a000000001976a9"
        "147d9a37c154facc9fd0068a5b8be0b1b1a637dd9b88ac00e1f505000000001976a9140a373caf0ab3c2b46cd05625b8d545c295b93d7a"
        "88ac00000000");
    CDataStream ss(txBytes, SER_NETWORK, CLIENT_VERSION);
    CMutableTransaction mtx;
    ss >> mtx;
    CTransaction tx(mtx);
    BOOST_CHECK_EQUAL(tx.ToString(), "CTransaction(txid=79851cf2de, ver=1, vin.size=1, vout.size=2, nLockTime=0)"
        "\n    CTxIn(COutPoint(e350ee1348, 1), scriptSig=483045022100e498300237c4)"
        "\n    CTxOut(nValue=4.45352901, scriptPubKey=76a9147d9a37c154facc9fd0068a5b)"
        "\n    CTxOut(nValue=1.00000000, scriptPubKey=76a9140a373caf0ab3c2b46cd05625)"
        "\n");
}

BOOST_AUTO_TEST_CASE(CTransaction_ToString_TokenData) {
    const std::vector<uint8_t> txBytes = ParseHex(
        "0200000002f9216e4d8853a41a9775a2542e91e549751403095471c16fb07209c9d63be650020000006a47304402204a76646d32f4ed67"
        "5b11340b2f3502c197c5d52cfca0834709cf4e3374d45e950220153e8697ea1c02b403f8f45dc84c0924bd15a1b00c629135f1184df6ca"
        "1b29504121036f679d3562595fbe5c0a8a7194a2a8e476f2a094afc73a1dec817e2373b37f56fffffffff9216e4d8853a41a9775a2542e"
        "91e549751403095471c16fb07209c9d63be650000000006a47304402203080d4d635e32746094d7dc2ee5e448fdea75486965b419346b1"
        "e32a0e46f4740220276087388b4c98512ca5135f9e7914786c31f976861013f14df7f4487472673a412102abaad90841057ddb1ed92960"
        "8b536535b0cd8a18ba0a90dba66ba7b1c1f7b4eaffffffff03a08601000000000044ef43c1044127e1274181e7458c70b02d5c75b49b31"
        "a337d85703d56480345cd2cc10ffffffffffffffff7f76a9140a373caf0ab3c2b46cd05625b8d545c295b93d7a88aca086010000000000"
        "44ef43c1044127e1274181e7458c70b02d5c75b49b31a337d85703d56480345cd2cc6208596f596f596f212176a914fd68d2c87f0dc179"
        "9e51657d32efb9aa367d161e88acf0e0ae2f000000001976a914ea873aaafbdd7a7c74d73ee1174e42f620b0a18c88ac00000000");
    CMutableTransaction mtx;
    CDataStream (txBytes, SER_NETWORK, CLIENT_VERSION) >> mtx;
    CTransaction tx(mtx);
    BOOST_CHECK_EQUAL(tx.ToString(), "CTransaction(txid=d546a26ff3, ver=2, vin.size=2, vout.size=3, nLockTime=0)\n"
        "    CTxIn(COutPoint(50e63bd6c9, 2), scriptSig=47304402204a76646d32f4ed)\n"
        "    CTxIn(COutPoint(50e63bd6c9, 0), scriptSig=47304402203080d4d635e327)\n"
        "    CTxOut(nValue=0.00100000, scriptPubKey=76a9140a373caf0ab3c2b46cd05625 "
        "token::OutputData(id=ccd25c348064d50357d837a3319bb4, bitfield=10, amount=9223372036854775807, commitment=))\n"
        "    CTxOut(nValue=0.00100000, scriptPubKey=76a914fd68d2c87f0dc1799e51657d "
        "token::OutputData(id=ccd25c348064d50357d837a3319bb4, bitfield=62, amount=0, commitment=596f596f596f2121))\n"
        "    CTxOut(nValue=7.99990000, scriptPubKey=76a914ea873aaafbdd7a7c74d73ee1)\n");
}

BOOST_AUTO_TEST_SUITE_END()
