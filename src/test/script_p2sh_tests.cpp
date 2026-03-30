// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2019-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>
#include <core_io.h>
#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/ismine.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <validation.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

// Helpers:
static std::vector<uint8_t> Serialize(const CScript &s) {
    std::vector<uint8_t> sSerialized(s.begin(), s.end());
    return sSerialized;
}

static bool Verify(const CScript &scriptSig, const CScript &scriptPubKey,
                   bool fStrict, ScriptError &err, bool fP2SH32) {
    // Create dummy to/from transactions:
    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = scriptPubKey;

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vin[0].scriptSig = scriptSig;
    txTo.vout[0].nValue = SATOSHI;

    const ScriptExecutionContext limited_context{0, txFrom.vout[0], txTo}; // It is Ok to have a limited context here.
    const uint32_t flags = SCRIPT_ENABLE_SIGHASH_FORKID
                           | (fStrict            ? SCRIPT_VERIFY_P2SH    : SCRIPT_VERIFY_NONE)
                           | (fStrict && fP2SH32 ? SCRIPT_ENABLE_P2SH_32 : SCRIPT_VERIFY_NONE);
    return VerifyScript(scriptSig, scriptPubKey, flags, TransactionSignatureChecker(limited_context), &err);
}

BOOST_FIXTURE_TEST_SUITE(script_p2sh_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sign) {
    const bool targetedVmLimitsEnabled = false; /* Use legacy VM limits for this test. */
    // This tests both regular p2sh (hash160) and p2sh_32 (hash256).
    for (const bool is_p2sh_32 : {false, true}) {
        const uint32_t flags = is_p2sh_32 ? STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32
                                          : STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32;

        LOCK(cs_main);
        // Pay-to-script-hash looks like this:
        // scriptSig:    <sig> <sig...> <serialized_script>
        // scriptPubKey: HASH160 <hash 20 bytes> EQUAL (p2sh)
        // scriptPubKey: HASH256 <hash 32 bytes> EQUAL (p2sh32)

        // Test SignSignature() (and therefore the version of Solver() that signs transactions)
        CBasicKeyStore keystore;
        CKey key[4];
        for (int i = 0; i < 4; i++) {
            key[i].MakeNewKey(true);
            BOOST_CHECK(keystore.AddKey(key[i]));
        }

        // 8 Scripts: checking all combinations of
        // different keys, straight/P2SH, pubkey/pubkeyhash
        CScript standardScripts[4];
        standardScripts[0] << key[0].GetPubKey() << OP_CHECKSIG;
        standardScripts[1] = GetScriptForDestination(key[1].GetPubKey().GetID());
        standardScripts[2] << key[1].GetPubKey() << OP_CHECKSIG;
        standardScripts[3] = GetScriptForDestination(key[2].GetPubKey().GetID());
        CScript evalScripts[4];
        for (int i = 0; i < 4; i++) {
            BOOST_CHECK(keystore.AddCScript(standardScripts[i], is_p2sh_32, targetedVmLimitsEnabled));
            evalScripts[i] = GetScriptForDestination(ScriptID(standardScripts[i], is_p2sh_32));
        }

        // Funding transaction:
        CMutableTransaction txFrom;
        std::string reason;
        txFrom.vout.resize(8);
        for (int i = 0; i < 4; i++) {
            txFrom.vout[i].scriptPubKey = evalScripts[i];
            txFrom.vout[i].nValue = COIN;
            txFrom.vout[i + 4].scriptPubKey = standardScripts[i];
            txFrom.vout[i + 4].nValue = COIN;
        }
        BOOST_CHECK(IsStandardTx(CTransaction(txFrom), reason, flags));

        // Spending transactions
        CMutableTransaction txTo[8];
        for (int i = 0; i < 8; i++) {
            txTo[i].vin.resize(1);
            txTo[i].vout.resize(1);
            txTo[i].vin[0].prevout = COutPoint(txFrom.GetId(), i);
            txTo[i].vout[0].nValue = SATOSHI;
            BOOST_CHECK_MESSAGE(IsMine(keystore, txFrom.vout[i].scriptPubKey),
                                strprintf("IsMine %d", i));
        }

        auto const null_context = std::nullopt;
        for (int i = 0; i < 8; i++) {
            BOOST_CHECK_MESSAGE(SignSignature(keystore, CTransaction(txFrom),
                                              txTo[i], 0,
                                              SigHashType().withFork(), flags, null_context),
                                strprintf("SignSignature %d", i));
        }

        // All of the above should be OK, and the txTos have valid signatures
        // Check to make sure signature verification fails if we use the wrong
        // ScriptSig:
        for (int i = 0; i < 8; i++) {
            CTransaction tx(txTo[i]);
            for (int j = 0; j < 8; j++) {
                CScript sigSave = txTo[i].vin[0].scriptSig;
                txTo[i].vin[0].scriptSig = txTo[j].vin[0].scriptSig;
                const CTxOut &output = txFrom.vout[txTo[i].vin[0].prevout.GetN()];
                const CTransaction tx2(txTo[i]);
                const ScriptExecutionContext limitedContext(0, output, tx2);
                const PrecomputedTransactionData txdata(limitedContext);
                const uint32_t flagsCheck = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID
                                            | (is_p2sh_32 ? SCRIPT_ENABLE_P2SH_32 : 0);
                bool sigOK = CScriptCheck(limitedContext, flagsCheck, false, txdata)();
                if (i == j) {
                    BOOST_CHECK_MESSAGE(sigOK,
                                        strprintf("VerifySignature %d %d", i, j));
                } else {
                    BOOST_CHECK_MESSAGE(!sigOK,
                                        strprintf("VerifySignature %d %d", i, j));
                }
                txTo[i].vin[0].scriptSig = sigSave;
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(norecurse) {
    // This tests p2sh_20 and p2sh_32 as well.
    for (const bool is_p2sh_32 : {false, true}) {
        ScriptError err;
        // Make sure only the outer pay-to-script-hash does the extra-validation thing:
        CScript invalidAsScript;
        invalidAsScript << INVALIDOPCODE << INVALIDOPCODE;

        CScript p2sh = GetScriptForDestination(ScriptID(invalidAsScript, is_p2sh_32));

        CScript scriptSig;
        scriptSig << Serialize(invalidAsScript);

        // Should not verify, because it will try to execute INVALIDOPCODE
        BOOST_CHECK(!Verify(scriptSig, p2sh, true, err, is_p2sh_32));
        BOOST_CHECK_MESSAGE(err == ScriptError::BAD_OPCODE, ScriptErrorString(err));

        // Try to recur, and verification should succeed because
        // the inner HASH160/HASH256 <> EQUAL should only check the hash:
        CScript p2sh2 = GetScriptForDestination(ScriptID(p2sh, is_p2sh_32));
        CScript scriptSig2;
        scriptSig2 << Serialize(invalidAsScript) << Serialize(p2sh);

        BOOST_CHECK(Verify(scriptSig2, p2sh2, true, err, is_p2sh_32));
        BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(set) {
    const bool targetedVmLimitsEnabled = false; /* Use legacy VM limits for this test. */
    // This tests p2sh_20 and p2sh_32 as well.
    for (const bool is_p2sh_32 : {false, true}) {
        const uint32_t flags = is_p2sh_32 ? STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32
                                          : STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32;

        LOCK(cs_main);
        // Test the CScript::Set* methods
        CBasicKeyStore keystore;
        CKey key[4];
        std::vector<CPubKey> keys;
        for (int i = 0; i < 4; i++) {
            key[i].MakeNewKey(true);
            BOOST_CHECK(keystore.AddKey(key[i]));
            keys.push_back(key[i].GetPubKey());
        }

        CScript inner[4];
        inner[0] = GetScriptForDestination(key[0].GetPubKey().GetID());
        inner[1] = GetScriptForMultisig(
            2, std::vector<CPubKey>(keys.begin(), keys.begin() + 2));
        inner[2] = GetScriptForMultisig(
            1, std::vector<CPubKey>(keys.begin(), keys.begin() + 2));
        inner[3] = GetScriptForMultisig(
            2, std::vector<CPubKey>(keys.begin(), keys.begin() + 3));

        CScript outer[4];
        for (int i = 0; i < 4; i++) {
            outer[i] = GetScriptForDestination(ScriptID(inner[i], is_p2sh_32));
            BOOST_CHECK(keystore.AddCScript(inner[i], is_p2sh_32, targetedVmLimitsEnabled));
        }

        // Funding transaction:
        CMutableTransaction txFrom;
        std::string reason;
        txFrom.vout.resize(4);
        for (int i = 0; i < 4; i++) {
            txFrom.vout[i].scriptPubKey = outer[i];
            txFrom.vout[i].nValue = CENT;
        }
        BOOST_CHECK(IsStandardTx(CTransaction(txFrom), reason, flags));

        // Spending transactions
        CMutableTransaction txTo[4];
        for (int i = 0; i < 4; i++) {
            txTo[i].vin.resize(1);
            txTo[i].vout.resize(1);
            txTo[i].vin[0].prevout = COutPoint(txFrom.GetId(), i);
            txTo[i].vout[0].nValue = 1 * CENT;
            txTo[i].vout[0].scriptPubKey = inner[i];
            BOOST_CHECK_MESSAGE(IsMine(keystore, txFrom.vout[i].scriptPubKey),
                                strprintf("IsMine %d", i));
        }

        auto const null_context = std::nullopt;
        for (int i = 0; i < 4; i++) {
            BOOST_CHECK_MESSAGE(SignSignature(keystore, CTransaction(txFrom),
                                              txTo[i], 0,
                                              SigHashType().withFork(), flags, null_context),
                                strprintf("SignSignature %d", i));
            BOOST_CHECK_MESSAGE(IsStandardTx(CTransaction(txTo[i]), reason, flags), strprintf("txTo[%d].IsStandard", i));
        }
    }
}

BOOST_AUTO_TEST_CASE(is) {
    // This tests p2sh_20 and p2sh_32 as well.
    for (const bool is_p2sh_32 : {false, true}) {
        const uint32_t flags = is_p2sh_32 ? STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32
                                          : STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32;

        // Test CScript::IsPayToScriptHash()
        uint160 dummy;
        CScript p2sh;
        p2sh << OP_HASH160 << dummy << OP_EQUAL;
        BOOST_CHECK(p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!p2sh.IsPayToPubKeyHash());

        // Test for p2sh32
        uint256 dummy32;
        CScript p2sh32;
        p2sh32 << OP_HASH256 << dummy32 << OP_EQUAL;
        BOOST_CHECK_EQUAL(p2sh32.IsPayToScriptHash(flags), is_p2sh_32);
        BOOST_CHECK(!p2sh32.IsPayToPubKeyHash());

        // Not considered pay-to-script-hash if using one of the OP_PUSHDATA
        // opcodes:
        static const uint8_t direct[] = {OP_HASH160, 20, 0, 0, 0, 0, 0,       0,
                                         0,          0,  0, 0, 0, 0, 0,       0,
                                         0,          0,  0, 0, 0, 0, OP_EQUAL};
        static const uint8_t direct32[] = {OP_HASH256, 32, 0, 0, 0, 0, 0,       0,
                                           0,          0,  0, 0, 0, 0, 0,       0,
                                           0,          0,  0, 0, 0, 0, 0,       0,
                                           0,          0,  0, 0, 0, 0, 0,       0,
                                           0,          0, OP_EQUAL};
        BOOST_CHECK(CScript(direct, direct + sizeof(direct)).IsPayToScriptHash(flags));
        BOOST_CHECK(!CScript(direct, direct + sizeof(direct)).IsPayToPubKeyHash());
        BOOST_CHECK_EQUAL(CScript(direct32, direct32 + sizeof(direct32)).IsPayToScriptHash(flags), is_p2sh_32);
        BOOST_CHECK(!CScript(direct32, direct32 + sizeof(direct32)).IsPayToPubKeyHash());
        static const uint8_t pushdata1[] = {OP_HASH160, OP_PUSHDATA1,
                                            20,         0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          OP_EQUAL};
        static const uint8_t pushdata1_32[] = {OP_HASH160, OP_PUSHDATA1,
                                               32,         0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          OP_EQUAL};
        BOOST_CHECK(
            !CScript(pushdata1, pushdata1 + sizeof(pushdata1)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata1, pushdata1 + sizeof(pushdata1)).IsPayToPubKeyHash());
        BOOST_CHECK(
            !CScript(pushdata1_32, pushdata1_32 + sizeof(pushdata1_32)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata1_32, pushdata1_32 + sizeof(pushdata1_32)).IsPayToPubKeyHash());
        static const uint8_t pushdata2[] = {OP_HASH160, OP_PUSHDATA2,
                                            20,         0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            OP_EQUAL};
        static const uint8_t pushdata2_32[] = {OP_HASH160, OP_PUSHDATA2,
                                               32,         0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               OP_EQUAL};
        BOOST_CHECK(
            !CScript(pushdata2, pushdata2 + sizeof(pushdata2)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata2, pushdata2 + sizeof(pushdata2)).IsPayToPubKeyHash());
        BOOST_CHECK(
            !CScript(pushdata2_32, pushdata2_32 + sizeof(pushdata2_32)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata2_32, pushdata2_32 + sizeof(pushdata2_32)).IsPayToPubKeyHash());
        static const uint8_t pushdata4[] = {OP_HASH160, OP_PUSHDATA4,
                                            20,         0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            0,          0,
                                            OP_EQUAL};
        static const uint8_t pushdata4_32[] = {OP_HASH160, OP_PUSHDATA4,
                                               20,         0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               0,          0,
                                               OP_EQUAL};
        BOOST_CHECK(
            !CScript(pushdata4, pushdata4 + sizeof(pushdata4)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata4, pushdata4 + sizeof(pushdata4)).IsPayToPubKeyHash());
        BOOST_CHECK(
            !CScript(pushdata4_32, pushdata4_32 + sizeof(pushdata4_32)).IsPayToScriptHash(flags));
        BOOST_CHECK(
            !CScript(pushdata4_32, pushdata4_32 + sizeof(pushdata4_32)).IsPayToPubKeyHash());

        CScript not_p2sh;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        not_p2sh.clear();
        not_p2sh << OP_HASH160 << dummy << dummy
                 << OP_EQUAL;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        not_p2sh.clear();
        not_p2sh << OP_HASH256 << dummy << dummy
                 << OP_EQUAL;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        not_p2sh.clear();
        not_p2sh << OP_NOP << dummy << OP_EQUAL;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        not_p2sh.clear();
        not_p2sh << OP_HASH160 << dummy << OP_CHECKSIG;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        not_p2sh.clear();
        not_p2sh << OP_HASH256 << dummy << OP_CHECKSIG;
        BOOST_CHECK(!not_p2sh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2sh.IsPayToPubKeyHash());

        // lastly, check p2pkh
        CScript p2pkh;
        p2pkh << OP_DUP << OP_HASH160 << dummy << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(!p2pkh.IsPayToScriptHash(flags));
        BOOST_CHECK(p2pkh.IsPayToPubKeyHash());
        // break p2pkh by erasing the 10th byte
        p2pkh.erase(p2pkh.begin() + 10);
        BOOST_CHECK(!p2pkh.IsPayToScriptHash(flags));
        BOOST_CHECK(!p2pkh.IsPayToPubKeyHash());

        CScript not_p2pkh;
        not_p2pkh << OP_DUP << OP_HASH160 << dummy32 << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(!not_p2pkh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2pkh.IsPayToPubKeyHash());

        not_p2pkh.clear();
        not_p2pkh << OP_DUP << OP_HASH256 << dummy32 << OP_EQUALVERIFY << OP_CHECKSIG;
        BOOST_CHECK(!not_p2pkh.IsPayToScriptHash(flags));
        BOOST_CHECK(!not_p2pkh.IsPayToPubKeyHash());
    }
}

BOOST_AUTO_TEST_CASE(switchover) {
    // This tests p2sh_20 and p2sh_32 as well.
    for (const bool is_p2sh_32 : {false, true}) {
        // Test switch over code
        CScript notValid;
        ScriptError err;
        notValid << OP_11 << OP_12 << OP_EQUALVERIFY;
        CScript scriptSig;
        scriptSig << Serialize(notValid);

        CScript fund = GetScriptForDestination(ScriptID(notValid, is_p2sh_32));

        // Validation should succeed under old rules (hash is correct):
        BOOST_CHECK(Verify(scriptSig, fund, false, err, is_p2sh_32));
        BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
        // Fail under new:
        BOOST_CHECK(!Verify(scriptSig, fund, true, err, is_p2sh_32));
        BOOST_CHECK_MESSAGE(err == ScriptError::EQUALVERIFY,
                            ScriptErrorString(err));
    }
}

BOOST_AUTO_TEST_CASE(AreInputsStandard) {
    const bool targetedVmLimitsEnabled = false; /* Use legacy VM limits for this test. */
    // This tests p2sh_20 and p2sh_32 as well.
    for (const bool is_p2sh_32 : {false, true}) {
        const uint32_t flags = is_p2sh_32 ? STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32
                                          : STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32;

        LOCK(cs_main);
        CCoinsView coinsDummy;
        CCoinsViewCache coins(&coinsDummy);
        CBasicKeyStore keystore;
        CKey key[6];
        std::vector<CPubKey> keys;
        for (int i = 0; i < 6; i++) {
            key[i].MakeNewKey(true);
            BOOST_CHECK(keystore.AddKey(key[i]));
        }
        for (int i = 0; i < 3; i++) {
            keys.push_back(key[i].GetPubKey());
        }

        CMutableTransaction txFrom;
        txFrom.vout.resize(4);

        // First three are standard:
        CScript pay1 = GetScriptForDestination(key[0].GetPubKey().GetID());
        BOOST_CHECK(keystore.AddCScript(pay1, is_p2sh_32, targetedVmLimitsEnabled));
        CScript pay1of3 = GetScriptForMultisig(1, keys);

        // P2SH (OP_CHECKSIG)
        txFrom.vout[0].scriptPubKey = GetScriptForDestination(ScriptID(pay1, is_p2sh_32));
        txFrom.vout[0].nValue = 1000 * SATOSHI;
        // ordinary OP_CHECKSIG
        txFrom.vout[1].scriptPubKey = pay1;
        txFrom.vout[1].nValue = 2000 * SATOSHI;
        // ordinary OP_CHECKMULTISIG
        txFrom.vout[2].scriptPubKey = pay1of3;
        txFrom.vout[2].nValue = 3000 * SATOSHI;

        // vout[3] is complicated 1-of-3 AND 2-of-3
        // ... that is OK if wrapped in P2SH:
        CScript oneAndTwo;
        oneAndTwo << OP_1 << key[0].GetPubKey()
                  << key[1].GetPubKey()
                  << key[2].GetPubKey();
        oneAndTwo << OP_3 << OP_CHECKMULTISIGVERIFY;
        oneAndTwo << OP_2 << key[3].GetPubKey()
                  << key[4].GetPubKey()
                  << key[5].GetPubKey();
        oneAndTwo << OP_3 << OP_CHECKMULTISIG;
        BOOST_CHECK(keystore.AddCScript(oneAndTwo, is_p2sh_32, targetedVmLimitsEnabled));
        txFrom.vout[3].scriptPubKey = GetScriptForDestination(ScriptID(oneAndTwo, is_p2sh_32));
        txFrom.vout[3].nValue = 4000 * SATOSHI;

        AddCoins(coins, CTransaction(txFrom), 0);

        CMutableTransaction txTo;
        txTo.vout.resize(1);
        txTo.vout[0].scriptPubKey = GetScriptForDestination(key[1].GetPubKey().GetID());

        txTo.vin.resize(5);
        for (int i = 0; i < 5; i++) {
            txTo.vin[i].prevout = COutPoint(txFrom.GetId(), i);
        }

        auto const null_context = std::nullopt; // It is Ok to have a null context here (not using SIGHASH_UTXOS)
        BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 0,
                                  SigHashType().withFork(), flags, null_context));
        BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 1,
                                  SigHashType().withFork(), flags, null_context));
        BOOST_CHECK(SignSignature(keystore, CTransaction(txFrom), txTo, 2,
                                  SigHashType().withFork(), flags, null_context));
    }
}

BOOST_AUTO_TEST_SUITE_END()
