// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/ismine.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sighashtype.h>
#include <script/sign.h>
#include <script/standard.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_FIXTURE_TEST_SUITE(multisig_tests, BasicTestingSetup)

static CScript sign_multisig(const CScript &scriptPubKey,
                             const std::vector<CKey> &keys,
                             const CMutableTransaction &tx, int whichIn) {
    const CTxOut fakeUtxo{Amount::zero(), scriptPubKey};
    const ScriptExecutionContext limitedContext{unsigned(whichIn), fakeUtxo, tx};
    uint256 hash = SignatureHash(scriptPubKey, limitedContext, SigHashType(), nullptr, STANDARD_SCRIPT_VERIFY_FLAGS).signatureHash;

    CScript result;
    // CHECKMULTISIG bug workaround
    result << OP_0;
    for (const CKey &key : keys) {
        std::vector<uint8_t> vchSig;
        BOOST_CHECK(key.SignECDSA(hash, vchSig));
        vchSig.push_back(uint8_t(SIGHASH_ALL));
        result << vchSig;
    }
    return result;
}

BOOST_AUTO_TEST_CASE(multisig_verify) {
    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC;

    ScriptError err;
    CKey key[4];
    Amount amount = Amount::zero();
    for (int i = 0; i < 4; i++) {
        key[i].MakeNewKey(true);
    }

    CScript a_and_b;
    a_and_b << OP_2 << key[0].GetPubKey()
            << key[1].GetPubKey() << OP_2 << OP_CHECKMULTISIG;

    CScript a_or_b;
    a_or_b << OP_1 << key[0].GetPubKey()
           << key[1].GetPubKey() << OP_2 << OP_CHECKMULTISIG;

    CScript escrow;
    escrow << OP_2 << key[0].GetPubKey()
           << key[1].GetPubKey()
           << key[2].GetPubKey() << OP_3 << OP_CHECKMULTISIG;

    // Funding transaction
    CMutableTransaction txFrom;
    txFrom.vout.resize(3);
    txFrom.vout[0].scriptPubKey = a_and_b;
    txFrom.vout[1].scriptPubKey = a_or_b;
    txFrom.vout[2].scriptPubKey = escrow;

    // Spending transaction
    CMutableTransaction txTo[3];
    for (int i = 0; i < 3; i++) {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0].prevout = COutPoint(txFrom.GetId(), i);
        txTo[i].vout[0].nValue = SATOSHI;
    }

    std::vector<CKey> keys;
    CScript s;

    // Test a AND b:
    keys.assign(1, key[0]);
    keys.push_back(key[1]);
    s = sign_multisig(a_and_b, keys, txTo[0], 0);
    BOOST_CHECK(VerifyScript(s, a_and_b, flags,
                             TransactionSignatureChecker(ScriptExecutionContext{0, CTxOut(amount, a_and_b), txTo[0]}),
                             &err));
    BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));

    for (int i = 0; i < 4; i++) {
        keys.assign(1, key[i]);
        s = sign_multisig(a_and_b, keys, txTo[0], 0);
        BOOST_CHECK_MESSAGE( ! VerifyScript(s, a_and_b, flags,
                                            TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                               CTxOut(amount, a_and_b),
                                                                                               txTo[0]}),
                                            &err),
            strprintf("a&b 1: %d", i));
        BOOST_CHECK_MESSAGE(err == ScriptError::INVALID_STACK_OPERATION, ScriptErrorString(err));

        keys.assign(1, key[1]);
        keys.push_back(key[i]);
        s = sign_multisig(a_and_b, keys, txTo[0], 0);
        BOOST_CHECK_MESSAGE( ! VerifyScript(s, a_and_b, flags,
                                            TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                               CTxOut(amount, a_and_b),
                                                                                               txTo[0]}),
                                            &err),
            strprintf("a&b 2: %d", i));
        BOOST_CHECK_MESSAGE(err == ScriptError::EVAL_FALSE, ScriptErrorString(err));
    }

    // Test a OR b:
    for (int i = 0; i < 4; i++) {
        keys.assign(1, key[i]);
        s = sign_multisig(a_or_b, keys, txTo[1], 0);
        if (i == 0 || i == 1) {
            BOOST_CHECK_MESSAGE(VerifyScript(s, a_or_b, flags,
                                             TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                                CTxOut(amount, a_or_b),
                                                                                                txTo[1]}),
                                             &err),
                                strprintf("a|b: %d", i));
            BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
        } else {
            BOOST_CHECK_MESSAGE( ! VerifyScript(s, a_or_b, flags,
                                                TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                                   CTxOut(amount, a_or_b),
                                                                                                   txTo[1]}),
                                                &err),
                                strprintf("a|b: %d", i));
            BOOST_CHECK_MESSAGE(err == ScriptError::EVAL_FALSE, ScriptErrorString(err));
        }
    }
    s.clear();
    s << OP_0 << OP_1;
    BOOST_CHECK( ! VerifyScript(s, a_or_b, flags, TransactionSignatureChecker(ScriptExecutionContext{0, CTxOut(amount, a_or_b), txTo[1]}),
                                                                              &err));
    BOOST_CHECK_MESSAGE(err == ScriptError::SIG_DER, ScriptErrorString(err));

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keys.assign(1, key[i]);
            keys.push_back(key[j]);
            s = sign_multisig(escrow, keys, txTo[2], 0);
            if (i < j && i < 3 && j < 3) {
                BOOST_CHECK_MESSAGE(VerifyScript(s, escrow, flags,
                                                 TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                                    CTxOut(amount, escrow),
                                                                                                    txTo[2]}),
                                                 &err),
                    strprintf("escrow 1: %d %d", i, j));
                BOOST_CHECK_MESSAGE(err == ScriptError::OK, ScriptErrorString(err));
            } else {
                BOOST_CHECK_MESSAGE( ! VerifyScript(s, escrow, flags,
                                                    TransactionSignatureChecker(ScriptExecutionContext{0,
                                                                                                       CTxOut(amount, escrow),
                                                                                                       txTo[2]}),
                                                    &err),
                    strprintf("escrow 2: %d %d", i, j));
                BOOST_CHECK_MESSAGE(err == ScriptError::EVAL_FALSE, ScriptErrorString(err));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(multisig_IsStandard) {
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_P2SH_32; // no p2sh_32

    CKey key[4];
    for (int i = 0; i < 4; i++) {
        key[i].MakeNewKey(true);
    }

    txnouttype whichType;

    CScript a_and_b;
    a_and_b << OP_2 << key[0].GetPubKey()
            << key[1].GetPubKey() << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(a_and_b, whichType, flags));

    CScript a_or_b;
    a_or_b << OP_1 << key[0].GetPubKey()
           << key[1].GetPubKey() << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(a_or_b, whichType, flags));

    CScript escrow;
    escrow << OP_2 << key[0].GetPubKey()
           << key[1].GetPubKey()
           << key[2].GetPubKey() << OP_3 << OP_CHECKMULTISIG;
    BOOST_CHECK(::IsStandard(escrow, whichType, flags));

    CScript one_of_four;
    one_of_four << OP_1 << key[0].GetPubKey()
                << key[1].GetPubKey()
                << key[2].GetPubKey()
                << key[3].GetPubKey() << OP_4 << OP_CHECKMULTISIG;
    BOOST_CHECK(!::IsStandard(one_of_four, whichType, flags));

    CScript malformed[6];
    malformed[0] << OP_3 << key[0].GetPubKey()
                 << key[1].GetPubKey() << OP_2
                 << OP_CHECKMULTISIG;
    malformed[1] << OP_2 << key[0].GetPubKey()
                 << key[1].GetPubKey() << OP_3
                 << OP_CHECKMULTISIG;
    malformed[2] << OP_0 << key[0].GetPubKey()
                 << key[1].GetPubKey() << OP_2
                 << OP_CHECKMULTISIG;
    malformed[3] << OP_1 << key[0].GetPubKey()
                 << key[1].GetPubKey() << OP_0
                 << OP_CHECKMULTISIG;
    malformed[4] << OP_1 << key[0].GetPubKey()
                 << key[1].GetPubKey() << OP_CHECKMULTISIG;
    malformed[5] << OP_1 << key[0].GetPubKey()
                 << key[1].GetPubKey();

    for (int i = 0; i < 6; i++) {
        BOOST_CHECK(!::IsStandard(malformed[i], whichType, flags));
    }
}

BOOST_AUTO_TEST_CASE(multisig_Sign) {
    // Test SignSignature() (and therefore the version of Solver() that signs transactions)
    // We add some special cases that are in particular gotchas or of interest for Schnorr multisignatures.
    // We also test signing the same inputs both with ECDSA and Schnorr, for belt-and-suspenders.
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS;
    CBasicKeyStore keystore, keystore_0_7, keystore_0_3_8, keystore_15;
    std::array<CKey, 20> key;
    for (size_t i = 0; i < key.size(); ++i) {
        auto & k = key.at(i);
        k.MakeNewKey(true);
        BOOST_REQUIRE(k.IsValid());
        BOOST_CHECK(keystore.AddKey(k));
        // Add only some keys to keystore so as to selectively sign for only certain pubkeys for cases 4, 5, and 6 below
        if (i == 0 || i == 7) BOOST_CHECK(keystore_0_7.AddKey(k));
        if (i == 0 || i == 3 || i == 8) BOOST_CHECK(keystore_0_3_8.AddKey(k));
        if (i == 15) BOOST_CHECK(keystore_15.AddKey(k));
    }

    CScript a_and_b;
    a_and_b << OP_2 << key.at(0).GetPubKey() << key.at(1).GetPubKey() << OP_2 << OP_CHECKMULTISIG;

    CScript a_or_b;
    a_or_b << OP_1 << key.at(0).GetPubKey() << key.at(1).GetPubKey() << OP_2 << OP_CHECKMULTISIG;

    CScript escrow;
    escrow << OP_2 << key.at(0).GetPubKey() << key.at(1).GetPubKey() << key.at(2).GetPubKey() << OP_3 << OP_CHECKMULTISIG;

    // Case 4: Schorr bitfield: single-byte case for 0x81 pattern (bit 0 and bit 7); this tests the OP_1NEGATE corner case
    CScript spk_2_of_8;
    spk_2_of_8 << OP_2;
    for (size_t i = 0; i < 8; ++i) {
        spk_2_of_8 << key.at(i).GetPubKey();
    }
    spk_2_of_8 << OP_8 << OP_CHECKMULTISIG;

    // Case 5: Schnorr bitfield: 2-byte case, bits 0,3,8 set
    CScript spk_3_of_9;
    spk_3_of_9 << OP_3;
    for (size_t i = 0; i < 9; ++i) {
        spk_3_of_9 << key.at(i).GetPubKey();
    }
    spk_3_of_9 << OP_9 << OP_CHECKMULTISIG;

    // Case 6: Schnorr bitfield: 2-byte case, only last bit set
    CScript spk_1_of_16;
    spk_1_of_16 << OP_1;
    for (size_t i = 0; i < 16; ++i) {
        spk_1_of_16 << key.at(i).GetPubKey();
    }
    spk_1_of_16 << OP_16 << OP_CHECKMULTISIG;

    // Funding transaction
    CTransaction txFrom{[&]{
        CMutableTransaction ret;
        ret.vout.resize(6, CTxOut(SATOSHI, {}));
        ret.vout[0].scriptPubKey = a_and_b;
        ret.vout[1].scriptPubKey = a_or_b;
        ret.vout[2].scriptPubKey = escrow;
        ret.vout[3].scriptPubKey = spk_2_of_8;
        ret.vout[4].scriptPubKey = spk_3_of_9;
        ret.vout[5].scriptPubKey = spk_1_of_16;
        return ret;
    }()};

    // Spending transactions
    std::array<CMutableTransaction, 6> txTo;
    for (size_t i = 0; i < txTo.size(); ++i) {
        txTo[i].vin.resize(1);
        txTo[i].vout.resize(1);
        txTo[i].vin[0].prevout = COutPoint(txFrom.GetId(), i);
        txTo[i].vout[0].nValue = SATOSHI;
    }

    auto const null_context = std::nullopt;
    for (const bool schnorr : {false, true}) { // test signing both Schnorr and ECDSA
        CMutableTransaction txToCopy;
        for (size_t i = 0; i < 3; ++i) {
            txToCopy = txTo.at(i);
            BOOST_CHECK_MESSAGE(SignSignature(keystore, txFrom, txToCopy, 0, SigHashType().withFork(),
                                              flags, null_context, schnorr),
                                strprintf("SignSignature case %d: schnorr: %i, sig: %s",
                                          i, schnorr, HexStr(txToCopy.vin[0].scriptSig)));
        }
        auto flagsCopy = flags;
        if (!schnorr) {
            // Disable input sigcheck limit for these for ECDSA since they would fail with this limit in place (due to
            // the way ECDSA multisig whereby it keeps trying all sigs against all remaining pubkeys).
            flagsCopy &= ~SCRIPT_VERIFY_INPUT_SIGCHECKS;
        }
        // Case 4:
        txToCopy = txTo.at(3);
        BOOST_CHECK_MESSAGE(SignSignature(keystore_0_7, txFrom, txToCopy, 0, SigHashType().withFork(),
                                          flagsCopy, null_context, schnorr),
                            strprintf("SignSignature case 4: schnorr bitfield '0x81' -> OP_1NEGATE, schnorr: %i, sig: %s",
                                      schnorr, HexStr(txToCopy.vin[0].scriptSig)));
        // Case 5:
        txToCopy = txTo.at(4);
        BOOST_CHECK_MESSAGE(SignSignature(keystore_0_3_8, txFrom, txToCopy, 0, SigHashType().withFork(),
                                          flagsCopy, null_context, schnorr),
                            strprintf("SignSignature case 5: 2-byte bitfield bits 0,3,8 set, schnorr: %i, sig: %s",
                                      schnorr, HexStr(txToCopy.vin[0].scriptSig)));
        // Case 6:
        txToCopy = txTo.at(5);
        BOOST_CHECK_MESSAGE(SignSignature(keystore_15, txFrom, txToCopy, 0, SigHashType().withFork(),
                                          flagsCopy, null_context, schnorr),
                            strprintf("SignSignature case 6: 2-byte bitfield bit 15 set, schnorr: %i, sig: %s",
                                      schnorr, HexStr(txToCopy.vin[0].scriptSig)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
