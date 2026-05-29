// Copyright (c) 2024-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

// to be removed once Boost 1.59+ is minimum version.
#ifndef BOOST_TEST_CONTEXT
#define BOOST_TEST_CONTEXT(x)
#endif

BOOST_FIXTURE_TEST_SUITE(vmlimits_tests, BasicTestingSetup)

namespace {

/**
 * Stand-in for proper signature check, in the absence of a proper
 * transaction context. We will use a dummy signature checker with
 * placeholder signatures / pubkeys that are correctly encoded.
 */

// First, correctly encoded ECDSA/Schnorr signatures in data/tx form.
const valtype sigecdsa = {0x30, 6, 2, 1, 0, 2, 1, 0};
const valtype txsigecdsa = {0x30, 6, 2, 1, 0, 2, 1, 0, 0x41};
const valtype sigschnorr(64);
const valtype txsigschnorr = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41
};

// An example message to use (9 bytes).
const valtype msg = {0x73, 0x69, 0x67, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x73};

// A valid pubkey
const valtype pub = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
// A special key that causes signature checks to return false (see below).
const valtype badpub = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// Some small constants with descriptive names to make the purpose clear.
const valtype nullsig = {};
const valtype vfalse = {};
const valtype vtrue = {1};

// Allows for literals e.g. "f00fb33f"_v to auto-parse to std::vector<uint8_t>
std::vector<uint8_t> operator""_v(const char *hex, size_t) { return ParseHex(hex); }

// A real context for a real blockchain txn that contains two inputs, and some token data on input 0
const std::vector<ScriptExecutionContext> realContexts = [] {
    static const CTransaction tx = [] {
        auto txdata =
            "020000000263b98b77b88dd484eef48c870cf0010ff2382905391f63104f42cb43e5908de702000000644155dece44d750d657"
            "c1aa95bffe61cd664293701aeca2289e58c6c6017091afd3c80f41848e508b0226066616ed5a9211dd0358af29de2c0d7bb971"
            "8f879871bb412103ef5d6aa43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5d00000000d53a63dc60595a"
            "f8b69217bdc979fdda465d73b9a9c042105df29ba5a1017cfa0100000064411a5d8f756eb93557274543b083f618380625e7e8"
            "3f83d7e08ee18505165ce5bb4acebce6fffcfd1220a582cff54b2e66faa2c2626977b872ef4900e245d6855e412103ef5d6aa4"
            "3de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5d0000000002e8030000000000003def91766574fa467a12"
            "b47e0ece6417c3654f579e3d4e43b2ab2d1a3c24256b4f5a60011676a9147ee7b62fa98a985c5553ff66120a91b8189f658188"
            "ace8a80000000000001976a91486403657f0c7b1789eb23472f10725061940f7b488ac00000000"_v;
        VectorReader vr(SER_NETWORK, PROTOCOL_VERSION, txdata, 0);
        return CTransaction(deserialize_type{}, vr);
    }();
    static const CTransaction prevTx0 = [] {
        auto prevtx0Data =
            "020000000348cde865126121b97b475a45fec586dadf2e5dd8cb5f93c92ba1eeb40de2c5a9000000003251302094e43e754df7"
            "598ca267bfab6cfd20adc290e8f3baa83b562f1777e4c794541051ce8851d0009d6300cdc0c7886851feffffff48cde8651261"
            "21b97b475a45fec586dadf2e5dd8cb5f93c92ba1eeb40de2c5a9010000006441a664d6d5acfa3c65f774ac55818a5d2b5a7514"
            "30e63c32c3eea2d2c974959bc507c5e3dd5f6968ff29491775a586bc020d22a2382c5477cc5c854419f2a40fff412103ef5d6a"
            "a43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dfeffffff48cde865126121b97b475a45fec586dadf2e"
            "5dd8cb5f93c92ba1eeb40de2c5a903000000644154010fd676bbff7fb5523729f6014bbbd1fed7263c890c4c6fbff747d8def4"
            "2c9587b8467400935a675ae8cfdf5d9cc2f7d740392832fb4a28fcca6b83f11a10412103ef5d6aa43de4c9bc8a1b7f2c2e325e"
            "0b9b2866782779248224be4d2c0c630f5dfeffffff04e8030000000000003bef91766574fa467a12b47e0ece6417c3654f579e"
            "3d4e43b2ab2d1a3c24256b4f5a620116a91453be7acaf98c40b09a65f0566d13939cb247e93487e8030000000000003def94e4"
            "3e754df7598ca267bfab6cfd20adc290e8f3baa83b562f1777e4c794541060010076a91486403657f0c7b1789eb23472f10725"
            "061940f7b488ace8030000000000003def91766574fa467a12b47e0ece6417c3654f579e3d4e43b2ab2d1a3c24256b4f5a6001"
            "1676a91486403657f0c7b1789eb23472f10725061940f7b488ac5e262300000000001976a91486403657f0c7b1789eb23472f1"
            "0725061940f7b488acb9970c00"_v;
        VectorReader vrPrev0(SER_NETWORK, PROTOCOL_VERSION, prevtx0Data, 0);
        return CTransaction(deserialize_type{}, vrPrev0);
    }();
    static const CTransaction prevTx1 = [] {
        auto prevtx1Data =
            "020000000504f5ae71ac435c940f67c515bd5598bfb68a05b8de7d66815ce4bd39a1ba575c000000006a47304402205b42b6b1"
            "b12e77f67151dd7491e407d9c9cee997317a0b35cec96c8429fa2536022058b5cebff9adc6332a8d9d431bfd777be93016718b"
            "08b9a59ea328f1cf63d6d1412103ef5d6aa43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dffffffffa0"
            "ab30c62115dcfbd60642c6d622cc441ca34b6501fe06d25e4cb51917db455d000000006a4730440220277ad14f4eee7948266d"
            "10669fbc25e2be6863243ce8ab0be5a3162a290b25f002203b0fa7e8f75dd47bef099e5937666dc2633abc49b550e51d0209f3"
            "723b209be9412103ef5d6aa43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dffffffff68a89c5006febe"
            "9c754f1077567205dab486998d13d1b2f118f1782a511cad94000000006b4830450221009051c9ed6436c77e6e2aa404a27a25"
            "3b06b48d5d7d38c5d3699daf1e6dffa56802203321ec3cb283a9236747c9e5f236d744be762269657358a56559c9f920ee2873"
            "412103ef5d6aa43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dffffffff22f00c75bfba62606c26245e"
            "1c30a54e026d73c34f0c4f30332e83f48f0a8eeb010000006a473044022001cf8f89fa5c0fb0d5bae095e151653910cf092aa8"
            "90ef443e2c50d6acb9fab902202b98710708f70f7c88f6920da7bb84bf7222631b28248337bdde1b9146e2716c412103ef5d6a"
            "a43de4c9bc8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dffffffff4825d0e3fe26f597249344e2fef4cca730db"
            "534d8feb8eb8894b47eeb8ce21f2010000006b483045022100dc23f31e1a3faedea4f2d819f21a776d2c3857e2e051552f0363"
            "535fd379f368022056c512a19f12bf97423a8728a4227f995c968024abc368cd58311df02fa0b6e5412103ef5d6aa43de4c9bc"
            "8a1b7f2c2e325e0b9b2866782779248224be4d2c0c630f5dffffffff026075e012000000001976a914447f4b921004503f9f0f"
            "2eb24f640a6cb35308de88ac75aa0000000000001976a91486403657f0c7b1789eb23472f10725061940f7b488ac00000000"_v;
        VectorReader vrPrev1(SER_NETWORK, PROTOCOL_VERSION, prevtx1Data, 0);
        return CTransaction(deserialize_type{}, vrPrev1);
    }();
    static const std::vector<PSBTInput> inputs = [] {
        std::vector<PSBTInput> ret;
        assert(tx.vout.size() == 2);
        ret.resize(2);
        assert(prevTx0.GetId() == tx.vin.at(0).prevout.GetTxId());
        ret[0].utxo = prevTx0.vout.at(tx.vin.at(0).prevout.GetN());
        assert(prevTx1.GetId() == tx.vin.at(1).prevout.GetTxId());
        ret[1].utxo = prevTx1.vout.at(tx.vin.at(1).prevout.GetN());
        return ret;
    }();
    return ScriptExecutionContext::createForAllInputs(tx, inputs);
}();

struct DummySigChecker : BaseSignatureChecker {
    /**
     * All null sigs verify false, and all checks using the magic 'bad pubkey'
     * value verify false as well. Otherwise, checks verify as true.
     */
    bool VerifySignature(const ByteView &vchSig,
                         const CPubKey &vchPubKey,
                         const uint256 & /* sighash */) const final {
        return !vchSig.empty() && vchPubKey != CPubKey(badpub);
    }

    bool CheckSig(const ByteView &vchSigIn,
                  const std::vector<uint8_t> &vchPubKey,
                  const ByteView &scriptCode, uint32_t /* flags */, size_t *pbytesHashed) const final {
        if (pbytesHashed) *pbytesHashed = 0u;
        if (vchSigIn.empty()) {
            return false;
        }
        if (pbytesHashed) {
            // we fake the bytes hashed as the lengths of the sig + pubkey + scriptCode
            *pbytesHashed = vchSigIn.size() + vchPubKey.size() + scriptCode.size();
        }
        return vchPubKey != badpub;
    }
};

const DummySigChecker dummysigchecker;

struct TestableScriptExecutionMetrics : ScriptExecutionMetrics {
    TestableScriptExecutionMetrics(int sigChecks = 0, int64_t opCost = 0, int64_t hashIters = 0)
        : ScriptExecutionMetrics(sigChecks, opCost, hashIters) {}
};

// construct a 'checkbits' stack element for OP_CHECKMULTISIG (set lower m bits
// to 1, but make sure it's at least n bits long).
valtype makebits(int m, int n) {
    valtype ret(0);
    uint64_t bits = (uint64_t(1) << m) - 1;
    for (; n > 0; n -= 8, bits >>= 8) {
        ret.push_back(uint8_t(bits & 0xff));
    }
    return ret;
}

// Two lists of flag sets to pass to CheckEvalScript.
const std::vector<uint32_t> allflags{
    STANDARD_SCRIPT_VERIFY_FLAGS,
    STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MAY2025 | SCRIPT_VM_LIMITS_STANDARD,
    STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MAY2025,
};

struct ExpectedCounts {
    int sigChecks;
    int64_t hashIters;
    int64_t opCostStd, opCostNonStd;

    ExpectedCounts(int sigChecksIn = 0, int64_t hashItersIn = 0, int64_t opCostStdIn = 0, int64_t opCostNonStdIn = -1)
        : sigChecks(sigChecksIn), hashIters(hashItersIn), opCostStd(opCostStdIn),
          opCostNonStd(opCostNonStdIn < 0 ? opCostStd : opCostNonStdIn) {}
};

void CheckEvalScript(const StackT &original_stack,
                     const CScript &script,
                     const StackT &expected_stack,
                     const ExpectedCounts &expected,
                     const std::vector<uint32_t> & flagset = allflags,
                     const ScriptError expect_error = ScriptError::OK) {
    for (uint32_t flags : flagset) {
        const bool expect_result = expect_error == ScriptError::OK;
        ScriptError err = ScriptError::UNKNOWN;
        StackT stack{original_stack};
        ScriptExecutionMetrics metrics;

        bool r = EvalScript(stack, script, flags, dummysigchecker, metrics, &err);
        BOOST_CHECK_EQUAL(r, expect_result);
        BOOST_CHECK_EQUAL(err, expect_error);
        BOOST_CHECK(stack == expected_stack);
        BOOST_CHECK_EQUAL(metrics.GetSigChecks(), expected.sigChecks);
        if (flags & SCRIPT_ENABLE_MAY2025) {
            BOOST_CHECK_EQUAL(metrics.GetHashDigestIterations(), expected.hashIters);
            if (flags & SCRIPT_VM_LIMITS_STANDARD) {
                BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(flags), expected.opCostStd);
            } else {
                BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(flags), expected.opCostNonStd);
            }
        }
    }
}

} // namespace

#define CHECK_EVALSCRIPT(...)  BOOST_TEST_CONTEXT(__FILE__ << ":" << __LINE__) {  CheckEvalScript(__VA_ARGS__); }

/* This test case was mostly taken from Mark Lundeberg's work in sigcheckcount_tests.cpp, but adapted to also
 * count the new opCost, hashIters, etc. */
BOOST_AUTO_TEST_CASE(test_evalscript_with_sigchecks) {
    CHECK_EVALSCRIPT({}, CScript(), {}, 0);

    const int64_t pubSz = pub.size(), msgSz = msg.size();
    CHECK_EVALSCRIPT({nullsig}, CScript() << pub << OP_CHECKSIG, {vfalse}, {0, 0, 200 + pubSz});
    CHECK_EVALSCRIPT({txsigecdsa}, CScript() << pub << OP_CHECKSIG, {vtrue}, {1, // sigchecks
                                                                              3, // hashiters
                                                                              26'000 + 201 + pubSz + 192*3, // std opcost
                                                                              26'000 + 201 + pubSz + 64*3}); // nonstd opcost
    CHECK_EVALSCRIPT({txsigschnorr}, CScript() << pub << OP_CHECKSIG, {vtrue}, {1,
                                                                                4,
                                                                                26'000 + 201 + pubSz + 192*4,
                                                                                26'000 + 201 + pubSz + 64*4});

    CHECK_EVALSCRIPT({nullsig}, CScript() << msg << pub << OP_CHECKDATASIG, {vfalse}, {0, 0, 300 + msgSz + pubSz});
    CHECK_EVALSCRIPT({sigecdsa}, CScript() << msg << pub << OP_CHECKDATASIG, {vtrue}, {1,
                                                                                       1,
                                                                                       26'000 + 301 + msgSz + pubSz + 192,
                                                                                       26'000 + 301 + msgSz + pubSz + 64});
    CHECK_EVALSCRIPT({sigschnorr}, CScript() << msg << pub << OP_CHECKDATASIG, {vtrue}, {1,
                                                                                         1,
                                                                                         26'000 + 301 + msgSz + pubSz + 192,
                                                                                         26'000 + 301 + msgSz + pubSz + 64});

    // Check all M-of-N OP_CHECKMULTISIGs combinations in all flavors.
    for (int n = 0; n <= MAX_PUBKEYS_PER_MULTISIG; ++n) {
        for (int m = 0; m <= n; ++m) {
            // first, generate the spending script
            CScript script;
            int64_t scriptOpCost = 0;
            script << ScriptInt::fromIntUnchecked(m);
            scriptOpCost += 100 + (m != 0);

            for (int i = 0; i < n; ++i) {
                script << pub;
                scriptOpCost += 100 + pub.size();
            }
            script << ScriptInt::fromIntUnchecked(n) << OP_CHECKMULTISIG;
            scriptOpCost += 200 + (n != 0);

            StackT sigs;

            // The all-null-signatures case with null dummy element counts as 0
            // sigchecks, since all signatures are null.
            sigs.assign(m + 1, {});
            sigs[0] = {};
            BOOST_TEST_MESSAGE(strprintf("M=%i N=%i", m, n));
            CHECK_EVALSCRIPT(sigs, script, {m ? vfalse : vtrue}, {0, 0, scriptOpCost + bool(!m)});

            // Check the all-null-signatures case with Schnorr multisigflags.
            // Result should be 0 sigchecks too.
            sigs.assign(m + 1, {});
            sigs[0] = {};
            BOOST_TEST_MESSAGE(strprintf("M=%i N=%i", m, n));
            CHECK_EVALSCRIPT(sigs, script, {m ? vfalse : vtrue}, {0, 0, scriptOpCost + bool(!m)});

            // The all-ECDSA-signatures case counts as N sigchecks, except when
            // M=0 (so that it counts as 'all-null-signatures" instead).
            sigs.assign(m + 1, txsigecdsa);
            sigs[0] = {};
            int nSigChecks = m ? n : 0;
            // Unlike sigchecks, which is N, ECDSA hash iters is a function of M (except in the nullsig case, where it's 0).
            int nHashIters = m ? m * (2 + ((txsigecdsa.size() + script.size() + pub.size() + 8) / 64)) : 0;
            CHECK_EVALSCRIPT(sigs, script, {vtrue}, {nSigChecks, nHashIters,
                                                     scriptOpCost + 1 + nHashIters * 192 + 26'000 * nSigChecks,
                                                     scriptOpCost + 1 + nHashIters * 64 + 26'000 * nSigChecks});

            // The all-Schnorr-signatures case counts as M sigchecks always.
            // (Note that for M=N=0, this actually produces a null dummy which
            // executes in legacy mode, but the behaviour is indistinguishable
            // from schnorr mode.)
            sigs.assign(m + 1, txsigschnorr);
            sigs[0] = makebits(m, n);
            nSigChecks = m;
            nHashIters = m * (2 + ((txsigschnorr.size() + script.size() + pub.size() + 8) / 64));
            CHECK_EVALSCRIPT(sigs, script, {vtrue}, {nSigChecks, nHashIters,
                                                     scriptOpCost + 1 + nHashIters * 192 + 26'000 * nSigChecks,
                                                     scriptOpCost + 1 + nHashIters * 64 + 26'000 * nSigChecks});
        }
    }
    CScript script;
    int scriptOpCost, hashIters;

    // repeated checks of the same signature count each time
    script = CScript() << pub << OP_2DUP << OP_CHECKSIGVERIFY << OP_CHECKSIGVERIFY;
    scriptOpCost = 402 + 2*pub.size() + txsigschnorr.size();
    hashIters = 2 + ((txsigschnorr.size() + script.size() + pub.size()) / 64);
    CHECK_EVALSCRIPT({txsigschnorr}, script, {},
                     {2, 2*hashIters, scriptOpCost + 2*hashIters*192 + 2*26'000, scriptOpCost + 2*hashIters*64 + 2*26'000});

    script =  CScript() << msg << pub << OP_3DUP << OP_CHECKDATASIGVERIFY << OP_CHECKDATASIGVERIFY;
    scriptOpCost = 502 + 2*msg.size() + 2*pub.size() + sigschnorr.size();
    hashIters = 1 + ((msg.size() + 8) / 64);
    CHECK_EVALSCRIPT({sigschnorr}, script, {}, {2, 2*hashIters,
                                                scriptOpCost + 2*hashIters*192 + 2*26'000,
                                                scriptOpCost + 2*hashIters*64 + 2*26'000});

    // unexecuted checks (behind if-branches) don't count.
    {
        script = CScript() << OP_IF << pub << OP_CHECKSIG << OP_ELSE << OP_DROP << OP_ENDIF;
        scriptOpCost = 600 + pub.size();
        CHECK_EVALSCRIPT({txsigecdsa, {1}}, script, {vtrue}, {1, 3, scriptOpCost + 3*192 + 26'000 + 1, scriptOpCost + 3*64 + 26'000 + 1});
        CHECK_EVALSCRIPT({txsigecdsa, {0}}, script, {}, {0, 0, 600});
    }

    // Without NULLFAIL, it is possible to have checksig/checkmultisig consume
    // CPU using non-null signatures and then return false to the stack, without
    // failing. Make sure that this historical case adds sigchecks, so that the
    // CPU usage of possible malicious alternate histories (branching off before
    // NULLFAIL activated in consensus) can be limited.
    CHECK_EVALSCRIPT({txsigecdsa}, CScript() << badpub << OP_CHECKSIG, {vfalse},
                     {1, 3, 200 + int(badpub.size()) + 26'000 + 3*64},
                     {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025});
    hashIters = 4 * (2 + (txsigecdsa.size() + badpub.size() + (1 + (1+badpub.size())*4 + 1 + 1) + 8) / 64);
    CHECK_EVALSCRIPT({{}, txsigecdsa},
                     CScript() << ScriptInt::fromIntUnchecked(1)
                               << badpub << badpub << badpub << badpub
                               << ScriptInt::fromIntUnchecked(4)
                               << OP_CHECKMULTISIG,
                     {vfalse},
                     {4, hashIters, 702 + int(badpub.size())*4 + hashIters*64 + 4*26'000},
                     {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025});

    // CHECKDATASIG and Schnorr need to be checked as well, since they have been
    // made retroactively valid since forever and thus alternate histories could
    // include them.
    hashIters = 1 + (msg.size() + 8)/64;
    CHECK_EVALSCRIPT({sigecdsa}, CScript() << msg << badpub << OP_CHECKDATASIG,
                     {vfalse},
                     {1, hashIters, 300 + int(msg.size() + badpub.size()) + 26'000 + hashIters*64},
                     {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025});
    hashIters = 2 + (txsigschnorr.size() + badpub.size()*2 + 2 + 8) / 64;
    CHECK_EVALSCRIPT({txsigschnorr}, CScript() << badpub << OP_CHECKSIG,
                     {vfalse},
                     {1, hashIters, 200 + int(badpub.size()) + hashIters*64 + 26'000},
                     {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025});
    hashIters = 1 + (msg.size() + 8) / 64;
    CHECK_EVALSCRIPT({sigschnorr}, CScript() << msg << badpub << OP_CHECKDATASIG,
                     {vfalse},
                     {1, hashIters, 300 + int(msg.size() + badpub.size()) + 26'000 + 64*hashIters},
                     {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025});

    // CHECKMULTISIG with schnorr cannot return false, it just fails instead
    // (hence, the sigchecks count is unimportant)
    {
        StackT stack{{1}, txsigschnorr}, expectstack{{1}, txsigschnorr, {1}, badpub, {1}};
        script = CScript() << ScriptInt::fromIntUnchecked(1) << badpub << ScriptInt::fromIntUnchecked(1) << OP_CHECKMULTISIG;
        CHECK_EVALSCRIPT(stack, script, expectstack,
                         {0, 0, 402 + int(badpub.size())},
                         {SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025}, ScriptError::SIG_BADLENGTH);
    }
    {
        StackT stack{{1}, txsigschnorr}, expectstack{{1}, txsigschnorr, {1}, badpub, {1}};
        script = CScript() << ScriptInt::fromIntUnchecked(1) << badpub << ScriptInt::fromIntUnchecked(1) << OP_CHECKMULTISIG;
        CHECK_EVALSCRIPT(stack, script, expectstack,
                         {0, 0, 402 + int(badpub.size())},
                         {SCRIPT_ENABLE_SCHNORR_MULTISIG|SCRIPT_ENABLE_MAY2025}, ScriptError::SIG_NULLFAIL);
    }

    // EvalScript cumulatively increases the sigchecks count.
    {
        StackT stack{txsigschnorr};
        TestableScriptExecutionMetrics metrics(12345, 6789, 101112);
        const auto flags = SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025;
        bool r = EvalScript(stack, CScript() << pub << OP_CHECKSIG, flags, dummysigchecker, metrics);
        BOOST_CHECK(r);
        hashIters = 2 + (txsigschnorr.size() + pub.size()*2 + 2 + 8) / 64;
        scriptOpCost = 201 + pub.size() + hashIters*64;
        BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 12346);
        BOOST_CHECK_EQUAL(metrics.GetHashDigestIterations(), 101112 + hashIters);
        BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 6789 + 201 + pub.size());
        BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(flags), 6789 + scriptOpCost + 101112*64 + 12346*26'000);
    }

    // Other opcodes may be cryptographic and/or CPU intensive, but they do not
    // add any additional sigchecks.
    static_assert(
        (MAX_SCRIPT_SIZE <= 10000 && MAX_OPS_PER_SCRIPT_LEGACY <= 201 &&
         MAX_STACK_SIZE <= 1000 && MAX_SCRIPT_ELEMENT_SIZE_LEGACY <= 520),
        "These can be made far worse with higher limits. Update accordingly.");

    // Hashing operations on the largest stack element.
    {
        valtype bigblob(MAX_SCRIPT_ELEMENT_SIZE_LEGACY);
        scriptOpCost = 1500 + bigblob.size()*5 + 20*3 + 32*2 + 52 + 84 + 104 + 124;
        hashIters = 2 + (1 + (bigblob.size() + 8) / 64) * 5;
        CHECK_EVALSCRIPT({},
                        CScript()
                            << bigblob << OP_RIPEMD160 << bigblob << OP_SHA1
                            << bigblob << OP_SHA256 << bigblob << OP_HASH160
                            << bigblob << OP_HASH256 << OP_CAT << OP_CAT
                            << OP_CAT << OP_CAT << OP_DROP,
                        {}, {0, hashIters, scriptOpCost + hashIters*192, scriptOpCost + hashIters*64});
    }

    // OP_ROLL grinding, see
    // https://bitslog.com/2017/04/17/new-quadratic-delays-in-bitcoin-scripts/
    {
        StackT bigstack;
        bigstack.assign(999, {1});
        script = CScript();
        scriptOpCost = 0;
        for (int i = 0; i < 200; ++i) {
            script << ScriptInt::fromIntUnchecked(998) << OP_ROLL;
            scriptOpCost += 202 + bigstack.front().size() + 998;
        }
        CHECK_EVALSCRIPT(bigstack, script, bigstack, {0, 0, scriptOpCost});
    }

    // OP_IF grinding, see
    // https://bitslog.com/2017/04/17/new-quadratic-delays-in-bitcoin-scripts/
    for (int extraDepth = 0; extraDepth < 3; ++extraDepth) {
        script = CScript() << ScriptInt::fromIntUnchecked(0);
        scriptOpCost = 100;
        for (int i = 0; i < 100 + extraDepth; ++i) {
            script << OP_IF;
            if (i <= 100) scriptOpCost += 100;
        }
        for (int i = 0; i < 9798 - (extraDepth * 3); ++i) {
            script << ScriptInt::fromIntUnchecked(0);
            if (!extraDepth) scriptOpCost += 100;
        }
        for (int i = 0; i < 100 + extraDepth; ++i) {
            script << OP_ENDIF;
            if (!extraDepth) scriptOpCost += 100;
        }
        script << ScriptInt::fromIntUnchecked(1);
        if (!extraDepth) scriptOpCost += 101;
        StackT expectedStack;
        if (!extraDepth) expectedStack = {vtrue};
        CHECK_EVALSCRIPT({}, script, expectedStack, {0, 0, scriptOpCost},
                         {STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MAY2025},
                         !extraDepth ? ScriptError::OK : ScriptError::CONDITIONAL_STACK_DEPTH);
    }

    // OP_CODESEPARATOR grinding, see
    // https://gist.github.com/markblundeberg/c2c88d25d5f34213830e48d459cbfb44
    // (this is a simplified form)
    {
        StackT stack;
        stack.assign(94, txsigecdsa);
        script = CScript();
        scriptOpCost = 0;
        hashIters = 0;
        int scriptCodeBegin = 0, scriptCodeEnd = 9666;
        for (int i = 0; i < 94; ++i) {
            script << pub << OP_CHECKSIGVERIFY << OP_CODESEPARATOR;
            scriptOpCost += 100 + pub.size() + 201;
            hashIters += 2 + (pub.size() + txsigecdsa.size() + (scriptCodeEnd-scriptCodeBegin) + 8) / 64;
            scriptCodeBegin = script.size();
        }
        // (remove last codesep)
        script.pop_back();
        scriptOpCost -= 100;
        // Push some garbage to lengthen the script.
        valtype bigblob(520);
        for (int i = 0; i < 6; ++i) {
            script << bigblob << bigblob << OP_2DROP;
            scriptOpCost += 300 + bigblob.size()*2;
        }
        script << ScriptInt::fromIntUnchecked(1);
        scriptOpCost += 101;
        BOOST_CHECK_EQUAL(script.size(), 9666);
        CHECK_EVALSCRIPT(stack, script, {vtrue}, {94, hashIters,
                                                  scriptOpCost + 94*26'000 + 192*hashIters,
                                                  scriptOpCost + 94*26'000 + 64*hashIters});
    }
}

namespace {
void CheckVerifyScript(CScript scriptSig, CScript scriptPubKey, uint32_t flags, int expected_sigchecks,
                       int expected_hashiters = 0, int expected_opcost = 0) {
    TestableScriptExecutionMetrics metricsRet(12345 ^ expected_sigchecks, expected_opcost ^ 12345, expected_hashiters ^ 12345);
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, flags, dummysigchecker, metricsRet));
    BOOST_CHECK_EQUAL(metricsRet.GetSigChecks(), expected_sigchecks);
    if (flags & SCRIPT_ENABLE_MAY2025) {
        BOOST_CHECK_EQUAL(metricsRet.GetHashDigestIterations(), expected_hashiters);
        BOOST_CHECK_EQUAL(metricsRet.GetCompositeOpCost(flags), expected_opcost);
    }
}
} // namespace

#define CHECK_VERIFYSCRIPT(...)                                                \
    BOOST_TEST_CONTEXT(__FILE__ << ":" << __LINE__) {                          \
        CheckVerifyScript(__VA_ARGS__);                                        \
    }

BOOST_AUTO_TEST_CASE(test_verifyscript) {
    // make sure that verifyscript is correctly resetting and accumulating
    // sigchecks for the input.

    // Simplest example
    CHECK_VERIFYSCRIPT(CScript() << OP_1, CScript(), SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025, 0, 0, 101);

    // Common example
    int hashIters, opCost;
    hashIters = 2 + (sigschnorr.size() + pub.size()*2 + 2 + 8)/64;
    opCost = 100 + sigschnorr.size() + 100 + pub.size() + 100 + hashIters*64 + 26'000 + 1;
    CHECK_VERIFYSCRIPT(CScript() << sigschnorr, CScript() << pub << OP_CHECKSIG, SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025,
                       1, hashIters, opCost);

    // Correct behaviour occurs for segwit recovery special case (which returns
    // success from an alternative location)
    CScript swscript;
    swscript << OP_0 << std::vector<uint8_t>(20);
    hashIters = 2 + (swscript.size() + 8) / 64;
    opCost = 100 + swscript.size() + 300 + 20 + 64*hashIters + 20 + 1;
    CHECK_VERIFYSCRIPT(CScript() << ByteView(swscript),
                       CScript()
                           << OP_HASH160 << ScriptID(swscript, false /*=p2sh_20*/)
                           << OP_EQUAL,
                       SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CLEANSTACK | SCRIPT_ENABLE_MAY2025,
                       0, hashIters, opCost);

    // If signature checks somehow occur in scriptsig, they do get counted.
    // This can happen in historical blocks pre SIGPUSHONLY, even with CHECKSIG.
    // (an analogous check for P2SH is not possible since it enforces
    // sigpushonly).
    hashIters = 2 * (1 + (msg.size() + 8) / 64);
    opCost =   400 + sigschnorr.size() + msg.size() + pub.size() + 1 /* scriptSig */
             + 400 + sigecdsa.size() + msg.size() + pub.size() + 1 /* scriptPubKey */
             + 2*26'000 + 64*hashIters; /* composite cost from hashing and signing */
    CHECK_VERIFYSCRIPT(CScript() << sigschnorr << msg << pub
                                 << OP_CHECKDATASIG /* scriptSig */,
                       CScript() << sigecdsa << msg << pub
                                 << OP_CHECKDATASIGVERIFY /* scriptPubKey */,
                       SCRIPT_VERIFY_NONE|SCRIPT_ENABLE_MAY2025, 2, hashIters, opCost);
}

// Test the expected sigcheck, opcost, and hastIters counts for each opcode individually.
// See: https://github.com/bitjson/bch-vm-limits/tree/master?tab=readme-ov-file#operation-cost-by-operation
BOOST_AUTO_TEST_CASE(test_individual_opcode_counts) {
    struct Test {
        int line;
        const char *debugSnippet;
        StackT stack;
        CScript script;
        StackT expectedStack;
        int sigChecks;
        int64_t hashIters;
        int64_t opCost;
        bool expectedResult = true;
        const BaseSignatureChecker *checker = &dummysigchecker;
    };

    std::vector<TransactionSignatureChecker> realTxCheckers;
    for (const auto &context : realContexts) {
        realTxCheckers.emplace_back(context);
    }
    BOOST_REQUIRE_EQUAL(realTxCheckers.size(), 2);

    auto Append = [](const auto &a, const auto &b) {
        auto ret = a;
        ret.push_back(b);
        return ret;
    };

    const uint32_t flags = (STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_TOKENS | SCRIPT_ENABLE_P2SH_32
                            | SCRIPT_ENABLE_MAY2025 | SCRIPT_VM_LIMITS_STANDARD)
                           & ~SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

    auto ScriptToStack = [](const CScript &script) -> StackT {
        StackT ret;
        EvalScript(ret, script, flags, dummysigchecker);
        return ret;
    };

    auto ToVec = [](const auto &container) -> valtype { return valtype(container.begin(), container.end()); };
#define ToStr__(...) #__VA_ARGS__
#define ToStr_(...) ToStr__(__VA_ARGS__)
#define MkT(...) Test{__LINE__, ToStr_(__VA_ARGS__), __VA_ARGS__}
    // opcode-level tests; we expect a certain cost, stack state, etc after the script in quetion is evaluated.
    Test tests[] = {
        // OP_N
        MkT({}, CScript() << OP_0, {CScriptNum::fromIntUnchecked(0).getvch()}, 0, 0, 100),
        MkT({}, CScript() << OP_1, {CScriptNum::fromIntUnchecked(1).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_2, {CScriptNum::fromIntUnchecked(2).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_3, {CScriptNum::fromIntUnchecked(3).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_4, {CScriptNum::fromIntUnchecked(4).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_5, {CScriptNum::fromIntUnchecked(5).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_6, {CScriptNum::fromIntUnchecked(6).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_7, {CScriptNum::fromIntUnchecked(7).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_8, {CScriptNum::fromIntUnchecked(8).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_9, {CScriptNum::fromIntUnchecked(9).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_10, {CScriptNum::fromIntUnchecked(10).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_11, {CScriptNum::fromIntUnchecked(11).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_12, {CScriptNum::fromIntUnchecked(12).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_13, {CScriptNum::fromIntUnchecked(13).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_14, {CScriptNum::fromIntUnchecked(14).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_15, {CScriptNum::fromIntUnchecked(15).getvch()}, 0, 0, 101),
        MkT({}, CScript() << OP_16, {CScriptNum::fromIntUnchecked(16).getvch()}, 0, 0, 101),
        // push_N
        MkT({}, CScript() << valtype(1), {valtype(1)}, 0, 0, 101), // Pushdata <= 75
        MkT({}, CScript() << valtype(75, 0xef), {valtype(75, 0xef)}, 0, 0, 175), // Pushdata <= 75
        MkT({}, CScript() << valtype(76, 0xef), {valtype(76, 0xef)}, 0, 0, 100 + 76), // Pushdata > 75
        MkT({}, CScript() << valtype(520, 0xef), {valtype(520, 0xef)}, 0, 0, 100 + 520), // Pushdata > 75
        MkT({}, CScript() << valtype(9'997, 0xef), {valtype(9'997, 0xef)}, 0, 0, 100 + 9'997), // Pushdata > 75
        MkT({}, CScript() << valtype(9'998, 0xef), {}, 0, 0, 0, false), // Pushdata, but entire script >= 10,001 bytes so fails

        MkT({}, CScript() << OP_NOP, {}, 0, 0, 100),

        // OP_IF, OP_ELSE, OP_NOTIF, OP_ENDIF
        MkT({vtrue}, CScript() << OP_IF, {}, 0, 0, 100, false), // OP_IF, unbalanced conditional
        MkT({vtrue}, CScript() << OP_NOTIF, {}, 0, 0, 100, false), // OP_NOTIF, unbalanced conditional
        MkT({vtrue}, CScript() << OP_ELSE, {vtrue}, 0, 0, 100, false), // OP_ELSE, unbalanced conditional
        MkT({vtrue}, CScript() << OP_ENDIF, {vtrue}, 0, 0, 100, false), // OP_ENDIF, unbalanced conditional
        MkT({vfalse}, CScript() << OP_IF << OP_1 << OP_ENDIF, {}, 0, 0, 300), // OP_IF, branch not taken
        MkT({vtrue}, CScript() << OP_IF << "fafa"_v << OP_ENDIF, {"fafa"_v}, 0, 0, 302), // OP_IF, branch taken
        MkT({vfalse}, CScript() << OP_IF << OP_ELSE << OP_1 << OP_ENDIF, {vtrue}, 0, 0, 401), // OP_IF/OP_ELSE, else taken
        MkT({vfalse}, CScript() << OP_IF << OP_ELSE << OP_ELSE << OP_1 << OP_ENDIF, {}, 0, 0, 500), // OP_IF with double else (not taken)
        MkT({vfalse}, CScript() << OP_IF << OP_ELSE << OP_ELSE << OP_ELSE << OP_2 << OP_ENDIF, {valtype(1, 2)}, 0, 0, 601), // OP_IF with triple else (taken)
        MkT({vtrue}, CScript() << OP_NOTIF << OP_1 << OP_ENDIF, {}, 0, 0, 300), // OP_NOTIF, branch not taken
        MkT({vfalse}, CScript() << OP_NOTIF << "fafa"_v << OP_ENDIF, {"fafa"_v}, 0, 0, 302), // OP_NOTIF, branch taken
        MkT({vtrue}, CScript() << OP_NOTIF << OP_ELSE << OP_1 << OP_ENDIF, {vtrue}, 0, 0, 401), // OP_NOTIF/OP_ELSE, else taken
        MkT({vtrue}, CScript() << OP_NOTIF << OP_ELSE << OP_ELSE << OP_1 << OP_ENDIF, {}, 0, 0, 500), // OP_NOTIF with double else (not taken)
        MkT({vtrue}, CScript() << OP_NOTIF << OP_ELSE << OP_ELSE << OP_ELSE << OP_2 << OP_ENDIF, {valtype(1, 2)}, 0, 0, 601), // OP_NOTIF with triple else (taken)

        MkT({vtrue}, CScript() << OP_VERIFY, {}, 0, 0, 100), // OP_VERIFY, success case
        MkT({vfalse}, CScript() << OP_VERIFY << OP_16, {vfalse}, 0, 0, 100, false), // OP_VERIFY, failure case
        MkT({valtype(10, 0xab)}, CScript() << OP_RETURN << valtype(100, 0xff), {valtype(10, 0xab)}, 0, 0, 100, false),// OP_RETURN
        MkT({valtype(10, 0xab)}, CScript() << OP_TOALTSTACK, {}, 0, 0, 100),// OP_TOALTSTACK
        MkT({valtype(10, 0xab)}, CScript() << OP_TOALTSTACK << OP_FROMALTSTACK, {valtype(10, 0xab)}, 0, 0, 210),// OP_FROMALTSTACK
        MkT({vtrue, vtrue}, CScript() << OP_2DROP, {}, 0, 0, 100),// OP_2DROP
        MkT(StackT(999, vtrue), CScript() << OP_2DROP, StackT(997, vtrue), 0, 0, 100), // OP_2DROP (big stack)
        MkT({vtrue, vfalse}, CScript() << OP_2DUP, {vtrue, vfalse, vtrue, vfalse}, 0, 0, 101),// OP_2DUP
        MkT({vfalse, vfalse}, CScript() << OP_2DUP, {vfalse, vfalse, vfalse, vfalse}, 0, 0, 100),// OP_2DUP
        MkT({vtrue, vtrue}, CScript() << OP_2DUP, {vtrue, vtrue, vtrue, vtrue}, 0, 0, 102),// OP_2DUP
        MkT({valtype(1), valtype(2), valtype(3)}, CScript() << OP_3DUP,
            {valtype(1), valtype(2), valtype(3), valtype(1), valtype(2), valtype(3)}, 0, 0, 106 ), // OP_3DUP
        MkT({valtype(1), valtype(2), valtype(3), valtype(4)}, CScript() << OP_2OVER,
            {valtype(1), valtype(2), valtype(3), valtype(4), valtype(1), valtype(2)}, 0, 0, 103 ), // OP_2OVER
        MkT({valtype(1), valtype(2), valtype(3), valtype(4), valtype(5), valtype(6)}, CScript() << OP_2ROT,
            {valtype(3), valtype(4), valtype(5), valtype(6), valtype(1), valtype(2)}, 0, 0, 103 ), // OP_2ROT
        MkT({valtype(1), valtype(2), valtype(3), valtype(4)}, CScript() << OP_2SWAP,
            {valtype(3), valtype(4), valtype(1), valtype(2)}, 0, 0, 100 ), // OP_2SWAP
        MkT({vfalse}, CScript() << OP_IFDUP, {vfalse}, 0, 0, 100), // OP_IFDUP (false case)
        MkT({valtype(100)}, CScript() << OP_IFDUP, {valtype(100)}, 0, 0, 100), // OP_IFDUP (false case, non-canonical boolean false)
        MkT({valtype(2, 42)}, CScript() << OP_IFDUP, {valtype(2, 42), valtype(2, 42)}, 0, 0, 102), // OP_IFDUP (true case)
        MkT(StackT(999, vtrue), CScript() << OP_DEPTH, Append(StackT(999, vtrue), "e703"_v), 0, 0, 102),// OP_DEPTH
        MkT(StackT(999, vtrue), CScript() << OP_DROP, StackT(998, vtrue), 0, 0, 100),// OP_DROP
        MkT({valtype(99, 0xd0)}, CScript() << OP_DUP, StackT(2, valtype(99, 0xd0)), 0, 0, 199),// OP_DUP
        MkT({valtype(9), valtype(10), valtype(11)}, CScript() << OP_NIP, {valtype(9), valtype(11)}, 0, 0, 100),// OP_NIP
        MkT({valtype(9), valtype(10), valtype(11)}, CScript() << OP_OVER,
            {valtype(9), valtype(10), valtype(11), valtype(10)}, 0, 0, 110), // OP_OVER
        MkT({valtype(9), valtype(10), valtype(11), "02"_v}, CScript() << OP_PICK,
            {valtype(9), valtype(10), valtype(11), valtype(9)}, 0, 0, 109), // OP_PICK
        MkT({valtype(9), valtype(10), valtype(11), "03"_v}, CScript() << OP_PICK,
            {valtype(9), valtype(10), valtype(11)}, 0, 0, 100, false), // OP_PICK (fail case, index exceeds stack size)
        MkT({valtype(9), valtype(10), valtype(11), "81"_v}, CScript() << OP_PICK,
            {valtype(9), valtype(10), valtype(11)}, 0, 0, 100, false), // OP_PICK (fail case, index is negative)
        MkT({valtype(9), valtype(10), valtype(11), "02"_v}, CScript() << OP_ROLL,
            {valtype(10), valtype(11), valtype(9)}, 0, 0, 109 + 2), // OP_ROLL
        MkT({valtype(9), valtype(10), valtype(11), {/* zero */}}, CScript() << OP_ROLL,
            {valtype(9), valtype(10), valtype(11)}, 0, 0, 111), // OP_ROLL (pointless case where index is 0, top is popped then re-pushed)
        MkT({valtype(9), valtype(10), valtype(11), "03"_v}, CScript() << OP_ROLL,
            {valtype(9), valtype(10), valtype(11)}, 0, 0, 100, false), // OP_ROLL (fail case, index exceeds stack size)
        MkT({valtype(9), valtype(10), valtype(11)}, CScript() << OP_ROT,
            {valtype(10), valtype(11), valtype(9)}, 0, 0, 100), // OP_ROT
        MkT({valtype(9), valtype(10), valtype(11)}, CScript() << OP_SWAP,
            {valtype(9), valtype(11), valtype(10)}, 0, 0, 100), // OP_SWAP
        MkT({valtype(10), valtype(11)}, CScript() << OP_TUCK,
            {valtype(11), valtype(10), valtype(11)}, 0, 0, 111), // OP_TUCK
        MkT({"deadbeef"_v, "b00bf00d"_v}, CScript() << OP_CAT,
            {"deadbeefb00bf00d"_v}, 0, 0, 108), // OP_CAT
        MkT({"deadbeefb00bf00d"_v, CScriptNum::fromInt(3)->getvch()}, CScript() << OP_SPLIT,
            {"deadbe"_v, "efb00bf00d"_v}, 0, 0, 108), // OP_SPLIT
        MkT({CScriptNum::fromInt(-42)->getvch(), CScriptNum::fromInt(8)->getvch()}, CScript() << OP_NUM2BIN,
            {"2a00000000000080"_v}, 0, 0, 108), // OP_NUM2BIN
        MkT({"2a00000000000080"_v}, CScript() << OP_BIN2NUM, {CScriptNum::fromInt(-42)->getvch()}, 0, 0, 101),// OP_BIN2NUM
        MkT({valtype(127, 0xfa)}, CScript() << OP_SIZE, {valtype(127, 0xfa), CScriptNum::fromInt(127)->getvch()}, 0, 0, 101), // OP_SIZE (1)
        MkT({valtype(256, 0xfa)}, CScript() << OP_SIZE, {valtype(256, 0xfa), CScriptNum::fromInt(256)->getvch()}, 0, 0, 102), // OP_SIZE (2)
        MkT({"f00f"_v, "baba"_v}, CScript() << OP_AND, {"b00a"_v}, 0, 0, 102),// OP_AND
        MkT({"f0"_v, "baba"_v}, CScript() << OP_AND, {"f0"_v, "baba"_v}, 0, 0, 100, false), // OP_AND (mismatched sizes)
        MkT({"f00f"_v, "baba"_v}, CScript() << OP_OR, {"fabf"_v}, 0, 0, 102),// OP_OR
        MkT({"f00f"_v, "baba"_v}, CScript() << OP_XOR, {"4ab5"_v}, 0, 0, 102),// OP_XOR
        MkT({"1234"_v, "1234"_v}, CScript() << OP_EQUAL, {vtrue}, 0, 0, 101),// OP_EQUAL
        MkT({"1234"_v, "1235"_v}, CScript() << OP_EQUAL, {vfalse}, 0, 0, 100),// OP_EQUAL
        MkT({"1234"_v, "1234"_v}, CScript() << OP_EQUALVERIFY, {}, 0, 0, 101),// OP_EQUALVERIFY
        MkT({"1234"_v, "1235"_v}, CScript() << OP_EQUALVERIFY, {vfalse}, 0, 0, 100, false), // OP_EQUALVERIFY fail case
        MkT({"00020342"_v}, CScript() << OP_1ADD, {"01020342"_v}, 0, 0, 100 + 4*2),// OP_1ADD
        MkT({"ffffffffffffff7f"_v}, CScript() << OP_1ADD, {"000000000000008000"_v}, 0, 0, 100 + 9*2), // OP_1ADD at 2^63 limit succeed since bigint exists
        MkT({(ScriptBigInt::bigIntConsensusMax() - 1).serialize()}, CScript() << OP_1ADD,
            {ScriptBigInt::bigIntConsensusMax().serialize()}, 0, 0,
            100 + ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT * 2), // OP_1ADD success just under bigint upper limit
        MkT({ScriptBigInt::bigIntConsensusMax().serialize()}, CScript() << OP_1ADD,
            {ScriptBigInt::bigIntConsensusMax().serialize()}, 0, 0, 100, false), // OP_1ADD fail beyond bigint limit due to wraparound
        MkT({"01020342"_v}, CScript() << OP_1SUB, {"00020342"_v}, 0, 0, 100 + 4*2),// OP_1SUB
        MkT({"ffffffffffffffff"_v}, CScript() << OP_1SUB, {"000000000000008080"_v}, 0, 0, 100 + 9*2), // OP_1SUB at 2^63 limit succeed since bigint exists
        MkT({(ScriptBigInt::bigIntConsensusMin() + 1).serialize()}, CScript() << OP_1SUB,
            {ScriptBigInt::bigIntConsensusMin().serialize()}, 0, 0,
            100 + ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT * 2), // OP_1SUB success just above bigint lower limit
        MkT({ScriptBigInt::bigIntConsensusMin().serialize()}, CScript() << OP_1SUB,
            {ScriptBigInt::bigIntConsensusMin().serialize()}, 0, 0, 100, false), // OP_1SUB fail beyond bigint limit due to wraparound
        MkT({CScriptNum::fromInt(42)->getvch()}, CScript() << OP_NEGATE, {CScriptNum::fromInt(-42)->getvch()}, 0, 0, 100 + 1*2),// OP_NEGATE
        MkT({CScriptNum::fromInt(424242)->getvch()}, CScript() << OP_NEGATE, {CScriptNum::fromInt(-424242)->getvch()}, 0, 0, 100 + 3*2), // OP_NEGATE (3 byte)
        MkT({CScriptNum::fromInt(-424242)->getvch()}, CScript() << OP_ABS, {CScriptNum::fromInt(424242)->getvch()}, 0, 0, 100 + 3*2),// OP_ABS
        MkT({vfalse}, CScript() << OP_NOT, {vtrue}, 0, 0, 101), // OP_NOT (true result)
        MkT({vtrue}, CScript() << OP_NOT, {vfalse}, 0, 0, 100), // OP_NOT (false result)
        MkT({"010204"_v}, CScript() << OP_0NOTEQUAL, {vtrue}, 0, 0, 101), // OP_NOT (true result)
        MkT({{}}, CScript() << OP_0NOTEQUAL, {vfalse}, 0, 0, 100), // OP_NOT (false result)
        MkT({CScriptNum::fromInt(1013224)->getvch(), CScriptNum::fromInt(32154)->getvch()}, CScript() << OP_ADD,
            {CScriptNum::fromInt(1013224 + 32154)->getvch()}, 0, 0, 100 + 3 * 2), // OP_ADD (3-byte result)
        MkT({CScriptNum::fromInt(1013224)->getvch(), CScriptNum::fromInt(32154)->getvch()}, CScript() << OP_SUB,
            {CScriptNum::fromInt(1013224 - 32154)->getvch()}, 0, 0, 100 + 3 * 2), // OP_SUB (3-byte result)
        MkT({CScriptNum::fromInt(1013224)->getvch(), CScriptNum::fromInt(32154)->getvch()}, CScript() << OP_MUL,
            {CScriptNum::fromInt(int64_t{1013224} * 32154)->getvch()}, 0, 0, 100 + 5*2 + 3*2), // OP_MUL (5-byte result, 2 & 3 byte operands)
        MkT({CScriptNum::fromInt(1013224)->getvch(), CScriptNum::fromInt(3215)->getvch()}, CScript() << OP_DIV,
            {CScriptNum::fromInt(int64_t{1013224} / 3215)->getvch()}, 0, 0, 100 + 2*2 + 3*2), // OP_DIV (2-byte result, 2 & 3 byte operands)
        MkT({CScriptNum::fromInt(21354141242352126LL)->getvch(), CScriptNum::fromInt(5231241412LL)->getvch()}, CScript() << OP_MOD,
            {CScriptNum::fromInt(21354141242352126LL % 5231241412LL)->getvch()}, 0, 0, 100 + 5*2 + 7*5), // OP_MOD (5-byte result, 7 & 5 byte operands)
        MkT({vtrue, vtrue}, CScript() << OP_BOOLAND, {vtrue}, 0, 0, 101), // OP_BOOLAND (true result)
        MkT({valtype(2, 0xca), vfalse}, CScript() << OP_BOOLAND, {vfalse}, 0, 0, 100), // OP_BOOLAND (false result)
        MkT({valtype(2, 0xca), vfalse}, CScript() << OP_BOOLOR, {vtrue}, 0, 0, 101), // OP_BOOLOR (true result)
        MkT({vfalse, vfalse}, CScript() << OP_BOOLOR, {vfalse}, 0, 0, 100), // OP_BOOLOR (false result)
        MkT({"1234"_v, "1234"_v}, CScript() << OP_NUMEQUAL, {vtrue}, 0, 0, 101), // OP_NUMEQUAL (true result)
        MkT({"1234"_v, "0234"_v}, CScript() << OP_NUMEQUAL, {vfalse}, 0, 0, 100), // OP_NUMEQUAL (false result)
        MkT({"1234"_v, "1234"_v}, CScript() << OP_NUMEQUALVERIFY, {}, 0, 0, 101), // OP_NUMEQUALVERIFY (true result)
        MkT({"1234"_v, "0234"_v}, CScript() << OP_NUMEQUALVERIFY, {vfalse}, 0, 0, 100, false), // OP_NUMEQUALVERIFY (false result)
        MkT({"1234"_v, "0234"_v}, CScript() << OP_NUMNOTEQUAL, {vtrue}, 0, 0, 101), // OP_NUMNOTEQUAL (true result)
        MkT({"1234"_v, "1234"_v}, CScript() << OP_NUMNOTEQUAL, {vfalse}, 0, 0, 100), // OP_NUMNOTEQUAL (false result)
        MkT({"0234"_v, "1234"_v}, CScript() << OP_LESSTHAN, {vtrue}, 0, 0, 101), // OP_LESSTHAN (true result)
        MkT({"1234"_v, "0234"_v}, CScript() << OP_LESSTHAN, {vfalse}, 0, 0, 100), // OP_LESSTHAN (false result)
        MkT({"1234"_v, "0234"_v}, CScript() << OP_GREATERTHAN, {vtrue}, 0, 0, 101), // OP_GREATERTHAN (true result)
        MkT({"0234"_v, "1234"_v}, CScript() << OP_GREATERTHAN, {vfalse}, 0, 0, 100), // OP_GREATERTHAN (false result)
        MkT({"1234"_v, "1234"_v}, CScript() << OP_LESSTHANOREQUAL, {vtrue}, 0, 0, 101), // OP_LESSTHANOREQUAL (true result)
        MkT({"2234"_v, "1234"_v}, CScript() << OP_LESSTHANOREQUAL, {vfalse}, 0, 0, 100), // OP_LESSTHANOREQUAL (false result)
        MkT({"1234"_v, "1234"_v}, CScript() << OP_GREATERTHANOREQUAL, {vtrue}, 0, 0, 101), // OP_GREATERTHANOREQUAL (true result)
        MkT({"0234"_v, "1234"_v}, CScript() << OP_GREATERTHANOREQUAL, {vfalse}, 0, 0, 100), // OP_GREATERTHANOREQUAL (false result)
        MkT({"2234"_v, "1234"_v}, CScript() << OP_MAX, {"2234"_v}, 0, 0, 100 + 2*2),// OP_MAX
        MkT({"fb81"_v, {}}, CScript() << OP_MAX, {{}}, 0, 0, 100), // OP_MAX (zero result)
        MkT({"2234"_v, "1234"_v}, CScript() << OP_MIN, {"1234"_v}, 0, 0, 100 + 2*2),// OP_MIN
        MkT({"2234"_v, {}}, CScript() << OP_MIN, {{}}, 0, 0, 100), // OP_MIN (zero result)
        MkT({CScriptNum::fromInt(42)->getvch(), CScriptNum::fromInt(-1000)->getvch(), CScriptNum::fromInt(10'000)->getvch()},
            CScript() << OP_WITHIN, {vtrue}, 0, 0, 101), // OP_WITHIN (true result)
        MkT({CScriptNum::fromInt(42)->getvch(), CScriptNum::fromInt(1000)->getvch(), CScriptNum::fromInt(10'000)->getvch()},
            CScript() << OP_WITHIN, {vfalse}, 0, 0, 100), // OP_WITHIN (false result)
        MkT({valtype(100, 0xaa)}, CScript() << OP_RIPEMD160, {"2e5fdf4bf17c3419123505f3ee8038af8e6618af"_v}, 0, 2, 120 + 192*2),// OP_RIPEMD160
        MkT({valtype(100, 0xaa)}, CScript() << OP_SHA1, {"7a86b804961d5d32c3413afa060bfcdb6b20ddcc"_v}, 0, 2, 120 + 192*2),// OP_SHA1
        MkT({valtype(100, 0xaa)}, CScript() << OP_SHA256, {"a2d9e521de7743fc225b901446065f62559c93924d807ae82ad8c534b7e2956e"_v}, 0, 2, 132 + 192*2),// OP_SHA256
        MkT({valtype(100, 0xaa)}, CScript() << OP_HASH160, {"858713392570746dc8f9b1c65193f42aad7092e4"_v}, 0, 3, 120 + 192*3),// OP_HASH160
        MkT({valtype(100, 0xaa)}, CScript() << OP_HASH256, {"548de329214742bd47408350af02ff6ba5b64a355d0239fd22107ae75de8dbb4"_v}, 0, 3, 132 + 192*3),// OP_HASH256
        MkT({valtype(2, 0xbb)}, CScript() << OP_CODESEPARATOR, {valtype(2, 0xbb)}, 0, 0, 100),// OP_CODESEPARATOR

        // NOTE: OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKDATASIG,
        // and OP_CHECKDATASIGVERIFY are checked by other test cases in this file. But for belt-and-suspenders we check
        // a real txn's inputs here.
        MkT(ScriptToStack(realContexts[0].scriptSig()), realContexts[0].coinScriptPubKey(), {vtrue}, 1, 7,
            501 + 20*2 + 26'000 + 192*7 + 1 + int(ScriptToStack(realContexts[0].scriptSig()).back().size()), // opCost
            true, &realTxCheckers[0]),
        MkT(ScriptToStack(realContexts[1].scriptSig()), realContexts[1].coinScriptPubKey(), {vtrue}, 1, 6,
            501 + 20*2 + 26'000 + 192*6 + 1 + int(ScriptToStack(realContexts[1].scriptSig()).back().size()), // opCost
            true, &realTxCheckers[1]),
        MkT({{}}, CScript() << OP_CHECKLOCKTIMEVERIFY, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_CHECKLOCKTIMEVERIFY
        MkT({{}}, CScript() << OP_CHECKSEQUENCEVERIFY, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_CHECKSEQUENCEVERIFY

        MkT({}, CScript() << OP_NOP1, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP4, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP5, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP6, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP7, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP8, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP9, {}, 0, 0, 100),
        MkT({}, CScript() << OP_NOP10, {}, 0, 0, 100),

        MkT({"abcdef012345"_v}, CScript() << OP_REVERSEBYTES, {"452301efcdab"_v}, 0, 0, 106),// OP_REVERSEBYTES
        MkT({}, CScript() << OP_INPUTINDEX, {"01"_v}, 0, 0, 101, true, &realTxCheckers.at(1)),// OP_INPUTINDEX
        MkT({}, CScript() << OP_ACTIVEBYTECODE, {"c1"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_ACTIVEBYTECODE
        MkT({}, CScript() << OP_TXVERSION, {"02"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_TXVERSION
        MkT({}, CScript() << OP_TXINPUTCOUNT, {"02"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_TXINPUTCOUNT
        MkT({}, CScript() << OP_TXOUTPUTCOUNT, {"02"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_TXOUTPUTCOUNT
        MkT({}, CScript() << OP_TXLOCKTIME, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_TXLOCKTIME
        MkT({"01"_v}, CScript() << OP_UTXOVALUE, {CScriptNum::fromInt(43637)->getvch()}, 0, 0, 103, true, &realTxCheckers.at(0)),// OP_UTXOVALUE
        MkT({"01"_v}, CScript() << OP_OUTPOINTTXHASH, {ToVec(realContexts.at(1).tx().vin().at(1).prevout.GetTxId())}, 0, 0, 132, true, &realTxCheckers.at(0)),// OP_OUTPOINTTXHASH
        MkT({{}}, CScript() << OP_OUTPOINTINDEX, {"02"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_OUTPOINTINDEX
        MkT({{}}, CScript() << OP_INPUTBYTECODE, {ToVec(realContexts.at(0).scriptSig())}, 0, 0, 100 + realContexts.at(0).scriptSig().size(), true, &realTxCheckers.at(0)),// OP_INPUTBYTECODE
        MkT({"01"_v}, CScript() << OP_INPUTSEQUENCENUMBER, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_INPUTSEQUENCENUMBER
        MkT({"01"_v}, CScript() << OP_OUTPUTVALUE, {CScriptNum::fromInt(43240)->getvch()}, 0, 0, 103, true, &realTxCheckers.at(0)),// OP_OUTPUTVALUE
        MkT({"01"_v}, CScript() << OP_OUTPUTBYTECODE, {ToVec(realContexts.at(0).tx().vout().at(1).scriptPubKey)}, 0, 0, 125, true, &realTxCheckers.at(0)),// OP_OUTPUTBYTECODE
        MkT({{}}, CScript() << OP_UTXOTOKENCATEGORY, {ToVec(realContexts.at(0).coinTokenData()->GetId())}, 0, 0, 132, true, &realTxCheckers.at(0)),// OP_UTXOTOKENCATEGORY
        MkT({{}}, CScript() << OP_UTXOTOKENCOMMITMENT, {ToVec(realContexts.at(0).coinTokenData()->GetCommitment())}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_UTXOTOKENCOMMITMENT
        MkT({{}}, CScript() << OP_UTXOTOKENAMOUNT, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_UTXOTOKENAMOUNT
        MkT({{}}, CScript() << OP_OUTPUTTOKENCATEGORY, {ToVec(realContexts.at(0).tx().vout().at(0).tokenDataPtr->GetId())}, 0, 0, 132, true, &realTxCheckers.at(0)),// OP_OUTPUTTOKENCATEGORY
        MkT({{}}, CScript() << OP_OUTPUTTOKENCOMMITMENT, {"16"_v}, 0, 0, 101, true, &realTxCheckers.at(0)),// OP_OUTPUTTOKENCOMMITMENT
        MkT({{}}, CScript() << OP_OUTPUTTOKENAMOUNT, {{}}, 0, 0, 100, true, &realTxCheckers.at(0)),// OP_OUTPUTTOKENAMOUNT
    };
#undef MkT
#undef ToStr_
#undef ToStr__

    for (const Test &t : tests) {
        BOOST_TEST_CONTEXT(__FILE__ << ":" << t.line << "\n    ---> Test{ " << t.debugSnippet << " }") {
            ScriptExecutionMetrics m;
            StackT stack = t.stack;
            const bool r = EvalScript(stack, t.script, flags, *t.checker, m);
            BOOST_CHECK_EQUAL(r, t.expectedResult);
            BOOST_CHECK(stack == t.expectedStack);
            if (stack != t.expectedStack) {
                // For debugging, show stack that we actually got
                auto ToStr = [](const auto &st) {
                    std::string str = "{ ";
                    for (const auto &vch : st) {
                        str += "\"" + HexStr(vch) + "\" ";
                    }
                    str += "}";
                    return str;
                };
                BOOST_ERROR("\n--> Result stack  : " + ToStr(stack) + "\n--> Expected stack: " + ToStr(t.expectedStack));
            }
            BOOST_CHECK_EQUAL(m.GetSigChecks(), t.sigChecks);
            BOOST_CHECK_EQUAL(m.GetHashDigestIterations(), t.hashIters);
            BOOST_CHECK_EQUAL(m.GetCompositeOpCost(flags), t.opCost);
        }
    }
}

BOOST_AUTO_TEST_CASE(digest_iterations_sanity) {
    // From: https://github.com/bitjson/bch-vm-limits/tree/master, section: "Digest Iteration Count Test Vectors"
    const std::initializer_list<std::pair<int, int>> tests = {
        {0, 1},
        {1, 1},
        {55, 1},
        {56, 2},
        {64, 2},
        {119, 2},
        {120, 3},
        {183, 3},
        {184, 4},
        {247, 4},
        {248, 5},
        {488, 8},
        {503, 8},
        {504, 9},
        {520, 9},
        {1015, 16},
        {1016, 17},
        {63928, 1000},
        {63991, 1000},
        {63992, 1001},
    };

    for (const auto & [msgLen, expectedIters] : tests) {
        BOOST_CHECK_EQUAL(may2025::CalcHashIters(msgLen, false), expectedIters);
        BOOST_CHECK_EQUAL(may2025::CalcHashIters(msgLen, true), expectedIters + 1);
    }
}

BOOST_AUTO_TEST_SUITE_END()
