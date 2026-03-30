// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cashaddrenc.h>
#include <chainparams.h>
#include <compressor.h>
#include <coins.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/tokens.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <hash.h>
#include <key.h>
#include <keystore.h>
#include <miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/token.h>
#include <random.h>
#include <script/script_flags.h>
#include <script/standard.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <util/defer.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>

#include <test/data/token_tests_prefix_invalid.json.h>
#include <test/data/token_tests_prefix_valid.json.h>
#include <test/jsonutil.h>
#include <test/scriptflags.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <clocale>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(token_tests, BasicTestingSetup)

static std::string GetRandomScriptPubKeyHexForAPubKey(const CPubKey destinationPubKey,
                                                      CScript *script_out = nullptr,
                                                      CScript *redeem_script_out = nullptr) {
    switch (InsecureRandRange(3)) {
    // p2pkh
    case 0: {
        const CTxDestination dest = destinationPubKey.GetID();
        const auto script = GetScriptForDestination(dest);
        if (script_out) *script_out = script;
        const std::string hex = HexStr(script);
        BOOST_TEST_MESSAGE("Returning p2pkh spk with hex bytes: " + hex + ", address: " + EncodeCashAddr(dest, ::Params()));
        return hex;
    }
    // p2sh wrapping a p2pk
    case 1: {
        CScript script = GetScriptForRawPubKey(destinationPubKey);
        const CTxDestination dest = ScriptID{script, false /* not ps2h_32 */};
        if (redeem_script_out) *redeem_script_out = script;
        script = GetScriptForDestination(dest);
        if (script_out) *script_out = script;
        const std::string hex = HexStr(script);
        BOOST_TEST_MESSAGE("Returning p2sh spk with hex bytes: " + hex + ", address: " + EncodeCashAddr(dest, ::Params()));
        return hex;
    }
    // raw pubkey
    case 2: {
        const auto script = GetScriptForRawPubKey(destinationPubKey);
        if (script_out) *script_out = script;
        const std::string hex = HexStr(script);
        BOOST_TEST_MESSAGE("Returning p2pk spk with hex bytes: " + hex);
        return hex;
    }
    }
    assert(0); // should never be reached
    return "";
}

static std::string GenRandomScriptPubKeyHexForAStandardDestination(CScript *script_out = nullptr,
                                                                   CScript *redeem_script_out = nullptr) {
    CKey destinationKey;
    destinationKey.MakeNewKey(true);
    return GetRandomScriptPubKeyHexForAPubKey(destinationKey.GetPubKey(), script_out, redeem_script_out);
}

struct TestVector_PrefixTokenEncoding_Valid {
    std::string name;
    bool hasNFT, isMutable, isMinting, isImmutable;
    int64_t amt;
    std::string expectedCommitment;
    std::string payload;
    std::string expectedSpk;
    std::string expectedId;
};

static std::vector<TestVector_PrefixTokenEncoding_Valid> GenVectors_PrefixTokenEncoding_Valid() {
    std::string spkHex;
    const std::string expectedId{HexStr(std::vector(32, uint8_t(0xbb)))};
    auto genSpk = [&spkHex] { return spkHex = GenRandomScriptPubKeyHexForAStandardDestination(); };
    return {{
        { "no NFT; 1 fungible", // name
           false /* hasNFT */, false /* mut */, false /* mint */, false /* immut. */, 1 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1001" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "no NFT; 252 fungible", // name
          false /* hasNFT */, false /* mut */, false /* mint */, false /* immut. */, 252 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10fc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "no NFT; 253 fungible", // name
          false /* hasNFT */, false /* mut */, false /* mint */, false /* immut. */, 253 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10fdfd00" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "no NFT; 9223372036854775807 fungible", // name
          false /* hasNFT */, false /* mut */, false /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10ffffffffffffffff7f" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte immutable NFT; 0 fungible",
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 0 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb20" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte immutable NFT; 1 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 1 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3001" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte immutable NFT; 253 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 253 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb30fdfd00" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte immutable NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 9223372036854775807LL /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb30ffffffffffffffff7f" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte immutable NFT; 0 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 0 /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6001cc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte immutable NFT; 252 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 252 /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7001ccfc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "2-byte immutable NFT; 253 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 253 /* amount */,
          "cccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7002ccccfdfd00" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "10-byte immutable NFT; 65535 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 65535 /* amount */,
          "cccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb700accccccccccccccccccccfdffff" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "40-byte immutable NFT; 65536 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 65536 /* amount */,
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7028ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccfe00000100" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "80-byte OUT OF CONSENSUS immutable NFT; 65536 fungible", // name
          true /* hasNFT */, false /* mut */, false /* mint */, true /* immut. */, 65536 /* amount */,
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7050ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccfe00000100" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte, mutable NFT; 0 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 0 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb21" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte, mutable NFT; 4294967295 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 4294967295LL /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb31feffffffff" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte, mutable NFT; 0 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 0 /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6101cc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte, mutable NFT; 4294967296 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 4294967296LL /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7101ccff0000000001000000" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "2-byte, mutable NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          "cccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7102ccccffffffffffffffff7f" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "10-byte, mutable NFT; 1 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 1 /* amount */,
          "cccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb710acccccccccccccccccccc01" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "40-byte, mutable NFT; 252 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 252 /* amount */,
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7128ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccfc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "520-byte, mutable NFT; 4294967296 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 4294967296LL /* amount */,
          std::string(size_t(520 * 2), 'c'), // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb71fd0802" + std::string(size_t(520 * 2), 'c') + "ff0000000001000000" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "32 MiB, mutable NFT; 4294967296 fungible", // name
          true /* hasNFT */, true /* mut */, false /* mint */, false /* immut. */, 4294967296LL /* amount */,
          std::string(size_t(0x2000000 * 2), 'c'), // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb71fe00000002"
                  + std::string(size_t(0x2000000 * 2), 'c') + "ff0000000001000000" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte, minting NFT; 0 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 0 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "0-byte, minting NFT; 253 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 253 /* amount */,
          "", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb32fdfd00" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte, minting NFT; 0 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 0 /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6201cc" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "1-byte, minting NFT; 65535 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 65535 /* amount */,
          "cc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7201ccfdffff" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "2-byte, minting NFT; 65536 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 65536 /* amount */,
          "cccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7202ccccfe00000100" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "10-byte, minting NFT; 4294967297 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 4294967297LL /* amount */,
          "cccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb720accccccccccccccccccccff0100000001000000" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "40-byte, minting NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // commitment
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7228ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccffffffffffffffff7f" + genSpk(), // payload
          spkHex /* expectedSpk */, expectedId},

        { "400-byte, minting NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          // commitment
          std::string(size_t(800), 'c'),
          // payload
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb72fd9001" + std::string(size_t(800), 'c') + "ffffffffffffffff7f" + genSpk(),
          spkHex /* expectedSpk */, expectedId},

        { "520-byte, minting NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          // commitment
          std::string(size_t(520 * 2), 'c'),
          // payload
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb72fd0802" + std::string(size_t(520 * 2), 'c') + "ffffffffffffffff7f" + genSpk(),
          spkHex /* expectedSpk */, expectedId},

        { "32 MiB, minting NFT; 9223372036854775807 fungible", // name
          true /* hasNFT */, false /* mut */, true /* mint */, false /* immut. */, 9223372036854775807LL /* amount */,
          // commitment
          std::string(size_t(0x2000000 * 2), 'c'),
          // payload
          "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb72fe00000002" + std::string(size_t(0x2000000 * 2), 'c') + "ffffffffffffffff7f" + genSpk(),
          spkHex /* expectedSpk */, expectedId},

    }};
}

// Test vectors taken from: https://github.com/bitjson/cashtokens#valid-prefix_token-prefix-encodings
BOOST_AUTO_TEST_CASE(prefix_token_encoding_test_vectors_valid) {
    SeedInsecureRand(/* deterministic */ true);
    const bool prev_g_mock_deterministic_tests = g_mock_deterministic_tests;
    g_mock_deterministic_tests = true;
    Defer d([&]{ g_mock_deterministic_tests = prev_g_mock_deterministic_tests; });

    // All of these should pass
    const auto valid_tests = GenVectors_PrefixTokenEncoding_Valid();

    BOOST_TEST_MESSAGE(strprintf("Running %d test vectors  ...", valid_tests.size()));
    for (const auto &t : valid_tests) {
        BOOST_TEST_MESSAGE(strprintf("Testing valid encoding: \"%s\" ...", t.name));
        const auto payloadVec = ParseHex(t.payload);
        const token::WrappedScriptPubKey wspk{payloadVec.begin(), payloadVec.end()};
        token::OutputDataPtr pdata;
        CScript spk;
        token::UnwrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION, true);
        BOOST_CHECK(bool(pdata));
        BOOST_CHECK_EQUAL(t.expectedId, pdata->GetId().GetHex());
        BOOST_CHECK_EQUAL(t.expectedSpk, HexStr(spk)); // ensure scriptPubKey made it out ok
        // Check various token data fields are what the test vector expects
        BOOST_CHECK_EQUAL(t.hasNFT, pdata->HasNFT());
        BOOST_CHECK_EQUAL(t.isMutable, pdata->IsMutableNFT());
        BOOST_CHECK_EQUAL(t.isMinting, pdata->IsMintingNFT());
        BOOST_CHECK_EQUAL(t.isImmutable, pdata->IsImmutableNFT());
        BOOST_CHECK_EQUAL(t.amt, pdata->GetAmount().getint64());
        if (t.expectedCommitment.size() + pdata->GetCommitment().size() < 1000u) {
            BOOST_CHECK_EQUAL(t.expectedCommitment, HexStr(pdata->GetCommitment()));
        } else {
            // to avoid excessive boost logging output for data >1KB, just use BOOST_CHECK
            BOOST_CHECK(t.expectedCommitment == HexStr(pdata->GetCommitment()));
        }
        BOOST_CHECK(!t.expectedCommitment.empty() == pdata->HasCommitmentLength());
        BOOST_CHECK(bool(t.amt) == pdata->HasAmount());

        // Ensure that it re-encodes to the same exact bytes
        token::WrappedScriptPubKey wspk2;
        token::WrapScriptPubKey(wspk2, pdata, spk, INIT_PROTO_VERSION);
        if (wspk.size() + wspk2.size() < 1000u) {
            BOOST_CHECK_EQUAL(HexStr(wspk), HexStr(wspk2));
        } else {
            // to avoid excessive boost logging output for data >1KB, just use BOOST_CHECK
            BOOST_CHECK(wspk == wspk2);
        }

        // Test that the CTxOut compressor works ok. Note that for now, CTxOut's with tokens in them do not get their
        // scriptPubKey portion compressed
        CTxOut txo{int64_t(InsecureRandRange(21 * 1e8)) * Amount::satoshi(), spk, pdata};
        BOOST_TEST_MESSAGE("Generated txo: " + txo.ToString());

        std::vector<uint8_t> vch;
        GenericVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0) << Using<TxOutCompression>(txo);
        BOOST_CHECK(bool(txo.tokenDataPtr));
        const size_t uncomp_size = GetSerializeSize(txo);
        const ssize_t bytes_saved_with_token = ssize_t(uncomp_size) - ssize_t(vch.size());
        BOOST_CHECK(bytes_saved_with_token >= 0);
        BOOST_TEST_MESSAGE(strprintf("Wrote %d byte blob as %d bytes: %s", uncomp_size, vch.size(),
                                     HexStr(vch).substr(0, 2000)));
        CTxOut txo2;
        BOOST_CHECK(!txo2.HasUnparseableTokenData());
        {
            GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, vch, 0);
            ::Unserialize(vr, Using<TxOutCompression>(txo2));
        }
        BOOST_CHECK_MESSAGE(txo == txo2, "TxOutCompression should serialized<->unserialize to the same data");
        BOOST_CHECK(txo2.tokenDataPtr == pdata); // paranoia
        BOOST_CHECK(!txo2.HasUnparseableTokenData());


        // lastly, as a sanity check, re-serialize without token data to observe compressor working ok
        txo.tokenDataPtr.reset();
        txo2.SetNull();
        BOOST_CHECK(txo != txo2);
        vch.clear();
        GenericVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0) << Using<TxOutCompression>(txo);
        const size_t uncomp_size2 = GetSerializeSize(txo);
        const ssize_t bytes_saved_no_token = ssize_t(uncomp_size2) - ssize_t(vch.size());
        BOOST_CHECK(bytes_saved_no_token >= 0);
        BOOST_TEST_MESSAGE(strprintf("(No token data) Wrote %d byte blob as %d bytes: %s", uncomp_size2, vch.size(),
                                     HexStr(vch).substr(0, 2000)));
        {
            GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, vch, 0);
            ::Unserialize(vr, Using<TxOutCompression>(txo2));
        }
        BOOST_CHECK_MESSAGE(txo == txo2, "(No token data) TxOutCompression should serialized<->unserialize to the same "
                                         "data");
        // For now, we absolutely should have saved more bytes in the non-token version of this TXO due to the
        // TxOutCompression working better for non-token scriptPubKey data...
        BOOST_CHECK_GT(bytes_saved_no_token, bytes_saved_with_token);
    }
}

// Test that the txout compressor behaves as we expect when there is embedded token data
BOOST_AUTO_TEST_CASE(txout_compressor_edge_case) {
    BOOST_TEST_MESSAGE("Check that 520 sized token commitment + 100000 byte spk is ok");
    token::WrappedScriptPubKey wspk;
    auto vec = ParseHex("ef1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d70fd0802"
                        + std::string(MAX_SCRIPT_ELEMENT_SIZE_LEGACY * 2, 'c') + "fc"
                        + std::string(MAX_SCRIPT_SIZE * 2, 'd'));
    wspk.assign(vec.begin(), vec.end());
    BOOST_CHECK_GT(vec.size(), MAX_SCRIPT_SIZE);
    token::OutputDataPtr pdata;
    CScript spk;
    token::UnwrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION, true);
    BOOST_CHECK(bool(pdata));
    BOOST_CHECK_EQUAL(spk.size(), MAX_SCRIPT_SIZE);
    BOOST_CHECK_EQUAL(HexStr(pdata->GetCommitment()), std::string(MAX_SCRIPT_ELEMENT_SIZE_LEGACY * 2, 'c'));
    BOOST_CHECK_EQUAL(HexStr(pdata->GetId()), "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");
    BOOST_CHECK_EQUAL(int(pdata->GetCapability()), int(token::Capability::None));
    BOOST_CHECK(pdata->HasAmount() && pdata->GetAmount().getint64() == 252LL);
    BOOST_CHECK(pdata->HasCommitmentLength());
    BOOST_CHECK(pdata->HasNFT());
    CScript expected;
    expected.resize(MAX_SCRIPT_SIZE, 0xdd);
    BOOST_CHECK(spk == expected);
    // - Use compressor to compress txo and then uncompress it and it should make it out alive identically
    // - However, if the spk payload is past 10000 bytes it will get modified to a short "OP_RETURN" script
    for (int i = 0; i < 2; ++i) {
        CTxOut txo, txo2;
        txo.nValue = 123 * SATOSHI;
        txo.scriptPubKey = spk;
        if (i) txo.scriptPubKey.resize(MAX_SCRIPT_SIZE + 1, 0xff);
        txo.tokenDataPtr = pdata;
        std::vector<uint8_t> buffer;
        GenericVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, buffer, 0) << Using<TxOutCompression>(txo);
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, buffer, 0);
        BOOST_CHECK_NO_THROW(::Unserialize(vr, Using<TxOutCompression>(txo2)));
        if (!i) {
            BOOST_CHECK_MESSAGE(txo.scriptPubKey == txo2.scriptPubKey && txo.nValue == txo2.nValue
                                && txo.tokenDataPtr == txo2.tokenDataPtr,
                                "After ser/deser cycle of an oversized payload with spk == 10,000, "
                                "txo should be unmolested");
        } else {
            BOOST_CHECK_MESSAGE(txo2.scriptPubKey == (CScript() << OP_RETURN)
                                && txo.nValue == txo2.nValue
                                && txo.tokenDataPtr == txo2.tokenDataPtr,
                                "However, if the embedded spk is >10000 bytes, it gets modified to a single"
                                " OP_RETURN instruction by the compressor (legacy txdb behavior)");
        }
    }
}

// returns a lambda that is the predicate which returns true if the exception message contains `txt` (case insensitive)
static auto ExcMessageContains(const std::string &txt) {
    return [txt](const std::exception &e) {
        const auto msg = e.what();
        BOOST_TEST_MESSAGE(strprintf("Exception message: \"%s\" must contain: \"%s\" (case insensitive)", msg, txt));
        return ToLower(msg).find(ToLower(TrimString(txt))) != std::string::npos;
    };
}

// Test vectors taken from: https://github.com/bitjson/cashtokens#invalid-prefix_token-prefix-encodings
BOOST_AUTO_TEST_CASE(prefix_token_encoding_test_vectors_invalid) {
    auto TryDecode = [](const std::string &name, const std::string &payload, const std::string &exc_substr = "")
                     -> std::pair<token::OutputDataPtr, CScript> {
        const auto payloadVec = ParseHex(payload);
        if ( ! payloadVec.empty() && payloadVec[0] == token::PREFIX_BYTE) {
            BOOST_TEST_MESSAGE("Doing txdb test for 'invalid' test vector: \"" + name + "\" ...");
            // Simulate what happens when a PREFIX_BYTE UTXO ends up in the txdb but is "invalid".
            // We should be able to serialize this "invalid" byte blob, we just don't treat it like
            // a token, but just like an unwrapped scriptPubKey.  We should be able to read it back
            // out again without any exceptions being thrown.
            std::vector<uint8_t> compressedTxoVec;
            const CTxOut txo(int64_t(InsecureRand32()) * SATOSHI, CScript(payloadVec.begin(), payloadVec.end()), {});
            {
                BOOST_CHECK(!txo.tokenDataPtr);
                BOOST_CHECK(!txo.IsNull());
                BOOST_CHECK(txo.HasUnparseableTokenData());
                GenericVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, compressedTxoVec, 0) << Using<TxOutCompression>(txo);
                token::last_unwrap_exception.reset();
                CTxOut txo2;
                BOOST_CHECK(txo != txo2);
                GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, compressedTxoVec, 0);
                BOOST_CHECK_NO_THROW(::Unserialize(vr, Using<TxOutCompression>(txo2)));
                BOOST_TEST_MESSAGE("Compressor should preserve data identically");
                BOOST_CHECK(token::last_unwrap_exception.has_value());
                BOOST_CHECK_MESSAGE(std::string{token::last_unwrap_exception.value().what()}.find(exc_substr)
                                    != std::string::npos, strprintf("Exception must contain: %s", exc_substr));
                BOOST_CHECK(txo == txo2);
                BOOST_CHECK(txo2.HasUnparseableTokenData());
            }

            // Simulate what happens if we read a txn off the network that has PREFIX_BYTE txos but is badly formatted.
            // This should work ok.  We just accept the scriptPubKey as-is.
            BOOST_TEST_MESSAGE("Doing ser/unser test for 'invalid' test vector: \"" + name + "\" ...");
            {
                std::vector<uint8_t> serializedTxoVec;
                GenericVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, serializedTxoVec, 0) << txo;
                BOOST_CHECK(serializedTxoVec.size() > compressedTxoVec.size());
                CTxOut txo2;
                BOOST_CHECK(txo != txo2);
                GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, serializedTxoVec, 0);
                BOOST_CHECK_NO_THROW(vr >> txo2);
                BOOST_CHECK(txo == txo2);
                BOOST_CHECK(txo2.HasUnparseableTokenData());
            }
        }
        BOOST_TEST_MESSAGE("Decoding and expecting an exception for 'invalid' test vector: \"" + name + "\" ...");
        token::OutputDataPtr pdata;
        CScript spk;
        const token::WrappedScriptPubKey wspk{payloadVec.begin(), payloadVec.end()};
        token::UnwrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION, true); // this may throw
        return {std::move(pdata), std::move(spk)};
    };
    BOOST_CHECK_THROW(TryDecode("PREFIX_TOKEN must encode at least one token",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00",
                                "Invalid token bitfield: 0x00"),
                      token::InvalidBitfieldError);
    BOOST_CHECK_EXCEPTION(TryDecode("PREFIX_TOKEN requires a token category ID",
                                    "ef", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Token category IDs must be 32 bytes",
                                    "efbbbbbbbb1001", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Category must be followed by token information",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                    "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_THROW(TryDecode("Token bitfield sets reserved bit",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9001",
                                "Invalid token bitfield: 0x90"),
                      token::InvalidBitfieldError);
    BOOST_CHECK_THROW(TryDecode("Unknown capability (0-byte NFT, capability 3)",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb23",
                                "Invalid token bitfield: 0x23"),
                      token::InvalidBitfieldError);
    BOOST_CHECK_THROW(TryDecode("Has commitment length without NFT (1 fungible)",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5001cc01",
                                "Invalid token bitfield: 0x50"),
                      token::InvalidBitfieldError);
    BOOST_CHECK_THROW(TryDecode("Prefix encodes a capability without an NFT",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1101",
                                "Invalid token bitfield: 0x11"),
                      token::InvalidBitfieldError);
    BOOST_CHECK_EXCEPTION(TryDecode("Commitment length must be specified (immutable token)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb60", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Commitment length must be specified (mutable token)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb61", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Commitment length must be specified (minting token)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb62", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Commitment length must be minimally encoded",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb60fd0100cc", "non-canonical ReadCompactSize"),
                          std::ios_base::failure, ExcMessageContains("non-canonical ReadCompactSize"));
    BOOST_CHECK_THROW(TryDecode("If specified, commitment length must be greater than 0",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6000",
                                "commitment may not be empty"),
                      token::CommitmentMustNotBeEmptyError);
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy commitment length (0/1 bytes)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6001", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy commitment length (mutable token, 0/1 bytes)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6101", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy commitment length (mutable token, 1/2 bytes)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6102cc", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy commitment length (minting token, 1/2 bytes)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb6202cc", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (no NFT, 1-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (no NFT, 2-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10fd00", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (no NFT, 4-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10fe000000", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (no NFT, 8-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10ff00000000000000", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (immutable NFT, 1-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7001cc", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (immutable NFT, 2-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7001ccfd00", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (immutable NFT, 4-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7001ccfe000000", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Not enough bytes remaining in locking bytecode to satisfy token amount (immutable NFT, 8-byte amount)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7001ccff00000000000000", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_EXCEPTION(TryDecode("Token amount must be specified)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb30", "end of data"),
                          std::ios_base::failure, ExcMessageContains("end of data"));
    BOOST_CHECK_THROW(TryDecode("If specified, token amount must be greater than 0 (no NFT)",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1000",
                                "amount may not be 0"),
                      token::AmountMustNotBeZeroError);
    BOOST_CHECK_THROW(TryDecode("If specified, token amount must be greater than 0 (0-byte NFT)",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3000",
                                "amount may not be 0"),
                      token::AmountMustNotBeZeroError);
    BOOST_CHECK_EXCEPTION(TryDecode("Token amount must be minimally-encoded",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb10fd0100", "non-canonical ReadCompactSize"),
                          std::ios_base::failure, ExcMessageContains("non-canonical ReadCompactSize"));
    BOOST_CHECK_THROW(TryDecode("Token amount (9223372036854775808) may not exceed 9223372036854775807",
                                "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb30ff0000000000000080",
                                "amount out of range"),
                      token::AmountOutOfRangeError);
    BOOST_CHECK_EXCEPTION(TryDecode("Commitment length must not be larger than 32 MiB (standard MAX_SIZE for serialization)",
                                    "efbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb70fe01000002"
                                    + std::string(42 * 2, 'c') + "fc", "ReadCompactSize(): size too large"),
                      std::ios_base::failure, ExcMessageContains("ReadCompactSize(): size too large"));
}

// Before activation of native tokens:
//   - allow any txn vout scriptPubKey with prefix byte token::PREFIX_BYTE (either parseable or unparseable)
//   - any txns with token outputs are non-standard
//   - any txn with inputs with token data prefix byte present (either parseable or or unparseable) MUST be rejected as
//     unspendable (to keep old consensus rules the same!)
// After activation:
//  - allow only scriptPubKeys with properly formatted token data if they have token::PREFIX_BYTE
//  - scriptPubKeys with prefix byte token::PREFIX_BYTES but that failed to parse are rejected
//  - tokens with commitment >40 bytes are non-standard but are accepted
//  - tokens with the combined token blob + realScriptPubKey adding up to >10,000 bytes are accepted
//    (so long as readlScriptPubKey part itself is <= 10000 bytes)
BOOST_AUTO_TEST_CASE(check_consensus_misc_activation) {
    SeedInsecureRand(/* deterministic */ true);
    const bool prev_g_mock_deterministic_tests = g_mock_deterministic_tests;
    g_mock_deterministic_tests = true;
    Defer d([&]{ g_mock_deterministic_tests = prev_g_mock_deterministic_tests; });
    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    static const uint32_t nUtxoHeight = 100;

    const CTransaction regularTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        const auto spkvec = ParseHex(GenRandomScriptPubKeyHexForAStandardDestination());
        tx.vout.emplace_back(int64_t(InsecureRand32()) * SATOSHI, CScript{spkvec.begin(), spkvec.end()});
        tx.nLockTime = 0;
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(tx.vin.back().prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh)), nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const CTransaction goodTokenSpendTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        auto real_spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        // build txo bytes manually to really test the unserializer behaves properly
        auto spk = HexStr({&pfx, 1}) + InsecureRand256().GetHex() + HexStr({&cap, 1}) + "20" + InsecureRand256().GetHex()
                   + "42" /* amount */ + real_spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0);
        vr >> txo;
        BOOST_CHECK(vr.empty()); // ensure no junk at end (everything parsed ok)
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(!txo.HasUnparseableTokenData());
        BOOST_CHECK(bool(txo.tokenDataPtr));
        BOOST_CHECK_EQUAL(txo.tokenDataPtr->GetAmount().getint64(), 0x42);
        BOOST_CHECK_EQUAL(HexStr(txo.scriptPubKey), real_spk);
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(tx.vin.back().prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh), txo.tokenDataPtr),
                                                  nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const CTransaction goodTokenSpendEmptyCommitmentTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        auto real_spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Capability::None);
        // build txo bytes manually to really test the unserializer behaves properly
        auto spk = HexStr({&pfx, 1}) + InsecureRand256().GetHex() + HexStr({&cap, 1})
                   + "42" /* amount */ + real_spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0);
        vr >> txo;
        BOOST_CHECK(vr.empty()); // ensure no junk at end (everything parsed ok)
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(!txo.HasUnparseableTokenData());
        BOOST_CHECK(bool(txo.tokenDataPtr));
        BOOST_CHECK_EQUAL(txo.tokenDataPtr->GetAmount().getint64(), 0x42);
        BOOST_CHECK(!txo.tokenDataPtr->HasCommitmentLength());
        BOOST_CHECK_EQUAL(HexStr(txo.scriptPubKey), real_spk);
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(tx.vin.back().prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh), txo.tokenDataPtr),
                                                  nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const CTransaction goodTokenMintTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        const auto &in = tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, 0), CScript() << randvec << randvec);
        auto real_spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        const token::Id id{in.prevout.GetTxId()};
        // build txo bytes manually to really test the unserializer behaves properly
        auto spk = HexStr({&pfx, 1}) + HexStr(id) + HexStr({&cap, 1}) + "20" + InsecureRand256().GetHex()
                   + "42" /* amount */ + real_spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0);
        vr >> txo;
        BOOST_CHECK(vr.empty()); // ensure no junk at end (everything parsed ok)
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(!txo.HasUnparseableTokenData());
        BOOST_CHECK(bool(txo.tokenDataPtr));
        BOOST_CHECK_EQUAL(txo.tokenDataPtr->GetAmount().getint64(), 0x42);
        BOOST_CHECK_EQUAL(HexStr(txo.scriptPubKey), real_spk);
        BOOST_CHECK_EQUAL(HexStr(txo.tokenDataPtr->GetId()), HexStr(id));
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(in.prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh)),
                                       nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const CTransaction badTokenMintTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        const auto &in = tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, 1), CScript() << randvec << randvec);
        auto real_spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        const token::Id id{in.prevout.GetTxId()};
        // build txo bytes manually to really test the unserializer behaves properly
        auto spk = HexStr({&pfx, 1}) + id.GetHex() + HexStr({&cap, 1}) + "20" + InsecureRand256().GetHex()
                   + "42" /* amount */ + real_spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0);
        vr >> txo;
        BOOST_CHECK(vr.empty()); // ensure no junk at end (everything parsed ok)
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(!txo.HasUnparseableTokenData());
        BOOST_CHECK(bool(txo.tokenDataPtr));
        BOOST_CHECK_EQUAL(txo.tokenDataPtr->GetAmount().getint64(), 0x42);
        BOOST_CHECK_EQUAL(HexStr(txo.scriptPubKey), real_spk);
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(in.prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh)),
                                       nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const auto MakeOversizedCommitmentTx = [&coins](const uint64_t commitmentLen, bool upgrade12 = false) {
        const size_t commitmentLimit = upgrade12 ? token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12
                                                 : token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE9;
        BOOST_CHECK_GT(commitmentLen, commitmentLimit);
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        auto real_spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        // build txo bytes manually to really test the unserializer behaves properly
        std::vector<uint8_t> csize;
        {
            GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
            vw << COMPACTSIZE(commitmentLen);
        }
        auto spk = HexStr({&pfx, 1}) + InsecureRand256().GetHex() + HexStr({&cap, 1})
                   + HexStr(csize) + std::string(commitmentLen * 2, 'c') // commitment of size 41
                   + "42" /* amount */ + real_spk;
        {
            csize.clear();
            GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
            vw << COMPACTSIZE(spk.size() / 2);

        }
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader vr(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0);
        vr >> txo;
        BOOST_CHECK(vr.empty()); // ensure no junk at end (everything parsed ok)
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(!txo.HasUnparseableTokenData());
        BOOST_CHECK(bool(txo.tokenDataPtr));
        BOOST_CHECK_EQUAL(txo.tokenDataPtr->GetAmount().getint64(), 0x42);
        BOOST_CHECK(txo.tokenDataPtr->GetCommitment() == token::NFTCommitment(uint32_t(commitmentLen), uint8_t{0xcc}));
        BOOST_CHECK_EQUAL(HexStr(txo.scriptPubKey), real_spk);
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(tx.vin.back().prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh), txo.tokenDataPtr),
                                                  nUtxoHeight, false), false);
        return CTransaction{tx};
    };
    const CTransaction outOfConsensusCommitmentTokenDataTx = MakeOversizedCommitmentTx(
        token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE9 + 1);
    const CTransaction outOfConsensusCommitmentTokenDataTx_upgrade12 = MakeOversizedCommitmentTx(
        token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12 + 1, true);
    const CTransaction outOfConsensusCommitmentTokenDataTx2 = MakeOversizedCommitmentTx(
        MAX_SCRIPT_ELEMENT_SIZE_LEGACY * 2, true);
    const CTransaction badTokenOutputDataTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        auto spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        // build txo bytes manually to really test the unserializer behaves properly
        spk = HexStr({&pfx, 1}) + InsecureRand256().GetHex() + HexStr({&cap, 1}) + "fd0902" /* invalid commitment length */
                + InsecureRand256().GetHex() + "42" + spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txo;
        GenericVectorReader(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0) >> txo;
        tx.vout.emplace_back(txo);
        tx.nLockTime = 0;
        BOOST_CHECK(txo.HasUnparseableTokenData());
        CKey inputKey;
        inputKey.MakeNewKey(true /* compressed */);
        const CKeyID p2pkh = inputKey.GetPubKey().GetID();
        coins.AddCoin(tx.vin.back().prevout, Coin(CTxOut(tx.vout.back().nValue, GetScriptForDestination(p2pkh)),
                                                  nUtxoHeight, false), false);
        return CTransaction{tx};
    }();
    const CTransaction badTokenInputDataTx = [&coins]{
        CMutableTransaction tx;
        const auto randhash = InsecureRand256();
        const std::vector<uint8_t> randvec{randhash.begin(), randhash.end()};
        tx.vin.emplace_back(COutPoint(TxId{InsecureRand256()}, InsecureRand32()), CScript() << randvec << randvec);
        auto spk = GenRandomScriptPubKeyHexForAStandardDestination();
        const uint8_t pfx = token::PREFIX_BYTE;
        const uint8_t cap = uint8_t(token::Structure::HasAmount) | uint8_t(token::Structure::HasNFT)
                            | uint8_t(token::Structure::HasCommitmentLength)
                            | uint8_t(token::Capability::Minting);
        // build txo bytes manually to really test the unserializer behaves properly
        spk = HexStr({&pfx, 1}) + InsecureRand256().GetHex() + HexStr({&cap, 1}) + "fdeb26" /* invalid commitment length */
                + InsecureRand256().GetHex() + "42" + spk;
        std::vector<uint8_t> csize;
        GenericVectorWriter vw(SER_NETWORK, INIT_PROTO_VERSION, csize, 0);
        vw << COMPACTSIZE(spk.size() / 2);
        auto hextxo = "0102030000000000" + HexStr(csize) + spk;
        const auto txodata = ParseHex(hextxo);
        CTxOut txoIn;
        GenericVectorReader(SER_NETWORK, INIT_PROTO_VERSION, txodata, 0) >> txoIn;
        CTxOut txoOut(txoIn.nValue, CScript() << OP_1);
        tx.vout.emplace_back(txoOut);
        tx.nLockTime = 0;
        BOOST_CHECK(txoIn.HasUnparseableTokenData());
        BOOST_CHECK(!txoOut.HasUnparseableTokenData());
        coins.AddCoin(tx.vin.back().prevout, Coin(txoIn, nUtxoHeight, false), false);
        return CTransaction{tx};
    }();

    CValidationState state;
    uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_TOKENS;

    // Check before SCRIPT_ENABLE_TOKENS activation for regular, goodToken and badToken txns
    BOOST_CHECK(CheckTxTokens(regularTx, state, coins, flags, nUtxoHeight + 1));
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(CheckTxTokens(goodTokenMintTx, state, coins, flags, nUtxoHeight + 1),
                        "Pre-activation, it should be possible to create new token outputs");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(CheckTxTokens(badTokenMintTx, state, coins, flags, nUtxoHeight + 1),
                        "Pre-activation, it should be possible to mint bogus tokens");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(! CheckTxTokens(goodTokenSpendTx, state, coins, flags, nUtxoHeight + 1),
                        "Pre-activation, should not be able to spend a token input");
    BOOST_CHECK_MESSAGE(! CheckTxTokens(goodTokenSpendEmptyCommitmentTx, state, coins, flags, nUtxoHeight + 1),
                        "Pre-activation, should not be able to spend a token input");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    state = CValidationState{};
    BOOST_CHECK(! CheckTxTokens(outOfConsensusCommitmentTokenDataTx, state, coins, flags, nUtxoHeight + 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    state = CValidationState{};
    BOOST_CHECK(! CheckTxTokens(outOfConsensusCommitmentTokenDataTx2, state, coins, flags, nUtxoHeight + 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    state = CValidationState{};
    BOOST_CHECK(! CheckTxTokens(outOfConsensusCommitmentTokenDataTx_upgrade12, state, coins, flags, nUtxoHeight + 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(CheckTxTokens(badTokenOutputDataTx, state, coins, flags, nUtxoHeight + 1),
                        "Before activation, the badTokenOutputDataTx should pass validation");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(! CheckTxTokens(badTokenInputDataTx, state, coins, flags, nUtxoHeight + 1),
                        "Before activation, the badTokenInputDataTx should NOT pass validation");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    state = CValidationState{};

    // Check AreInputsStandard
    BOOST_CHECK(   AreInputsStandard(regularTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(goodTokenSpendTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(goodTokenSpendEmptyCommitmentTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(goodTokenMintTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(badTokenMintTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(outOfConsensusCommitmentTokenDataTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(outOfConsensusCommitmentTokenDataTx2, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(outOfConsensusCommitmentTokenDataTx_upgrade12, coins, flags));
    BOOST_CHECK(   AreInputsStandard(badTokenOutputDataTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(badTokenInputDataTx, coins, flags));
    // Check IsStandardTx
    std::string reason;
    BOOST_CHECK(   IsStandardTx(regularTx, reason, flags));
    BOOST_CHECK( ! IsStandardTx(goodTokenSpendTx, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(goodTokenSpendEmptyCommitmentTx, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(goodTokenMintTx, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(badTokenMintTx, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(outOfConsensusCommitmentTokenDataTx, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(outOfConsensusCommitmentTokenDataTx2, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(outOfConsensusCommitmentTokenDataTx_upgrade12, reason, flags)); // pre-activation: token txouts are non-standard
    BOOST_CHECK_EQUAL(reason, "txn-tokens-before-activation");
    BOOST_CHECK( ! IsStandardTx(badTokenOutputDataTx, reason, flags));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    BOOST_CHECK( ! IsStandardTx(badTokenInputDataTx, reason, flags));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    // Activate Native Tokens
    flags |= SCRIPT_ENABLE_TOKENS;

    // Check *after* SCRIPT_ENABLE_TOKENS for regular, goodToken and badToken txns
    BOOST_CHECK(CheckTxTokens(regularTx, state, coins, flags, nUtxoHeight - 1));
    state = CValidationState{};
    BOOST_CHECK(CheckTxTokens(goodTokenSpendTx, state, coins, flags, nUtxoHeight - 1));
    state = CValidationState{};
    BOOST_CHECK(CheckTxTokens(goodTokenSpendEmptyCommitmentTx, state, coins, flags, nUtxoHeight - 1));
    state = CValidationState{};
    BOOST_CHECK(CheckTxTokens(goodTokenMintTx, state, coins, flags, nUtxoHeight - 1));
    BOOST_TEST_MESSAGE(state.GetRejectReason());
    state = CValidationState{};
    BOOST_CHECK_MESSAGE(! CheckTxTokens(badTokenMintTx, state, coins, flags, nUtxoHeight - 1),
                        "After activation, out-of-consensus minting of tokens forbidden");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-invalid-category");
    state = CValidationState{};

    // Pre-upgrade 12, commitments over 40 bytes are oversized and rejected
    BOOST_CHECK( ! CheckTxTokens(outOfConsensusCommitmentTokenDataTx, state, coins, flags, nUtxoHeight - 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");
    state = CValidationState{};
    BOOST_CHECK( ! CheckTxTokens(outOfConsensusCommitmentTokenDataTx2, state, coins, flags, nUtxoHeight - 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");
    state = CValidationState{};
    BOOST_CHECK( ! CheckTxTokens(outOfConsensusCommitmentTokenDataTx_upgrade12, state, coins, flags, nUtxoHeight - 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");

    // Post-upgrade 12 enabled, the 41-byte commitment is accepted, the others >128 are still rejected
    BOOST_CHECK(CheckTxTokens(outOfConsensusCommitmentTokenDataTx, state, coins, flags | SCRIPT_ENABLE_MAY2026, nUtxoHeight - 1));
    state = CValidationState{};
    BOOST_CHECK( ! CheckTxTokens(outOfConsensusCommitmentTokenDataTx2, state, coins, flags | SCRIPT_ENABLE_MAY2026, nUtxoHeight - 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");
    state = CValidationState{};
    BOOST_CHECK( ! CheckTxTokens(outOfConsensusCommitmentTokenDataTx_upgrade12, state, coins, flags | SCRIPT_ENABLE_MAY2026, nUtxoHeight - 1));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");

    // Bad token data
    state = CValidationState{};
    BOOST_CHECK_MESSAGE( ! CheckTxTokens(badTokenOutputDataTx, state, coins, flags, nUtxoHeight - 1),
                        "After activation, the badTokenOutputDataTx should fail validation");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vout-tokenprefix");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE( ! CheckTxTokens(badTokenInputDataTx, state, coins, flags, nUtxoHeight - 1),
                        "After activation, the badTokenInputDataTx should fail validation");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-tokenprefix");
    state = CValidationState{};

    // Check AreInputsStandard
    BOOST_CHECK(   AreInputsStandard(regularTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(goodTokenSpendTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(goodTokenSpendEmptyCommitmentTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(goodTokenMintTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(badTokenMintTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(outOfConsensusCommitmentTokenDataTx, coins, flags));
    BOOST_CHECK(   AreInputsStandard(outOfConsensusCommitmentTokenDataTx2, coins, flags));
    BOOST_CHECK(   AreInputsStandard(outOfConsensusCommitmentTokenDataTx_upgrade12, coins, flags));
    BOOST_CHECK(   AreInputsStandard(badTokenOutputDataTx, coins, flags));
    BOOST_CHECK( ! AreInputsStandard(badTokenInputDataTx, coins, flags));
    // Check IsStandardTx
    BOOST_CHECK(   IsStandardTx(regularTx, reason, flags));
    BOOST_CHECK(   IsStandardTx(goodTokenSpendTx, reason, flags)); // post-activation: token txouts are standard
    BOOST_CHECK(   IsStandardTx(goodTokenSpendEmptyCommitmentTx, reason, flags)); // post-activation: token txouts are standard
    BOOST_CHECK(   IsStandardTx(goodTokenMintTx, reason, flags)); // post-activation: token txouts are standard
    BOOST_CHECK(   IsStandardTx(badTokenMintTx, reason, flags)); // post-activation: token txouts are standard
    BOOST_CHECK(   IsStandardTx(outOfConsensusCommitmentTokenDataTx, reason, flags)); // post-activation: token txouts with commitment >40 is "standard" (but still fails consensus later in pipeline)
    BOOST_CHECK(   IsStandardTx(outOfConsensusCommitmentTokenDataTx2, reason, flags)); // post-activation: token txouts with commitment >40 is "standard" (but still fails consensus later in pipeline)
    BOOST_CHECK(   IsStandardTx(outOfConsensusCommitmentTokenDataTx_upgrade12, reason, flags)); // post-activation: token txouts with commitment >128 is "standard" (but still fails consensus later in pipeline)
    BOOST_CHECK( ! IsStandardTx(badTokenOutputDataTx, reason, flags));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
    BOOST_CHECK( ! IsStandardTx(badTokenInputDataTx, reason, flags));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    // Also check the failure mode of disallowing spends of tokens for utxo's created before activation
    BOOST_CHECK_MESSAGE( ! CheckTxTokens(goodTokenSpendTx, state, coins, flags, nUtxoHeight + 1),
                         "After activation, UTXOs that have valid token data but that were created before activation"
                         " may not be spent");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-token-created-pre-activation");
    state = CValidationState{};
    BOOST_CHECK_MESSAGE( ! CheckTxTokens(goodTokenSpendEmptyCommitmentTx, state, coins, flags, nUtxoHeight + 1),
                         "After activation, UTXOs that have valid token data but that were created before activation"
                         " may not be spent");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vin-token-created-pre-activation");
    state = CValidationState{};
}

/// Create a block against the current tip, using a custom coinbase txn (and optional txns), with sufficient PoW
static CBlock MakeBlock(const CChainParams &params, bool replaceCoinbase = true, bool includeMempool = false,
                        const CMutableTransaction &coinbaseTx = {}, const std::vector<CMutableTransaction> & txns = {}) {
    const Config &config = GetConfig();
    const CBlockIndex *pindexMinedTip;
    auto pblocktemplate = BlockAssembler(config, g_mempool).CreateNewBlock({}, 0 /* time limit (seconds) */,
                                                                           false /* test validity */, &pindexMinedTip);
    CBlock &block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    auto keepNumber = includeMempool ? block.vtx.size() : 1;
    block.vtx.reserve(keepNumber + txns.size());
    block.vtx.resize(keepNumber);
    if (replaceCoinbase) {
        block.vtx[0] = MakeTransactionRef(coinbaseTx); // override coinbase
    }

    for (const auto &tx : txns) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }

    // Order transactions by canonical order
    std::sort(std::begin(block.vtx) + 1, std::end(block.vtx),
              [](const auto &txa, const auto &txb) { return txa->GetId() < txb->GetId(); });

    unsigned int extraNonce = 0;
    do {
        // IncrementExtraNonce creates a valid coinbase and merkleRoot
        IncrementExtraNonce(&block, pindexMinedTip, config, extraNonce);
        bool found;
        while ( ! (found = CheckProofOfWork(block.GetHash(), block.nBits, params.GetConsensus()))) {
            if ( ! ++block.nNonce ) break;
        }
        if (found) break;
        if ( ! extraNonce) throw std::runtime_error("Unable to find a solution"); // wrapped around to 0
    } while (true);

    return std::move(block);
}

/// Activates or deactivates upgrade 9 by setting the activation height for a past or future block
[[nodiscard]]
static Defer<std::function<void()>> SetUpgrade9Active(bool active) {
    const auto prevVal = g_Upgrade9HeightOverride;
    const auto currentHeight = []{
        LOCK(cs_main);
        return CHECK_NONFATAL(::ChainActive().Tip())->nHeight;
    }();
    const auto activationHeight = active ? currentHeight - 1 : currentHeight + 1;
    g_Upgrade9HeightOverride = activationHeight;
    return Defer(std::function<void()>{
        [prevVal] {
            g_Upgrade9HeightOverride = prevVal;
        }
    });
}

/// Activates or deactivates upgrade 12 by setting the activation time via the gArgs mechanism to past or future
[[nodiscard]]
static Defer<std::function<void()>> SetUpgrade12Active(bool active) {
    constexpr auto argName = "-upgrade12activationtime";
    std::optional<int64_t> prevVal;
    if (gArgs.IsArgSet(argName)) {
        prevVal = gArgs.GetArg(argName, ::GetConfig().GetChainParams().GetConsensus().upgrade12ActivationTime);
    }
    const int64_t currentMTP = []{
        LOCK(cs_main);
        return CHECK_NONFATAL(::ChainActive().Tip())->GetMedianTimePast();
    }();
    const auto activationTime = active ? currentMTP - 1 : currentMTP + 1;
    gArgs.ForceSetArg(argName, strprintf("%i", activationTime));
    return Defer(std::function<void()>{
        [prevVal] {
            if (prevVal) {
                gArgs.ForceSetArg(argName, strprintf("%i", *prevVal));
            } else {
                gArgs.ClearArg(argName);
            }
        }
    });
}

// Before activation of native tokens:
//    - allow coinbase transactions with correctly parsed token outputs.
//    - allow coinbase transactions to contain a scriptPubKey that starts with token::PREFIX_BYTE (but is otherwise
//      unparseable as token data).
// After activation:
//    - do not allow coinbase transactions with any token outputs.
//    - do not allow coinbase transactions to contain a scriptPubKey that starts with token::PREFIX_BYTE
BOOST_FIXTURE_TEST_CASE(check_consensus_rejection_of_coinbase_tokens, TestChain100Setup) {
    SeedInsecureRand(/* deterministic */ true);
    const bool prev_g_mock_deterministic_tests = g_mock_deterministic_tests;
    g_mock_deterministic_tests = true;
    Defer d([&]{ g_mock_deterministic_tests = prev_g_mock_deterministic_tests; });

    const auto [currentHeight, currentMTP] = []{
        LOCK(cs_main);
        const CBlockIndex * const tip = ::ChainActive().Tip();
        assert(tip != nullptr);
        return std::pair(tip->nHeight, tip->GetMedianTimePast());
    }();

    // Create two coinbase transactions (one with token data and one with unparseable token data)
    const auto & [coinbaseTxWithTokenData, coinbaseTxWithUnparseableTokenData] = [](int nHeight){
        CMutableTransaction mtx;
        auto & txin = mtx.vin.emplace_back(); // default constructed CTxIn is a coinbase
        txin.scriptSig = CScript() << ScriptInt::fromInt(nHeight + 1).value(); // encode BIP34 height correctly
        txin.scriptSig.resize(100, 0); // fill scriptSig up to 100 bytes to make coinbase txn >100 bytes
        // Attach the token output data
        const token::Id token_id{InsecureRand256()};
        const auto token_amount = token::SafeAmount::fromInt(1).value();
        CScript spk;
        GenRandomScriptPubKeyHexForAStandardDestination(&spk);
        auto & txo = mtx.vout.emplace_back(50 * COIN, spk, token::OutputDataPtr{token::OutputData(token_id, token_amount)});
        CMutableTransaction tx1 = mtx; // save this txn
        // clear token data
        txo.tokenDataPtr.reset();
        // insert prefix byte (will generate, in effect, an "unparseable" token data output)
        txo.scriptPubKey.insert(txo.scriptPubKey.begin(), token::PREFIX_BYTE);
        return std::pair<CTransaction, CTransaction>{std::move(tx1), std::move(mtx)};
    }(currentHeight);
    BOOST_CHECK(coinbaseTxWithTokenData.IsCoinBase());
    BOOST_CHECK( ! coinbaseTxWithTokenData.vout.back().HasUnparseableTokenData());

    BOOST_CHECK(coinbaseTxWithUnparseableTokenData.IsCoinBase());
    BOOST_CHECK(coinbaseTxWithUnparseableTokenData.vout.back().HasUnparseableTokenData());

    const auto &params = ::GetConfig().GetChainParams();
    CValidationState state;
    BlockValidationOptions options(::GetConfig());
    options = options.withCheckMerkleRoot().withCheckPoW();

    auto MakeBlockAndTestValidity = [&](const auto &coinbaseTx) {
        const auto &block = MakeBlock(params, true /* replaceCoinbase */, false /* includeMempool */,
                                      CMutableTransaction{coinbaseTx});
        LOCK(cs_main);
        return TestBlockValidity(state, params, block, ::ChainActive().Tip(), options);
    };

    // Pre-activation
    auto a1 = SetUpgrade9Active(false);
    BOOST_CHECK_MESSAGE(MakeBlockAndTestValidity(coinbaseTxWithTokenData),
                        "Before activation, the Coinbase transaction may contain valid token outputs");
    state = CValidationState{};

    BOOST_CHECK_MESSAGE(MakeBlockAndTestValidity(coinbaseTxWithUnparseableTokenData),
                        "Before activation, the Coinbase transaction may contain unparseable token outputs");
    state = CValidationState{};

    // Activate Upgrade9 by setting Upgarde9 MTP below the tip's MTP
    auto a2 = SetUpgrade9Active(true);

    BOOST_CHECK_MESSAGE( ! MakeBlockAndTestValidity(coinbaseTxWithTokenData),
                        "After activation, the Coinbase transaction may not contain valid token outputs");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-coinbase-has-tokens");
    state = CValidationState{};

    BOOST_CHECK_MESSAGE( ! MakeBlockAndTestValidity(coinbaseTxWithUnparseableTokenData),
                        "After activation, no transaction may contain unparseable token outputs");
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vout-tokenprefix");
    state = CValidationState{};
}

BOOST_AUTO_TEST_CASE(prefix_token_encoding_json_test_vectors_valid) {
    // paranoia: since we use std::atoll below, we need to ensure "C" locale
    const std::string origLocale = std::setlocale(LC_ALL, nullptr);
    std::setlocale(LC_ALL, "C");
    Defer d0([&origLocale]{
         std::setlocale(LC_ALL, origLocale.c_str());
    });

    // load json tests
    static_assert(sizeof(json_tests::token_tests_prefix_valid[0]) == 1);
    const UniValue::Array tests = read_json({reinterpret_cast<const char *>(&json_tests::token_tests_prefix_valid[0]),
                                             std::size(json_tests::token_tests_prefix_valid)});
    BOOST_CHECK( ! tests.empty());
    unsigned ctr = 0;
    for (const UniValue &tv : tests) {
        BOOST_TEST_MESSAGE(strprintf("Checking 'valid' test vector %i ...", ctr++));
        token::OutputDataPtr pdata;
        {
            // Unserialize the "prefix" hex into pdata
            const std::vector<uint8_t> serializedPrefix = ParseHex(tv["prefix"].get_str());
            token::WrappedScriptPubKey wspk;
            CScript spk;
            wspk.insert(wspk.end(), serializedPrefix.begin(), serializedPrefix.end());
            token::UnwrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION, true /* throw if unparseable */);
            BOOST_CHECK(bool(pdata));
            BOOST_CHECK(spk.empty()); // all of the JSON test vectors omit the scriptPubKey data that would follow
            // check that re-serialization produces identical serialized data
            wspk.clear();
            token::WrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION);
            BOOST_CHECK_EQUAL(HexStr(wspk), HexStr(serializedPrefix));
        }

        // Next, check the deserialized token data matches what is expected from the test vector
        const UniValue::Object &d = tv["data"].get_obj();
        // Check category id matches
        // -- Note that the hex representation in the JSON is big endian but our memory order for
        // -- hashes is little endian.  However uint256::GetHex() returns a big endian hex string.
        // -- See: https://github.com/bitjson/cashtokens/issues/53
        BOOST_CHECK_EQUAL(pdata->GetId().GetHex(), d["category"].get_str());
        // Check amount
        {
            int64_t amt = 0;
            if (const UniValue *pamt = d.locate("amount")) {
                if (pamt->isNum()) {
                    amt = pamt->get_int64();
                } else {
                    // parse amount
                    amt = std::atoll(pamt->getValStr().c_str());
                    const auto verifyStr = strprintf("%d", amt);
                    // paranoia to ensure there are no "surprises" in the test vectors with amounts we cannot parse
                    BOOST_CHECK_EQUAL(verifyStr, pamt->getValStr());
                }
            }
            BOOST_CHECK_EQUAL(pdata->HasAmount(), amt != 0LL);
            BOOST_CHECK_EQUAL(pdata->GetAmount().getint64(), amt);
        }
        // Check NFT (if any)
        if (const UniValue *pnft = d.locate("nft")) {
            // Check commitment
            std::string commitment = "";
            if (const UniValue *pcommitment = pnft->locate("commitment")) {
                commitment = pcommitment->get_str();
            }
            BOOST_CHECK_EQUAL(HexStr(pdata->GetCommitment()), commitment);
            BOOST_CHECK(pdata->HasCommitmentLength() == !commitment.empty());

            // Check capability
            std::string cap;
            switch (pdata->GetCapability()) {
            case token::Capability::None: cap = "none"; break;
            case token::Capability::Mutable: cap = "mutable"; break;
            case token::Capability::Minting: cap = "minting"; break;
            }
            const auto &capuv = (*pnft)["capability"];
            BOOST_CHECK_EQUAL(cap, capuv.get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(prefix_token_encoding_json_test_vectors_invalid) {
    static_assert(sizeof(json_tests::token_tests_prefix_invalid[0]) == 1);
    const UniValue::Array tests = read_json({reinterpret_cast<const char *>(&json_tests::token_tests_prefix_invalid[0]),
                                             std::size(json_tests::token_tests_prefix_invalid)});
    BOOST_CHECK( ! tests.empty());
    unsigned ctr = 0;
    for (const UniValue &tv : tests) {
        BOOST_TEST_MESSAGE(strprintf("Checking 'invalid' test vector %i ...", ctr++));
        const auto serializedPrefix = ParseHex(tv["prefix"].get_str());
        const auto expectedExcMsg = TrimString(tv["bchn_exception_message"].get_str());
        BOOST_CHECK( ! expectedExcMsg.empty()); // ensure the JSON entry specifies a non-empty exception message
        token::WrappedScriptPubKey wspk;
        wspk.insert(wspk.end(), serializedPrefix.begin(), serializedPrefix.end());
        token::OutputDataPtr pdata;
        CScript spk;
        // All of the "invalid" tests should throw here, and the exception message we expect comes from the
        // JSON "bchn_exception_message" key
        BOOST_CHECK_EXCEPTION(token::UnwrapScriptPubKey(wspk, pdata, spk, INIT_PROTO_VERSION, true /* throws */),
                              std::ios_base::failure, ExcMessageContains(expectedExcMsg));
    }
}

/// Mine a block by first adding the specified list of transactions to the mempool, consuming these into a
/// block with sufficient PoW, and adding it to the chain.
static bool MineTransactions(const std::vector<CMutableTransaction> transactions, CValidationState &state) {
    const uint32_t scriptFlags = []{
        LOCK(cs_main);
        return GetMemPoolScriptFlags(::Params().GetConsensus(), ::ChainActive().Tip());
    }();
    BOOST_TEST_MESSAGE(strprintf("%s: scriptFlags = %s", __func__, FormatScriptFlags(scriptFlags)));

    // Send the transactions to the mempool
    auto mempoolInitSize = g_mempool.size();
    {
        LOCK(cs_main);
        for (const auto &tx : transactions) {
            auto txref = MakeTransactionRef(tx);
            bool missingInputs = false;
            if ( ! AcceptToMemoryPool(::GetConfig(), g_mempool, state, txref, &missingInputs,
                                      true /* bypass_limits */, Amount::zero() /* nAbsurdFee */)) {
                if ( ! state.IsValid()) {
                    BOOST_TEST_MESSAGE("AcceptToMemoryPool failed: " + state.GetRejectReason());
                }
                if (missingInputs) {
                    BOOST_TEST_MESSAGE("AcceptToMemoryPool failed: Missing inputs detected");
                }
                return false;
            }
            state = CValidationState{};
        }
    }
    // The mempool should now contain our transactions
    BOOST_CHECK_EQUAL(g_mempool.size(), mempoolInitSize + transactions.size());

    // Create and test a block, consuming the mempool
    const CBlock block = MakeBlock(::GetConfig().GetChainParams(), false /* replaceCoinbase */,
                                   true /* includeMempool */);
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    BlockValidationOptions options(::GetConfig());
    options = options.withCheckMerkleRoot().withCheckPoW();
    {
        LOCK(cs_main);
        BOOST_CHECK(TestBlockValidity(state, ::GetConfig().GetChainParams(), block,
                                      ::ChainActive().Tip(), options));
        if (!state.IsValid()) {
            BOOST_TEST_MESSAGE(state.GetRejectReason());
            return false;
        }
    }
    // Check that the block contains the right number of txs - the mempool txs plus the coinbase tx
    BOOST_CHECK_EQUAL(block.vtx.size(), g_mempool.size() + 1);

    // Process the block
    if (!ProcessNewBlock(::GetConfig(), shared_pblock, true, nullptr)) {
        BOOST_TEST_MESSAGE("ProcessNewBlock failed");
        return false;
    }
    // The mempool should now be clear
    BOOST_CHECK_EQUAL(g_mempool.size(), 0);

    return true;
}

/// Helper function to produce signed transactions with the following characteristics:
/// - A single input 'inputTx' (at n=0) with corresponding key 'senderKey'.
/// - Use 'vout' to configure the outputs.
/// - A single destination is automatically generated and each output is adjusted to spend to it. The key
///   for this destination can be retrieved with 'destinationKey_out'.
/// - Each output's nValue is set to COIN if not already set.
static CMutableTransaction CreateAndSignTx(const CKey senderKey, const CTransactionRef inputTx,
                                           const std::vector<CTxOut> vout,
                                           CKey *destinationKey_out = nullptr) {
    // Create a destination
    CScript scriptPubKey;
    if (destinationKey_out) {
        destinationKey_out->MakeNewKey(true);
        GetRandomScriptPubKeyHexForAPubKey(destinationKey_out->GetPubKey(), &scriptPubKey);
    } else {
        GenRandomScriptPubKeyHexForAStandardDestination(&scriptPubKey);
    }

    // Create the transaction
    const CTxOut &inputCoin = inputTx->vout.at(0);
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(inputTx->GetId(), 0 /* n */);
    tx.vout = vout;
    for (auto &output : tx.vout) {
        if (output.nValue == -SATOSHI) { // This is how a null CTxOut value is determined
            output.nValue = inputCoin.nValue / int64_t(tx.vout.size()) - int64_t(500) * SATOSHI;
        }
        output.scriptPubKey = scriptPubKey;
    }

    const uint32_t scriptFlags = []{
        LOCK(cs_main);
        return GetMemPoolScriptFlags(::Params().GetConsensus(), ::ChainActive().Tip());
    }();
    BOOST_TEST_MESSAGE(strprintf("%s: scriptFlags = %s", __func__, FormatScriptFlags(scriptFlags)));

    // Sign the transaction
    CBasicKeyStore keystore;
    keystore.AddKey(senderKey);
    // support p2sh wrapping p2pk for this key
    keystore.AddCScript(GetScriptForRawPubKey(senderKey.GetPubKey()), false /* not p2sh_32 */, false /* legacy vm limits */);
    BOOST_CHECK(SignSignature(keystore, *inputTx, tx, 0, SigHashType().withFork(),
                              scriptFlags,
                              ScriptExecutionContext{0u, inputCoin, tx}));

    return tx;
}

/// txn-tokens-before-activation: Check that valid genesis token transactions can be mined only after
/// activation of native tokens
BOOST_FIXTURE_TEST_CASE(with_mempool_check_valid_genesis_token, TestChain100Setup) {
    // Create a token category genesis transaction. To be a genesis tx, the token category id must be equal
    // to the prevout tx id and the tx prevout must be n=0
    std::vector<CTxOut> vout(1);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value());
    // Attempt to mine the transaction pre-activation
    auto a1 = SetUpgrade9Active(false);
    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout);

    CValidationState state;
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx1}, state),
                        "Before activation, valid genesis tokens may not be mined into a block via the mempool path");
    BOOST_CHECK( ! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "txn-tokens-before-activation");
    state = CValidationState{};

    // Attempt to mine the transaction post-activation
    auto a2 = SetUpgrade9Active(true);
    BOOST_CHECK_MESSAGE(MineTransactions({tx1}, state),
                        "After activation, valid genesis tokens may be mined into a block via the mempool path");
}

/// bad-txns-token-invalid-category: Check that we cannot spend tokens with no matching input tokens
BOOST_FIXTURE_TEST_CASE(with_mempool_check_invalid_mint, TestChain100Setup) {
    // Create a token "from nothing" - with no matching genesis or input token
    std::vector<CTxOut> vout(1);
    // Random ID ensures no matching token category
    vout[0].tokenDataPtr.emplace(token::Id{InsecureRand256()}, token::SafeAmount::fromInt(1).value());
    auto a1 = SetUpgrade9Active(true);

    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout);

    // Attempt to mine the transaction
    CValidationState state;
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx1}, state),
                        "Output tokens must have a corresponding input token with matching ID");
    BOOST_CHECK(! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-invalid-category");
}

/// bad-txns-inputs-missingorspent: Check that we cannot spend from a spent input
// This error is caught by AcceptToMemoryPool returning with 'missingInputs' set to true
BOOST_FIXTURE_TEST_CASE(with_mempool_check_spent_coin_with_token_spend, TestChain100Setup) {
    // Create a token category genesis transaction and render the reward spent
    std::vector<CTxOut> vout(1);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value());

    auto a1 = SetUpgrade9Active(true);

    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout, nullptr);

    // Mine the transaction
    CValidationState state;
    BOOST_CHECK(MineTransactions({tx1}, state));
    state = CValidationState{};

    // Attempt to spend from the same (spent) reward coin again
    CMutableTransaction tx2 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout, nullptr);

    BOOST_CHECK_MESSAGE( ! MineTransactions({tx2}, state),
                        "Transactions with spent inputs may not be mined into a block");
}

/// bad-txns-token-in-belowout: Check that we cannot mine transactions that spend more tokens
/// than are available in the inputs
BOOST_FIXTURE_TEST_CASE(with_mempool_check_token_overspend, TestChain100Setup) {
    // Create a token category genesis transaction
    std::vector<CTxOut> vout(1);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value());
    CKey firstDestinationKey;

    auto a1 = SetUpgrade9Active(true);

    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout, &firstDestinationKey);
    const CTransactionRef tx1ref = MakeTransactionRef(tx1);

    // Mine the transaction
    CValidationState state;
    BOOST_CHECK(MineTransactions({tx1}, state));
    state = CValidationState{};

    // Create a transaction spending more of the token than exists in the input
    vout[0].tokenDataPtr->SetAmount(token::SafeAmount::fromInt(2).value());
    CMutableTransaction tx2 = CreateAndSignTx(firstDestinationKey, tx1ref, vout);

    // Attempt to mine it
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx2}, state),
                        "Transactions spending more tokens than exist in the transaction inputs cannot be "
                        "mined into a block");
    BOOST_CHECK( ! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-in-belowout");
    state = CValidationState{};

    // Attempt to mine it, this time respecting the out >= in predicate
    vout[0].tokenDataPtr->SetAmount(token::SafeAmount::fromInt(1).value());
    CMutableTransaction tx3 = CreateAndSignTx(firstDestinationKey, tx1ref, vout);
    BOOST_CHECK_MESSAGE(MineTransactions({tx3}, state), "However we can spend it ok if in is not below out");
}

/// bad-txns-token-nft-ex-nihilo: Check that we cannot mine transactions that spend more NFTs
/// than are available in the inputs
BOOST_FIXTURE_TEST_CASE(with_mempool_check_invalid_nft_mint, TestChain100Setup) {
    // Create an nft genesis transaction
    std::vector<CTxOut> vout(1);
    const token::NFTCommitment goodCommitment{3u, uint8_t(0xaa)};
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value(),
                                 goodCommitment,
                                 true /* hasNFT */, false /* isMutableNFT */,
                                 false /* isMintingNFT */, false /* uncheckedNFT */ );
    CKey firstDestinationKey;
    auto a1 = SetUpgrade9Active(true);
    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout, &firstDestinationKey);
    const CTransactionRef tx1ref = MakeTransactionRef(tx1);

    // Mine the genesis transaction
    CValidationState state;
    BOOST_CHECK_MESSAGE(MineTransactions({tx1}, state),
                        "Valid NFT genesis transactions may be mined into a block");

    // Create a transaction spending an NFT that doesn't exist in the inputs
    vout[0].tokenDataPtr->SetCommitment(token::NFTCommitment{3u, uint8_t(0xbb)});// 0xbb instead of 0xaa
    CMutableTransaction tx2 = CreateAndSignTx(firstDestinationKey, tx1ref, vout);

    // Attempt to mine the spend transaction
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx2}, state),
                        "Output NFT tokens must have a corresponding input token with matching "
                        "commitment");
    BOOST_CHECK(! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-nft-ex-nihilo");
    state = CValidationState{};

    // Attempt to mine the spend transaction -- this time respecting the NFT predicate
    vout[0].tokenDataPtr->SetCommitment(goodCommitment);// restore the good commitment
    CMutableTransaction tx3 = CreateAndSignTx(firstDestinationKey, tx1ref, vout);
    BOOST_CHECK(MineTransactions({tx3}, state));
    BOOST_CHECK(state.IsValid());
}

/// bad-txns-token-amount-overflow: Check that the sum total of genesis tokens cannot exceed numerical
/// maximum limits
BOOST_FIXTURE_TEST_CASE(with_mempool_check_token_amount_overflow, TestChain100Setup) {
    // Create a token category genesis transaction with multiple outputs with a total token count greater
    // than int64_t max.
    std::vector<CTxOut> vout(2);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(std::numeric_limits<int64_t>::max()).value());
    vout[1].tokenDataPtr = vout[0].tokenDataPtr;
    vout[1].tokenDataPtr->SetAmount(token::SafeAmount::fromInt(100).value());
    auto a1 = SetUpgrade9Active(true);
    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout);

    // Attempt to mine the transaction
    CValidationState state;
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx1}, state),
                        "Transactions resulting in a number of tokens greater than the numerical maximum "
                        "may not be mined into a block");
    BOOST_CHECK( ! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-amount-overflow");
    state = CValidationState{};
}

/// bad-txns-token-non-nft-amount-zero: Check that a zero amount of fungible tokens cannot be sent
// This error is caught by the exception 'InvalidBitfieldError' raised during token data serialization
BOOST_FIXTURE_TEST_CASE(with_mempool_check_zero_ft_amount, TestChain100Setup) {
    // Create a fungible token genesis transaction
    std::vector<CTxOut> vout(1);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value());
    CKey firstDestinationKey;
    auto a1 = SetUpgrade9Active(true);
    CMutableTransaction tx1 = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout, &firstDestinationKey);
    const CTransactionRef tx1ref = MakeTransactionRef(tx1);

    // Mine the transaction
    CValidationState state;
    BOOST_CHECK(MineTransactions({tx1}, state));
    state = CValidationState{};

    // Attempt to create a transaction spending a zero amount of the token
    vout[0].tokenDataPtr->SetAmount(token::SafeAmount::fromInt(0).value());
    BOOST_CHECK_THROW(CreateAndSignTx(firstDestinationKey, tx1ref, vout),
                      token::InvalidBitfieldError);
}

/// bad-txns-token-fungible-with-commitment: Check that fungible tokens with a commitment cannot be created
// This error is caught by the exception 'InvalidBitfieldError' raised during token data serialization
BOOST_FIXTURE_TEST_CASE(with_mempool_check_invalid_ft_with_commitment, TestChain100Setup) {
    std::vector<CTxOut> vout(1);
    vout[0].tokenDataPtr.emplace(token::Id{m_coinbase_txns[0]->GetId()},
                                 token::SafeAmount::fromInt(1).value(),
                                 token::NFTCommitment{3u, uint8_t(0xaa)},
                                 false /* hasNFT */, false /* isMutableNFT */,
                                 false /* isMintingNFT */, false /* uncheckedNFT */ );
    auto a1 = SetUpgrade9Active(true);
    BOOST_CHECK_THROW(CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout),
                      token::InvalidBitfieldError);
}

/// bad-txns-token-commitment-oversized: Check that tokens with oversized commitments cannot be mined
BOOST_FIXTURE_TEST_CASE(with_mempool_check_oversized_token_commitment, TestChain100Setup) {
    std::vector<CTxOut> vout(1), vout2(1);
    BOOST_REQUIRE_GE(m_coinbase_txns.size(), 2);
    BOOST_REQUIRE_GT(token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12, token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE9);
    vout[0].tokenDataPtr.emplace( token::Id{m_coinbase_txns[0]->GetId()},
                                  token::SafeAmount::fromInt(1).value(),
                                  token::NFTCommitment{token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12,
                                                       uint8_t(0xaa)},
                                  true /* hasNFT */, false /* isMutableNFT */,
                                  true /* isMintingNFT */, false /* uncheckedNFT */ );
    vout2[0].tokenDataPtr.emplace( token::Id{m_coinbase_txns[1]->GetId()},
                                   token::SafeAmount::fromInt(1).value(),
                                   token::NFTCommitment{token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12 + 1,
                                                        uint8_t(0xab)},
                                   true /* hasNFT */, false /* isMutableNFT */,
                                   true /* isMintingNFT */, false /* uncheckedNFT */ );
    auto u9_on = SetUpgrade9Active(true);
    auto u12_off = SetUpgrade12Active(false);
    CMutableTransaction tx_oversized_upgrade9_only = CreateAndSignTx(coinbaseKey, m_coinbase_txns[0], vout);
    CreateAndProcessBlock({}, {}); // Ensures we can spend m_coinbase_txs[1]
    CMutableTransaction tx_always_oversized = CreateAndSignTx(coinbaseKey, m_coinbase_txns[1], vout2);

    // Attempt to mine the transaction, using upgrade 9 rules only, no upgrade 12.
    CValidationState state;
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx_oversized_upgrade9_only}, state),
                        "Pre-upgrade 12: Tokens with an oversized commitment >40 bytes may not be mined into a block");
    BOOST_CHECK(! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");
    // Try the same with the "commitment is always too big" tx.
    state = {};
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx_always_oversized}, state),
                        "Tokens with an oversized commitment >128 bytes may not be mined into a block");
    BOOST_CHECK(! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");

    // Now, turn on upgrade 12, and the 128 byte commitment should mine ok
    state = {};
    auto u12_on = SetUpgrade12Active(true);
    BOOST_REQUIRE_MESSAGE(MineTransactions({tx_oversized_upgrade9_only}, state),
                          "Post-upgrade 12: Tokens with a commitment >40 but <=128 bytes may be mined into a block");
    BOOST_CHECK(state.IsValid());
    // Consume the coin we just spent so as to not confuse other tests in this file.
    m_coinbase_txns.erase(m_coinbase_txns.begin());

    // Attempt to mine a commitment that is too large for both upgrade 9 and upgrade 12
    state = {};
    BOOST_CHECK_MESSAGE( ! MineTransactions({tx_always_oversized}, state),
                        "Tokens with an oversized commitment >128 bytes may not be mined into a block");
    BOOST_CHECK(! state.IsValid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-token-commitment-oversized");
}

// Test basic behavior of SIGHASH_UTXOS as a valid signing scheme. It should fail consensus if the upgrade is not
// active, but work otherwise if used correctly in client code (requires a full and valid ScriptExecutionContext).
BOOST_FIXTURE_TEST_CASE(sighash_utxos_test, TestChain100Setup) {
    size_t coinbase_txn_idx = 0;
    CScript const p2pk_scriptPubKey = CScript() << coinbaseKey.GetPubKey() << OP_CHECKSIG;

    for (const bool isUpgrade9Active : {false, true}) {
        // Paranoia: mine 2 blocks to ensure maturity of up to 2 coinbase txns
        CreateAndProcessBlock({}, p2pk_scriptPubKey);
        CreateAndProcessBlock({}, p2pk_scriptPubKey);

        auto d1 = SetUpgrade9Active(isUpgrade9Active);

        CMutableTransaction spend_tx;
        spend_tx.nVersion = 1;
        spend_tx.vin.resize(2);
        spend_tx.vin[0].prevout = COutPoint(m_coinbase_txns[coinbase_txn_idx++]->GetId(), 0);
        spend_tx.vin[1].prevout = COutPoint(m_coinbase_txns[coinbase_txn_idx++]->GetId(), 0);
        spend_tx.vout.resize(1);
        spend_tx.vout[0].nValue =   m_coinbase_txns[coinbase_txn_idx - 2u]->vout[0].nValue
                                  + m_coinbase_txns[coinbase_txn_idx - 1u]->vout[0].nValue
                                  - (1000 * SATOSHI);
        spend_tx.vout[0].scriptPubKey = p2pk_scriptPubKey;

        const auto real_contexts = [&] {
            LOCK(cs_main); // access to pcoinsTip shoule be done with cs_main held
            return ScriptExecutionContext::createForAllInputs(spend_tx, *pcoinsTip);
        }();

        // "Manually" sign the txn with SIGHASH_UTXOS for each input
        for (unsigned inp = 0; inp < spend_tx.vin.size(); ++inp) {
            std::vector<uint8_t> vchSig;
            const ScriptExecutionContext limited_context{inp,  // input number
                                                         m_coinbase_txns[coinbase_txn_idx - 2u + inp]->vout[0],  // coin
                                                         spend_tx}; // tx context
            uint256 sigHash, sigHashNoUtxos, sigHashNoUtxos2;
            const auto sigHashType = SigHashType().withFork().withUtxos();
            const uint32_t signingFlags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_TOKENS;
            // Check that a limited context doesn't work for SIGHASH_UTXOS (it throws due to missing input data)
            BOOST_REQUIRE_THROW(SignatureHash(p2pk_scriptPubKey, limited_context, sigHashType, nullptr, signingFlags),
                                SignatureHashMissingUtxoDataError);
            // But a full context does work.
            sigHash = SignatureHash(p2pk_scriptPubKey, real_contexts[inp], sigHashType, nullptr, signingFlags).signatureHash;

            // Also get a sighash without the flag to test that it is indeed different
            sigHashNoUtxos = SignatureHash(p2pk_scriptPubKey, real_contexts[inp], sigHashType.withUtxos(false), nullptr,
                                           signingFlags).signatureHash;
            BOOST_CHECK(sigHashNoUtxos != sigHash);

            // Get a sighash but with SCRIPT_ENABLE_TOKENS disabled while the sighash type is still set to .withUtxos().
            // This "works" but yields a different, nonsensical signature hash not equivalent to the valid one.
            // (This codepath cannot happen in normal signing code, but is worth testing here)
            sigHashNoUtxos2 = SignatureHash(p2pk_scriptPubKey, real_contexts[inp], sigHashType, nullptr,
                                           signingFlags & ~SCRIPT_ENABLE_TOKENS).signatureHash;
            BOOST_CHECK(sigHashNoUtxos2 != sigHash);
            BOOST_CHECK(sigHashNoUtxos2 != sigHashNoUtxos);

            // Sign even inputs as Schnorr, odd as ECDSA
            BOOST_CHECK((inp % 2u) == 0
                        ? coinbaseKey.SignSchnorr(sigHash, vchSig)
                        : coinbaseKey.SignECDSA(sigHash, vchSig) );
            vchSig.push_back(static_cast<uint8_t>(sigHashType.getRawSigHashType())); // must append sighash byte to sig
            spend_tx.vin[inp].scriptSig << vchSig;
        }

        // Attempt to mine the above in a block
        CBlock const block = CreateAndProcessBlock({spend_tx}, p2pk_scriptPubKey);

        // CreateAndProcessBlock() doesn't actually tell us if the block was accepted, so check the chain
        LOCK(cs_main);
        if (isUpgrade9Active) {
            // Upgrade9 active: Mining success
            BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() == block.GetHash());
            BOOST_CHECK(pcoinsTip->GetBestBlock() == block.GetHash());
        } else {
            // Upgrade9 inactive: Mining failure (SIGHASH_UTXOS not enabled yet so signature is invalid/unknown/etc)
            BOOST_CHECK(::ChainActive().Tip()->GetBlockHash() != block.GetHash());
            BOOST_CHECK(pcoinsTip->GetBestBlock() != block.GetHash());
        }
    }
}

// Test the lower-level CheckTxTokens() function for more esoteric failure modes that shouldn't normally
// happen (most of these are caught by the deserializer), but we should check that the function fails
// as expected for these modes regardless as a belt-and-suspenders check.
BOOST_AUTO_TEST_CASE(check_tx_tokens_esoteric_failure_modes) {
    CCoinsView dummy;

    struct TxTokensValidationContext {
        std::unique_ptr<CCoinsViewCache> coins;
        CMutableTransaction tx;
        CValidationState state;
        uint32_t scriptFlags;
        int64_t activationHeight;
    };

    auto MakeValidContext = [&](bool has_nft = true, bool upgrade12 = false) {
        TxTokensValidationContext ret{std::make_unique<CCoinsViewCache>(&dummy),
                                      {}, {}, STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_TOKENS, 0};
        if (upgrade12) {
            ret.scriptFlags |= SCRIPT_ENABLE_MAY2026;
        }
        auto & coins = ret.coins;
        auto & tx = ret.tx;
        tx.vin.resize(2);
        tx.vin[0].prevout = COutPoint(TxId{InsecureRand256()}, 0);
        tx.vin[1].prevout = COutPoint(TxId{InsecureRand256()}, 0);
        const CScript trivial_spk = CScript() << OP_1;
        const Amount nValue = COIN;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            token::NFTCommitment commitment;
            if (has_nft) {
                commitment.resize(32);
                GetRandBytes(commitment.data(), commitment.size());
            }
            const token::OutputData tok_data(token::Id{InsecureRand256()}, token::SafeAmount::fromIntUnchecked(100),
                                             std::move(commitment), has_nft, has_nft, has_nft);
            coins->AddCoin(tx.vin[i].prevout, Coin(CTxOut{nValue, trivial_spk,
                                                          token::OutputDataPtr(tok_data)}, 1, false), false);
            tx.vout.emplace_back(CTxOut{nValue, trivial_spk, token::OutputDataPtr(tok_data)});
        }
        return ret;
    };

    // Sanity check: Check that MakeValidContext() produces data that always passes for both nft/non-nft cases
    {
        auto ctx = MakeValidContext();
        BOOST_CHECK(CheckTxTokens(CTransaction{ctx.tx}, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "");

        ctx = MakeValidContext(false);
        BOOST_CHECK(CheckTxTokens(CTransaction{ctx.tx}, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "");
    }

    // Check that invalid bitfields in token data are rejected with: "bad-txns-token-bad-bitfield"
    {
        auto ctx = MakeValidContext();
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetBitfieldUnchecked(0xff);
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-bad-bitfield");

        // Force an invalid bitfield in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext();
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetBitfieldUnchecked(0xff);
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-bad-bitfield");
    }

    // Check that negative amounts are rejected with: "bad-txns-token-amount-negative"
    {
        auto ctx = MakeValidContext();
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetAmount(token::SafeAmount::fromIntUnchecked(-1));
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-amount-negative");

        // Force a negative amount in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext();
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetAmount(token::SafeAmount::fromIntUnchecked(-1));
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-amount-negative");
    }

    // Check that spending 0 fungible-only tokens is not possible: "bad-txns-token-non-nft-amount-zero"
    {
        auto ctx = MakeValidContext(false);
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetAmount(token::SafeAmount::fromIntUnchecked(0), false);
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-non-nft-amount-zero");

        // Force a zero amount in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext(false);
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetAmount(token::SafeAmount::fromIntUnchecked(0), false);
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-non-nft-amount-zero");
    }

    // Check that amount bitfield must match amount: "bad-txns-token-amount-bitfield-mismatch"
    {
        auto ctx = MakeValidContext();
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetAmount(token::SafeAmount::fromIntUnchecked(0)); // set bitfield to indicate no amount
        modifiedCoin.GetTxOut().tokenDataPtr->SetAmount(token::SafeAmount::fromIntUnchecked(1), false); // force inconsistent bitfield
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-amount-bitfield-mismatch");

        // Force a zero amount in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext();
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetAmount(token::SafeAmount::fromIntUnchecked(0));
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetAmount(token::SafeAmount::fromIntUnchecked(1), false);
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-amount-bitfield-mismatch");
    }

    // Check that commitment bitfield must match commitment: "bad-txns-token-commitment-bitfield-mismatch"
    {
        auto ctx = MakeValidContext();
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetCommitment({}, false); // force-set to empty commitment without auto-set-bitfield
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-commitment-bitfield-mismatch");

        // Force a zero amount in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext();
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetCommitment({}, false);
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-commitment-bitfield-mismatch");
    }

    // Check that commitment cannot exceed the max consensus length: "bad-txns-token-commitment-oversized"
    //   - upgrade9: 40 bytes is the limit
    //   - after upgrade12: 128 bytes is the limit
    for (const bool upgrade12 : {false, true}) {
        token::NFTCommitment big_commitment;
        const size_t maxCommitment = upgrade12 ? token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12
                                               : token::MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE9;
        big_commitment.resize(maxCommitment + 1u, 0xcc);
        auto ctx = MakeValidContext(true /* has_nft */, upgrade12);
        // Force an invalid bitfield in one of the input coins
        Coin modifiedCoin = ctx.coins->AccessCoin(ctx.tx.vin[0].prevout);
        modifiedCoin.GetTxOut().tokenDataPtr->SetCommitment(big_commitment);
        ctx.coins->AddCoin(ctx.tx.vin[0].prevout, modifiedCoin, true /* overwrite */);
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-commitment-oversized");

        // Force a zero amount in one of the output coins (requires a less-than-ideal const_cast to achieve due
        // to implementation details about how CTransaction is constructed and the serialize code not allowing us to
        // calculate a hash for invalid token data)
        ctx = MakeValidContext(true /* has_nft */, upgrade12);
        CTransaction tx{ctx.tx};
        const_cast<token::OutputData &>(*tx.vout[0].tokenDataPtr).SetCommitment(big_commitment);
        BOOST_CHECK(!CheckTxTokens(tx, ctx.state, *ctx.coins, ctx.scriptFlags, ctx.activationHeight));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-token-commitment-oversized");
    }

    // Check that inputs to a txn cannot contain token data pre-activation
    {
        auto ctx = MakeValidContext();
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags & ~SCRIPT_ENABLE_TOKENS,
                                   999'999'999));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");

        // Do this check another way: we cannot spend any locking script containing PREFIX_BYTE, pre-activation, even
        // if the token data is null.
        for (const auto & inp : ctx.tx.vin) {
            Coin modifiedCoin = ctx.coins->AccessCoin(inp.prevout);
            BOOST_REQUIRE(!modifiedCoin.GetTxOut().HasUnparseableTokenData());
            modifiedCoin.GetTxOut().tokenDataPtr.reset(); // clear token data for this input
            BOOST_REQUIRE(!modifiedCoin.GetTxOut().HasUnparseableTokenData());
            // insert PREFIX_BYTE into scriptPubKey
            CScript &spk = modifiedCoin.GetTxOut().scriptPubKey;
            spk.insert(spk.begin(), token::PREFIX_BYTE);
            BOOST_REQUIRE(modifiedCoin.GetTxOut().HasUnparseableTokenData());
            ctx.coins->AddCoin(inp.prevout, modifiedCoin, true);
        }
        for (auto & output : ctx.tx.vout) {
            output.tokenDataPtr.reset(); // clear token data
        }
        BOOST_CHECK(!CheckTxTokens(CTransaction(ctx.tx), ctx.state, *ctx.coins, ctx.scriptFlags & ~SCRIPT_ENABLE_TOKENS,
                                   999'999'999));
        BOOST_CHECK_EQUAL(ctx.state.GetRejectReason(), "bad-txns-vin-tokenprefix-preactivation");
    }
}

BOOST_AUTO_TEST_CASE(token_safeamount_cannot_be_negative) {
    // Cannot directly construct a negative amount with the "checked method"
    const auto opt_safe_amount = token::SafeAmount::fromInt(-1);
    BOOST_REQUIRE( ! opt_safe_amount.has_value());

    // CAN construct one with the less-safe "unchecked" method
    auto safe_amount = token::SafeAmount::fromIntUnchecked(-1);
    BOOST_CHECK_EQUAL(safe_amount.getint64(), -1);

    // However, cannot serialize a negative quantity
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    BOOST_REQUIRE_THROW(ds << safe_amount, token::AmountOutOfRangeError);

    // Also ensure that attempting to unserialize a negative amount fails
    ds.clear();
    ds << Using<CompactSizeFormatter<false>>(static_cast<uint64_t>(-1));
    BOOST_REQUIRE_THROW(ds >> safe_amount, token::AmountOutOfRangeError);
}

BOOST_AUTO_TEST_CASE(token_safeamount_cannot_serialize_zero) {
    const auto opt_safe_amount = token::SafeAmount::fromInt(0);
    BOOST_REQUIRE(opt_safe_amount.has_value());
    // Cannot serialize a zero token amount
    CDataStream ds(SER_NETWORK, INIT_PROTO_VERSION);
    BOOST_REQUIRE_THROW(ds << *opt_safe_amount, token::AmountMustNotBeZeroError);

    // Also ensure that attempting to unserialize a zero amount fails
    ds.clear();
    token::SafeAmount safe_amount;
    ds << Using<CompactSizeFormatter<false>>(static_cast<uint64_t>(0));
    BOOST_REQUIRE_THROW(ds >> safe_amount, token::AmountMustNotBeZeroError);
}

BOOST_AUTO_TEST_SUITE_END()
