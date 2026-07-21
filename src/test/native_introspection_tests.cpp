// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <core_io.h>
#include <policy/policy.h>
#include <primitives/blockhash.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <tinyformat.h>
#include <util/defer.h>
#include <util/strencodings.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

BOOST_FIXTURE_TEST_SUITE(native_introspection_tests, BasicTestingSetup)


namespace detail {
    template <typename T, typename F, std::size_t... Is>
    constexpr
    std::array<T, sizeof...(Is)> genArr(F& f, std::index_sequence<Is...>) {
        return {{f(std::integral_constant<std::size_t, Is>{})...}};
    }
}

template <typename T, std::size_t N, typename F>
constexpr
auto genArr(F&& f) {
    return detail::genArr<T>(f, std::make_index_sequence<N>{});
}

using valtype = StackVec;
using MyStackT = std::vector<valtype>;

static
StackT ConvertStack(const MyStackT &s) {
    StackT ret;
    ret.reserve(s.size());
    for (const auto &v : s) {
        ret.emplace_back(v);
    }
    return ret;
}

static
MyStackT ConvertStack(const StackT &s) {
    MyStackT ret;
    ret.reserve(s.size());
    for (const auto &item : s) {
        ret.push_back(item.vec());
    }
    return ret;
}

static
std::string ToString(const MyStackT &s) {
    std::string ret = "[";
    int ctr = 0;
    for (const auto &v : s) {
        if (ctr++) ret += ", ";
        ret += "\"" + HexStr(v) + "\"";
    }
    ret += "]";
    return ret;
}

static
void CheckErrorWithFlags(uint32_t flags, MyStackT const& original_stack, CScript const& script, ScriptExecutionContextOpt const& context, ScriptError expected) {
    const ContextOptSignatureChecker sigchecker(context);
    ScriptError err = ScriptError::OK;
    StackT stack = ConvertStack(original_stack);
    bool r = EvalScript(stack, script, flags, sigchecker, &err);
    BOOST_CHECK_MESSAGE(!r, strprintf("CheckError Result: %d for script: \"%s\" with stack: %s, resulting stack: %s, "
                                      "flags: %x",
                                      int(r), HexStr(script), ToString(original_stack), ToString(ConvertStack(stack)), flags));
    BOOST_CHECK_MESSAGE(err == expected,
                        strprintf("err == expected: %s == %s", ScriptErrorString(err), ScriptErrorString(expected)));
}

static
void CheckPassWithFlags(uint32_t flags, MyStackT const& original_stack, CScript const& script, ScriptExecutionContextOpt const& context,
                        MyStackT const& expected) {
    const ContextOptSignatureChecker sigchecker(context);
    ScriptError err = ScriptError::OK;
    StackT stack = ConvertStack(original_stack);
    bool r = EvalScript(stack, script, flags, sigchecker, &err);
    BOOST_CHECK_MESSAGE(r, strprintf("CheckPass Result: %d for script: \"%s\" with stack: %s, resulting stack: %s, "
                                     "flags: %x",
                                     int(r), HexStr(script), ToString(original_stack), ToString(ConvertStack(stack)), flags));
    BOOST_CHECK(err == ScriptError::OK);
    BOOST_CHECK_MESSAGE(stack == ConvertStack(expected),
                        strprintf("stack == expected: %s == %s", ToString(ConvertStack(stack)), ToString(expected)));
}

static
std::vector<uint8_t> MakeOversizedData(size_t targetSize = MAX_SCRIPT_ELEMENT_SIZE_LEGACY + 1) {
    std::vector<uint8_t> ret;
    ret.reserve(targetSize);
    // fill with random bytes (32 bytes at a time since that is the limit of GetRandBytes())
    for (size_t size = ret.size(); size < targetSize; size = ret.size()) {
        constexpr size_t chunkSize = 32;
        size_t const nBytes = std::min<size_t>(chunkSize, targetSize - size);
        ret.resize(size + nBytes);
        GetRandBytes(ret.data() + size, nBytes);
    }
    return ret;
}

static
CScript MakeOversizedScript(bool pushOnly = false) {
    // Generate an "oversized" script, that is, a script that exceeds MAX_SCRIPT_ELEMENT_SIZE, by being
    // composed of many smaller 32-byte pushes.
    size_t const chunkSize = 32;
    CScript ret;
    if (pushOnly) {
        // for scriptSigs, "push only" -- keep pushing 32-byte blobs until we exceed the total size
        while (ret.size() < MAX_SCRIPT_ELEMENT_SIZE_LEGACY + 1) {
            ret << MakeOversizedData(chunkSize);
        }
    } else {
        // for scriptPubKeys, keep pushing an untaken branch
        while (ret.size() < MAX_SCRIPT_ELEMENT_SIZE_LEGACY + 1) {
            ret << OP_0 << OP_IF << MakeOversizedData(chunkSize) << OP_ENDIF;
        }
    }
    return ret;
}

BOOST_AUTO_TEST_CASE(opcodes_basic) {
    uint32_t const flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    uint32_t const flags_tokens = flags | SCRIPT_ENABLE_TOKENS;

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);

    COutPoint const ins[] = {
        {TxId(uint256S("be89ae9569526343105994a950775869a910f450d337a6c29d43a37f093b662f")), 5},
        {TxId(uint256S("08d5fc002b094fced39381b7e9fa15fb8c944164e48262a2c0b8edef9866b348")), 7},
        {TxId(uint256S("64ee0a1cf5bdb83d4882204c49fe3b01b91d5988690ec7f06bc246f4838e2f9a")), 8},
        {TxId(uint256S("b882f60dd5ff9c6145490ae7184c30b68ff81b8234bd22ce69ae93804ebc0e49")), 2},
        {TxId(uint256S("c0fdde4ecc648b38f0945989fb028fa8e82c958bd3ba44016be2f346e0172916")), 4},
        {TxId(uint256S("641c630845e84d6e9be940f062d52bbef38f78f9a21014d3c0c8248fcae89b9b")), 1},
        {TxId(uint256S("9840c9252d8c0de8b2648683443e40af619bce890d19f04b81cfbf267efeba35")), 5},
        {TxId(uint256S("120e438cd283fa46484979c90e11648cba296d8f5cff8624b3ed8950bbfbe0e0")), 3},
        {TxId(uint256S("8024808fd4e7959b342f0b1e4c1254edb1f60edfcb928463a8098c9f3c6eba86")), 2},
        {TxId(uint256S("109dafc04e629809fbf64c04abe76fe2835398848c28b44cfddb203ee91b5816")), 8},
        {TxId(uint256S("30824bf6be8c656d894f48b2ee900130d720fe969bcce4f19c8d24fa8ba83145")), 4},
        {TxId(uint256S("eeedb9492f570482e1b4460894b22f83163cf8053cd8ae81d9604c6f0cf8a9bb")), 0}, // token genesis in
        {TxId(uint256S("81766a636f99138dee8200bfba55ff124bcdb424cde8e932ccb8e4890004f984")), 3},
        {TxId(uint256S("943aebc64feed8112af2bc065297bc84f1b28940e8ddb0ff35948963886c0e40")), 2},
        {TxId(uint256S("1b86fb3052e98e86254ebaec891442c960f803b2ce4b40f470fd9df6dca18893")), 6},
        {TxId(uint256S("e64f16f94392e8f0564be4858d8bbc300c21a8c079b0f836bec28ad94ed9f421")), 4},
        {TxId(uint256S("4fe8ec6dde591cb34196bb4c54beab863492628a8109fd38f7fce9808f004202")), 7},
        {TxId(uint256S("ed84f34d806b8900f822459f203b6e9c1a0bb963f8d81b4c5eeec2ca4761489f")), 6},
        {TxId(uint256S("f79103534dfe073d2de397673b72baf2b75d6ae21005c5685305878a4c6cbcab")), 0},
    };

    constexpr size_t oversized_in = std::size(ins) - 1; // this input's scriptPubKey and scriptSig both exceed MAX_SCRIPT_ELEMENT_SIZE
    constexpr size_t token_genesis_in = 11; // this one spends index0 of its outputs so it is the only legal one
    static_assert(token_genesis_in < std::size(ins));
    static_assert(oversized_in != token_genesis_in);


    constexpr auto vals = genArr<Amount, std::size(ins)>([](auto inNum) {
        return (2000 + int(inNum) * 1000) * Amount::satoshi();
    });
    auto const coinScriptPubKeys = genArr<CScript, std::size(ins)>([&oversized_in](auto inNum) {
        CScript ret;
        if (inNum == oversized_in) {
            // Make a script consisting of many small pushes on an untaken branch.
            // We add OP_CODESEPARATOR to the end to test that OP_UTXOBYTECODE ignores this op-code.
            ret = MakeOversizedScript() << OP_CODESEPARATOR;
        } else {
            ret << ScriptInt::fromInt(2 + inNum).value() << OP_ADD << OP_0 << OP_GREATERTHAN;
        }
        return ret;
    });

    COutPoint const& in0 = ins[0];
    COutPoint const& in1 = ins[1];
    Amount const& val0 = vals[0];
    Amount const& val1 = vals[1];
    CScript const& coinScriptPubKey0 = coinScriptPubKeys[0];
    CScript const& coinScriptPubKey1 = coinScriptPubKeys[1];
    CScript const& coinScriptPubKey2 = coinScriptPubKeys[2];

    CMutableTransaction tx;
    tx.vin.resize(std::size(ins));

    const token::OutputData tokenInputData[] = {
        // NFT with 3-byte commitment
        {token::Id{uint256S("1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d")},
         token::SafeAmount::fromIntUnchecked(42), token::NFTCommitment{3u, uint8_t(0x5e)}, true /* hasNFT */},
        // NFT with 0-byte commitment
        {token::Id{uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")},
         token::SafeAmount::fromIntUnchecked(1337), {} /* 0-byte commitment */, true /* hasNFT */, true /* mutable */ },
        // NFT with 520-byte commitment
        {token::Id{uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")},
         token::SafeAmount::fromIntUnchecked(1337), token::NFTCommitment(520u, uint8_t(0xaa)), true /* hasNFT */,
         true /* mutable */},
        // NFT with 521-byte commitment
        {token::Id{uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")},
         token::SafeAmount::fromIntUnchecked(1337), token::NFTCommitment(521u, uint8_t(0xbb)), true /* hasNFT */,
         false /* mutable */, true /* minting */},
        // FT-only
        {token::Id{uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")},
         token::SafeAmount::fromIntUnchecked(100)},
    };
    constexpr size_t n_token_ins = std::size(tokenInputData);
    static_assert(n_token_ins < oversized_in);


    {
        for (size_t i = 0; i < std::size(ins); ++i) {
            token::OutputDataPtr pdata;
            if (i < n_token_ins) {
                // this in also has its own token it's bringing forward...
                pdata = tokenInputData[i];
            }
            Coin coin(CTxOut(vals[i], coinScriptPubKeys[i], std::move(pdata)), 1, false);
            coins.AddCoin(ins[i], std::move(coin), false);
            tx.vin[i].prevout = ins[i];
            if (i == oversized_in) {
                // large scriptsig here (lots of smaller pushes)
                tx.vin[i].scriptSig = MakeOversizedScript(true /* push only*/);
            } else {
                tx.vin[i].scriptSig = CScript() << ScriptInt::fromInt(i).value();
            }
            tx.vin[i].nSequence = 0x010203;
        }
    }

    tx.vout.resize(7);
    tx.vout[0].nValue = 1000 * Amount::satoshi();
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    tx.vout[1].nValue = 1900 * Amount::satoshi();
    tx.vout[1].scriptPubKey = CScript() << OP_3;
    tx.vout[2].nValue = 2100 * Amount::satoshi();
    tx.vout[2].scriptPubKey = CScript() << OP_4;
    tx.vout[3].nValue = 3100 * Amount::satoshi();
    // We append OP_CODESEPARATOR to the scriptPubKey to check that OP_OUTPUTBYTECODE ignores this op-code.
    tx.vout[3].scriptPubKey = MakeOversizedScript() << OP_CODESEPARATOR;
    tx.vout[4].nValue = 4240 * Amount::satoshi();
    tx.vout[4].scriptPubKey = CScript() << OP_5;
    tx.vout[5].nValue = 4241 * Amount::satoshi();
    tx.vout[5].scriptPubKey = CScript() << OP_6;
    // no token on [6]
    tx.vout[6].nValue = 4242 * Amount::satoshi();
    tx.vout[6].scriptPubKey = CScript() << OP_7;
    tx.nVersion = 101;
    tx.nLockTime = 10;
    size_t const oversized_out = 3;

    // setup a token genesis output and a normal token output (will be used for testing token introspection)
    const token::OutputData outputTokens[] = {
        //[0] is a genesis token, comes from prevtxid of to token_genesis_out_idx (11)
        {
            token::Id{tx.vin[token_genesis_in].prevout.GetTxId()}, // category Id
            token::SafeAmount::fromIntUnchecked(123456),  // FT amount
            token::NFTCommitment{10u, uint8_t(0xbf)},  // commitment = "bf" * 10
            true, false, true /* hasNFT, isMutable, isMinting */
        },
        // the rest are just the input tokens forwarded out to the outputs
        tokenInputData[0], tokenInputData[1], tokenInputData[2], tokenInputData[3], tokenInputData[4],
    };
    constexpr size_t nOutputTokens = std::size(outputTokens);
    static_assert(nOutputTokens == std::size(tokenInputData) + 1);
    assert(nOutputTokens < tx.vout.size());
    for (size_t i = 0; i < nOutputTokens; ++i) {
        tx.vout.at(i).tokenDataPtr = outputTokens[i];
    }

    auto const context = ScriptExecutionContext::createForAllInputs(tx, coins);

    std::vector<ScriptExecutionContext> limited_context;
    limited_context.reserve(context.size());
    for (auto& ctx : context) {
        limited_context.emplace_back(ctx.inputIndex(), ctx.coin().GetTxOut(), tx, ctx.coin().GetHeight(),
                                     ctx.coin().IsCoinBase());
    }

    BOOST_CHECK(context.size() == tx.vin.size());

    BOOST_TEST_MESSAGE("Native Introspection (nullary) tests ...");

    // OP_INPUTINDEX (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_INPUTINDEX ...");
        valtype const expected0 (CScriptNum::fromInt(0).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_INPUTINDEX, context[0], {expected0});

        valtype const expected1 (CScriptNum::fromInt(1).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_INPUTINDEX, context[1], {expected1});

        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_INPUTINDEX, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_ACTIVEBYTECODE (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_ACTIVEBYTECODE ...");
        auto const bytecode0 = CScript() << OP_ACTIVEBYTECODE << OP_9;
        auto const bytecode1 = CScript() << OP_ACTIVEBYTECODE << OP_10;

        auto const bytecode2 = CScript() << OP_10
                                         << OP_11
                                         << ScriptInt::fromInt(7654321).value()
                                         << OP_CODESEPARATOR
                                         << ScriptInt::fromInt(123123).value() << OP_DROP
                                         << OP_ACTIVEBYTECODE
                                         << OP_CODESEPARATOR
                                         << OP_1;
        auto const bytecode2b = CScript() << ScriptInt::fromInt(123123).value() << OP_DROP
                                          << OP_ACTIVEBYTECODE
                                          << OP_CODESEPARATOR
                                          << OP_1;

        auto const bytecode3 = MakeOversizedScript() << OP_CODESEPARATOR << OP_ACTIVEBYTECODE << OP_1;
        auto const bytecode3b = CScript() << OP_ACTIVEBYTECODE << OP_1;

        auto const bytecode4 = MakeOversizedScript() << OP_ACTIVEBYTECODE << OP_1;

        valtype const expected0 (bytecode0.begin(), bytecode0.end());
        CheckPassWithFlags(flags, {}, bytecode0, context[0], {expected0, CScriptNum::fromIntUnchecked(9).getvch()});

        valtype const expected1 (bytecode1.begin(), bytecode1.end());
        CheckPassWithFlags(flags, {}, bytecode1, context[0], {expected1, CScriptNum::fromIntUnchecked(10).getvch()});

        // check that OP_CODESEPARATOR is respected properly
        valtype const expected2b (bytecode2b.begin(), bytecode2b.end());
        CheckPassWithFlags(flags, {}, bytecode2, context[0], {CScriptNum::fromIntUnchecked(10).getvch(),
                                                              CScriptNum::fromIntUnchecked(11).getvch(),
                                                              CScriptNum::fromIntUnchecked(7654321).getvch(),
                                                              expected2b,
                                                              CScriptNum::fromIntUnchecked(1).getvch()});

        // ScriptError::PUSH_SIZE should *not* be triggered if using OP_CODESEPARATOR and result would be under
        // MAX_SCRIPT_ELEMENT_SIZE even if entire script is over MAX_SCRIPT_ELEMENT_SIZE.
        valtype const expected3b (bytecode3b.begin(), bytecode3b.end());
        CheckPassWithFlags(flags, {}, bytecode3, context[oversized_in], {expected3b, CScriptNum::fromIntUnchecked(1).getvch()});

        // failure (MAX_SCRIPT_ELEMENT_SIZE exceeded)
        CheckErrorWithFlags(flags, {}, bytecode4, context[oversized_in], ScriptError::PUSH_SIZE);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, bytecode1, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_TXVERSION (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_TXVERSION ...");
        valtype const expected (CScriptNum::fromInt(tx.nVersion).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_TXVERSION, context[0], {expected});
        CheckPassWithFlags(flags, {}, CScript() << OP_TXVERSION, context[1], {expected});

        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_TXVERSION, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_TXINPUTCOUNT (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_TXINPUTCOUNT ...");
        valtype const expected (CScriptNum::fromInt(tx.vin.size()).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_TXINPUTCOUNT, context[0], {expected});
        CheckPassWithFlags(flags, {}, CScript() << OP_TXINPUTCOUNT, context[1], {expected});

        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_TXINPUTCOUNT, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_TXOUTPUTCOUNT (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_TXOUTPUTCOUNT ...");
        valtype const expected (CScriptNum::fromInt(tx.vout.size()).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_TXOUTPUTCOUNT, context[0], {expected});
        CheckPassWithFlags(flags, {}, CScript() << OP_TXOUTPUTCOUNT, context[1], {expected});

        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_TXOUTPUTCOUNT, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_TXLOCKTIME (nullary)
    {
        BOOST_TEST_MESSAGE("Testing OP_TXLOCKTIME ...");
        valtype const expected (CScriptNum::fromInt(tx.nLockTime).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_TXLOCKTIME, context[0], {expected});
        CheckPassWithFlags(flags, {}, CScript() << OP_TXLOCKTIME, context[1], {expected});

        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_TXLOCKTIME, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    BOOST_TEST_MESSAGE("Native Introspection (unary) tests ...");

    // OP_UTXOVALUE (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_UTXOVALUE ...");
        valtype const expected0 (CScriptNum::fromInt(val0 / SATOSHI).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOVALUE, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOVALUE, context[1], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOVALUE, limited_context[0], {expected0});

        valtype const expected1 (CScriptNum::fromInt(val1 / SATOSHI).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOVALUE, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOVALUE, context[1], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOVALUE, limited_context[1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_UTXOVALUE, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_UTXOVALUE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_UTXOVALUE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOVALUE, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (limited context but querying sibling input)
        CheckErrorWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOVALUE, limited_context[0],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOVALUE, limited_context[1],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
    }

    // OP_UTXOBYTECODE (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_UTXOBYTECODE ...");
        token::WrappedScriptPubKey wspk0;
        token::WrapScriptPubKey(wspk0, token::OutputDataPtr{tokenInputData[0]}, coinScriptPubKey0, INIT_PROTO_VERSION);
        valtype const expected0 (wspk0.begin(), wspk0.end()),
                      expected0_tokens(coinScriptPubKey0.begin(), coinScriptPubKey0.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOBYTECODE, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOBYTECODE, context[1], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOBYTECODE, limited_context[0], {expected0});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOBYTECODE, context[0], {expected0_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOBYTECODE, context[1], {expected0_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOBYTECODE, limited_context[0], {expected0_tokens});

        token::WrappedScriptPubKey wspk1;
        token::WrapScriptPubKey(wspk1, token::OutputDataPtr{tokenInputData[1]}, coinScriptPubKey1, INIT_PROTO_VERSION);
        valtype const expected1 (wspk1.begin(), wspk1.end()),
                      expected1_tokens(coinScriptPubKey1.begin(), coinScriptPubKey1.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOBYTECODE, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOBYTECODE, context[1], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOBYTECODE, limited_context[1], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_1 << OP_UTXOBYTECODE, context[0], {expected1_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_1 << OP_UTXOBYTECODE, context[1], {expected1_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_1 << OP_UTXOBYTECODE, limited_context[1], {expected1_tokens});

        // This input has a wrapped spk pre-token-activation that exceeds 520b limit due to oversized token data, so it
        // should fail because pre-token-activation we push the entire token blob.  Post-token-activation it will just
        // push the spk without the token data, so it will succeed.
        valtype const expected2_tokens(coinScriptPubKey2.begin(), coinScriptPubKey2.end());
        CheckErrorWithFlags(flags, {}, CScript() << OP_2 << OP_UTXOBYTECODE, context[0], ScriptError::PUSH_SIZE);
        CheckErrorWithFlags(flags, {}, CScript() << OP_2 << OP_UTXOBYTECODE, context[1], ScriptError::PUSH_SIZE);
        CheckErrorWithFlags(flags, {}, CScript() << OP_2 << OP_UTXOBYTECODE, context[2], ScriptError::PUSH_SIZE);
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_2 << OP_UTXOBYTECODE, context[0], {expected2_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_2 << OP_UTXOBYTECODE, context[1], {expected2_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_2 << OP_UTXOBYTECODE, limited_context[2], {expected2_tokens});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_UTXOBYTECODE, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_UTXOBYTECODE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_UTXOBYTECODE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (MAX_SCRIPT_ELEMENT_SIZE exceeded)
        for (auto const& ctx : context) {
            CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(oversized_in).value() << OP_UTXOBYTECODE,
                                ctx, ScriptError::PUSH_SIZE);
            CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(oversized_in).value() << OP_UTXOBYTECODE,
                                ctx, ScriptError::PUSH_SIZE);
        }
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOBYTECODE, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (limited context but querying sibling input)
        CheckErrorWithFlags(flags, {}, CScript() << OP_1 << OP_UTXOBYTECODE, limited_context[0],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_UTXOBYTECODE, limited_context[1],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
    }

    // OP_OUTPOINTTXHASH (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPOINTTXHASH ...");
        valtype const expected0 (in0.GetTxId().begin(), in0.GetTxId().end());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTTXHASH, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTTXHASH, context[1], {expected0});

        valtype const expected1 (in1.GetTxId().begin(), in1.GetTxId().end());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPOINTTXHASH, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPOINTTXHASH, context[1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_OUTPOINTTXHASH, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_OUTPOINTTXHASH,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPOINTTXHASH,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTTXHASH, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_OUTPOINTINDEX (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPOINTINDEX ...");
        valtype const expected0 (CScriptNum::fromInt(in0.GetN()).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTINDEX, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTINDEX, context[1], {expected0});

        valtype const expected1 (CScriptNum::fromInt(in1.GetN()).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPOINTINDEX, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPOINTINDEX, context[1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_OUTPOINTINDEX, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_OUTPOINTINDEX,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPOINTINDEX,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPOINTINDEX, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_INPUTBYTECODE (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_INPUTBYTECODE ...");
        valtype const expected0 (tx.vin[0].scriptSig.begin(), tx.vin[0].scriptSig.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTBYTECODE, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTBYTECODE, context[1], {expected0});

        valtype const expected1 (tx.vin[1].scriptSig.begin(), tx.vin[1].scriptSig.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_INPUTBYTECODE, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_INPUTBYTECODE, context[1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_INPUTBYTECODE, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_INPUTBYTECODE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_INPUTBYTECODE,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (MAX_SCRIPT_ELEMENT_SIZE exceeded)
        for (auto const& ctx : context) {
            CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(oversized_in).value() << OP_INPUTBYTECODE,
                                ctx, ScriptError::PUSH_SIZE);
        }
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTBYTECODE, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_INPUTSEQUENCENUMBER (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_INPUTSEQUENCENUMBER ...");
        valtype const expected0 (CScriptNum::fromInt(tx.vin[0].nSequence).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTSEQUENCENUMBER, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTSEQUENCENUMBER, context[1], {expected0});

        valtype const expected1 (CScriptNum::fromInt(tx.vin[1].nSequence).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_INPUTSEQUENCENUMBER, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_INPUTSEQUENCENUMBER, context[1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_INPUTSEQUENCENUMBER, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_INPUTSEQUENCENUMBER,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_INPUTSEQUENCENUMBER,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_INPUTSEQUENCENUMBER, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_OUTPUTVALUE (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPUTVALUE ...");
        valtype const expected0 (CScriptNum::fromInt(tx.vout[0].nValue / SATOSHI).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTVALUE, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTVALUE, context[1], {expected0});

        valtype const expected1 (CScriptNum::fromInt(tx.vout[1].nValue / SATOSHI).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPUTVALUE, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPUTVALUE, context[1], {expected1});

        valtype const expected2 (CScriptNum::fromInt(tx.vout[2].nValue / SATOSHI).value().getvch());
        CheckPassWithFlags(flags, {}, CScript() << OP_2 << OP_OUTPUTVALUE, context[0], {expected2});
        CheckPassWithFlags(flags, {}, CScript() << OP_2 << OP_OUTPUTVALUE, context[1], {expected2});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_OUTPUTVALUE, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vout.size()).value() << OP_OUTPUTVALUE,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPUTVALUE,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTVALUE, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // OP_OUTPUTBYTECODE (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPUTBYTECODE ...");
        token::WrappedScriptPubKey wspk0;
        token::WrapScriptPubKey(wspk0, tx.vout.at(0).tokenDataPtr, tx.vout.at(0).scriptPubKey, INIT_PROTO_VERSION);
        valtype const expected0 (wspk0.begin(), wspk0.end()),
                      expected0_tokens (tx.vout[0].scriptPubKey.begin(), tx.vout[0].scriptPubKey.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTBYTECODE, context[0], {expected0});
        CheckPassWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTBYTECODE, context[1], {expected0});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTBYTECODE, context[0], {expected0_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTBYTECODE, context[1], {expected0_tokens});

        token::WrappedScriptPubKey wspk1;
        token::WrapScriptPubKey(wspk1, tx.vout.at(1).tokenDataPtr, tx.vout.at(1).scriptPubKey, INIT_PROTO_VERSION);
        valtype const expected1 (wspk1.begin(), wspk1.end()),
                      expected1_tokens (tx.vout[1].scriptPubKey.begin(), tx.vout[1].scriptPubKey.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPUTBYTECODE, context[0], {expected1});
        CheckPassWithFlags(flags, {}, CScript() << OP_1 << OP_OUTPUTBYTECODE, context[1], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_1 << OP_OUTPUTBYTECODE, context[0], {expected1_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_1 << OP_OUTPUTBYTECODE, context[1], {expected1_tokens});

        token::WrappedScriptPubKey wspk2;
        token::WrapScriptPubKey(wspk2, tx.vout.at(2).tokenDataPtr, tx.vout.at(2).scriptPubKey, INIT_PROTO_VERSION);
        valtype const expected2 (wspk2.begin(), wspk2.end()),
                      expected2_tokens (tx.vout[2].scriptPubKey.begin(), tx.vout[2].scriptPubKey.end());
        CheckPassWithFlags(flags, {}, CScript() << OP_2 << OP_OUTPUTBYTECODE, context[0], {expected2});
        CheckPassWithFlags(flags, {}, CScript() << OP_2 << OP_OUTPUTBYTECODE, context[1], {expected2});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_2 << OP_OUTPUTBYTECODE, context[0], {expected2_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_2 << OP_OUTPUTBYTECODE, context[1], {expected2_tokens});

        token::WrappedScriptPubKey wspk4;
        token::WrapScriptPubKey(wspk4, tx.vout.at(4).tokenDataPtr, tx.vout.at(4).scriptPubKey, INIT_PROTO_VERSION);
        valtype const expected4_tokens (tx.vout[4].scriptPubKey.begin(), tx.vout[4].scriptPubKey.end());
        // This one has an oversized token, so the push fails pre-token-activation because it attempts to push a
        // byte blob that is >520b
        CheckErrorWithFlags(flags, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, context[0], ScriptError::PUSH_SIZE);
        CheckErrorWithFlags(flags, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, context[1], ScriptError::PUSH_SIZE);
        CheckErrorWithFlags(flags, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, limited_context[4], ScriptError::PUSH_SIZE);
        // But post-token activation it works ok because then we strip the token data from the pushed blob
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, context[0], {expected4_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, context[1], {expected4_tokens});
        CheckPassWithFlags(flags_tokens, {}, CScript() << OP_4 << OP_OUTPUTBYTECODE, limited_context[3], {expected4_tokens});

        // failure (missing arg)
        CheckErrorWithFlags(flags, {}, CScript() << OP_OUTPUTBYTECODE, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(tx.vout.size()).value() << OP_OUTPUTBYTECODE,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPUTBYTECODE,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        // failure (MAX_SCRIPT_ELEMENT_SIZE exceeded)
        for (auto const& ctx : context) {
            CheckErrorWithFlags(flags, {}, CScript() << ScriptInt::fromInt(oversized_out).value() << OP_OUTPUTBYTECODE,
                                ctx, ScriptError::PUSH_SIZE);
            CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(oversized_out).value() << OP_OUTPUTBYTECODE,
                                ctx, ScriptError::PUSH_SIZE);
        }
        // failure (no context)
        CheckErrorWithFlags(flags, {}, CScript() << OP_0 << OP_OUTPUTBYTECODE, {}, ScriptError::CONTEXT_NOT_PRESENT);
    }

    // --- Token Introspection ---
    BOOST_TEST_MESSAGE("Native Token Introspection (unary) tests ...");

    // OP_UTXOTOKENCATEGORY (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_UTXOTOKENCATEGORY ...");
        for (size_t token_containing_in = 0; token_containing_in < n_token_ins; ++token_containing_in) {
            const auto &tokenData = tokenInputData[token_containing_in];
            valtype expected (tokenData.GetId().begin(), tokenData.GetId().end());
            if (const auto c = tokenData.GetCapability(); c == token::Capability::Minting || c == token::Capability::Mutable) {
                // 0x01 or 0x02 appended for these types of tokens
                expected.push_back(static_cast<uint8_t>(c));
            }
            const auto script = CScript() << ScriptInt::fromIntUnchecked(token_containing_in) << OP_UTXOTOKENCATEGORY;
            CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, limited_context[token_containing_in], {expected});
        }
        assert(n_token_ins + 1 < std::size(ins));
        const auto sn = ScriptInt::fromIntUnchecked(n_token_ins + 1);
        valtype const expected1{}; // empty bytes for this op-code when there is no token for the input
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCATEGORY, context[0], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCATEGORY, context[1], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCATEGORY, limited_context[n_token_ins + 1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_UTXOTOKENCATEGORY, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_UTXOTOKENCATEGORY,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_UTXOTOKENCATEGORY,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOTOKENCATEGORY, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (limited context but querying sibling input)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(1)
                                                        << OP_UTXOTOKENCATEGORY, limited_context[0],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(0)
                                                        << OP_UTXOTOKENCATEGORY, limited_context[1],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_UTXOTOKENCATEGORY,
                            context[0], ScriptError::BAD_OPCODE);
    }

    // OP_UTXOTOKENCOMMITMENT (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_UTXOTOKENCOMMITMENT ...");
        for (size_t token_containing_in = 0; token_containing_in < n_token_ins; ++token_containing_in) {
            const auto &tokenData = tokenInputData[token_containing_in];
            const auto script = CScript() << ScriptInt::fromIntUnchecked(token_containing_in) << OP_UTXOTOKENCOMMITMENT;
            if (tokenData.GetCommitment().size() <= MAX_SCRIPT_ELEMENT_SIZE_LEGACY) {
                valtype expected;
                if (tokenData.HasNFT()) {
                    expected = valtype(tokenData.GetCommitment().begin(), tokenData.GetCommitment().end());
                } // else everything else, we expect an empty vector
                CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
                CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
                CheckPassWithFlags(flags_tokens, {}, script, limited_context[token_containing_in], {expected});
            } else {
                // failure (commitment too large to push onto stack)
                CheckErrorWithFlags(flags_tokens, {}, script, context[token_containing_in], ScriptError::PUSH_SIZE);
            }
        }
        assert(n_token_ins + 1 < std::size(ins));
        const auto sn = ScriptInt::fromIntUnchecked(n_token_ins + 1);
        valtype const expected1{}; // empty bytes for this op-code when there is no token for the input
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCOMMITMENT, context[0], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCOMMITMENT, context[1], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENCOMMITMENT, limited_context[n_token_ins + 1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_UTXOTOKENCOMMITMENT, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_UTXOTOKENCOMMITMENT,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_UTXOTOKENCOMMITMENT,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOTOKENCOMMITMENT, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (limited context but querying sibling input)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(1)
                                                        << OP_UTXOTOKENCOMMITMENT, limited_context[0],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(0)
                                                        << OP_UTXOTOKENCOMMITMENT, limited_context[1],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_UTXOTOKENCOMMITMENT,
                            context[0], ScriptError::BAD_OPCODE);
    }

    // OP_UTXOTOKENAMOUNT (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_UTXOTOKENAMOUNT ...");
        for (size_t token_containing_in = 0; token_containing_in < n_token_ins; ++token_containing_in) {
            const auto &tokenData = tokenInputData[token_containing_in];
            const valtype expected = CScriptNum::fromInt(tokenData.GetAmount().getint64()).value().getvch();
            const auto script = CScript() << ScriptInt::fromIntUnchecked(token_containing_in) << OP_UTXOTOKENAMOUNT;
            CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, limited_context[token_containing_in], {expected});
        }
        assert(n_token_ins + 1 < std::size(ins));
        const auto sn = ScriptInt::fromIntUnchecked(n_token_ins + 1);
        valtype const expected1 = CScriptNum::fromInt(0).value().getvch(); // VM number 0 (empty vector)
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENAMOUNT, context[0], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENAMOUNT, context[1], {expected1});
        CheckPassWithFlags(flags_tokens, {}, CScript() << sn << OP_UTXOTOKENAMOUNT, limited_context[n_token_ins + 1], {expected1});

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_UTXOTOKENAMOUNT, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vin.size()).value() << OP_UTXOTOKENAMOUNT,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_UTXOTOKENAMOUNT,
                            context[1], ScriptError::INVALID_TX_INPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_UTXOTOKENAMOUNT, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (limited context but querying sibling input)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(1)
                                                        << OP_UTXOTOKENAMOUNT, limited_context[0],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromIntUnchecked(0)
                                                        << OP_UTXOTOKENAMOUNT, limited_context[1],
                            ScriptError::LIMITED_CONTEXT_NO_SIBLING_INFO);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_UTXOTOKENAMOUNT,
                            context[0], ScriptError::BAD_OPCODE);
    }

    // OP_OUTPUTTOKENCATEGORY (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPUTTOKENCATEGORY ...");
        // Ensure the first outputs have token data and the last one does not for this test.
        assert(!tx.vout.empty() && !tx.vout.back().tokenDataPtr && tx.vout.front().tokenDataPtr);
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            const auto &pdata = tx.vout[i].tokenDataPtr;
            valtype expected{};
            if (pdata) {
                expected.assign(pdata->GetId().begin(), pdata->GetId().end());
                if (const auto c = pdata->GetCapability(); c == token::Capability::Minting || c == token::Capability::Mutable) {
                    // 0x01 or 0x02 appended for these types of tokens
                    expected.push_back(static_cast<uint8_t>(c));
                }
            } // else empty bytes if the output has no tokens (the last output has no tokens in this test)
            const auto script = CScript() << ScriptInt::fromIntUnchecked(i) << OP_OUTPUTTOKENCATEGORY;
            CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, limited_context[i], {expected});
        }

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_OUTPUTTOKENCATEGORY, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vout.size()).value() << OP_OUTPUTTOKENCATEGORY,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPUTTOKENCATEGORY,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTTOKENCATEGORY, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_OUTPUTTOKENCATEGORY,
                            context[0], ScriptError::BAD_OPCODE);
    }

    // OP_OUTPUTTOKENCOMMITMENT (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPUTTOKENCOMMITMENT ...");
        // Ensure the first outputs have token data and the last one does not for this test.
        assert(!tx.vout.empty() && !tx.vout.back().tokenDataPtr && tx.vout.front().tokenDataPtr);
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            const auto &pdata = tx.vout[i].tokenDataPtr;
            const auto script = CScript() << ScriptInt::fromIntUnchecked(i) << OP_OUTPUTTOKENCOMMITMENT;
            if (!pdata || pdata->GetCommitment().size() <= MAX_SCRIPT_ELEMENT_SIZE_LEGACY) {
                valtype expected{};
                if (pdata && pdata->HasNFT()) {
                    expected.assign(pdata->GetCommitment().begin(), pdata->GetCommitment().end());
                } // else empty bytes if the output has no commitment (the last output has no tokens in this test, thus no commitment)
                CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
                CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
                CheckPassWithFlags(flags_tokens, {}, script, limited_context[i], {expected});
            } else {
                // failure (commitment too large to push onto stack)
                CheckErrorWithFlags(flags_tokens, {}, script, limited_context[i], ScriptError::PUSH_SIZE);
            }
        }

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_OUTPUTTOKENCOMMITMENT, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vout.size()).value() << OP_OUTPUTTOKENCOMMITMENT,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPUTTOKENCOMMITMENT,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTTOKENCOMMITMENT, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_OUTPUTTOKENCOMMITMENT,
                            context[0], ScriptError::BAD_OPCODE);
    }

    // OP_OUTPUTTOKENAMOUNT (unary)
    {
        BOOST_TEST_MESSAGE("Testing OP_OUTPUTTOKENAMOUNT ...");
        // Ensure the first outputs have token data and the last one does not for this test.
        assert(!tx.vout.empty() && !tx.vout.back().tokenDataPtr && tx.vout.front().tokenDataPtr);
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            const auto &pdata = tx.vout[i].tokenDataPtr;
            valtype const expected = pdata ? CScriptNum::fromInt(pdata->GetAmount().getint64()).value().getvch()
                                             // missing token data is the same as amount == 0
                                           : CScriptNum::fromInt(0).value().getvch();
            const auto script = CScript() << ScriptInt::fromIntUnchecked(i) << OP_OUTPUTTOKENAMOUNT;
            CheckPassWithFlags(flags_tokens, {}, script, context[0], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, context[1], {expected});
            CheckPassWithFlags(flags_tokens, {}, script, limited_context[i], {expected});
        }

        // failure (missing arg)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_OUTPUTTOKENAMOUNT, context[0], ScriptError::INVALID_STACK_OPERATION);
        // failure (out of range)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(tx.vout.size()).value() << OP_OUTPUTTOKENAMOUNT,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        CheckErrorWithFlags(flags_tokens, {}, CScript() << ScriptInt::fromInt(-1).value() << OP_OUTPUTTOKENAMOUNT,
                            context[1], ScriptError::INVALID_TX_OUTPUT_INDEX);
        // failure: intentionally sabotage the VM by forcing a very illegal value (INT64_MIN) for the token amount
        // (can't normally happen in real code since this is outside consensus)
        {
            const auto origAmount = tx.vout.front().tokenDataPtr->GetAmount();
            Defer d([&]{ tx.vout.front().tokenDataPtr->SetAmount(origAmount);}); // restore original amount on scope end
            // set INT64_MIN...
            tx.vout.front().tokenDataPtr->SetAmount(token::SafeAmount::fromIntUnchecked(std::numeric_limits<int64_t>::min()));
            // We expect an "Unknown" error because pushing INT64_MIN to the stack fails in the VM, since it would
            // be a 9-byte int64 and that is forbidden. This causes an exception to be thrown in script VM,
            // aborting execution with an "Unknown" error...
            CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTTOKENAMOUNT, context[0], ScriptError::UNKNOWN);
        }
        // failure (no context)
        CheckErrorWithFlags(flags_tokens, {}, CScript() << OP_0 << OP_OUTPUTTOKENAMOUNT, {}, ScriptError::CONTEXT_NOT_PRESENT);
        // failure (not activated)
        CheckErrorWithFlags(flags /* no tokens */, {}, CScript() << OP_0 << OP_OUTPUTTOKENAMOUNT,
                            context[0], ScriptError::BAD_OPCODE);
    }
}

BOOST_AUTO_TEST_SUITE_END()
