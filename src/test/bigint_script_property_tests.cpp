// Copyright (c) 2024-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/script_flags.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

// We need to do this because BOOST_CHECK_MESSAGE actually evaluates the argument 'M' making these tests slower
// than they need to be since they end up building strings that are never used in the common case of checks passing.
#define CHECK_MESSAGE(P, M) \
do { \
    const bool ok = static_cast<bool>(P); \
    if (ok) { \
        BOOST_CHECK(BOOST_STRINGIZE(P)); \
    } else { \
        BOOST_CHECK_MESSAGE(!BOOST_STRINGIZE(P), M); \
    } \
} while(0)

namespace {

using ::StackT;

BigInt::InsecureRand randGen; // BigInt random number generator
FastRandomContext fastRand; // Regular int random number generator

const BigInt MIN_SCRIPTNUM = ScriptBigInt::bigIntConsensusMin();
const BigInt MAX_SCRIPTNUM = ScriptBigInt::bigIntConsensusMax();
const size_t MAX_ELEM_SIZE = may2025::MAX_SCRIPT_ELEMENT_SIZE;


[[nodiscard]] [[maybe_unused]]
std::string DumpStack(const StackT &stack) { // used for debugging
    std::string ret;
    ret += "Stack (top to bottom):\n";
    for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
        ret += "  [" + HexStr(it->vec()) + "]\n";
    }
    return ret;
}

[[nodiscard]]
bool TestScript(const CScript &testScript, StackT &stack, ScriptError expectedError, bool suppressMsg = false) {
    constexpr uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_MAY2025 | SCRIPT_ENABLE_MAY2026;
    static const BaseSignatureChecker dummyChecker;
    ScriptError serror;
    //BOOST_TEST_MESSAGE("Before: " << DumpStack(stack));
    bool ret = EvalScript(stack, testScript, flags, dummyChecker, &serror);
    //BOOST_TEST_MESSAGE("After: " << DumpStack(stack));
    if (ret) {
        if (stack.empty() || !CastToBool(stack.back())) {
            serror = ScriptError::EVAL_FALSE;
        } else if (stack.size() != 1) {
            serror = ScriptError::CLEANSTACK;
        }
    }
    ret = (expectedError == serror);
    if (!suppressMsg) {
        CHECK_MESSAGE(ret, "Got script error: " << ScriptErrorString(serror)
                            << ", expected: " << ScriptErrorString(expectedError));
    }
    return ret;
}

// Stack Depth Tests
//     - Fail: `{undersized stack} {opcode} OP_DEPTH OP_{depthOut} OP_NUMEQUALVERIFY {OP_DROP x depthOut} OP_1`
//     - Pass: `{exact-sized stack} {opcode} OP_DEPTH OP_{depthOut} OP_NUMEQUALVERIFY {OP_DROP x depthOut} OP_1`
//     - Fail: `{oversized stack} {opcode} OP_DEPTH OP_{depthOut} OP_NUMEQUALVERIFY {OP_DROP x depthOut} OP_1`
void TestStack(const size_t depthIn, const size_t depthOut, const opcodetype &opcode) {
    assert(depthOut < 16);
    auto script = CScript() << opcode << OP_DEPTH << (depthOut == 0 ? OP_0 : opcodetype(0x50 + depthOut)) << OP_NUMEQUALVERIFY;
    for (size_t i = 0; i < depthOut; ++i) {
        script = script << OP_DROP;
    }
    script = script << OP_1;

    assert(depthIn < 16);
    StackT stack = {};
    size_t i = 0;
    // Test undersized stack
    for (; i <= depthIn; ++i) {
        BOOST_CHECK(TestScript(script, stack, ScriptError::INVALID_STACK_OPERATION));
        stack.clear();
        stack.resize(i+1, StackItem(StackVec{1}));
    }
    // Test exact-sized stack
    BOOST_CHECK(TestScript(script, stack, ScriptError::OK));
    // Test oversized stack
    stack.resize(i+1, StackItem(StackVec{1}));
    BOOST_CHECK(TestScript(script, stack, ScriptError::NUMEQUALVERIFY));
}

using TestFuncUnary = std::function<void(const BigInt &)>;

// call given function for each random value in geometric series of subranges of given [min, max] range, e.g:
// testFunction(0), testFunction(random(0, 1)), testFunction(random(1, 8)), testFunction(random(8, 64)), ...
void TestRange(const TestFuncUnary &testFunction, const size_t min, const size_t max, size_t percentGrowth) {
    assert(min <= max && max < std::numeric_limits<size_t>::max());
    const double growthFactor = percentGrowth / 100.0;
    for (size_t i = min, j = min;;) { // see loop end
        testFunction(j);

        if (j >= max) break; // terminate loop once we processed the edge case
        // else calc the next edge and pick a random size between
        const size_t ip = i;
        const size_t delta = std::max<size_t>(1u, static_cast<size_t>(i * growthFactor));
        i += delta;
        j = ip + fastRand.randrange(i + 1u); // NB: randrange arg is exclusive range
        j = std::min<size_t>(j, max); // clamp to last value
    }
}

// for each random value in geometric series of subranges of given [size(min), size(max)] range, e.g:
// random(0, 1), random(1, 8), random(8, 64), ...
// and using the value as size, generate 3 BigInt values: lowest, random and highest value for that size
// and call a test function for each of the 3 values
void TestRange(const TestFuncUnary &testFunction, const BigInt &min, const BigInt &max, bool testNegative, size_t percentGrowth) {
    assert(min >= 0);
    assert(min <= max);

    const size_t ifirst = min.absValNumBytes(); // NB: absValNumBytes always returns a value >= 1
    const size_t ilast = max.absValNumBytes();

    assert(ilast < std::numeric_limits<size_t>::max());

    if (min == 0) {
        testFunction(0);
    }

    auto testRun = [&](BigInt &a) {
        a = std::clamp(a, min, max);
        if (testNegative) {
            testFunction(-a);
        } else {
            testFunction(a);
        }
    };

    const double growthFactor = percentGrowth / 100.0;
    BigInt a;
    for (size_t i = ifirst, j = ifirst;;) { // see loop end
        // byte lower boundary a
        a = BigInt(2).pow((j - 1) * 8); // e.g. j = 4; a = 16777216;
        testRun(a);
        // random a
        a = randGen.randLength(j); // e.g. j = 4; a = random value in range [16777216, 2147483647]
        testRun(a);
        // byte upper boundary a
        a = BigInt(2).pow(j * 8 - 1) - 1; // e.g. j = 4; a = 2147483647;
        testRun(a);

        if (j >= ilast) break; // terminate loop once we processed the edge case
        // else calc the next edge and pick a random size between
        const size_t ip = i;
        const size_t delta = std::max<size_t>(1u, static_cast<size_t>(i * growthFactor));
        i += delta;
        j = ip + fastRand.randrange(i + 1u); // NB: randrange arg is exclusive range
        j = std::min<size_t>(j, ilast); // clamp to last value
    }
}

// Minimally-encoded Operand Tests (Unary)
//     - Fail: `{stack: 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN {opcode} OP_DROP OP_1`
void TestMinimalEncodingUnary(const opcodetype &opcode) {
    auto TestMinimalEncodingNegativeZero = [&](const BigInt &n) {
        StackT stack = {BigInt(0).serialize(), n.serialize()};
        CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                   << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                   << opcode << OP_DROP << OP_1;
        CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                            "TestMinimalEncodingNegativeZero passed (expected to fail) for n = " << n.ToString());
    };

    auto TestMinimalEncoding = [&](const BigInt &a) {
        auto aser = a.serialize();
        auto WithSize = [&](const BigInt &n) {
            StackT stack = {aser, n.serialize()};
            CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                       << opcode << OP_DROP << OP_1;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                            "TestMinimalEncodingNegativeZero passed (expected to fail) for a = " << a.ToString() << ", n = " << n.ToString());
        };
        size_t bytesToAdd = MAX_ELEM_SIZE - aser.size();
        if (bytesToAdd > 0) {
            // capture a, loop n
            TestRange(WithSize, 1, bytesToAdd, 700);
        }
    };

    // n >= 0, "negative 0"
    // 0x80, 0x0080, 0x00..80
    TestRange(TestMinimalEncodingNegativeZero, 0, MAX_ELEM_SIZE - 1, 700);
    // n > 0, a < 0
    // 0x123480, 0x12340080, 0x12340000..80
    TestRange(TestMinimalEncoding, 1, MAX_SCRIPTNUM, true, 700);
    // n > 0, a >= 0
    // 0x123400, 0x12340000, 0x12340000..00
    TestRange(TestMinimalEncoding, 0, MAX_SCRIPTNUM, false, 700);
}

// Minimally-encoded Operand Tests (Binary)
//     - Fail: `{stack: a, n} OP_0 OP_SWAP OP_NUM2BIN 0x0180 OP_CAT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: b, n} OP_0 OP_SWAP OP_NUM2BIN 0x0180 OP_CAT OP_SWAP {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, n} OP_ROT OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_SWAP {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN {opcode} OP_DROP OP_1`
void TestMinimalEncodingBinary(const opcodetype &opcode,
                               bool onlyPositiveA = false, bool onlyPositiveB = false,
                               BigInt maxA = MAX_SCRIPTNUM, BigInt maxB = MAX_SCRIPTNUM,
                               unsigned char abflags = 0b11) {
    auto TestMinimalEncodingNegativeZeroA = [&](const BigInt &n) {
        auto WithA = [&](const BigInt &a) {
            StackT stack = {BigInt(a).serialize(), BigInt(0).serialize(), n.serialize()};
            CScript script = CScript() << OP_0 << OP_SWAP << OP_NUM2BIN
                                       << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                       << opcode << OP_DROP << OP_1;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                "TestMinimalEncodingBinaryNegativeZeroA passed (expected to fail) for a = " << a.ToString() << ", n = " << n.ToString());
        };
        TestRange(WithA, 0, maxA, false, 700);
        if (!onlyPositiveA) {
            TestRange(WithA, 1, maxA, true, 700);
        }
    };
    auto TestMinimalEncodingNegativeZeroB = [&](const BigInt &n) {
        auto WithB = [&](const BigInt &a) {
            StackT stack = {BigInt(a).serialize(), BigInt(0).serialize(), n.serialize()};
            CScript script = CScript() << OP_0 << OP_SWAP << OP_NUM2BIN
                                       << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                       << OP_SWAP // swap the operands for the 2nd run
                                       << opcode << OP_DROP << OP_1;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                "TestMinimalEncodingBinaryNegativeZeroB passed (expected to fail) for b = " << a.ToString() << ", n = " << n.ToString());
        };
        TestRange(WithB, 0, maxB, false, 700);
        if (!onlyPositiveB) {
            TestRange(WithB, 1, maxB, true, 700);
        }
    };

    // n >= 0, "negative 0"
    // 0x80, 0x0080, 0x00..80
    if (abflags & 0b01) {
        TestRange(TestMinimalEncodingNegativeZeroA, 0, maxB.serialize().size() - 1, 700);
    }
    if (abflags & 0b10) {
        TestRange(TestMinimalEncodingNegativeZeroB, 0, maxA.serialize().size() - 1, 700);
    }

    auto TestMinimalEncoding = [&](const BigInt &a) {
        auto WithB = [&](const BigInt &b) {
            auto aser = a.serialize();
            auto bser = b.serialize();
            auto WithSizeA = [&](const BigInt &n) {
                StackT stack = {aser, bser, n.serialize()};
                CScript script = CScript() << OP_ROT << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN << OP_SWAP
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                "TestMinimalEncodingBinaryA passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString() << ", n = " << n.ToString());
            };
            auto WithSizeB = [&](const BigInt &n) {
                StackT stack = {aser, bser, n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                "TestMinimalEncodingBinaryB passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString() << ", n = " << n.ToString());
            };
            size_t maxBytesToAddA = maxA.serialize().size() - aser.size();
            size_t maxBytesToAddB = maxB.serialize().size() - bser.size();
            if (maxBytesToAddA > 0 && (abflags & 0b10)) {
                // capture a & b, loop n, pad A
                TestRange(WithSizeA, 1, maxBytesToAddA, 700);
            }
            if (maxBytesToAddB > 0 && (abflags & 0b01)) {
                // capture a & b, loop n, pad B
                TestRange(WithSizeB, 1, maxBytesToAddB, 700);
            }
        };
        // n > 0, b >= 0
        // 0x123400, 0x12340000, 0x12340000..00
        TestRange(WithB, 0, maxB/256, false, 700);
        if (!onlyPositiveB) {
            // n > 0, b < 0
            // 0x123480, 0x12340080, 0x12340000..80
            TestRange(WithB, 1, maxB/256, true, 700);
        }
    };
    TestRange(TestMinimalEncoding, 0, maxA/256, false, 700);
    if (!onlyPositiveA) {
        TestRange(TestMinimalEncoding, 1, maxA/256, true, 700);
    }
}

// Minimally-encoded Operand Tests (Ternary)
//     - Fail: `{stack: a, b, 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT OP_ROT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT OP_ROT OP_ROT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, c, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, c, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_ROT {opcode} OP_DROP OP_1`
//     - Fail: `{stack: a, b, c, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_ROT OP_ROT {opcode} OP_DROP OP_1`
void TestMinimalEncodingTernary(const opcodetype &opcode) {
    auto TestMinimalEncodingNegativeZero = [&](const BigInt &n) {
        auto WithA = [&](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize(), BigInt(0).serialize(), n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingNegativeZeroI passed (expected to fail) for a = " << a.ToString()
                                    << ", b = " << b.ToString() << ", n = " << n.ToString());

                stack = {a.serialize(), b.serialize(), BigInt(0).serialize(), n.serialize()};
                script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                           << OP_ROT // rotate the operands for the 2nd run
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingNegativeZeroII passed (expected to fail) for a = " << a.ToString()
                                    << ", b = " << b.ToString() << ", n = " << n.ToString());

                stack = {a.serialize(), b.serialize(), BigInt(0).serialize(), n.serialize()};
                script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                           << OP_ROT << OP_ROT // rotate the operands twice for the 3rd run
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingNegativeZeroIII passed (expected to fail) for a = " << a.ToString()
                                    << ", b = " << b.ToString() << ", n = " << n.ToString());
            };

            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };
        TestRange(WithA, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(WithA, 0, MAX_SCRIPTNUM, false, 700);
    };

    // n >= 0, "negative 0"
    // 0x80, 0x0080, 0x00..80
    TestRange(TestMinimalEncodingNegativeZero, 0, MAX_ELEM_SIZE - 1, 700);

    auto TestMinimalEncoding = [&](const BigInt &a) {
        auto WithB = [&](const BigInt &b) {
            auto WithC = [&](const BigInt &c) {
                auto cser = c.serialize();
                auto WithSize = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), b.serialize(), cser, n.serialize()};
                    CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                               << opcode << OP_DROP << OP_1;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingI passed (expected to fail) for a = " << a.ToString() << ", b = "
                                    << b.ToString() << "c = " << c.ToString() << ", n = " << n.ToString());

                    stack = {a.serialize(), b.serialize(), cser, n.serialize()};
                    script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                               << OP_ROT // rot the operands for the 2nd run
                                               << opcode << OP_DROP << OP_1;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingII passed (expected to fail) for a = " << a.ToString() << ", b = "
                                    << b.ToString() << "c = " << c.ToString() << ", n = " << n.ToString());

                    stack = {a.serialize(), b.serialize(), cser, n.serialize()};
                    script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                               << OP_ROT << OP_ROT // rot the operands twice for the 3rd run
                                               << opcode << OP_DROP << OP_1;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::MINIMALNUM),
                                    "TestMinimalEncodingIII passed (expected to fail) for a = " << a.ToString() << ", b = "
                                    << b.ToString() << "c = " << c.ToString() << ", n = " << n.ToString());
                };
                size_t maxBytesToAdd = MAX_ELEM_SIZE - cser.size();
                if (maxBytesToAdd > 0) {
                    // n range
                    TestRange(WithSize, 1, maxBytesToAdd, 1500);
                    // note, we test all paddings of c, e.g.:
                    // n > 0, c < 0: 0x123480, 0x12340080, 0x12340000..80
                    // n > 0, c >= 0: 0x123400, 0x12340000, 0x12340000..00
                }
            };
            // c range
            TestRange(WithC, 1, MAX_SCRIPTNUM, true, 1500);
            TestRange(WithC, 0, MAX_SCRIPTNUM, false, 1500);
        };
        // b range
        TestRange(WithB, 1, MAX_SCRIPTNUM, true, 1500);
        TestRange(WithB, 0, MAX_SCRIPTNUM, false, 1500);
    };
    // a range
    TestRange(TestMinimalEncoding, 1, MAX_SCRIPTNUM, true, 1500);
    TestRange(TestMinimalEncoding, 0, MAX_SCRIPTNUM, false, 1500);
    // note: these tests are O(N^4) !!!
    // that's why test more sparsely, by setting percentGrowth to 1500 (x16 geometric series)
}

} // namespace

BOOST_AUTO_TEST_SUITE(bigint_script_property_tests)

BOOST_AUTO_TEST_CASE(assumptions) {
    CHECK_MESSAGE(MAX_SCRIPTNUM == -MIN_SCRIPTNUM, "Assumption failed: MAX_SCRIPTNUM == -MIN_SCRIPTNUM");
    CHECK_MESSAGE(BigInt(2).pow(MAX_ELEM_SIZE * 8 - 1) - 1 == MAX_SCRIPTNUM, "Assumption failed: BigInt(2).pow(MAX_ELEM_SIZE * 8 - 1) - 1 == MAX_SCRIPTNUM");
}

// OP_NUM2BIN (0x80)
BOOST_AUTO_TEST_CASE(op_num2bin_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_NUM2BIN);
    }

    // Minimally-encoded Operand Test (the number to be converted needs NOT be a minimally encoded number):
    //     - Pass: `{stack: 0, m, n} OP_ROT OP_ROT OP_NUM2BIN 0x0180 OP_CAT OP_DUP OP_ROT OP_NUM2BIN OP_BIN2NUM OP_SWAP OP_BIN2NUM OP_NUMEQUAL`
    //     - Pass: `{stack: a, m, n} OP_ROT OP_ROT OP_NUM2BIN OP_DUP OP_ROT OP_NUM2BIN OP_BIN2NUM OP_SWAP OP_BIN2NUM OP_NUMEQUAL`
    {
        auto TestMinimalEncodingNegativeZero = [&](const BigInt &m) {
            auto WithN = [&](const BigInt &n) {
                StackT stack = {BigInt(0).serialize(), m.serialize(), n.serialize()};
                CScript script = CScript() << OP_ROT << OP_ROT << OP_NUM2BIN
                                           << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                           << OP_DUP << OP_ROT << OP_NUM2BIN << OP_BIN2NUM << OP_SWAP << OP_BIN2NUM << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestMinimalEncodingNegativeZero failed (expected to pass) for m = " << m.ToString() << ", n = " << n.ToString());
            };
            // capture m, loop n
            TestRange(WithN, 1, MAX_ELEM_SIZE, 700);
        };
        // loop m
        TestRange(TestMinimalEncodingNegativeZero, 1, MAX_ELEM_SIZE - 1, 700);

        auto TestMinimalEncoding = [&](const BigInt &a) {
            auto aser = a.serialize();
            auto WithM = [&](const BigInt &m) {
                auto WithN = [&](const BigInt &n) {
                    StackT stack = {aser, m.serialize(), n.serialize()};
                    CScript script = CScript() << OP_ROT << OP_ROT << OP_NUM2BIN
                                               << OP_DUP << OP_ROT << OP_NUM2BIN << OP_BIN2NUM << OP_SWAP << OP_BIN2NUM << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestMinimalEncoding failed (expected to pass) for a = " << a.ToString() << ", m = " << m.ToString() << ", n = " << n.ToString());
                };
                // capture a & m, loop n
                TestRange(WithN, aser.size(), MAX_ELEM_SIZE, 700);
            };
            // capture a, loop m
            TestRange(WithM, aser.size(), MAX_ELEM_SIZE, 700);
        };
        // loop a
        TestRange(TestMinimalEncoding, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestMinimalEncoding, 0, MAX_SCRIPTNUM, false, 700);
    }

    // Minimally-encoded Operand Test (the requested size MUST be a minimally encoded number):
    //     - Fail: `{stack: a, 0, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT {opcode} OP_DROP OP_1`
    //     - Fail: `{stack: a, b, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN {opcode} OP_DROP OP_1`
    {
        const opcodetype opcode = OP_NUM2BIN;
        auto TestMinimalEncodingNegativeZero = [&](const BigInt &n) {
            auto WithA = [&](const BigInt &a) {
                StackT stack = {BigInt(a).serialize(), BigInt(0).serialize(), n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                           << opcode << OP_DROP << OP_1;
                CHECK_MESSAGE(!TestScript(script, stack, ScriptError::OK, true),
                                    "TestMinimalEncodingNegativeZero passed (expected to fail) for a = " << a.ToString() << ", n = " << n.ToString());
            };
            TestRange(WithA, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithA, 0, MAX_SCRIPTNUM, false, 700);
        };

        // n >= 0, "negative 0"
        // 0x80, 0x0080, 0x00..80
        TestRange(TestMinimalEncodingNegativeZero, 0, MAX_ELEM_SIZE - 1, 700);

        auto TestMinimalEncoding = [&](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto bser = b.serialize();
                auto WithSize = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), bser, n.serialize()};
                    CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                               << opcode << OP_DROP << OP_1;
                    CHECK_MESSAGE(!TestScript(script, stack, ScriptError::OK, true),
                                    "TestMinimalEncoding passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString() << ", n = " << n.ToString());
                };
                size_t maxBytesToAdd = MAX_ELEM_SIZE - bser.size();
                if (maxBytesToAdd > 0) {
                    // capture a & b, loop n
                    TestRange(WithSize, 1, maxBytesToAdd, 700);
                }
            };
            // n > 0, b < 0
            // 0x123480, 0x12340080, 0x12340000..80
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            // n > 0, b >= 0
            // 0x123400, 0x12340000, 0x12340000..00
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };
        TestRange(TestMinimalEncoding, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestMinimalEncoding, 0, MAX_SCRIPTNUM, false, 700);
    }

    // Requested size must be sufficient to accommodate lossless encoding:
    //     - Fail: `{stack: a} OP_SIZE OP_1SUB OP_NUM2BIN OP_DUP OP_EQUAL` (must fail with `ScriptError::IMPOSSIBLE_ENCODING` error)
    {
        auto TestMinSize = [&](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_SIZE << OP_1SUB << OP_NUM2BIN << OP_DUP << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::IMPOSSIBLE_ENCODING),
                            "TestMinimalEncoding failed (expected to pass) for a = " << a.ToString());
        };
        // loop a
        TestRange(TestMinSize, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestMinSize, 1, MAX_SCRIPTNUM, false, 700);
    }

    // - Pad a number with n 0-bytes (while shifting the sign bit where present), then split and verify it matches the source number and requested size:
    //     - Pass: `{stack: a, n} OP_2DUP OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_ROT OP_SIZE OP_ROT OP_SWAP OP_SPLIT OP_DUP OP_BIN2NUM OP_0 OP_NUMEQUALVERIFY OP_SIZE OP_ROT OP_ROT OP_CAT OP_BIN2NUM OP_ROT OP_NUMEQUALVERIFY OP_NUMEQUAL`
    {
        auto TestPaddedNumbers = [&](const BigInt &a) {
            auto aser = a.serialize();
            auto WithSize = [&](const BigInt &n) {
                StackT stack = {aser, n.serialize()};
                CScript script = CScript() << OP_2DUP << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN << OP_ROT << OP_SIZE << OP_ROT
                                           << OP_SWAP << OP_SPLIT << OP_DUP << OP_BIN2NUM << OP_0 << OP_NUMEQUALVERIFY << OP_SIZE << OP_ROT
                                           << OP_ROT << OP_CAT << OP_BIN2NUM << OP_ROT << OP_NUMEQUALVERIFY << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestPaddedNumbers failed (expected to pass) for a = " << a.ToString() << ", n = " << n.ToString());
            };
            size_t bytesToAdd = MAX_ELEM_SIZE - aser.size();
            TestRange(WithSize, 0, bytesToAdd, 100);
        };
        // n >= 0, a < 0
        // 0x12b4, 0x123480, 0x12340080, 0x12340000..80
        TestRange(TestPaddedNumbers, 1, MAX_SCRIPTNUM, true, 100);
        // n >= 0, a >= 0
        // 0x1234, 0x123400, 0x12340000, 0x12340000..00
        TestRange(TestPaddedNumbers, 0, MAX_SCRIPTNUM, false, 100);
    }

    // - Overflow
    //     - Pass: `{stack: a, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_DUP OP_EQUAL`, where `size(a) + n < MAX_ELEM_SIZE`
    //     - Fail: `{stack: a, n} OP_SWAP OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_DUP OP_EQUAL`, where `size(a) + n >= MAX_ELEM_SIZE` (must fail with `ScriptError::PUSH_SIZE` error)
    {
        auto TestOverflow = [&](const BigInt &a) {
            auto aser = a.serialize();
            auto WithSize = [&](const BigInt &n) {
                StackT stack = {aser, n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN << OP_DUP << OP_EQUAL;
                if (aser.size() + n <= MAX_ELEM_SIZE) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestOverflow passed (expected to fail) for a = " << a.ToString() << ", n = " << n.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::PUSH_SIZE),
                                    "TestOverflow failed (expected to pass) for a = " << a.ToString() << ", n = " << n.ToString());
                }
            };
            TestRange(WithSize, 0, MAX_ELEM_SIZE, 100);
        };
        TestRange(TestOverflow, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestOverflow, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_BIN2NUM (0x81)
BOOST_AUTO_TEST_CASE(op_bin2num_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_BIN2NUM);
    }

    // - Any stack item is a valid input, and the operation will produce a valid, minimally-encoded, script number:
    //     - Pass: `{stack: 0, n} OP_OVER OP_SIZE OP_ROT OP_ADD OP_NUM2BIN 0x0180 OP_CAT OP_BIN2NUM OP_NUMEQUAL`
    //     - Pass: `{stack: a, n} OP_OVER OP_SIZE OP_ROT OP_ADD OP_NUM2BIN OP_BIN2NUM OP_NUMEQUAL`
    {
        auto TestNegativeZero = [&](const BigInt &n) {
            StackT stack = {BigInt(0).serialize(), n.serialize()};
            CScript script = CScript() << OP_OVER << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                       << opcodetype(0x01) << opcodetype(0x80) << OP_CAT
                                       << OP_BIN2NUM << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestNegativeZero failed (expected to pass) for n = " << n.ToString());
        };
        // n >= 0, variations of "negative 0"
        // 0x80, 0x0080, 0x00..80
        TestRange(TestNegativeZero, 0, MAX_ELEM_SIZE - 1, 100);

        auto TestPaddedNumbers = [&](const BigInt &a) {
            auto aser = a.serialize();
            auto WithSize = [&](const BigInt &n) {
                StackT stack = {aser, n.serialize()};
                CScript script = CScript() << OP_OVER << OP_SIZE << OP_ROT << OP_ADD << OP_NUM2BIN
                                           << OP_BIN2NUM << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestPaddedNumbers failed (expected to pass) for a = " << a.ToString() << ", n = " << n.ToString());
            };
            size_t bytesToAdd = MAX_ELEM_SIZE - aser.size();
            if (bytesToAdd > 0) {
                // capture a, loop n
                TestRange(WithSize, 0, bytesToAdd, 100);
            }
        };
        // n >= 0, a < 0
        // 0x12b4, 0x123480, 0x12340080, 0x12340000..80
        TestRange(TestPaddedNumbers, 1, MAX_SCRIPTNUM, true, 100);
        // n >= 0, a >= 0
        // 0x1234, 0x123400, 0x12340000, 0x12340000..00
        TestRange(TestPaddedNumbers, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_1ADD (0x8b)
BOOST_AUTO_TEST_CASE(op_1add_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_1ADD);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_1ADD);
    }

    // - Successor: a < op1add(a)
    //     - Pass: `{stack: a} OP_DUP OP_1ADD OP_LESSTHAN`
    // - Increment: op1add(a) - a == 1
    //     - Pass: `{stack: a} OP_DUP OP_1ADD OP_SWAP OP_SUB OP_1 OP_NUMEQUAL`
    // - Inverse: a == op1sub(op1add(a))
    //     - Pass: `{stack: a} OP_DUP OP_1ADD OP_1SUB OP_NUMEQUAL`
    {
        auto TestSuccessor = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1ADD << OP_LESSTHAN;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestSuccessor failed (expected to pass) for a = " << a.ToString());
        };

        auto TestOneMore = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1ADD << OP_SWAP << OP_SUB << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestOneMore failed (expected to pass) for a = " << a.ToString());
        };

        auto TestWithSub = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1ADD << OP_1SUB << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestWithSub failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestSuccessor,
            TestOneMore,
            TestWithSub
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM - 1, false, 100);
        }
    }

    // - Apply Multiple: a + 3 == op1add(op1add(op1add(a)))
    //     - Pass: `{stack: a} OP_DUP OP_3 OP_ADD OP_SWAP OP_1ADD OP_1ADD OP_1ADD OP_NUMEQUAL`
    {
        auto TestApplyMultiple = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_3 << OP_ADD << OP_SWAP << OP_1ADD << OP_1ADD << OP_1ADD << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestApplyMultiple failed (expected to pass) for a = " << a.ToString());
        };
        TestRange(TestApplyMultiple, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestApplyMultiple, 0, MAX_SCRIPTNUM - 3, false, 100);
    }

    // - Overflow:
    //     - Pass: `{stack: a} OP_1ADD OP_DROP OP_1`, where a < MAX_SCRIPTNUM
    //     - Fail: `{stack: a} OP_1ADD OP_DROP OP_1`, where a == MAX_SCRIPTNUM
    {
        auto TestOverflow = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_1ADD << OP_DROP << OP_1;
            if (a < MAX_SCRIPTNUM) {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestOverflow failed (expected to pass) for a = " << a.ToString());
            } else {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                "TestOverflow passed (expected to fail) for a = " << a.ToString());
            }
        };
        TestRange(TestOverflow, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestOverflow, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_1SUB (0x8c)
BOOST_AUTO_TEST_CASE(op_1sub_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_1SUB);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_1SUB);
    }

    // - Predecessor: a > op1sub(a)
    //     - Pass: `{stack: a} OP_DUP OP_1SUB OP_GREATERTHAN`
    // - Decrement: a - op1sub(a) == 1
    //     - Pass: `{stack: a} OP_DUP OP_1SUB OP_SUB OP_1 OP_NUMEQUAL`
    // - Inverse: a == op1add(op1sub(a))
    //     - Pass: `{stack: a} OP_DUP OP_1SUB OP_1ADD OP_NUMEQUAL`
    {
        auto TestPredecessor = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1SUB << OP_GREATERTHAN;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestPredecessor failed (expected to pass) for a = " << a.ToString());
        };

        auto TestOneLess = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1SUB << OP_SUB << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestOneLess failed (expected to pass) for a = " << a.ToString());
        };

        auto TestWithAdd = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1SUB << OP_1ADD << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestWithAdd failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestPredecessor,
            TestOneLess,
            TestWithAdd
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM - 1, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Apply Multiple: a - 3 == op1sub(op1sub(op1sub(a)))
    //     - Pass: `{stack: a} OP_DUP OP_3 OP_SUB OP_SWAP OP_1SUB OP_1SUB OP_1SUB OP_NUMEQUAL`
    {
        auto TestApplyMultiple = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_3 << OP_SUB << OP_SWAP << OP_1SUB << OP_1SUB << OP_1SUB << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestApplyMultiple failed (expected to pass) for a = " << a.ToString());
        };
        TestRange(TestApplyMultiple, 1, MAX_SCRIPTNUM - 3, true, 100);
        TestRange(TestApplyMultiple, 0, MAX_SCRIPTNUM, false, 100);
    }

    // - Underflow:
    //     - Pass: `{stack: a} OP_1SUB OP_DROP OP_1`, where a > -MAX_SCRIPTNUM
    //     - Fail: `{stack: a} OP_1SUB OP_DROP OP_1`, where a == -MAX_SCRIPTNUM
    {
        auto TestUnderflow = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_1SUB << OP_DROP << OP_1;
            if (a > MIN_SCRIPTNUM) {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestUnderflow failed (expected to pass) for a = " << a.ToString());
            } else {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                "TestUnderflow passed (expected to fail) for a = " << a.ToString());
            }
        };
        TestRange(TestUnderflow, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestUnderflow, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_NEGATE (0x8f)
BOOST_AUTO_TEST_CASE(op_negate_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_NEGATE);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_NEGATE);
    }

    // - Zero negation: -0 == 0
    //     - Pass: `OP_0 OP_NEGATE OP_0 OP_NUMEQUAL`
    {
        StackT stack = {};
        CScript script = CScript() << OP_0 << OP_NEGATE << OP_0 << OP_NUMEQUAL;
        CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZeroNegation failed (expected to pass)");
    }

    // - Double negation: a == -(-a)
    //     - Pass: `{stack: a} OP_DUP OP_NEGATE OP_NEGATE OP_NUMEQUAL`
    // - Multiplication equivalence: -a == a * (-1)
    //     - Pass: `{stack: a} OP_DUP OP_NEGATE OP_SWAP OP_1NEGATE OP_MUL OP_NUMEQUAL`
    // - Zero sum: -a + a == 0
    //     - Pass: `{stack: a} OP_DUP OP_NEGATE OP_ADD OP_0 OP_NUMEQUAL`
    {
        auto TestDoubleNegation = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NEGATE << OP_NEGATE << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestDoubleNegation failed (expected to pass) for a = " << a.ToString());
        };

        auto TestNegationMulEquivalence = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NEGATE << OP_SWAP << OP_1NEGATE << OP_MUL << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNegationMulEquivalence failed (expected to pass) for a = " << a.ToString());
        };

        auto TestNegationSumZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NEGATE << OP_ADD << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNegationSumZero failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestDoubleNegation,
            TestNegationMulEquivalence,
            TestNegationSumZero
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_ABS (0x90)
BOOST_AUTO_TEST_CASE(op_abs_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_ABS);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_ABS);
    }

    // - Absolute of a positive number: a == abs(a)
    //     - Pass: `{stack: a} OP_DUP OP_ABS OP_NUMEQUAL`, where a >= 0
    //     - Fail: `{stack: a} OP_DUP OP_ABS OP_NUMEQUAL`, where a < 0 (must fail with `ScriptError::EVAL_FALSE` error)
    // - Absolute of a negative number: a == -abs(a)
    //     - Pass: `{stack: a} OP_DUP OP_ABS OP_NEGATE OP_NUMEQUAL`, where a <= 0
    //     - Fail: `{stack: a} OP_DUP OP_ABS OP_NEGATE OP_NUMEQUAL`, where a > 0 (must fail with `ScriptError::EVAL_FALSE` error)
    {
        auto TestAbs = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_ABS << OP_NUMEQUAL;
            if (a >= 0) {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestAbs failed (expected to pass) for a = " << a.ToString());
            } else {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::EVAL_FALSE), "TestAbs passed (expected to fail) for a = " << a.ToString());
            }
        };

        auto TestNegAbs = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_ABS << OP_NEGATE << OP_NUMEQUAL;
            if (a <= 0) {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNegAbs failed (expected to pass) for a = " << a.ToString());
            } else {
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::EVAL_FALSE), "TestNegAbs passed (expected to fail) for a = " << a.ToString());
            }
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestAbs,
            TestNegAbs
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_NOT (0x91)
BOOST_AUTO_TEST_CASE(op_not_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_NOT);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_NOT);
    }

    // - Zero: !0 == 1
    //     - Pass: `OP_0 OP_NOT OP_1 OP_NUMEQUAL`
    {
        StackT stack = {};
        CScript script = CScript() << OP_0 << OP_NOT << OP_1 << OP_NUMEQUAL;
        CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZero failed (expected to pass)");
    }

    // - Non-zero: !a == 0
    //     - Pass: `{stack: a} OP_NOT OP_0 OP_NUMEQUAL`, where a > 0
    {
        auto TestNonZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_NOT << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNonZero failed (expected to pass) for a = " << a.ToString());
        };

        TestRange(TestNonZero, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestNonZero, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Double: !(!a) == !(a == 0)
    //     - Pass: `{stack: a} OP_DUP OP_NOT OP_NOT OP_SWAP OP_0 OP_NUMEQUAL OP_NOT OP_NUMEQUAL`
    {
        auto TestDoubleNot = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NOT << OP_NOT << OP_SWAP << OP_0 << OP_NUMEQUAL << OP_NOT << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestDoubleNot failed (expected to pass) for a = " << a.ToString());
        };

        TestRange(TestDoubleNot, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestDoubleNot, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_0NOTEQUAL (0x92)
BOOST_AUTO_TEST_CASE(op_0notequal_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_0NOTEQUAL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingUnary(OP_0NOTEQUAL);
    }

    // - Zero: !(0 == 0) == 1
    //     - Pass: `OP_0 OP_0NOTEQUAL OP_0 OP_NUMEQUAL`
    {
        StackT stack = {};
        CScript script = CScript() << OP_0 << OP_0NOTEQUAL << OP_0 << OP_NUMEQUAL;
        CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZero failed (expected to pass)");
    }

    // - Non-zero: !(a == 0) == 1
    //     - Pass: `{stack: a} OP_0NOTEQUAL OP_1 OP_NUMEQUAL`
    {
        auto TestNonZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_0NOTEQUAL << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNonZero failed (expected to pass) for a = " << a.ToString());
        };

        TestRange(TestNonZero, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestNonZero, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Double: !(!a) == !(!(a == 0) == 0)
    //     - Pass: `{stack: a} OP_DUP OP_0NOTEQUAL OP_0NOTEQUAL OP_SWAP OP_NOT OP_NOT OP_NUMEQUAL`
    {
        auto TestDouble0Notequal = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0NOTEQUAL << OP_0NOTEQUAL << OP_SWAP << OP_NOT << OP_NOT << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestDouble0Notequal failed (expected to pass) for a = " << a.ToString());
        };

        TestRange(TestDouble0Notequal, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestDouble0Notequal, 0, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_ADD (0x93)
BOOST_AUTO_TEST_CASE(op_add_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_ADD);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_ADD);
    }

    // - Identity: a + 0 == a && 0 + a == a
    //     - Pass: `{stack: a} OP_DUP OP_0 OP_ADD OP_OVER OP_NUMEQUAL OP_0 OP_2 OP_PICK OP_ADD OP_ROT OP_NUMEQUAL OP_BOOLAND`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_ADD << OP_OVER << OP_NUMEQUAL << OP_0 << OP_2 << OP_PICK << OP_ADD
                                       << OP_ROT << OP_NUMEQUAL << OP_BOOLAND;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdentity failed (expected to pass) for a = " << a.ToString());
        };

        TestRange(TestIdentity, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdentity, 0, MAX_SCRIPTNUM, false, 100);
    }

    // - Commutativity: a + b == b + a
    //     - Pass: `{stack: a, b} OP_2DUP OP_ADD OP_SWAP OP_ROT OP_ADD OP_NUMEQUAL`
    // - Successor: a < a + b
    //     - Pass: `{stack: a, b} OP_OVER OP_ADD OP_LESSTHAN`, where b > 0
    //     - Fail: `{stack: a, b} OP_OVER OP_ADD OP_LESSTHAN`, where b <= 0 (must fail with `ScriptError::EVAL_FALSE` error)
    // - Inverse: (a + b) - b == a
    //     - Pass: `{stack: a, b} OP_2DUP OP_ADD OP_SWAP OP_SUB OP_NUMEQUAL`
    // - Range:
    //     - Pass: `{stack: a, b} OP_ADD OP_DROP OP_1`, where `a + b` is within `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range
    //     - Fail: `{stack: a, b} OP_ADD OP_DROP OP_1`, where `a + b` is out of `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range (must fail with `ScriptError::INVALID_NUMBER_RANGE_BIG_INT` error)
    {
        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_ADD << OP_SWAP << OP_ROT << OP_ADD << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a > 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, false, 100);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            }
        };

        auto TestSuccessor = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_OVER << OP_ADD << OP_LESSTHAN;
                if (b > 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestSuccessor failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::EVAL_FALSE),
                                    "TestSuccessor passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            if (a > 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, false, 100);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            }
        };

        auto TestInverse = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_ADD << OP_SWAP << OP_SUB << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestInverse failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a > 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, false, 100);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            }
        };

        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_ADD << OP_DROP << OP_1;
                if ((a + b).abs() <= MAX_SCRIPTNUM) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestCommutativity,
            TestSuccessor,
            TestInverse,
            TestValidRange
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Associativity: (a + b) + c == a + (b + c)
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_ADD OP_OVER OP_ADD OP_2SWAP OP_3 OP_ROLL OP_ADD OP_ADD OP_NUMEQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_ADD << OP_OVER << OP_ADD << OP_2SWAP
                                               << OP_3 << OP_ROLL << OP_ADD << OP_ADD << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                auto ap = a > 0;
                auto bp = b > 0;
                if (ap && bp) {
                    TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM - (a + b), false, 700);
                } else if (ap && !bp) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM + b, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM - (a + b).abs(), false, 700);
                } else if (!ap && bp) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM - (a + b).abs(), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM - b, false, 700);
                } else {
                    TestRange(WithC, 0, MAX_SCRIPTNUM + (a + b), true, 700);
                    TestRange(WithC, 1, MAX_SCRIPTNUM, false, 700);
                }
            };
            if (a > 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, false, 700);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 700);
            }
        };

        TestRange(TestAssociativity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestAssociativity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_SUB (0x94)
BOOST_AUTO_TEST_CASE(op_sub_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_SUB);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_SUB);
    }

    // - Identity: a - 0 == a
    //     - Pass: `{stack: a} OP_DUP OP_0 OP_SUB OP_NUMEQUAL`
    // - Sign: 0 - a == -a
    //     - Pass: `{stack: a} OP_0 OP_OVER OP_SUB OP_SWAP OP_NEGATE OP_NUMEQUAL`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_SUB << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdentity failed (expected to pass) for a = " << a.ToString());
        };

        auto TestSign = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_0 << OP_OVER << OP_SUB << OP_SWAP << OP_NEGATE << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestSign failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestIdentity,
            TestSign
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Anti-commutativity: a - b == -(b - a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_SUB OP_SWAP OP_ROT OP_SUB OP_NEGATE OP_NUMEQUAL`
    // - Predecessor: a > a - b
    //     - Pass: `{stack: a, b} OP_OVER OP_SWAP OP_SUB OP_GREATERTHAN`, where b > 0
    //     - Fail: `{stack: a, b} OP_OVER OP_SWAP OP_SUB OP_GREATERTHAN`, where b <= 0 (must fail with `ScriptError::EVAL_FALSE` error)
    // - Inverse: (a - b) + b == a
    //     - Pass: `{stack: a, b} OP_2DUP OP_SUB OP_ADD OP_NUMEQUAL`
    // - Range:
    //     - Pass: `{stack: a, b} OP_SUB OP_DROP OP_1`, where `a - b` is within `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range
    //     - Fail: `{stack: a, b} OP_SUB OP_DROP OP_1`, where `a - b` is out of `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range (must fail with `ScriptError::INVALID_NUMBER_RANGE_BIG_INT` error)
    {
        auto TestAntiCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_SUB << OP_SWAP << OP_ROT << OP_SUB << OP_NEGATE << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAntiCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a > 0) {
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            } else {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, false, 100);
            }
        };

        auto TestPredecessor = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_OVER << OP_SWAP << OP_SUB << OP_GREATERTHAN;
                if (b > 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestPredecessor failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::EVAL_FALSE),
                                    "TestPredecessor passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            if (a > 0) {
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            } else {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, false, 100);
            }
        };

        auto TestInverse = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_SUB << OP_ADD << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestInverse failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a > 0) {
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            } else {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, false, 100);
            }
        };

        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_SUB << OP_DROP << OP_1;
                if ((a - b).abs() <= MAX_SCRIPTNUM) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestAntiCommutativity,
            TestPredecessor,
            TestInverse,
            TestValidRange
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Non-associativity: (a - b) - c == a - (b + c)
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_SUB OP_OVER OP_SUB OP_2SWAP OP_3 OP_ROLL OP_ADD OP_SUB OP_NUMEQUAL`
    {
        auto TestNonAssociativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_SUB << OP_OVER << OP_SUB << OP_2SWAP
                                               << OP_3 << OP_ROLL << OP_ADD << OP_SUB << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestNonAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                auto ap = a > 0;
                auto bp = b > 0;
                if (ap && bp) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM - (a - b), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM - b, false, 700);
                } else if (ap && !bp) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM - (a - b), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
                } else if (!ap && bp) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM + (a - b), false, 700);
                } else {
                    TestRange(WithC, 0, MAX_SCRIPTNUM + b, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM + (a - b), false, 700);
                }
            };
            if (a > 0) {
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 700);
            } else {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, false, 700);
            }
        };

        TestRange(TestNonAssociativity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestNonAssociativity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_MUL (0x95)
BOOST_AUTO_TEST_CASE(op_mul_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_MUL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_MUL);
    }

    // - Identity: a * 1 == a && 1 * a == a
    //     - Pass: `{stack: a} OP_DUP OP_1 OP_MUL OP_OVER OP_NUMEQUAL OP_1 OP_2 OP_PICK OP_MUL OP_ROT OP_NUMEQUAL OP_BOOLAND`
    // - Negation: a * (-1) == -a
    //     - Pass: `{stack: a} OP_DUP OP_1NEGATE OP_MUL OP_SWAP OP_NEGATE OP_NUMEQUAL`
    // - Zero: a * 0 == 0 && 0 * a == 0
    //     - Pass: `{stack: a} OP_DUP OP_0 OP_MUL OP_0 OP_NUMEQUAL OP_0 OP_ROT OP_MUL OP_0 OP_NUMEQUAL OP_BOOLAND`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1 << OP_MUL << OP_OVER << OP_NUMEQUAL << OP_1 << OP_2 << OP_PICK << OP_MUL
                                       << OP_ROT << OP_NUMEQUAL << OP_BOOLAND;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdentity failed (expected to pass) for a = " << a.ToString());
        };

        auto TestNegation = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1NEGATE << OP_MUL << OP_SWAP << OP_NEGATE << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestNegation failed (expected to pass) for a = " << a.ToString());
        };

        auto TestZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_MUL << OP_0 << OP_NUMEQUAL << OP_0 << OP_ROT << OP_MUL << OP_0
                                       << OP_NUMEQUAL << OP_BOOLAND;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZero failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestIdentity,
            TestNegation,
            TestZero
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Equivalence with multiple additions: a * 4 == a + a + a + a
    //     - Pass: `{stack: a} OP_DUP OP_4 OP_MUL OP_OVER OP_2 OP_PICK OP_ADD OP_2 OP_PICK OP_ADD OP_ROT OP_ADD OP_NUMEQUAL`
    // - Equivalence with multiple subtractions: a * (-4) == a - a - a - a - a - a
    //     - Pass: `{stack: a} OP_DUP OP_4 OP_NEGATE OP_MUL OP_OVER OP_2 OP_PICK OP_SUB OP_2 OP_PICK OP_SUB OP_2 OP_PICK OP_SUB OP_2 OP_PICK OP_SUB OP_ROT OP_SUB OP_NUMEQUAL`
    {
        auto TestAdditionEquivalence = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_4 << OP_MUL << OP_OVER << OP_2 << OP_PICK << OP_ADD << OP_2 << OP_PICK << OP_ADD
                                       << OP_ROT << OP_ADD << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestAdditionEquivalence failed (expected to pass) for a = " << a.ToString());
        };

        auto TestSubtractionEquivalence = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_4 << OP_NEGATE << OP_MUL << OP_OVER << OP_2 << OP_PICK << OP_SUB << OP_2 << OP_PICK
                                       << OP_SUB << OP_2 << OP_PICK << OP_SUB << OP_2 << OP_PICK << OP_SUB << OP_ROT << OP_SUB << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestSubtractionEquivalence failed (expected to pass) for a = " << a.ToString());
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestAdditionEquivalence,
            TestSubtractionEquivalence,
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM / 4, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM / 4, false, 100);
        }
    }

    // - Commutativity: a * b == b * a
    //     - Pass: `{stack: a, b} OP_2DUP OP_MUL OP_SWAP OP_ROT OP_MUL OP_NUMEQUAL`
    // - Inverse: (a * b) / b == a, where b != 0
    //     - Pass: `{stack: a, b} OP_2DUP OP_MUL OP_SWAP OP_DIV OP_NUMEQUAL`
    // - Range:
    //     - Pass: `{stack: a, b} OP_MUL OP_DROP OP_1`, where `a * b` is within `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range
    //     - Fail: `{stack: a, b} OP_MUL OP_DROP OP_1`, where `a * b` is out of `[-MAX_SCRIPTNUM, MAX_SCRIPTNUM]` range (must fail with `ScriptError::INVALID_NUMBER_RANGE_BIG_INT` error)
    {
        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_MUL << OP_SWAP << OP_ROT << OP_MUL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a == 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM / a.abs(), true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), false, 100);
            }
        };

        auto TestInverse = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_MUL << OP_SWAP << OP_DIV << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestInverse failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            if (a == 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
            } else {
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), true, 100);
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), false, 100);
            }
        };

        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_MUL << OP_DROP << OP_1;
                if (a.abs() <= MAX_SCRIPTNUM / (b == 0 ? 1 : b.abs())) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestCommutativity,
            TestInverse,
            TestValidRange
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Order: a * b < a * c
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_ROT OP_MUL OP_ROT OP_ROT OP_MUL OP_LESSTHAN`, where (a > 0 and b < c) or (a < 0 and b > c)
    //     - Fail: `{stack: a, b, c} OP_2 OP_PICK OP_ROT OP_MUL OP_ROT OP_ROT OP_MUL OP_LESSTHAN`, otherwise (must fail with `ScriptError::EVAL_FALSE` error)
    // - Associativity: (a * b) * c == a * (b * c)
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_MUL OP_OVER OP_MUL OP_2SWAP OP_3 OP_ROLL OP_MUL OP_MUL OP_NUMEQUAL`
    // - Distributivity: a * (b + c) == (a * b) + (a * c)
    //     - Pass: `{stack: a, b, c} OP_3DUP OP_ADD OP_MUL OP_3 OP_PICK OP_3 OP_ROLL OP_MUL OP_2SWAP OP_MUL OP_ADD OP_NUMEQUAL`
    {
        auto TestOrder = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_ROT << OP_MUL << OP_ROT << OP_ROT << OP_MUL << OP_LESSTHAN;
                    if ((a > 0 && b < c) || (a < 0 && b > c)) {
                        CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                        "TestOrder failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                    } else {
                        CHECK_MESSAGE(TestScript(script, stack, ScriptError::EVAL_FALSE),
                                        "TestOrder passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                    }
                };
                if (a == 0) {
                    TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
                } else {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                    TestRange(WithC, 1, MAX_SCRIPTNUM / a.abs(), false, 700);
                }
            };
            if (a == 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), false, 700);
            }
        };

        auto TestAssociativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_MUL << OP_OVER << OP_MUL
                                               << OP_2SWAP << OP_3 << OP_ROLL << OP_MUL << OP_MUL << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                auto az = a == 0;
                auto bz = b == 0;
                if (az && bz) {
                    TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
                } else if (az && !bz) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / b.abs(), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM / b.abs(), false, 700);
                } else if (!az && bz) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs(), false, 700);
                } else {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / (a * b).abs(), true, 700);
                    TestRange(WithC, 1, MAX_SCRIPTNUM / (a * b).abs(), false, 700);
                }
            };
            if (a == 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), false, 700);
            }
        };

        auto TestDistributivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_ADD << OP_MUL << OP_3 << OP_PICK << OP_3 << OP_ROLL
                                               << OP_MUL << OP_2SWAP << OP_MUL << OP_ADD << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestDistributivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                auto az = a == 0;
                auto bz = b == 0;
                if (az && bz) {
                    TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
                } else if (az && !bz) {
                    if (b > 0) {
                        TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                    } else {
                        TestRange(WithC, 0, MAX_SCRIPTNUM + b, false, 700);
                    }
                } else if (!az && bz) {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs(), false, 700);
                } else {
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs() - b.abs(), true, 700);
                    TestRange(WithC, 0, MAX_SCRIPTNUM / a.abs() - b.abs(), false, 700);
                }
            };
            if (a == 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM / a.abs(), true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM / a.abs(), false, 700);
            }
        };

        std::vector<TestFuncUnary> testFunctions = {
            TestOrder,
            TestAssociativity,
            TestDistributivity
        };
        for (const auto& testFunc : testFunctions) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 700);
        }
    }
}

// OP_DIV (0x96)
BOOST_AUTO_TEST_CASE(op_div_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_DIV);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_DIV);
    }

    // - Identity: a / 1 == a
    //     - Pass: `{stack: a} OP_DUP OP_1 OP_DIV OP_NUMEQUAL`
    // - Negation: a / (-1) == -a
    //     - Pass: `{stack: a} OP_DUP OP_1NEGATE OP_DIV OP_SWAP OP_NEGATE OP_NUMEQUAL`
    // - Division by zero: a / 0 must fail.
    //     - Fail: `{stack: a} OP_0 OP_DIV OP_DROP OP_1` (must fail with `ScriptError::DIV_BY_ZERO` error)
    // - Self-division: a / a == 1, where a != 0
    //     - Pass: `{stack: a} OP_DUP OP_DIV OP_1 OP_NUMEQUAL`
    // - Dividing a zero: 0 / a == 0, where a != 0
    //     - Pass: `{stack: a} OP_0 OP_SWAP OP_DIV OP_0 OP_NUMEQUAL`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1 << OP_DIV << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "Identity failed (expected to pass)" << " for a = " << a.ToString());
        };

        auto TestNegation = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1NEGATE << OP_DIV << OP_SWAP << OP_NEGATE << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "Negation failed (expected to pass)" << " for a = " << a.ToString());
        };

        auto TestDivideByZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_0 << OP_DIV << OP_DROP << OP_1;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::DIV_BY_ZERO), "DivideByZero passed (expected to fail)" << " for a = " << a.ToString());
        };

        auto TestSelfDivision = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DIV << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "SelfDivision failed (expected to pass)" << " for a = " << a.ToString());
        };

        auto TestDivideAZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_0 << OP_SWAP << OP_DIV << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "DivideAZero failed (expected to pass)" << " for a = " << a.ToString());
        };

        // any a
        std::vector<TestFuncUnary> testFunctionsI = {
            TestIdentity,
            TestNegation,
            TestDivideByZero
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
        // a != 0
        std::vector<TestFuncUnary> testFunctionsII = {
            TestSelfDivision,
            TestDivideAZero
        };
        for (const auto& testFunc : testFunctionsII) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 1, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Inverse: (a / b) * b + (a % b) == a, where b != 0
    //     - Pass: `{stack: a, b} OP_2DUP OP_DIV OP_OVER OP_MUL OP_2 OP_PICK OP_ROT OP_MOD OP_ADD OP_NUMEQUAL`
    {
        auto TestInverse = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_DIV << OP_OVER << OP_MUL << OP_2 << OP_PICK << OP_ROT
                                           << OP_MOD << OP_ADD << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestInverse failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestInverse, 1, MAX_SCRIPTNUM, true, 100);
        TestRange(TestInverse, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Distributivity: (a + b) / c == a / c + b / c + (a % c + b % c - (a + b) % c) / c, where c != 0
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_ADD OP_OVER OP_DIV OP_3 OP_PICK OP_2 OP_PICK OP_DIV OP_2OVER OP_DIV OP_ADD OP_4 OP_PICK OP_3 OP_PICK OP_MOD OP_4 OP_PICK OP_4 OP_PICK OP_MOD OP_ADD OP_2ROT OP_ADD OP_4 OP_PICK OP_MOD OP_SUB OP_3 OP_ROLL OP_DIV OP_ADD OP_NUMEQUAL`
    {
        auto TestDistributivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_ADD << OP_OVER << OP_DIV << OP_3
                                               << OP_PICK << OP_2 << OP_PICK << OP_DIV << OP_2OVER << OP_DIV << OP_ADD << OP_4
                                               << OP_PICK << OP_3 << OP_PICK << OP_MOD << OP_4 << OP_PICK << OP_4 << OP_PICK
                                               << OP_MOD << OP_ADD << OP_2ROT << OP_ADD << OP_4 << OP_PICK << OP_MOD << OP_SUB
                                               << OP_3 << OP_ROLL << OP_DIV << OP_ADD << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestDistributivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 1, MAX_SCRIPTNUM, false, 700);

            };

            if (a > 0) {
                TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithB, 0, MAX_SCRIPTNUM - a, false, 700);
            } else {
                TestRange(WithB, 0, MAX_SCRIPTNUM + a, true, 700);
                TestRange(WithB, 1, MAX_SCRIPTNUM, false, 700);
            }
        };

        TestRange(TestDistributivity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestDistributivity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_MOD (0x97)
BOOST_AUTO_TEST_CASE(op_mod_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_MOD);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_MOD);
    }

    // - Power identity: (a * a) % a == 0, where a != 0
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_MUL OP_SWAP OP_MOD OP_0 OP_NUMEQUAL`
    {
        auto TestPowerIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_MUL << OP_SWAP << OP_MOD << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestPowerIdentity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestPowerIdentity, 1, MAX_SCRIPTNUM.sqrt(), true, 100);
        TestRange(TestPowerIdentity, 1, MAX_SCRIPTNUM.sqrt(), false, 100);
    }

    // - Modulo by zero: a % 0 must fail.
    //     - Fail: `{stack: a} OP_0 OP_MOD OP_DROP OP_1` (must fail with `ScriptError::MOD_BY_ZERO` error)
    // - Repeat identity: (a % b) % b == a % b, where b != 0
    //     - Pass: `{stack: a, b} OP_2DUP OP_MOD OP_OVER OP_MOD OP_ROT OP_ROT OP_MOD OP_NUMEQUAL`
    // - Sign absorption: a % (-b) == a % b, where b != 0
    //     - Pass: `{stack: a, b} OP_2DUP OP_NEGATE OP_MOD OP_ROT OP_ROT OP_MOD OP_NUMEQUAL`
    // - Sign preservation: (-a) % b == -(a % b), where b != 0
    //     - Pass: `{stack: a, b} OP_OVER OP_NEGATE OP_OVER OP_MOD OP_ROT OP_ROT OP_MOD OP_NEGATE OP_NUMEQUAL`
    {
        auto TestModuloByZero = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_0 << OP_MOD << OP_DROP << OP_1;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::MOD_BY_ZERO), "TestModuloByZero passed (expected to fail)" << " for a = " << a.ToString());
        };

        auto TestRepeatIdentity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_MOD << OP_OVER << OP_MOD << OP_ROT << OP_ROT << OP_MOD << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestRepeatIdentity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
        };

        auto TestSignAbsorption = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NEGATE << OP_MOD << OP_ROT << OP_ROT << OP_MOD << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestSignAbsorption failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
        };

        auto TestSignPreservation = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_OVER << OP_NEGATE << OP_OVER << OP_MOD << OP_ROT << OP_ROT << OP_MOD << OP_NEGATE
                                           << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestSignPreservation failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 1, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestModuloByZero,
            TestRepeatIdentity,
            TestSignAbsorption,
            TestSignPreservation
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_BOOLAND (0x9a)
BOOST_AUTO_TEST_CASE(op_booland_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_BOOLAND);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_BOOLAND);
    }

    // - Idempotence: (a && a) == (a != false)
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_BOOLAND OP_SWAP OP_0 OP_NUMNOTEQUAL OP_NUMEQUAL`
    {
        auto TestIdempotence = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_BOOLAND << OP_SWAP << OP_0 << OP_NUMNOTEQUAL << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdempotence failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestIdempotence, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdempotence, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Casting: (a && b) == (a != false && b != false)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLAND OP_ROT OP_0 OP_NUMNOTEQUAL OP_ROT OP_0 OP_NUMNOTEQUAL OP_BOOLAND OP_NUMEQUAL`
    // - Commutativity: (a && b) == (b && a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLAND OP_SWAP OP_ROT OP_BOOLAND OP_NUMEQUAL`
    // - De Morgan's law: !(a && b) == (!a || !b)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLAND OP_NOT OP_ROT OP_NOT OP_ROT OP_NOT OP_BOOLOR OP_NUMEQUAL`
    // - Absorption: (a || (a && b)) == (a != false)
    //     - Pass: `{stack: a, b} OP_OVER OP_2 OP_PICK OP_ROT OP_BOOLAND OP_BOOLOR OP_SWAP OP_0 OP_NUMNOTEQUAL OP_NUMEQUAL`
    {
        auto TestCasting = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLAND << OP_ROT << OP_0 << OP_NUMNOTEQUAL << OP_ROT << OP_0
                                           << OP_NUMNOTEQUAL << OP_BOOLAND << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCasting failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLAND << OP_SWAP << OP_ROT << OP_BOOLAND << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestDeMorgan = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLAND << OP_NOT << OP_ROT << OP_NOT << OP_ROT << OP_NOT
                                           << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestDeMorgan failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestAbsorption = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_OVER << OP_2 << OP_PICK << OP_ROT << OP_BOOLAND << OP_BOOLOR << OP_SWAP
                                           << OP_0 << OP_NUMNOTEQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAbsorption failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestCasting,
            TestCommutativity,
            TestDeMorgan,
            TestAbsorption
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Associativity: ((a && b) && c) == (a && (b && c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_BOOLAND OP_OVER OP_BOOLAND OP_2SWAP OP_3 OP_ROLL OP_BOOLAND OP_BOOLAND OP_NUMEQUAL`
    // - Distributivity: ((a || b) && c) == ((a && c) || (b && c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_BOOLOR OP_OVER OP_BOOLAND OP_3 OP_ROLL OP_2 OP_PICK OP_BOOLAND OP_2SWAP OP_BOOLAND OP_BOOLOR OP_NUMEQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_BOOLAND << OP_OVER << OP_BOOLAND << OP_2SWAP << OP_3
                                               << OP_ROLL << OP_BOOLAND << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        auto TestDistributivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_BOOLOR << OP_OVER << OP_BOOLAND << OP_3 << OP_ROLL << OP_2
                                               << OP_PICK << OP_BOOLAND << OP_2SWAP << OP_BOOLAND << OP_BOOLOR << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestDistributivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAssociativity,
            TestDistributivity
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 700);
        }
    }
}

// OP_BOOLOR (0x9b)
BOOST_AUTO_TEST_CASE(op_boolor_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_BOOLOR);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_BOOLOR);
    }

    // - Idempotence: (a || a) == (a != false)
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_BOOLOR OP_SWAP OP_0 OP_NUMNOTEQUAL OP_NUMEQUAL`
    {
        auto TestIdempotence = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_BOOLOR << OP_SWAP << OP_0 << OP_NUMNOTEQUAL << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdempotence failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestIdempotence, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdempotence, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Casting: (a || b) == (a != false || b != false)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLOR OP_ROT OP_0 OP_NUMNOTEQUAL OP_ROT OP_0 OP_NUMNOTEQUAL OP_BOOLOR OP_NUMEQUAL`
    // - Commutativity: (a || b) == (b || a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLOR OP_SWAP OP_ROT OP_BOOLOR OP_NUMEQUAL`
    // - De Morgan's law: !(a || b) == (!a && !b)
    //     - Pass: `{stack: a, b} OP_2DUP OP_BOOLOR OP_NOT OP_ROT OP_NOT OP_ROT OP_NOT OP_BOOLAND OP_NUMEQUAL`
    // - Absorption: (a && (a || b)) == (a != false)
    //     - Pass: `{stack: a, b} OP_OVER OP_2 OP_PICK OP_ROT OP_BOOLOR OP_BOOLAND OP_SWAP OP_0 OP_NUMNOTEQUAL OP_NUMEQUAL`
    {
        auto TestCasting = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLOR << OP_ROT << OP_0 << OP_NUMNOTEQUAL << OP_ROT << OP_0
                                           << OP_NUMNOTEQUAL << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCasting failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLOR << OP_SWAP << OP_ROT << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestDeMorgan = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_BOOLOR << OP_NOT << OP_ROT << OP_NOT << OP_ROT << OP_NOT
                                           << OP_BOOLAND << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestDeMorgan failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestAbsorption = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_OVER << OP_2 << OP_PICK << OP_ROT << OP_BOOLOR << OP_BOOLAND << OP_SWAP
                                           << OP_0 << OP_NUMNOTEQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAbsorption failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestCasting,
            TestCommutativity,
            TestDeMorgan,
            TestAbsorption
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Associativity: ((a || b) || c) == (a || (b || c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_BOOLOR OP_OVER OP_BOOLOR OP_2SWAP OP_3 OP_ROLL OP_BOOLOR OP_BOOLOR OP_NUMEQUAL`
    // - Distributivity: ((a && b) || c) == ((a || c) && (b || c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_2 OP_PICK OP_BOOLAND OP_OVER OP_BOOLOR OP_3 OP_ROLL OP_2 OP_PICK OP_BOOLOR OP_2SWAP OP_BOOLOR OP_BOOLAND OP_NUMEQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_BOOLOR << OP_OVER << OP_BOOLOR << OP_2SWAP << OP_3
                                               << OP_ROLL << OP_BOOLOR << OP_BOOLOR << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        auto TestDistributivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_BOOLAND << OP_OVER << OP_BOOLOR << OP_3 << OP_ROLL
                                               << OP_2 << OP_PICK << OP_BOOLOR << OP_2SWAP << OP_BOOLOR << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestDistributivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAssociativity,
            TestDistributivity
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 700);
        }
    }
}

// OP_NUMEQUAL (0x9c)
BOOST_AUTO_TEST_CASE(op_numequal_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_NUMEQUAL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_NUMEQUAL);
    }

    // - Reflexivity: (a == a) == true
    //     - Pass: `{stack: a} OP_DUP OP_NUMEQUAL OP_1 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NUMEQUAL << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Commutativity: (a == b) == (b == a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMEQUAL OP_SWAP OP_ROT OP_NUMEQUAL OP_NUMEQUAL`
    // - Equivalence: (a == b) == !((a < b) || (a > b))
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMEQUAL OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_2SWAP OP_GREATERTHAN OP_BOOLOR OP_NOT OP_NUMEQUAL`
    {
        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMEQUAL << OP_SWAP << OP_ROT << OP_NUMEQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMEQUAL << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_LESSTHAN
                                           << OP_2SWAP << OP_GREATERTHAN << OP_BOOLOR << OP_NOT << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_NUMEQUALVERIFY (0x9d)
BOOST_AUTO_TEST_CASE(op_numequalverify_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 0, OP_NUMEQUALVERIFY);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_NUMEQUALVERIFY);
    }

    // - Reflexivity: (a == a) == true
    //     - Pass: `{stack: a} OP_DUP OP_NUMEQUAL OP_1 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NUMEQUAL << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Commutativity: (a == b) == (b == a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMEQUALVERIFY OP_1 OP_SWAP OP_ROT OP_NUMEQUALVERIFY OP_1 OP_NUMEQUAL`, where a == b
    //     - Fail: `{stack: a, b} OP_2DUP OP_NUMEQUALVERIFY OP_1 OP_SWAP OP_ROT OP_NUMEQUALVERIFY OP_1 OP_NUMEQUAL`, where a != b
    // - Equivalence: (a == b) == !((a < b) || (a > b))
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMEQUALVERIFY OP_1 OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_2SWAP OP_GREATERTHAN OP_BOOLOR OP_NOT OP_NUMEQUAL`, where a == b
    //     - Fail: `{stack: a, b} OP_2DUP OP_NUMEQUALVERIFY OP_1 OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_2SWAP OP_GREATERTHAN OP_BOOLOR OP_NOT OP_NUMEQUAL`, where a != b
    {
        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMEQUALVERIFY << OP_1 << OP_SWAP << OP_ROT << OP_NUMEQUALVERIFY
                                           << OP_1 << OP_NUMEQUAL;
                if (a == b) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::NUMEQUALVERIFY),
                                    "TestCommutativity passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMEQUALVERIFY << OP_1 << OP_2 << OP_PICK << OP_2 << OP_PICK
                                           << OP_LESSTHAN << OP_2SWAP << OP_GREATERTHAN << OP_BOOLOR << OP_NOT << OP_NUMEQUAL;
                if (a == b) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::NUMEQUALVERIFY),
                                    "TestEquivalence passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_NUMNOTEQUAL (0x9e)
BOOST_AUTO_TEST_CASE(op_numnotequal_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_NUMNOTEQUAL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_NUMNOTEQUAL);
    }

    // - Reflexivity: (a != a) == false
    //     - Pass: `{stack: a} OP_DUP OP_NUMNOTEQUAL OP_0 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_NUMNOTEQUAL << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Commutativity: (a != b) == (b != a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMNOTEQUAL OP_SWAP OP_ROT OP_NUMNOTEQUAL OP_NUMEQUAL`
    // - Equivalence: (a != b) == ((a < b) || (a > b))
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMNOTEQUAL OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_2SWAP OP_GREATERTHAN OP_BOOLOR OP_NUMEQUAL`
    {
        auto TestCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMNOTEQUAL << OP_SWAP << OP_ROT << OP_NUMNOTEQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMNOTEQUAL << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_LESSTHAN
                                           << OP_2SWAP << OP_GREATERTHAN << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }
}

// OP_LESSTHAN (0x9f)
BOOST_AUTO_TEST_CASE(op_lessthan_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_LESSTHAN);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_LESSTHAN);
    }

    // - Reflexivity: (a < a) == false
    //     - Pass: `{stack: a} OP_DUP OP_LESSTHAN OP_0 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_LESSTHAN << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Anti-commutativity: (a < b) == (-b < -a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_LESSTHAN OP_SWAP OP_NEGATE OP_ROT OP_NEGATE OP_LESSTHAN OP_NUMEQUAL`
    // - Equivalence: (a < b) == !((a == b) || (a > b))
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMNOTEQUAL OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_2SWAP OP_GREATERTHAN OP_BOOLOR OP_NUMEQUAL`
    {
        auto TestAntiCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_LESSTHAN << OP_SWAP << OP_NEGATE << OP_ROT << OP_NEGATE << OP_LESSTHAN << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAntiCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMNOTEQUAL << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_LESSTHAN << OP_2SWAP
                                           << OP_GREATERTHAN << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAntiCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Transitivity: ((a < c) && (a < b) && (b < c)) == ((a < b) && (b < c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_OVER OP_LESSTHAN OP_2OVER OP_LESSTHAN OP_BOOLAND OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_BOOLAND OP_3 OP_ROLL OP_3 OP_PICK OP_LESSTHAN OP_2SWAP OP_LESSTHAN OP_BOOLAND OP_EQUAL`
    {
        auto TestTransitivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_OVER << OP_LESSTHAN << OP_2OVER << OP_LESSTHAN << OP_BOOLAND
                                               << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_LESSTHAN << OP_BOOLAND << OP_3 << OP_ROLL
                                               << OP_3 << OP_PICK << OP_LESSTHAN << OP_2SWAP << OP_LESSTHAN << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestTransitivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestTransitivity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestTransitivity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_GREATERTHAN (0xa0)
BOOST_AUTO_TEST_CASE(op_greaterthan_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_GREATERTHAN);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_GREATERTHAN);
    }

    // - Reflexivity: (a > a) == false
    //     - Pass: `{stack: a} OP_DUP OP_GREATERTHAN OP_0 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_GREATERTHAN << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Anti-commutativity: (a > b) == (-b > -a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_GREATERTHAN OP_SWAP OP_NEGATE OP_ROT OP_NEGATE OP_GREATERTHAN OP_NUMEQUAL`
    // - Equivalence: (a > b) == !((a == b) || (a < b))
    //     - Pass: `{stack: a, b} OP_2DUP OP_NUMNOTEQUAL OP_2 OP_PICK OP_2 OP_PICK OP_GREATERTHAN OP_2SWAP OP_LESSTHAN OP_BOOLOR OP_NUMEQUAL`
    {
        auto TestAntiCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_GREATERTHAN << OP_SWAP << OP_NEGATE << OP_ROT << OP_NEGATE << OP_GREATERTHAN << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAntiCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_NUMNOTEQUAL << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_GREATERTHAN << OP_2SWAP
                                           << OP_LESSTHAN << OP_BOOLOR << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAntiCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Transitivity: ((a > c) && (a > b) && (b > c)) == ((a > b) && (b > c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_OVER OP_LESSTHAN OP_2OVER OP_LESSTHAN OP_BOOLAND OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHAN OP_BOOLAND OP_3 OP_ROLL OP_3 OP_PICK OP_LESSTHAN OP_2SWAP OP_LESSTHAN OP_BOOLAND OP_EQUAL`
    {
        auto TestTransitivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_OVER << OP_GREATERTHAN << OP_2OVER << OP_GREATERTHAN << OP_BOOLAND
                                               << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_GREATERTHAN << OP_BOOLAND << OP_3 << OP_ROLL
                                               << OP_3 << OP_PICK << OP_GREATERTHAN << OP_2SWAP << OP_GREATERTHAN << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestTransitivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestTransitivity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestTransitivity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_LESSTHANOREQUAL (0xa1)
BOOST_AUTO_TEST_CASE(op_lessthanorequal_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_LESSTHANOREQUAL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_LESSTHANOREQUAL);
    }

    // - Reflexivity: (a <= a) == false
    //     - Pass: `{stack: a} OP_DUP OP_LESSTHANOREQUAL OP_1 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_LESSTHANOREQUAL << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Anti-commutativity: (a <= b) == (-b <= -a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_LESSTHANOREQUAL OP_SWAP OP_NEGATE OP_ROT OP_NEGATE OP_LESSTHANOREQUAL OP_NUMEQUAL`
    // - Equivalence: (a <= b) == !(a > b)
    //     - Pass: `{stack: a, b} OP_2DUP OP_LESSTHANOREQUAL OP_ROT OP_ROT OP_GREATERTHAN OP_NOT OP_NUMEQUAL`
    {
        auto TestAntiCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_LESSTHANOREQUAL << OP_SWAP << OP_NEGATE << OP_ROT << OP_NEGATE << OP_LESSTHANOREQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAntiCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_LESSTHANOREQUAL << OP_ROT << OP_ROT << OP_GREATERTHAN << OP_NOT << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAntiCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Transitivity: ((a <= c) && (a <= b) && (b <= c)) == ((a <= b) && (b <= c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_OVER OP_LESSTHANOREQUAL OP_2OVER OP_LESSTHANOREQUAL OP_BOOLAND OP_2 OP_PICK OP_2 OP_PICK OP_LESSTHANOREQUAL OP_BOOLAND OP_3 OP_ROLL OP_3 OP_PICK OP_LESSTHANOREQUAL OP_2SWAP OP_LESSTHANOREQUAL OP_BOOLAND OP_EQUAL`
    {
        auto TestTransitivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_OVER << OP_LESSTHANOREQUAL << OP_2OVER << OP_LESSTHANOREQUAL << OP_BOOLAND
                                               << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_LESSTHANOREQUAL << OP_BOOLAND << OP_3 << OP_ROLL
                                               << OP_3 << OP_PICK << OP_LESSTHANOREQUAL << OP_2SWAP << OP_LESSTHANOREQUAL << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestTransitivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestTransitivity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestTransitivity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_GREATERTHANOREQUAL (0xa2)
BOOST_AUTO_TEST_CASE(op_greaterthanorequal_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_GREATERTHANOREQUAL);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_GREATERTHANOREQUAL);
    }

    // - Reflexivity: (a >= a) == true
    //     - Pass: `{stack: a} OP_DUP OP_GREATERTHANOREQUAL OP_1 OP_NUMEQUAL`
    {
        auto TestReflexivity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_GREATERTHANOREQUAL << OP_1 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestReflexivity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestReflexivity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Anti-commutativity: (a >= b) == (-b >= -a)
    //     - Pass: `{stack: a, b} OP_2DUP OP_GREATERTHANOREQUAL OP_SWAP OP_NEGATE OP_ROT OP_NEGATE OP_GREATERTHANOREQUAL OP_NUMEQUAL`
    // - Equivalence: (a >= b) == !(a < b)
    //     - Pass: `{stack: a, b} OP_2DUP OP_GREATERTHANOREQUAL OP_ROT OP_ROT OP_LESSTHAN OP_NOT OP_NUMEQUAL`
    {
        auto TestAntiCommutativity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_GREATERTHANOREQUAL << OP_SWAP << OP_NEGATE << OP_ROT << OP_NEGATE
                                           << OP_GREATERTHANOREQUAL << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestAntiCommutativity failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_GREATERTHANOREQUAL << OP_ROT << OP_ROT << OP_LESSTHAN << OP_NOT << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        std::vector<TestFuncUnary> testFunctionsI = {
            TestAntiCommutativity,
            TestEquivalence,
        };
        for (const auto& testFunc : testFunctionsI) {
            TestRange(testFunc, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(testFunc, 0, MAX_SCRIPTNUM, false, 100);
        }
    }

    // - Transitivity: ((a >= c) && (a >= b) && (b >= c)) == ((a >= b) && (b >= c))
    //     - Pass: `{stack: a, b, c} OP_2 OP_PICK OP_OVER OP_GREATERTHANOREQUAL OP_2OVER OP_GREATERTHANOREQUAL OP_BOOLAND OP_2 OP_PICK OP_2 OP_PICK OP_GREATERTHANOREQUAL OP_BOOLAND OP_3 OP_ROLL OP_3 OP_PICK OP_GREATERTHANOREQUAL OP_2SWAP OP_GREATERTHANOREQUAL OP_BOOLAND OP_EQUAL`
    {
        auto TestTransitivity = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_2 << OP_PICK << OP_OVER << OP_GREATERTHANOREQUAL << OP_2OVER << OP_GREATERTHANOREQUAL << OP_BOOLAND
                                               << OP_2 << OP_PICK << OP_2 << OP_PICK << OP_GREATERTHANOREQUAL << OP_BOOLAND << OP_3 << OP_ROLL << OP_3
                                               << OP_PICK << OP_GREATERTHANOREQUAL << OP_2SWAP << OP_GREATERTHANOREQUAL << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestTransitivity failed (expected to pass) for a = "
                                        << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };
                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestTransitivity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestTransitivity, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_MIN (0xa3)
BOOST_AUTO_TEST_CASE(op_min_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_MIN);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_MIN);
    }

    // - Identity: min(a, a) == a
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_MIN OP_NUMEQUAL`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_MIN << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdentity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestIdentity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdentity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Order: (min(a, b) <= a && min(a, b) <= b) == true
    //     - Pass: `{stack: a, b} OP_2DUP OP_MIN OP_2 OP_PICK OP_LESSTHANOREQUAL OP_ROT OP_2 OP_PICK OP_MIN OP_ROT OP_LESSTHANOREQUAL OP_BOOLAND OP_1 OP_NUMEQUAL`
    {
        auto TestOrder = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_MIN << OP_2 << OP_PICK << OP_LESSTHANOREQUAL << OP_ROT << OP_2 << OP_PICK
                                           << OP_MIN << OP_ROT << OP_LESSTHANOREQUAL << OP_BOOLAND << OP_1 << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestOrder failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestOrder, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestOrder, 1, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_MAX (0xa4)
BOOST_AUTO_TEST_CASE(op_max_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_MAX);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_MAX);
    }

    // - Identity: max(a, a) == a
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_MAX OP_NUMEQUAL`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_MAX << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestIdentity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestIdentity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdentity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Order: (max(a, b) >= a && max(a, b) >= b) == true
    //     - Pass: `{stack: a, b} OP_2DUP OP_MAX OP_2 OP_PICK OP_GREATERTHANOREQUAL OP_ROT OP_2 OP_PICK OP_MAX OP_ROT OP_GREATERTHANOREQUAL OP_BOOLAND OP_1 OP_NUMEQUAL`
    {
        auto TestOrder = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_2DUP << OP_MAX << OP_2 << OP_PICK << OP_GREATERTHANOREQUAL << OP_ROT << OP_2 << OP_PICK
                                           << OP_MAX << OP_ROT << OP_GREATERTHANOREQUAL << OP_BOOLAND << OP_1 << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestOrder failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestOrder, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestOrder, 1, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_WITHIN (0xa4)
BOOST_AUTO_TEST_CASE(op_within_tests) {
    // Stack Depth Tests
    {
        TestStack(2, 1, OP_WITHIN);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingTernary(OP_WITHIN);
    }

    // - Reflexivity: within(a, a, a) == false
    //     - Pass: `{stack: a} OP_DUP OP_DUP OP_WITHIN OP_0 OP_NUMEQUAL`
    {
        auto TestIdentity = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_DUP << OP_WITHIN << OP_0 << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestReflexivity failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestIdentity, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestIdentity, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Equivalence: within(a, b, c) == (a >= b && a < c)
    //     - Pass: `{stack: a, b, c} OP_3DUP OP_WITHIN OP_3 OP_PICK OP_3 OP_ROLL OP_GREATERTHANOREQUAL OP_2SWAP OP_LESSTHAN OP_BOOLAND OP_NUMEQUAL`
    {
        auto TestEquivalence = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                auto WithC = [&](const BigInt &c) {
                    StackT stack = {a.serialize(), b.serialize(), c.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_WITHIN << OP_3 << OP_PICK << OP_3 << OP_ROLL << OP_GREATERTHANOREQUAL
                                               << OP_2SWAP << OP_LESSTHAN << OP_BOOLAND << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestEquivalence failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString() << ", c = " << c.ToString());
                };

                TestRange(WithC, 1, MAX_SCRIPTNUM, true, 700);
                TestRange(WithC, 0, MAX_SCRIPTNUM, false, 700);
            };

            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 700);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestEquivalence, 0, MAX_SCRIPTNUM, true, 700);
        TestRange(TestEquivalence, 1, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_INVERT (0x83)
BOOST_AUTO_TEST_CASE(op_invert_tests) {
    // Stack Depth Tests
    {
        TestStack(0, 1, OP_INVERT);
    }

    // - Implementation using only xor: `~a = a ^ ~(binary_string_of_1s_equal_to_byte_length_of_a)`
    //   - Pass: `{stack: binary_string_of_1s, a} OP_DUP OP_INVERT OP_SWAP OP_2 OP_ROLL OP_XOR OP_EQUAL
    {
        auto TestXOR = [](const BigInt &a) {
            auto aser = a.serialize();
            const size_t nBytes = aser.size();
            std::vector<uint8_t> invertedData(nBytes, ~uint8_t{0u});
            StackT stack = {std::move(invertedData), std::move(aser)};
            CScript script = CScript() << OP_DUP << OP_INVERT << OP_SWAP << OP_2 << OP_ROLL << OP_XOR << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestXOR failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestXOR, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestXOR, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Implementation using shift, invert, and xor: `~a = a ^ ~(a << sizeof(a) * 8)`
    //   - Pass: `{stack: a} OP_DUP OP_INVERT OP_SWAP OP_DUP OP_SIZE OP_8 OP_MUL OP_LSHIFTBIN OP_INVERT OP_XOR OP_EQUAL`
    {
        auto TestShiftInvertXOR = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_INVERT << OP_SWAP << OP_DUP << OP_SIZE << OP_8 << OP_MUL << OP_LSHIFTBIN << OP_INVERT << OP_XOR << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestShiftInvertXOR failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestShiftInvertXOR, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestShiftInvertXOR, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Double inversion: `invert(invert(a)) == a`
    //   - Pass: `{stack: a} OP_DUP OP_INVERT OP_INVERT OP_EQUAL`
    {
        auto TestDoubleInversion = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_INVERT << OP_INVERT << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestDoubleInversion failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestDoubleInversion, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestDoubleInversion, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Byte-wise independence:
    //   - Pass: `{stack: n, a} OP_DUP OP_ROT OP_SPLIT OP_INVERT OP_SWAP OP_INVERT OP_SWAP OP_CAT OP_SWAP OP_INVERT OP_EQUAL`
    {
        auto TestByteWiseIndependence = [](const BigInt &a) {
            auto aser = a.serialize();
            auto WithN = [&](const BigInt &n) { 
                StackT stack = {n.serialize(), aser};
                CScript script = CScript() << OP_DUP << OP_ROT << OP_SPLIT << OP_INVERT << OP_SWAP << OP_INVERT << OP_SWAP << OP_CAT << OP_SWAP << OP_INVERT << OP_EQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestByteWiseIndependence failed (expected to pass)" << " for a = " << a.ToString() << ", n = " << n.ToString());
            };

            TestRange(WithN, 0, aser.size(), 700);
        };

        TestRange(TestByteWiseIndependence, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestByteWiseIndependence, 1, MAX_SCRIPTNUM, false, 100);
    }
}

// OP_LSHIFTNUM (0x8d)
BOOST_AUTO_TEST_CASE(op_lshiftnum_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_LSHIFTNUM);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_LSHIFTNUM, false, true, MAX_SCRIPTNUM, MAX_SCRIPTNUM);
    }

    // - Zero shift: `a << 0 == a`
    //   - Pass: `{stack: a} OP_DUP OP_0 OP_LSHIFTNUM OP_NUMEQUAL`
    {
        auto TestZeroShift = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_LSHIFTNUM << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZeroShift failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestZeroShift, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestZeroShift, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Shift by 1: `a << 1 == a * 2`
    //   - Pass: `{stack: a} OP_DUP OP_1 OP_LSHIFTNUM OP_SWAP OP_2 OP_MUL OP_NUMEQUAL`
    {
        auto TestShiftByOne = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1 << OP_LSHIFTNUM << OP_SWAP << OP_2 << OP_MUL << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestShiftByOne failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestShiftByOne, 0, MAX_SCRIPTNUM / 2, true, 100);
        TestRange(TestShiftByOne, 1, MAX_SCRIPTNUM / 2, false, 100);
    }

    // - Chain shift: `(a << m) << n == a << (m + n)`
    //     - Pass: `{stack: a, m, n} OP_3DUP OP_ADD OP_LSHIFTNUM OP_TOALTSTACK OP_TOALTSTACK OP_LSHIFTNUM OP_FROMALTSTACK OP_LSHIFTNUM OP_FROMALTSTACK OP_NUMEQUAL`
    {
        auto TestChainShift = [](const BigInt &a) {
            auto WithM = [&](const BigInt &m) {
                auto WithN = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), m.serialize(), n.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_ADD << OP_LSHIFTNUM << OP_TOALTSTACK << OP_TOALTSTACK
                                               << OP_LSHIFTNUM << OP_FROMALTSTACK << OP_LSHIFTNUM << OP_FROMALTSTACK << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestChainShift failed (expected to pass) for a = "
                                        << a.ToString() << ", m = " << m.ToString() << ", n = " << n.ToString());
                };
                TestRange(WithN, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1 - *m.getUInt(), 700);
            };
            TestRange(WithM, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1, 700);
        };

        TestRange(TestChainShift, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestChainShift, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Range & overflow:
    //     - Pass: `{stack: a, b} OP_LSHIFTNUM OP_DROP OP_1`, where b >= 0 and
    //          - If a = 0 then pass for any b
    //          - If a != 0 then pass only if a << b < MAX_SCRIPTNUM
    //     - Fail: `{stack: a, b} OP_LSHIFTNUM OP_DROP OP_1`, with
    //          - `ScriptError::INVALID_BIT_SHIFT` if a < 0
    //          - `ScriptError::INVALID_NUMBER_RANGE_BIG_INT` if result would overflow
    {
        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_LSHIFTNUM << OP_DROP << OP_1;
                if (b < 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_BIT_SHIFT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                    return;
                }
                if (a == 0 || (b <= MAX_ELEM_SIZE * 8 - 1 && a.absValNumBits() + *b.getUInt() < MAX_ELEM_SIZE * 8)) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_NUMBER_RANGE_BIG_INT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestValidRange, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestValidRange, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_RSHIFTNUM (0x8e)
BOOST_AUTO_TEST_CASE(op_rshiftnum_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_RSHIFTNUM);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_RSHIFTNUM, false, true, MAX_SCRIPTNUM, MAX_SCRIPTNUM);
    }

    // - Zero shift: `a >> 0 == a`
    //   - Pass: `{stack: a} OP_DUP OP_0 OP_RSHIFTNUM OP_NUMEQUAL`
    {
        auto TestZeroShift = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_RSHIFTNUM << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZeroShift failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestZeroShift, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestZeroShift, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Shift by 1: `a >> 1 == a / 2` for a >= 0 and `a >> 1 == a / 2 + a % 2` for a < 0
    //   - Pass: `{stack: a} OP_DUP OP_1 OP_RSHIFTNUM OP_SWAP OP_2 OP_OVER OP_0 OP_LESSTHAN OP_IF OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_ADD OP_ELSE OP_DIV OP_ENDIF OP_NUMEQUAL`
    {
        auto TestShiftByOne = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_1 << OP_RSHIFTNUM << OP_SWAP << OP_2 << OP_OVER << OP_0 << OP_LESSTHAN
                                       << OP_IF << OP_2DUP << OP_DIV << OP_ROT << OP_ROT << OP_MOD << OP_ADD << OP_ELSE << OP_DIV << OP_ENDIF << OP_NUMEQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestShiftByOne failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestShiftByOne, 0, MAX_SCRIPTNUM / 2, true, 100);
        TestRange(TestShiftByOne, 1, MAX_SCRIPTNUM / 2, false, 100);
    }

    // - Chain Shift: `(a >> m) >> n == a >> (m + n)`
    //     - Pass: `{stack: a, m, n} OP_3DUP OP_ADD OP_RSHIFTNUM OP_TOALTSTACK OP_TOALTSTACK OP_RSHIFTNUM OP_FROMALTSTACK OP_RSHIFTNUM OP_FROMALTSTACK OP_NUMEQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithM = [&](const BigInt &m) {
                auto WithN = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), m.serialize(), n.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_ADD << OP_RSHIFTNUM << OP_TOALTSTACK << OP_TOALTSTACK
                                               << OP_RSHIFTNUM << OP_FROMALTSTACK << OP_RSHIFTNUM << OP_FROMALTSTACK << OP_NUMEQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", m = " << m.ToString() << ", n = " << n.ToString());
                };
                TestRange(WithN, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1 - *m.getUInt(), 700);
            };
            TestRange(WithM, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1, 700);
        };

        TestRange(TestAssociativity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestAssociativity, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Range:
    //     - Pass: `{stack: a, b} OP_RSHIFTNUM OP_DROP OP_1`, where b >= 0
    //     - Fail: `{stack: a, b} OP_RSHIFTNUM OP_DROP OP_1`, where b < 0 with `ScriptError::INVALID_BIT_SHIFT`
    {
        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_RSHIFTNUM << OP_DROP << OP_1;
                if (b < 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_BIT_SHIFT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestValidRange, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestValidRange, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_LSHIFTBIN (0x98)
BOOST_AUTO_TEST_CASE(op_lshiftbin_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_LSHIFTBIN);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_LSHIFTBIN, false, true, MAX_SCRIPTNUM, MAX_SCRIPTNUM, 0b01);
    }

    // - Zero shift: `a << 0 == a`
    //   - Pass: `{stack: a} OP_DUP OP_0 OP_LSHIFTBIN OP_EQUAL`
    {
        auto TestZeroShift = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_LSHIFTBIN << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZeroShift failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestZeroShift, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestZeroShift, 1, MAX_SCRIPTNUM, false, 100);
    }

    // - Length preservation: `size(a) == size(a >> n)`
    //     - Pass: `{stack: a, n} OP_SWAP OP_SIZE OP_SWAP OP_ROT OP_LSHIFTBIN OP_SIZE OP_NIP OP_NUMEQUAL`
    {
        auto TestLengthPreservation = [](const BigInt &a) {
            auto WithN = [&](const BigInt &n) {
                StackT stack = {a.serialize(), n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_SWAP << OP_ROT << OP_LSHIFTBIN << OP_SIZE << OP_NIP << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestLengthPreservation failed (expected to pass) for a = "
                                    << a.ToString() << ", n = " << n.ToString());
            };
            TestRange(WithN, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestLengthPreservation, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestLengthPreservation, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Left then right: `(a << n) >> n == a & (~0 >> n)`
    //     - Pass: `{stack: a, n} OP_2DUP OP_DUP OP_ROT OP_SWAP OP_LSHIFTBIN OP_SWAP OP_RSHIFTBIN OP_ROT OP_ROT OP_SWAP OP_SIZE OP_0 OP_SWAP OP_NUM2BIN OP_INVERT OP_ROT OP_RSHIFTBIN OP_AND OP_EQUAL`
    {
        auto TestLeftThenRight = [](const BigInt &a) {
            auto WithN = [&](const BigInt &n) {
                StackT stack = {a.serialize(), n.serialize()};
                CScript script = CScript() << OP_2DUP << OP_DUP << OP_ROT << OP_SWAP << OP_LSHIFTBIN << OP_SWAP
                                           << OP_RSHIFTBIN << OP_ROT << OP_ROT << OP_SWAP << OP_SIZE << OP_0 << OP_SWAP
                                           << OP_NUM2BIN << OP_INVERT << OP_ROT << OP_RSHIFTBIN << OP_AND << OP_EQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "LeftThenRight failed (expected to pass) for a = "
                                    << a.ToString() << ", n = " << n.ToString());
            };
            TestRange(WithN, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestLeftThenRight, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestLeftThenRight, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Chain shift: `(a << m) << n == a << (m + n)`
    //     - Pass: `{stack: a, m, n} OP_3DUP OP_ADD OP_LSHIFTBIN OP_TOALTSTACK OP_TOALTSTACK OP_LSHIFTBIN OP_FROMALTSTACK OP_LSHIFTBIN OP_FROMALTSTACK OP_EQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithM = [&](const BigInt &m) {
                auto WithN = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), m.serialize(), n.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_ADD << OP_LSHIFTBIN << OP_TOALTSTACK << OP_TOALTSTACK
                                               << OP_LSHIFTBIN << OP_FROMALTSTACK << OP_LSHIFTBIN << OP_FROMALTSTACK << OP_EQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", m = " << m.ToString() << ", n = " << n.ToString());
                };
                TestRange(WithN, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1 - *m.getUInt(), 700);
            };
            TestRange(WithM, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1, 700);
        };

        TestRange(TestAssociativity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestAssociativity, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Range:
    //     - Pass: `{stack: a, b} OP_LSHIFTBIN OP_DROP OP_1`, where b >= 0
    //     - Fail: `{stack: a, b} OP_LSHIFTBIN OP_DROP OP_1`, where b < 0 with `ScriptError::INVALID_BIT_SHIFT`
    {
        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_LSHIFTBIN << OP_DROP << OP_1;
                if (b < 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_BIT_SHIFT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestValidRange, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestValidRange, 0, MAX_SCRIPTNUM, false, 700);
    }
}

// OP_RSHIFTBIN (0x99)
BOOST_AUTO_TEST_CASE(op_rshiftbin_tests) {
    // Stack Depth Tests
    {
        TestStack(1, 1, OP_RSHIFTBIN);
    }

    // - Zero shift: `a >> 0 == a`
    //   - Pass: `{stack: a} OP_DUP OP_0 OP_RSHIFTBIN OP_EQUAL`
    {
        auto TestZeroShift = [](const BigInt &a) {
            StackT stack = {a.serialize()};
            CScript script = CScript() << OP_DUP << OP_0 << OP_RSHIFTBIN << OP_EQUAL;
            CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK), "TestZeroShift failed (expected to pass)" << " for a = " << a.ToString());
        };

        TestRange(TestZeroShift, 0, MAX_SCRIPTNUM, true, 100);
        TestRange(TestZeroShift, 1, MAX_SCRIPTNUM, false, 100);
    }

    // Minimally-encoded Operand Tests
    {
        TestMinimalEncodingBinary(OP_RSHIFTBIN, false, true, MAX_SCRIPTNUM, MAX_SCRIPTNUM, 0b01);
    }

    // - Length preservation: `size(a) == size(a >> n)`
    //     - Pass: `{stack: a, n} OP_SWAP OP_SIZE OP_SWAP OP_ROT OP_RSHIFTBIN OP_SIZE OP_NIP OP_NUMEQUAL`
    {
        auto TestLengthPreservation = [](const BigInt &a) {
            auto WithN = [&](const BigInt &n) {
                StackT stack = {a.serialize(), n.serialize()};
                CScript script = CScript() << OP_SWAP << OP_SIZE << OP_SWAP << OP_ROT << OP_RSHIFTBIN << OP_SIZE << OP_NIP << OP_NUMEQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "TestLengthPreservation failed (expected to pass) for a = "
                                    << a.ToString() << ", n = " << n.ToString());
            };
            TestRange(WithN, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestLengthPreservation, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestLengthPreservation, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Right then left: `(a >> n) << n == a & (~0 << n)`
    //     - Pass: `{stack: a, n} OP_2DUP OP_DUP OP_ROT OP_SWAP OP_RSHIFTBIN OP_SWAP OP_LSHIFTBIN OP_ROT OP_ROT OP_SWAP OP_SIZE OP_0 OP_SWAP OP_NUM2BIN OP_INVERT OP_ROT OP_LSHIFTBIN OP_AND OP_EQUAL`
    {
        auto TestRightThenLeft = [](const BigInt &a) {
            auto WithN = [&](const BigInt &n) {
                StackT stack = {a.serialize(), n.serialize()};
                CScript script = CScript() << OP_2DUP << OP_DUP << OP_ROT << OP_SWAP << OP_RSHIFTBIN << OP_SWAP
                                           << OP_LSHIFTBIN << OP_ROT << OP_ROT << OP_SWAP << OP_SIZE << OP_0 << OP_SWAP
                                           << OP_NUM2BIN << OP_INVERT << OP_ROT << OP_LSHIFTBIN << OP_AND << OP_EQUAL;
                CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                "RightThenLeft failed (expected to pass) for a = "
                                    << a.ToString() << ", n = " << n.ToString());
            };
            TestRange(WithN, 0, MAX_SCRIPTNUM, false, 700);
        };

        TestRange(TestRightThenLeft, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestRightThenLeft, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Chain shift: `(a >> m) >> n == a >> (m + n)`
    //     - Pass: `{stack: a, m, n} OP_3DUP OP_ADD OP_RSHIFTBIN OP_TOALTSTACK OP_TOALTSTACK OP_RSHIFTBIN OP_FROMALTSTACK OP_RSHIFTBIN OP_FROMALTSTACK OP_EQUAL`
    {
        auto TestAssociativity = [](const BigInt &a) {
            auto WithM = [&](const BigInt &m) {
                auto WithN = [&](const BigInt &n) {
                    StackT stack = {a.serialize(), m.serialize(), n.serialize()};
                    CScript script = CScript() << OP_3DUP << OP_ADD << OP_RSHIFTBIN << OP_TOALTSTACK << OP_TOALTSTACK
                                               << OP_RSHIFTBIN << OP_FROMALTSTACK << OP_RSHIFTBIN << OP_FROMALTSTACK << OP_EQUAL;
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestAssociativity failed (expected to pass) for a = "
                                        << a.ToString() << ", m = " << m.ToString() << ", n = " << n.ToString());
                };
                TestRange(WithN, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1 - *m.getUInt(), 700);
            };
            TestRange(WithM, 0, MAX_ELEM_SIZE * 8 - a.absValNumBits() - 1, 700);
        };

        TestRange(TestAssociativity, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestAssociativity, 0, MAX_SCRIPTNUM, false, 700);
    }

    // - Range:
    //     - Pass: `{stack: a, b} OP_RSHIFTBIN OP_DROP OP_1`, where b >= 0
    //     - Fail: `{stack: a, b} OP_RSHIFTBIN OP_DROP OP_1`, where b < 0 with `ScriptError::INVALID_BIT_SHIFT`
    {
        auto TestValidRange = [](const BigInt &a) {
            auto WithB = [&](const BigInt &b) {
                StackT stack = {a.serialize(), b.serialize()};
                CScript script = CScript() << OP_RSHIFTBIN << OP_DROP << OP_1;
                if (b < 0) {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::INVALID_BIT_SHIFT),
                                    "TestValidRange passed (expected to fail) for a = " << a.ToString() << ", b = " << b.ToString());
                } else {
                    CHECK_MESSAGE(TestScript(script, stack, ScriptError::OK),
                                    "TestValidRange failed (expected to pass) for a = " << a.ToString() << ", b = " << b.ToString());
                }
            };
            TestRange(WithB, 1, MAX_SCRIPTNUM, true, 100);
            TestRange(WithB, 0, MAX_SCRIPTNUM, false, 100);
        };

        TestRange(TestValidRange, 1, MAX_SCRIPTNUM, true, 700);
        TestRange(TestValidRange, 0, MAX_SCRIPTNUM, false, 700);
    }
}

BOOST_AUTO_TEST_SUITE_END()
