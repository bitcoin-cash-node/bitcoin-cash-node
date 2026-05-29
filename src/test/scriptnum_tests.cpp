// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2021-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if HAVE_CONFIG_H
#include <config/bitcoin-config.h>
#endif

#include <random.h>
#include <script/script.h>

#include <test/scriptnum10.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <type_traits>

BOOST_FIXTURE_TEST_SUITE(scriptnum_tests, BasicTestingSetup)

static constexpr int64_t int64_t_min = std::numeric_limits<int64_t>::min();
static constexpr int64_t int64_t_max = std::numeric_limits<int64_t>::max();
static constexpr int64_t int64_t_min_8_bytes = int64_t_min + 1;

static const int64_t values[] = {0,
                                 1,
                                 -1,
                                 -2,
                                 127,
                                 128,
                                 -255,
                                 256,
                                 (1LL << 15) - 1,
                                 -(1LL << 16),
                                 (1LL << 24) - 1,
                                 (1LL << 31),
                                 1 - (1LL << 32),
                                 1LL << 40,
                                 int64_t_min_8_bytes,
                                 int64_t_min,
                                 int64_t_max,
                                 int64_t_max - 1};

static const int64_t offsets[] = {1, 0x79, 0x80, 0x81, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x10000};

template <typename ScriptNumType>
std::enable_if_t<std::is_same_v<ScriptNumType, CScriptNum>
                     || std::is_same_v<ScriptNumType, ScriptBigInt>
                     || std::is_same_v<ScriptNumType, FastBigNum>, bool>
/* bool */ verify(const CScriptNum10 &bignum, const ScriptNumType &scriptnum) {
    return bignum.getvch() == scriptnum.getvch() && bignum.getint() == scriptnum.getint32();
}

static
void CheckCreateVchOldRules(int64_t x) {
    size_t const maxIntegerSize = 4; // Legacy 32-bit ints (no longer used in consensus)

    CScriptNum10 bigx(x);
    auto const scriptx = CScriptNum::fromIntUnchecked(x);
    BOOST_CHECK(verify(bigx, scriptx));
    auto const scriptx2 = ScriptBigInt::fromIntUnchecked(x);
    BOOST_CHECK(verify(bigx, scriptx2));
    auto const scriptx2_fbn = FastBigNum::fromIntUnchecked(x);
    BOOST_CHECK(verify(bigx, scriptx2_fbn));

    CScriptNum10 bigb(bigx.getvch(), false);
    CScriptNum scriptb(scriptx.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb));
    ScriptBigInt scriptb2(scriptx2.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb2));
    FastBigNum scriptb2_fbn(scriptx2_fbn.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb2_fbn));

    CScriptNum10 bigx3(scriptb.getvch(), false);
    CScriptNum scriptx3(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3));
    ScriptBigInt scriptx3_2(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3_2));
    FastBigNum scriptx3_2_fbn(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3_2_fbn));
}

static
void CheckCreateVchNewRules(int64_t x) {
    size_t const maxIntegerSize = CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT;

    auto res = CScriptNum::fromInt(x);
    auto res2 = ScriptBigInt::fromInt(x);
    BOOST_REQUIRE(res2);// Creation for BigInt based script num should work for all possible int64's
    if ( ! res) {
        BOOST_CHECK(x == int64_t_min);
        return;
    }
    auto const scriptx = *res;
    auto const scriptx2 = *res2;
    auto const scriptx_fbn = FastBigNum::fromIntUnchecked(x);

    CScriptNum10 bigx(x);
    BOOST_CHECK(verify(bigx, scriptx));
    BOOST_CHECK(verify(bigx, scriptx2));
    BOOST_CHECK(verify(bigx, scriptx_fbn));

    CScriptNum10 bigb(bigx.getvch(), false, maxIntegerSize);
    CScriptNum scriptb(scriptx.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb));
    ScriptBigInt scriptb2(scriptx2.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb2));
    FastBigNum scriptb_fbn(scriptx_fbn.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigb, scriptb_fbn));

    CScriptNum10 bigx3(scriptb.getvch(), false, maxIntegerSize);
    CScriptNum scriptx3(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3));
    ScriptBigInt scriptx3_2(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3_2));
    FastBigNum scriptx3_2_fbn(bigb.getvch(), false, maxIntegerSize);
    BOOST_CHECK(verify(bigx3, scriptx3_2_fbn));
}

static
void CheckCreateIntOldRules(int64_t x) {
    auto const scriptx = CScriptNum::fromIntUnchecked(x);
    CScriptNum10 const bigx(x);
    auto const scriptx2 = ScriptBigInt ::fromIntUnchecked(x);
    auto const scriptx2_fbn = FastBigNum ::fromIntUnchecked(x);
    BOOST_CHECK(verify(bigx, scriptx));
    BOOST_CHECK(verify(bigx, scriptx2));
    BOOST_CHECK(verify(bigx, scriptx2_fbn));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), CScriptNum::fromIntUnchecked(scriptx.getint32())));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), ScriptBigInt::fromIntUnchecked(scriptx2.getint32())));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), FastBigNum::fromIntUnchecked(scriptx2_fbn.getint32())));
    BOOST_CHECK(verify(CScriptNum10(scriptx.getint32()), CScriptNum::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(scriptx2.getint32()), ScriptBigInt::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(scriptx2_fbn.getint32()), FastBigNum::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx.getint32()).getint()),
                       CScriptNum::fromIntUnchecked(CScriptNum::fromIntUnchecked(bigx.getint()).getint32())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx.getint32()).getint()),
                       ScriptBigInt::fromIntUnchecked(ScriptBigInt::fromIntUnchecked(bigx.getint()).getint32())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx.getint32()).getint()),
                       FastBigNum::fromIntUnchecked(FastBigNum::fromIntUnchecked(bigx.getint()).getint32())));
}

static
void CheckCreateIntNewRules(int64_t x) {
    auto res = CScriptNum::fromInt(x);
    auto res2 = ScriptBigInt::fromInt(x);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(x == int64_t_min);
        return;
    }
    auto const scriptx = *res;
    auto const scriptx2 = *res2;
    auto const scriptx2_fbn = FastBigNum::fromIntUnchecked(x);

    CScriptNum10 const bigx(x);
    BOOST_CHECK(verify(bigx, scriptx));
    BOOST_CHECK(verify(bigx, scriptx2));
    BOOST_CHECK(verify(bigx, scriptx2_fbn));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), CScriptNum::fromIntUnchecked(scriptx.getint32())));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), ScriptBigInt::fromIntUnchecked(scriptx2.getint32())));
    BOOST_CHECK(verify(CScriptNum10(bigx.getint()), FastBigNum::fromIntUnchecked(scriptx2_fbn.getint32())));
    BOOST_CHECK(verify(CScriptNum10(scriptx.getint32()), CScriptNum::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(scriptx2.getint32()), ScriptBigInt::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(scriptx2.getint32()), FastBigNum::fromIntUnchecked(bigx.getint())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx.getint32()).getint()),
                       CScriptNum::fromIntUnchecked(CScriptNum::fromIntUnchecked(bigx.getint()).getint32())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx2.getint32()).getint()),
                       ScriptBigInt::fromIntUnchecked(ScriptBigInt::fromIntUnchecked(bigx.getint()).getint32())));
    BOOST_CHECK(verify(CScriptNum10(CScriptNum10(scriptx2_fbn.getint32()).getint()),
                       FastBigNum::fromIntUnchecked(FastBigNum::fromIntUnchecked(bigx.getint()).getint32())));
}

static
void CheckAddOldRules(int64_t a, int64_t b) {
    if (a == int64_t_min || b == int64_t_min) {
        return;
    }

    CScriptNum10 const biga(a);
    CScriptNum10 const bigb(b);
    auto const scripta = CScriptNum::fromIntUnchecked(a);
    auto const scriptb = CScriptNum::fromIntUnchecked(b);
    auto const scripta2 = ScriptBigInt::fromIntUnchecked(a);
    auto const scriptb2 = ScriptBigInt::fromIntUnchecked(b);
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    // int64_t overflow is undefined.
    bool overflowing = (b > 0 && a > int64_t_max - b) ||
                       (b < 0 && a < int64_t_min_8_bytes - b);

    if ( ! overflowing) {
        auto res = scripta.safeAdd(scriptb);
        auto res2 = scripta2.safeAdd(scriptb2);
        auto a_fbn = scripta_fbn, b_fbn = scriptb_fbn; // copy
        BOOST_CHECK(a_fbn.safeAddInPlace(b_fbn));
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga + bigb, *res));
        BOOST_CHECK(verify(biga + bigb, *res2));
        BOOST_CHECK(verify(biga + bigb, a_fbn));
        if (b == 1 || b == -1) {
            // test safeIncr() / safeDecr()
            a_fbn = scripta_fbn; // restore
            BOOST_CHECK(b == 1 ? a_fbn.safeIncr() : a_fbn.safeDecr());
            BOOST_CHECK(verify(biga + bigb, a_fbn));
        }
        res = scripta.safeAdd(b);
        res2 = scripta2.safeAdd(b);
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga + bigb, *res));
        BOOST_CHECK(verify(biga + bigb, *res2));
        a_fbn = scripta_fbn; // restore
        res = scriptb.safeAdd(scripta);
        res2 = scriptb2.safeAdd(scripta2);
        BOOST_CHECK(b_fbn.safeAddInPlace(a_fbn));
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga + bigb, *res));
        BOOST_CHECK(verify(biga + bigb, *res2));
        BOOST_CHECK(verify(biga + bigb, b_fbn));
        res = scriptb.safeAdd(a);
        res2 = scriptb2.safeAdd(a);
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga + bigb, *res));
        BOOST_CHECK(verify(biga + bigb, *res2));
    } else {
        BOOST_CHECK(!scripta.safeAdd(scriptb));
        BOOST_CHECK(!scripta.safeAdd(b));
        BOOST_CHECK(!scriptb.safeAdd(a));
        // BigInt version won't overflow in this case
        BOOST_CHECK(scripta2.safeAdd(scriptb2));
        BOOST_CHECK(scripta2.safeAdd(b));
        BOOST_CHECK(scriptb2.safeAdd(a));
        BOOST_CHECK(FastBigNum(scripta_fbn).safeAddInPlace(scriptb_fbn));
        BOOST_CHECK(FastBigNum(scriptb_fbn).safeAddInPlace(scripta_fbn));
    }
}

static
void CheckAddNewRules(int64_t a, int64_t b) {
    auto res = CScriptNum::fromInt(a);
    auto res2 = ScriptBigInt::fromInt(a);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(a == int64_t_min);
        BOOST_CHECK(*res2 == int64_t_min);
        return;
    }
    auto const scripta = *res;
    auto const scripta2 = *res2;
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);

    res = CScriptNum::fromInt(b);
    res2 = ScriptBigInt::fromInt(b);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(b == int64_t_min);
        return;
    }
    auto const scriptb = *res;
    auto const scriptb2 = *res2;
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    bool overflowing = (b > 0 && a > int64_t_max - b) ||
                       (b < 0 && a < int64_t_min_8_bytes - b);

    res = scripta.safeAdd(scriptb);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || a + b == res->getint64());
    res2 = scripta2.safeAdd(scriptb2);
    BOOST_REQUIRE(bool(res2));
    BOOST_CHECK(BigInt(a) + b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) + BigInt(b) == res2->getBigInt());
    BOOST_CHECK( ! res || res->getvch() == res2->getvch());

    // Check FastBigNum
    auto a_fbn = scripta_fbn, b_fbn = scriptb_fbn; // take copy
    BOOST_CHECK(a_fbn.safeAddInPlace(b_fbn));
    BOOST_CHECK(res2->getvch() == a_fbn.getvch());
    a_fbn = scripta_fbn; // restore original
    BOOST_CHECK(b_fbn.safeAddInPlace(a_fbn)); // add in reverse
    BOOST_CHECK(res2->getvch() == b_fbn.getvch());

    res = scripta.safeAdd(b);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || a + b == res->getint64());
    res2 = scripta2.safeAdd(b);
    BOOST_CHECK(bool(res2));
    BOOST_CHECK(BigInt(a) + b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) + BigInt(b) == res2->getBigInt());

    res = scriptb.safeAdd(scripta);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || b + a == res->getint64());
    res2 = scriptb2.safeAdd(scripta2);
    BOOST_CHECK(bool(res2));
    BOOST_CHECK(BigInt(b) + a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) + BigInt(a) == res2->getBigInt());

    res = scriptb.safeAdd(a);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || b + a == res->getint64());
    res2 = scriptb2.safeAdd(a);
    BOOST_CHECK(bool(res2));
    BOOST_CHECK(BigInt(b) + a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) + BigInt(a) == res2->getBigInt());
}

static
void CheckSubtractOldRules(int64_t a, int64_t b) {
    if (a == int64_t_min || b == int64_t_min) {
        return;
    }

    CScriptNum10 const biga(a);
    CScriptNum10 const bigb(b);
    auto const scripta = CScriptNum::fromIntUnchecked(a);
    auto const scriptb = CScriptNum::fromIntUnchecked(b);
    auto const scripta2 = ScriptBigInt::fromIntUnchecked(a);
    auto const scriptb2 = ScriptBigInt::fromIntUnchecked(b);

    // int64_t overflow is undefined.
    bool overflowing = (b > 0 && a < int64_t_min_8_bytes + b) ||
                       (b < 0 && a > int64_t_max + b);

    if ( ! overflowing) {
        auto res = scripta.safeSub(scriptb);
        auto res2 = scripta2.safeSub(scriptb2);
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga - bigb, *res));
        BOOST_CHECK(verify(biga - bigb, *res2));
        res = scripta.safeSub(b);
        res2 = scripta2.safeSub(b);
        BOOST_CHECK(res);
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(biga - bigb, *res));
        BOOST_CHECK(verify(biga - bigb, *res2));
    } else {
        BOOST_CHECK(!scripta.safeSub(scriptb));
        BOOST_CHECK(!scripta.safeSub(b));
        // BigInt won't overflow here
        BOOST_CHECK(scripta2.safeSub(scriptb2));
        BOOST_CHECK(scripta2.safeSub(b));
    }

    overflowing = (a > 0 && b < int64_t_min_8_bytes + a) ||
                  (a < 0 && b > int64_t_max + a);

    if ( ! overflowing) {
        auto res = scriptb.safeSub(scripta);
        auto res2 = scriptb2.safeSub(scripta2);
        BOOST_CHECK(res);
        BOOST_CHECK(verify(bigb - biga, *res));
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(bigb - biga, *res2));
        res = scriptb.safeSub(a);
        res2 = scriptb2.safeSub(a);
        BOOST_CHECK(res);
        BOOST_CHECK(verify(bigb - biga, *res));
        BOOST_CHECK(res2);
        BOOST_CHECK(verify(bigb - biga, *res2));
    } else {
        BOOST_CHECK(!scriptb.safeSub(scripta));
        BOOST_CHECK(!scriptb.safeSub(a));
        // BigInt won't overflow here
        BOOST_CHECK(scriptb2.safeSub(scripta2));
        BOOST_CHECK(scriptb2.safeSub(a));
    }
}

static
void CheckSubtractNewRules(int64_t a, int64_t b) {
    auto res = CScriptNum::fromInt(a);
    auto res2 = ScriptBigInt::fromInt(a);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(a == int64_t_min);
        return;
    }
    auto const scripta = *res;
    auto const scripta2 = *res2;
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);
    BOOST_CHECK(scripta2.getvch() == scripta_fbn.getvch());

    res = CScriptNum::fromInt(b);
    res2 = ScriptBigInt::fromInt(b);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(b == int64_t_min);
        return;
    }
    auto const scriptb = *res;
    auto const scriptb2 = *res2;
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);
    BOOST_CHECK(scriptb2.getvch() == scriptb_fbn.getvch());

    bool overflowing = (b > 0 && a < int64_t_min_8_bytes + b) ||
                       (b < 0 && a > int64_t_max + b);

    res = scripta.safeSub(scriptb);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || a - b == res->getint64());
    res2 = scripta2.safeSub(scriptb2);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(a) - b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) - BigInt(b) == res2->getBigInt());

    // FastBigNum: a - b
    auto a_fbn = scripta_fbn, b_fbn = scriptb_fbn; // take copy
    BOOST_CHECK(a_fbn.safeSubInPlace(b_fbn));
    BOOST_CHECK(res2->getvch() == a_fbn.getvch());
    a_fbn = scripta_fbn; // restore

    res = scripta.safeSub(b);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || a - b == res->getint64());
    res2 = scripta2.safeSub(b);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(a) - b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) - BigInt(b) == res2->getBigInt());

    overflowing = (a > 0 && b < int64_t_min_8_bytes + a) ||
                  (a < 0 && b > int64_t_max + a);

    res = scriptb.safeSub(scripta);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || b - a == res->getint64());
    res2 = scriptb2.safeSub(scripta2);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(b) - a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) - BigInt(a) == res2->getBigInt());

    // FastBigNum: b - a
    BOOST_CHECK(b_fbn.safeSubInPlace(a_fbn));
    BOOST_CHECK(res2->getvch() == b_fbn.getvch());
    b_fbn = scriptb_fbn; // restore

    res = scriptb.safeSub(a);
    BOOST_CHECK(bool(res) != overflowing);
    BOOST_CHECK( ! res || b - a == res->getint64());
    res2 = scriptb2.safeSub(a);
    BOOST_CHECK(res2);
    BOOST_CHECK(BigInt(b) - a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) - BigInt(a) == res2->getBigInt());
}

static
void CheckMultiply(int64_t a, int64_t b) {
    auto res = CScriptNum::fromInt(a);
    auto res2 = ScriptBigInt::fromInt(a);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(a == int64_t_min);
        return;
    }
    auto const scripta = *res;
    auto const scripta2 = *res2;
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);

    res = CScriptNum::fromInt(b);
    res2 = ScriptBigInt::fromInt(b);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(b == int64_t_min);
        return;
    }
    auto const scriptb = *res;
    auto const scriptb2 = *res2;
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    res = scripta.safeMul(scriptb);
    BOOST_CHECK( ! res || a * b == res->getint64());
    res = scripta.safeMul(b);
    BOOST_CHECK( ! res || a * b == res->getint64());
    res = scriptb.safeMul(scripta);
    BOOST_CHECK( ! res || b * a == res->getint64());
    res = scriptb.safeMul(a);
    BOOST_CHECK( ! res || b * a == res->getint64());

    res2 = scripta2.safeMul(scriptb2);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(a) * b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) * BigInt(b) == res2->getBigInt());

    // Check FastBigNum: a * b
    auto a_fbn = scripta_fbn; // take copy
    BOOST_CHECK(a_fbn.safeMulInPlace(scriptb_fbn));
    BOOST_CHECK(a_fbn.getvch() == res2->getvch());
    a_fbn = scripta_fbn; // restore

    res2 = scripta2.safeMul(b);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(a) * b == res2->getBigInt());
    BOOST_CHECK(BigInt(a) * BigInt(b) == res2->getBigInt());

    res2 = scriptb2.safeMul(scripta2);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(b) * a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) * BigInt(a) == res2->getBigInt());

    // Check FastBigNum: b * a
    auto b_fbn = scriptb_fbn; // take copy
    BOOST_CHECK(b_fbn.safeMulInPlace(scripta_fbn));
    BOOST_CHECK(b_fbn.getvch() == res2->getvch());
    b_fbn = scripta_fbn; // restore

    res2 = scriptb2.safeMul(a);
    BOOST_REQUIRE(res2);
    BOOST_CHECK(BigInt(b) * a == res2->getBigInt());
    BOOST_CHECK(BigInt(b) * BigInt(a) == res2->getBigInt());
}

static
void CheckDivideOldRules(int64_t a, int64_t b) {
    CScriptNum10 const biga(a);
    CScriptNum10 const bigb(b);
    auto const scripta = CScriptNum::fromIntUnchecked(a);
    auto const scriptb = CScriptNum::fromIntUnchecked(b);
    auto const scripta2 = ScriptBigInt::fromIntUnchecked(a);
    auto const scriptb2 = ScriptBigInt::fromIntUnchecked(b);

    // int64_t overflow is undefined.
    bool overflowing = a == int64_t_min && b == -1;

    if (b != 0) {
        if ( ! overflowing) {
            auto res = scripta / scriptb;
            auto res2 = scripta2 / scriptb2;
            BOOST_CHECK(verify(CScriptNum10(a / b), res));
            BOOST_CHECK(verify(CScriptNum10(a / b), res2));
            res = scripta / b;
            res2 = scripta2 / b;
            BOOST_CHECK(verify(CScriptNum10(a / b), res));
            BOOST_CHECK(verify(CScriptNum10(a / b), res2));
        } else {
            BOOST_CHECK(scripta / scriptb == scripta);
            BOOST_CHECK(verify(biga, scripta / b));
            // BigInt-based impl doesn't overflow here, so check sanity
            BOOST_CHECK(BigInt(a) / b == (scripta2 / scriptb2).getBigInt());
        }
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(a) / b, std::invalid_argument);
        BOOST_CHECK_THROW(scripta2 / b, std::invalid_argument);
        BOOST_CHECK_THROW(scripta2 / scriptb2, std::invalid_argument);
    }

    overflowing = b == int64_t_min && a == -1;

    if (a != 0) {
        if ( ! overflowing) {
            auto res = scriptb / scripta;
            auto res2 = scriptb2 / scripta2;
            BOOST_CHECK(verify(CScriptNum10(b / a), res));
            BOOST_CHECK(verify(CScriptNum10(b / a), res2));
            res = scriptb / a;
            res2 = scriptb2 / a;
            BOOST_CHECK(verify(CScriptNum10(b / a), res));
            BOOST_CHECK(verify(CScriptNum10(b / a), res2));
        } else {
            BOOST_CHECK(scriptb / scripta == scriptb);
            BOOST_CHECK(verify(bigb, scriptb / a));
            // BigInt-based impl doesn't overflow here, so check sanity
            BOOST_CHECK(BigInt(b) / a == (scriptb2 / scripta2).getBigInt());
        }
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(b) / a, std::invalid_argument);
        BOOST_CHECK_THROW(scriptb2 / a, std::invalid_argument);
        BOOST_CHECK_THROW(scriptb2 / scripta2, std::invalid_argument);
    }
}

static
void CheckDivideNewRules(int64_t a, int64_t b) {
    auto res = CScriptNum::fromInt(a);
    auto res2 = ScriptBigInt::fromInt(a);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(a == int64_t_min);
        return;
    }
    auto const scripta = *res;
    auto const scripta2 = *res2;
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);

    res = CScriptNum::fromInt(b);
    res2 = ScriptBigInt::fromInt(b);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(b == int64_t_min);
        return;
    }
    auto const scriptb = *res;
    auto const scriptb2 = *res2;
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    if (b != 0) { // Prevent divide by 0
        auto val = scripta / scriptb;
        BOOST_CHECK(a / b == val.getint64());
        val = scripta / b;
        BOOST_CHECK(a / b == val.getint64());

        // Check BigInt also conforms (it has a slightly different interface for getint64())
        auto val2 = scripta2 / scriptb2;
        auto opti = val2.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(a / b == *opti);
        val2 = scripta2 / b; // int64_t based operator/
        opti = val2.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(a / b == *opti);
        val2 = scripta2 / BigInt(b); // BigInt based operator/
        opti = val2.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(a / b == *opti);

        // Check FastBigNum
        auto fbn = scripta_fbn;
        fbn /= scriptb_fbn;
        BOOST_CHECK(a / b == fbn.getint64().value());
        BOOST_CHECK(fbn.getvch() == (scripta2 / scriptb2).getvch());
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(a) / b, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(a) / BigInt(b), std::invalid_argument);
        BOOST_CHECK_THROW(scripta2 / b, std::invalid_argument);
        BOOST_CHECK_THROW(scripta2 / scriptb2, std::invalid_argument);
        BOOST_CHECK_THROW(FastBigNum(scripta_fbn) /= scriptb_fbn, std::invalid_argument);
    }
    if (a != 0) { // Prevent divide by 0
        auto val = scriptb / scripta;
        BOOST_CHECK(b / a == val.getint64());
        val = scriptb / a;
        BOOST_CHECK(b / a == val.getint64());

        // Check BigInt also conforms (it has a slightly different interface for getint64())
        auto val2 = scriptb2 / scripta2;
        auto opti = val2.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(b / a == *opti);

        // Check FastBigNum
        auto fbn = scriptb_fbn;
        fbn /= scripta_fbn;
        BOOST_CHECK(b / a == fbn.getint64().value());
        BOOST_CHECK(fbn.getvch() == val2.getvch());
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(b) / a, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(b) / BigInt(a), std::invalid_argument);
        BOOST_CHECK_THROW(scriptb2 / a, std::invalid_argument);
        BOOST_CHECK_THROW(scriptb2 / BigInt(a), std::invalid_argument);
        BOOST_CHECK_THROW(scriptb2 / scripta2, std::invalid_argument);
        BOOST_CHECK_THROW(FastBigNum(scriptb_fbn) /= scripta_fbn, std::invalid_argument);
    }
}

static
void CheckModulo(int64_t a, int64_t b) {
    auto res = ScriptBigInt::fromInt(a);
    BOOST_REQUIRE(res);
    auto const scripta = *res;
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);

    res = ScriptBigInt::fromInt(b);
    BOOST_REQUIRE(res);
    auto const scriptb = *res;
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    if (b != 0) { // Prevent divide by 0
        auto val = scripta % scriptb;
        auto val_fbn = scripta_fbn;
        val_fbn %= scriptb_fbn;
        auto opti = val.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(*opti == val_fbn.getint64().value());
        BOOST_CHECK(val.getvch() == val_fbn.getvch());
        if (a != int64_t_min || b != -1) BOOST_CHECK(a % b == *opti);
        else BOOST_CHECK(0 == *opti);
        BOOST_CHECK(BigInt(a) % b == *opti);
        BOOST_CHECK(BigInt(a) % BigInt(b) == *opti);
        val = scripta % b;
        opti = val.getint64();
        BOOST_REQUIRE(opti);
        if (a != int64_t_min || b != -1) BOOST_CHECK(a % b == *opti);
        else BOOST_CHECK(0 == *opti);
        val = scripta % BigInt(b);
        opti = val.getint64();
        BOOST_REQUIRE(opti);
        if (a != int64_t_min || b != -1) BOOST_CHECK(a % b == *opti);
        else BOOST_CHECK(0 == *opti);
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(a) % b, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(a) % BigInt(b), std::invalid_argument);
        BOOST_CHECK_THROW(scripta % b, std::invalid_argument);
        BOOST_CHECK_THROW(scripta % BigInt(b), std::invalid_argument);
        BOOST_CHECK_THROW(scripta % scriptb, std::invalid_argument);
        BOOST_CHECK_THROW(FastBigNum(scripta_fbn) %= scriptb_fbn, std::invalid_argument);
    }
    if (a != 0) { // Prevent divide by 0
        auto val = scriptb % scripta;
        auto val_fbn = scriptb_fbn;
        val_fbn %= scripta_fbn;
        auto opti = val.getint64();
        BOOST_REQUIRE(opti);
        BOOST_CHECK(*opti == val_fbn.getint64().value());
        BOOST_CHECK(val.getvch() == val_fbn.getvch());
        if (b != int64_t_min || a != -1) BOOST_CHECK(b % a == *opti);
        else BOOST_CHECK(0 == *opti);
        val = scriptb % a;
        opti = val.getint64();
        BOOST_REQUIRE(opti);
        if (b != int64_t_min || a != -1) BOOST_CHECK(b % a == *opti);
        else BOOST_CHECK(0 == *opti);
        val = scriptb % BigInt(a);
        opti = val.getint64();
        BOOST_REQUIRE(opti);
        if (b != int64_t_min || a != -1) BOOST_CHECK(b % a == *opti);
        else BOOST_CHECK(0 == *opti);
    } else {
        // BigInt-based impl will throw on divide-by-zero, so check that behavior.
        BOOST_CHECK_THROW(BigInt(b) % a, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(b) % BigInt(a), std::invalid_argument);
        BOOST_CHECK_THROW(scriptb % a, std::invalid_argument);
        BOOST_CHECK_THROW(scriptb % BigInt(a), std::invalid_argument);
        BOOST_CHECK_THROW(scriptb % scripta, std::invalid_argument);
        BOOST_CHECK_THROW(FastBigNum(scriptb_fbn) %= scripta_fbn, std::invalid_argument);
    }
}

static
void CheckNegateOldRules(int64_t x) {
    const CScriptNum10 bigx(x);
    auto const scriptx = CScriptNum::fromIntUnchecked(x);
    auto const scriptx2 = ScriptBigInt::fromIntUnchecked(x);
    auto scriptx_fbn = FastBigNum::fromIntUnchecked(x);

    // -INT64_MIN is undefined
    if (x != int64_t_min) {
        BOOST_CHECK(verify(-bigx, -scriptx));
        BOOST_CHECK(verify(-bigx, -scriptx2));
        BOOST_CHECK(verify(-bigx, scriptx_fbn.negate()));
    }
}

static
void CheckNegateNewRules(int64_t x) {
    auto res = CScriptNum::fromInt(x);
    auto res2 = ScriptBigInt::fromInt(x);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(x == int64_t_min);
        return;
    }
    auto const scriptx = *res;
    CScriptNum10 const bigx(x);
    BOOST_CHECK(verify(-bigx, -scriptx));
    BOOST_CHECK(verify(-(-bigx), -(-scriptx)));

    auto const scriptx2 = *res2;
    BOOST_CHECK(verify(-bigx, -scriptx2));
    BOOST_CHECK(verify(-bigx, -scriptx2));
    BOOST_CHECK(verify(-(-bigx), -(-scriptx2)));

    auto scriptx_fbn = FastBigNum::fromIntUnchecked(x);
    BOOST_CHECK(verify(-bigx, scriptx_fbn.negate()));
    BOOST_CHECK(verify(-(-bigx), scriptx_fbn.negate()));
}

static
void CheckCompare(int64_t a, int64_t b) {
    const CScriptNum10 biga(a);
    const CScriptNum10 bigb(b);
    auto const scripta = CScriptNum::fromIntUnchecked(a);
    auto const scriptb = CScriptNum::fromIntUnchecked(b);
    auto const scripta2 = ScriptBigInt::fromIntUnchecked(a);
    auto const scriptb2 = ScriptBigInt::fromIntUnchecked(b);
    auto const scripta_fbn = FastBigNum::fromIntUnchecked(a);
    auto const scriptb_fbn = FastBigNum::fromIntUnchecked(b);

    // vs bare int64_t
    BOOST_CHECK((biga == biga) == (a == a));
    BOOST_CHECK((biga != biga) == (a != a));
    BOOST_CHECK((biga < biga) == (a < a));
    BOOST_CHECK((biga > biga) == (a > a));
    BOOST_CHECK((biga >= biga) == (a >= a));
    BOOST_CHECK((biga <= biga) == (a <= a));
    // vs CScriptNum
    BOOST_CHECK((biga == biga) == (scripta == scripta));
    BOOST_CHECK((biga != biga) == (scripta != scripta));
    BOOST_CHECK((biga < biga) == (scripta < scripta));
    BOOST_CHECK((biga > biga) == (scripta > scripta));
    BOOST_CHECK((biga >= biga) == (scripta >= scripta));
    BOOST_CHECK((biga <= biga) == (scripta <= scripta));
    // vs ScriptBigNum
    BOOST_CHECK((biga == biga) == (scripta2 == scripta2));
    BOOST_CHECK((biga != biga) == (scripta2 != scripta2));
    BOOST_CHECK((biga < biga) == (scripta2 < scripta2));
    BOOST_CHECK((biga > biga) == (scripta2 > scripta2));
    BOOST_CHECK((biga >= biga) == (scripta2 >= scripta2));
    BOOST_CHECK((biga <= biga) == (scripta2 <= scripta2));
    // vs FastBigNum
    BOOST_CHECK((biga == biga) == (scripta_fbn == scripta_fbn));
    BOOST_CHECK((biga != biga) == (scripta_fbn != scripta_fbn));
    BOOST_CHECK((biga < biga) == (scripta_fbn < scripta_fbn));
    BOOST_CHECK((biga > biga) == (scripta_fbn > scripta_fbn));
    BOOST_CHECK((biga >= biga) == (scripta_fbn >= scripta_fbn));
    BOOST_CHECK((biga <= biga) == (scripta_fbn <= scripta_fbn));

    // vs CScriptNum
    BOOST_CHECK((biga == biga) == (scripta == a));
    BOOST_CHECK((biga != biga) == (scripta != a));
    BOOST_CHECK((biga < biga) == (scripta < a));
    BOOST_CHECK((biga > biga) == (scripta > a));
    BOOST_CHECK((biga >= biga) == (scripta >= a));
    BOOST_CHECK((biga <= biga) == (scripta <= a));
    // vs ScriptBigNum
    BOOST_CHECK((biga == biga) == (scripta2 == a));
    BOOST_CHECK((biga != biga) == (scripta2 != a));
    BOOST_CHECK((biga < biga) == (scripta2 < a));
    BOOST_CHECK((biga > biga) == (scripta2 > a));
    BOOST_CHECK((biga >= biga) == (scripta2 >= a));
    BOOST_CHECK((biga <= biga) == (scripta2 <= a));
    // vs FastBigNum
    BOOST_CHECK((biga == biga) == (scripta_fbn == a));
    BOOST_CHECK((biga != biga) == (scripta_fbn != a));
    BOOST_CHECK((biga < biga) == (scripta_fbn < a));
    BOOST_CHECK((biga > biga) == (scripta_fbn > a));
    BOOST_CHECK((biga >= biga) == (scripta_fbn >= a));
    BOOST_CHECK((biga <= biga) == (scripta_fbn <= a));

    // vs CScriptNum
    BOOST_CHECK((biga == bigb) == (scripta == scriptb));
    BOOST_CHECK((biga != bigb) == (scripta != scriptb));
    BOOST_CHECK((biga < bigb) == (scripta < scriptb));
    BOOST_CHECK((biga > bigb) == (scripta > scriptb));
    BOOST_CHECK((biga >= bigb) == (scripta >= scriptb));
    BOOST_CHECK((biga <= bigb) == (scripta <= scriptb));
    // vs ScriptBigNum
    BOOST_CHECK((biga == bigb) == (scripta2 == scriptb2));
    BOOST_CHECK((biga != bigb) == (scripta2 != scriptb2));
    BOOST_CHECK((biga < bigb) == (scripta2 < scriptb2));
    BOOST_CHECK((biga > bigb) == (scripta2 > scriptb2));
    BOOST_CHECK((biga >= bigb) == (scripta2 >= scriptb2));
    BOOST_CHECK((biga <= bigb) == (scripta2 <= scriptb2));
    // vs FastBigNum
    BOOST_CHECK((biga == bigb) == (scripta_fbn == scriptb_fbn));
    BOOST_CHECK((biga != bigb) == (scripta_fbn != scriptb_fbn));
    BOOST_CHECK((biga < bigb) == (scripta_fbn < scriptb_fbn));
    BOOST_CHECK((biga > bigb) == (scripta_fbn > scriptb_fbn));
    BOOST_CHECK((biga >= bigb) == (scripta_fbn >= scriptb_fbn));
    BOOST_CHECK((biga <= bigb) == (scripta_fbn <= scriptb_fbn));

    // vs CScriptNum
    BOOST_CHECK((biga == bigb) == (scripta == b));
    BOOST_CHECK((biga != bigb) == (scripta != b));
    BOOST_CHECK((biga < bigb) == (scripta < b));
    BOOST_CHECK((biga > bigb) == (scripta > b));
    BOOST_CHECK((biga >= bigb) == (scripta >= b));
    BOOST_CHECK((biga <= bigb) == (scripta <= b));
    // vs ScriptBigNum
    BOOST_CHECK((biga == bigb) == (scripta2 == b));
    BOOST_CHECK((biga != bigb) == (scripta2 != b));
    BOOST_CHECK((biga < bigb) == (scripta2 < b));
    BOOST_CHECK((biga > bigb) == (scripta2 > b));
    BOOST_CHECK((biga >= bigb) == (scripta2 >= b));
    BOOST_CHECK((biga <= bigb) == (scripta2 <= b));
    // vs FastBigNum
    BOOST_CHECK((biga == bigb) == (scripta_fbn == b));
    BOOST_CHECK((biga != bigb) == (scripta_fbn != b));
    BOOST_CHECK((biga < bigb) == (scripta_fbn < b));
    BOOST_CHECK((biga > bigb) == (scripta_fbn > b));
    BOOST_CHECK((biga >= bigb) == (scripta_fbn >= b));
    BOOST_CHECK((biga <= bigb) == (scripta_fbn <= b));
}

static
void CheckShift(const int64_t v) {
    auto res = CScriptNum::fromInt(v);
    auto res2 = ScriptBigInt::fromInt(v);
    auto fastBigNum = FastBigNum::fromIntUnchecked(v);
    BOOST_REQUIRE(res2);
    BOOST_REQUIRE(res2->getint64().value() == v);
    BOOST_REQUIRE(fastBigNum.getint64().value() == v);
    if ( ! res) {
        BOOST_CHECK(v == int64_t_min);
    } else {
        // test CScriptNum shift ops
        const auto & csn = *res;
        BOOST_REQUIRE(csn.getint64() == v);
        const bool neg = v < 0;
        const uint64_t uv = static_cast<uint64_t>(std::abs(v));
        BOOST_CHECK_EQUAL(std::max<unsigned>(1, std::bit_width(uv)), csn.absValNumBits());
        BOOST_CHECK_EQUAL(std::max<unsigned>(1, std::bit_width(uv)), res2->absValNumBits());
        BOOST_CHECK_EQUAL(std::max<unsigned>(1, std::bit_width(uv)), fastBigNum.absValNumBits());
        // for performance, don't run through every bit shift; intentionally attempt shifts in key spots, and past 63
        constexpr size_t maxBits = ScriptBigInt::MAX_BITS;
        const unsigned shiftAmts[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 17, 18, 22, 23, 24, 25, 26, 30, 31,
                                      32, 33, 34, 61, 62, 63, 64, 65, 126, 127, 128, 129, 130, 1000,
                                      maxBits - 10, maxBits - 1, maxBits, maxBits + 1};
        for (const unsigned i : shiftAmts) {
            // left shift
            auto c = csn; // copy
            ScriptBigInt sbi = *res2; // copy
            FastBigNum fbn = fastBigNum; // copy
            BOOST_REQUIRE(sbi.getint64() == v);
            const bool okSbi = sbi.checkedLeftShift(i);
            BOOST_REQUIRE(okSbi || i + sbi.absValNumBits() > ScriptBigInt::MAX_BITS);
            BOOST_REQUIRE(fbn.getint64() == v);
            const bool okFbn = fbn.checkedLeftShift(i);
            BOOST_REQUIRE(okFbn || i + fbn.absValNumBits() > ScriptBigInt::MAX_BITS);
            BOOST_CHECK(okSbi == okFbn);
            BOOST_CHECK(!okSbi || !okFbn || sbi.getvch() == fbn.getvch());
            const bool okC = c.checkedLeftShift(i);
            BOOST_CHECK(!okC || (okSbi && okFbn)); // if int64 left-shift succeeded, then bigint-based should always succeed
            if (okC) {
                BOOST_CHECK(c == 0 || std::bit_width(uv) + i < 64);
                BOOST_CHECK_EQUAL(c.absValNumBits(), fbn.absValNumBits());
                const unsigned safe_i = std::min(i, 63u); // avoid UB in C++, since shifting past 63 is UB
                const int64_t lshifted = neg ? -(uv << safe_i) : uv << safe_i;
                BOOST_CHECK(c.getint64() != int64_t_min);
                // check equality via getint64()
                BOOST_CHECK(sbi.getint64().value() == c.getint64());
                BOOST_CHECK(fbn.getint64().value() == c.getint64());
                BOOST_CHECK(c.getint64() == lshifted);
                // check operator==
                BOOST_CHECK(c == lshifted);
                BOOST_CHECK(sbi == lshifted);
                BOOST_CHECK(fbn == lshifted);
                // ensure inverse op returns us back to the same value
                auto c2 = c;
                BOOST_REQUIRE(c2 == c /* sanity check */);
                BOOST_REQUIRE(c2.checkedRightShift(i));
                BOOST_CHECK(c2.getint64() == v);
                BOOST_CHECK(c2 == v);
            } else {
                BOOST_CHECK(c != 0 && std::bit_width(uv) + i > 63);
            }

            if (okSbi && okFbn) {
                BOOST_CHECK_EQUAL(sbi.absValNumBits(), fbn.absValNumBits());
                // ensure inverse op returns us back to the same value
                auto sbi2 = sbi;
                auto fbn2 = fbn;
                BOOST_REQUIRE(sbi2 == sbi && fbn == fbn2 /* sanity check */);
                BOOST_REQUIRE(sbi2.checkedRightShift(i));
                BOOST_CHECK(sbi2 == v);
                BOOST_CHECK(sbi2.getint64().value() == v);
                BOOST_REQUIRE(fbn2.checkedRightShift(i));
                BOOST_CHECK(fbn2 == v);
                BOOST_CHECK(fbn2.getint64().value() == v);
                BOOST_CHECK(sbi2.getvch() == fbn2.getvch());
            }

#if HAVE_INT128
            if (std::bit_width(uv) + i < 128) {
                BOOST_CHECK(okSbi && okFbn);
                const BigInt::int128_t lshifted = static_cast<BigInt::int128_t>(v) << i;
                BOOST_CHECK(sbi.getBigInt() == lshifted);
            }
#endif

            // right shift
            c = csn; // copy original v
            sbi = *res2; // copy original v
            fbn = fastBigNum; // copy of original
            BOOST_REQUIRE(c.checkedRightShift(i)); // always succeeds
            BOOST_REQUIRE(sbi.checkedRightShift(i)); // always succeeds
            BOOST_REQUIRE(fbn.checkedRightShift(i)); // always succeeds
            BOOST_CHECK(c.getvch() == sbi.getvch());
            BOOST_CHECK(sbi.getvch() == fbn.getvch());
            BOOST_CHECK((v < 0) == (c < 0)); // resulting sign of a right-shift must match
            BOOST_CHECK((v < 0) == (sbi < 0)); // resulting sign of a right-shift must match
            BOOST_CHECK((v < 0) == (fbn < 0)); // resulting sign of a right-shift must match
            if (i >= unsigned(std::bit_width(uv))) {
                // shifting more than number of bits in the number is supported; always yields -1 for neg, 0 for pos
                BOOST_CHECK_EQUAL(c.getint64(), v < 0 ? -1 : 0);
                BOOST_CHECK_EQUAL(sbi.getint64().value(), v < 0 ? -1 : 0);
                BOOST_CHECK_EQUAL(fbn.getint64().value(), v < 0 ? -1 : 0);
            }
            if (i < 64) {
                const int64_t rshifted = v >> i;
                BOOST_CHECK(c.getint64() == rshifted);
                BOOST_CHECK(sbi.getint64().value() == rshifted);
                BOOST_CHECK(fbn.getint64().value() == rshifted);
            }
#if HAVE_INT128
            if (i < 128) {
                const BigInt::int128_t rshifted = static_cast<BigInt::int128_t>(v) >> i;
                BOOST_CHECK(sbi.getBigInt().getInt128().value() == rshifted);
                BOOST_CHECK(sbi.getBigInt() == rshifted);
            }
#endif
        }
    }
}

static
void RunCreateOldRules(CScriptNum const& scriptx) {
    size_t const maxIntegerSize = 4u; // legacy 32-bit limit (no longer used in consensus)
    int64_t const x = scriptx.getint64();
    CheckCreateIntOldRules(x);
    if (scriptx.getvch().size() <= maxIntegerSize) {
        CheckCreateVchOldRules(x);
    } else {
        BOOST_CHECK_THROW(CheckCreateVchOldRules(x), scriptnum10_error);
    }
}

static
void RunCreateOldRulesSet(int64_t v, int64_t o) {
    auto const value = CScriptNum::fromIntUnchecked(v);
    auto const offset = CScriptNum::fromIntUnchecked(o);
    auto const value2 = ScriptBigInt::fromIntUnchecked(v);
    auto const offset2 = ScriptBigInt::fromIntUnchecked(o);
    auto value3 = FastBigNum::fromIntUnchecked(v);
    auto const offset3 = FastBigNum::fromIntUnchecked(o);

    RunCreateOldRules(value);

    auto res = value.safeAdd(offset);
    if (res) {
        RunCreateOldRules(*res);
    }

    auto res2 = value2.safeAdd(offset2);
    BOOST_REQUIRE(res2);

    BOOST_REQUIRE(value3.safeAddInPlace(offset3));
    BOOST_CHECK(res2->getvch() == value3.getvch());
    value3 = FastBigNum::fromIntUnchecked(v); // restore

    res = value.safeSub(offset);
    if (res) {
        RunCreateOldRules(*res);
    }

    res2 = value2.safeSub(offset2);
    BOOST_REQUIRE(res2);

    BOOST_REQUIRE(value3.safeSubInPlace(offset3));
    BOOST_CHECK(res2->getvch() == value3.getvch());
}

static
void RunCreateNewRules(CScriptNum const& scriptx) {
    size_t const maxIntegerSize = CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT;
    int64_t const x = scriptx.getint64();
    CheckCreateIntNewRules(x);
    if (scriptx.getvch().size() <= maxIntegerSize) {
        CheckCreateVchNewRules(x);
    } else {
        BOOST_CHECK_THROW(CheckCreateVchNewRules(x), scriptnum10_error);
    }
}

static
void RunCreateNewRulesSet(int64_t v, int64_t o) {
    auto res = CScriptNum::fromInt(v);
    auto res2 = ScriptBigInt::fromInt(v);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(v == int64_t_min);
        return;
    }
    auto const value = *res;
    auto const value2 = *res2;
    auto value3 = FastBigNum::fromIntUnchecked(v);

    res = CScriptNum::fromInt(o);
    res2 = ScriptBigInt::fromInt(o);
    BOOST_REQUIRE(res2);
    if ( ! res) {
        BOOST_CHECK(o == int64_t_min);
        return;
    }
    auto const offset = *res;
    auto const offset2 = *res2;
    auto const offset3 = FastBigNum::fromIntUnchecked(o);

    RunCreateNewRules(value);

    res = value.safeAdd(offset);
    res2 = value2.safeAdd(offset2);
    bool ok3 = value3.safeAddInPlace(offset3);
    BOOST_REQUIRE(res2);
    BOOST_REQUIRE(ok3);
    BOOST_CHECK(res2->getvch() == value3.getvch());
    value3 = FastBigNum::fromIntUnchecked(v); // restore
    if (res) {
        RunCreateNewRules(*res);
    }

    res = value.safeSub(offset);
    res2 = value2.safeSub(offset2);
    ok3 = value3.safeSubInPlace(offset3);
    BOOST_REQUIRE(res2);
    BOOST_REQUIRE(ok3);
    BOOST_CHECK(res2->getvch() == value3.getvch());
    if (res) {
        RunCreateNewRules(*res);
    }
}

static
void RunOperators(int64_t a, int64_t b) {
    CheckAddOldRules(a, b);
    CheckAddNewRules(a, b);
    CheckSubtractOldRules(a, b);
    CheckSubtractNewRules(a, b);
    CheckMultiply(a, b);
    CheckDivideOldRules(a, b);
    CheckDivideNewRules(a, b);
    CheckModulo(a, b);
    CheckNegateOldRules(a);
    CheckNegateNewRules(a);
    CheckCompare(a, b);
    CheckShift(a);
    if (a != b) CheckShift(b);
}

BOOST_AUTO_TEST_CASE(creation) {
    for (auto value : values) {
        for (auto offset : offsets) {
            RunCreateOldRulesSet(value, offset);
            RunCreateNewRulesSet(value, offset);
        }
    }
}

BOOST_AUTO_TEST_CASE(operators) {
    // Prevent potential UB below
    auto negate = [](int64_t x) { return x != int64_t_min ? -x : int64_t_min; };

    std::vector<int64_t> vals(std::begin(values), std::end(values)); // start with the hard-coded values
    FastRandomContext rng;
    for (size_t i = 0; i < 10; ++i) { // add 10 random values
        vals.push_back(static_cast<int64_t>(rng.rand64()));
    }

    for (const auto a : vals) {
        RunOperators(a, a);
        RunOperators(a, negate(a));
        for (const auto b : vals) {
            RunOperators(a, b);
            RunOperators(a, negate(b));
            int64_t tmp;
            const bool ovradd = __builtin_add_overflow(a, b, &tmp); // we need to do these checks to prevent UB
            const bool ovrsub = __builtin_sub_overflow(a, b, &tmp);
            if (a != int64_t_max && a != int64_t_min && a != int64_t_min_8_bytes &&
                b != int64_t_max && b != int64_t_min && b != int64_t_min_8_bytes) {
                if (!ovradd) RunOperators(a + b, a);
                if (!ovradd) RunOperators(a + b, b);
                if (!ovrsub) RunOperators(a - b, a);
                if (!ovrsub) RunOperators(a - b, b);
                if (!ovradd) RunOperators(a + b, a + b);
                if (!ovradd && !ovrsub) RunOperators(a + b, a - b);
                if (!ovradd && !ovrsub) RunOperators(a - b, a + b);
                if (!ovrsub) RunOperators(a - b, a - b);
                if (!ovradd) RunOperators(a + b, negate(a));
                if (!ovradd) RunOperators(a + b, negate(b));
                if (!ovrsub) RunOperators(a - b, negate(a));
                if (!ovrsub) RunOperators(a - b, negate(b));
            }
        }
    }
}

static
void CheckMinimalyEncode(std::vector<uint8_t> data, const std::vector<uint8_t> &expected) {
    bool alreadyEncoded = CScriptNum::IsMinimallyEncoded(data, data.size());
    if (!alreadyEncoded) {
        // While we are here, ensure that non-minimally-encoded numbers throw
        if (data.size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT) {
            BOOST_CHECK_THROW(CScriptNum(data, true, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT), scriptnum_error);
        }
        BOOST_CHECK_THROW(ScriptBigInt(data, true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT), scriptnum_error);
        BOOST_CHECK_THROW(FastBigNum(data, true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT), scriptnum_error);
    } else {
        // And minimally encoded numbers should not throw
        if (data.size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT) {
            BOOST_CHECK_NO_THROW(CScriptNum(data, true, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT));
        }
        BOOST_CHECK_NO_THROW(ScriptBigInt(data, true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT));
        BOOST_CHECK_NO_THROW(FastBigNum(data, true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT));
    }
    bool hasEncoded = CScriptNum::MinimallyEncode(data);
    BOOST_CHECK_EQUAL(hasEncoded, !alreadyEncoded);
    BOOST_CHECK(data == expected);
}

BOOST_AUTO_TEST_CASE(minimize_encoding_test) {
    CheckMinimalyEncode({}, {});

    for (const size_t elemSize : {MAX_SCRIPT_ELEMENT_SIZE_LEGACY, may2025::MAX_SCRIPT_ELEMENT_SIZE}) {
        // Check that positive and negative zeros encode to nothing.
        std::vector<uint8_t> zero, negZero;
        for (size_t i = 0; i < elemSize; i++) {
            zero.push_back(0x00);
            CheckMinimalyEncode(zero, {});

            negZero.push_back(0x80);
            CheckMinimalyEncode(negZero, {});

            // prepare for next round.
            negZero[negZero.size() - 1] = 0x00;
        }

        // Keep one leading zero when sign bit is used.
        std::vector<uint8_t> n{0x80, 0x00}, negn{0x80, 0x80};
        std::vector<uint8_t> npadded = n, negnpadded = negn;
        for (size_t i = 0; i < elemSize; i++) {
            CheckMinimalyEncode(npadded, n);
            npadded.push_back(0x00);

            CheckMinimalyEncode(negnpadded, negn);
            negnpadded[negnpadded.size() - 1] = 0x00;
            negnpadded.push_back(0x80);
        }

        // Mege leading byte when sign bit isn't used.
        std::vector<uint8_t> k{0x7f}, negk{0xff};
        std::vector<uint8_t> kpadded = k, negkpadded = negk;
        for (size_t i = 0; i < elemSize; i++) {
            CheckMinimalyEncode(kpadded, k);
            kpadded.push_back(0x00);

            CheckMinimalyEncode(negkpadded, negk);
            negkpadded[negkpadded.size() - 1] &= 0x7f;
            negkpadded.push_back(0x80);
        }
    }
}

// Test that FastBigNum uses the correct "backing" for the integer it's given (either native or BigInt-backed)
BOOST_AUTO_TEST_CASE(check_fast_big_num_uses_correct_backing) {
    constexpr size_t maxIntSize = ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT;

    // Test that FastBigNum uses native ints if the size is <= 8, BigInt otherwise
    for (size_t i = 0; i < maxIntSize; ++i) {
        std::vector<uint8_t> data(i, static_cast<uint8_t>(0x42u)); // i-sized data blob, consisting of `0x42` bytes
        ScriptNumEncoding::MinimallyEncode(data); // ensure minimally encoded

        FastBigNum fbn(data, true, maxIntSize);
        // If the blob is <= 8 bytes, it should be using native
        BOOST_CHECK_EQUAL(fbn.usesNative(), data.size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT);
    }

    // Check native ints should all be .usesNative() except for int64_t_min which exceeds 8 bytes serialized size and
    // cannot "use native"
    size_t nativeCt = 0, nonnativeCt = 0, int64MaxCt = 0, int64MinCt = 0, notZeroCt = 0;
    for (const auto val : values) {
        int64MinCt += val == int64_t_min;

        auto fbn = FastBigNum::fromIntUnchecked(val);

        BOOST_CHECK(fbn.usesNative() || val == int64_t_min);
        BOOST_CHECK(fbn >= int64_t_min && fbn <= int64_t_max);

        if (fbn.usesNative()) {
            ++nativeCt;
            BOOST_CHECK(fbn.getvch().size() <= CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT);
            if (fbn != 0) {
                ++notZeroCt;

                // See about breaking us out of native by doing arithmetic with an out-of-range value
                FastBigNum copy = fbn;
                // Add using another native FastBigNum
                FastBigNum other = copy < 0 ? FastBigNum::fromIntUnchecked(int64_t_min + 1)
                                            : FastBigNum::fromIntUnchecked(int64_t_max);
                BOOST_CHECK(other.usesNative());
                auto ok = copy.safeAddInPlace(other);
                BOOST_CHECK(ok);
                BOOST_CHECK(!copy.usesNative());

                // Add us to a non-native FastBigNum
                copy = fbn;
                other = FastBigNum(18446744073709551616_bi .serialize(), true, maxIntSize);
                BOOST_CHECK(!other.usesNative());
                ok = copy.safeAddInPlace(other);
                BOOST_CHECK(ok);
                BOOST_CHECK(!copy.usesNative());

                // Mul us to a non-native FastBigNum
                copy = fbn;
                other = FastBigNum(9223372036854775809_bi .serialize(), true, maxIntSize);
                BOOST_CHECK(!other.usesNative());
                ok = copy.safeMulInPlace(other);
                BOOST_CHECK(ok);
                BOOST_CHECK(!copy.usesNative());

                // Div us with a non-native FastBigNum
                copy = fbn;
                other = FastBigNum(9223372036854775809_bi .serialize(), true, maxIntSize);
                BOOST_CHECK(!other.usesNative());
                copy /= other;
                BOOST_CHECK(!copy.usesNative());
                BOOST_CHECK(copy == 0); // we should be 0, even if we are using BigInt
            }
        } else {
            ++nonnativeCt;
            BOOST_CHECK(fbn.getvch().size() == CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT + 1u);
        }

        if (val == int64_t_max) {
            ++int64MaxCt;

            // Adding 1 to the max value breaks us out of native
            BOOST_CHECK(fbn.usesNative());
            BOOST_CHECK(fbn.safeIncr());
            BOOST_CHECK(!fbn.usesNative());

            // Subtracting 1 back won't restore us to native. BigInt mode is "sticky"
            BOOST_CHECK(fbn.safeDecr());
            BOOST_CHECK(fbn == int64_t_max);
            BOOST_CHECK(!fbn.usesNative());
        }

    }

    // Check that all paths above were taken and tested
    BOOST_CHECK(nativeCt > 0u);
    BOOST_CHECK(nonnativeCt > 0u);
    BOOST_CHECK(int64MaxCt > 0u);
    BOOST_CHECK(int64MinCt > 0u);
    BOOST_CHECK(notZeroCt > 0u);
}

BOOST_AUTO_TEST_SUITE_END()
