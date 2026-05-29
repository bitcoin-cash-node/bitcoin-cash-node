// Copyright (c) 2024-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bigint.h>

#include <compat/endian.h>
#include <random.h>
#include <script/script.h>
#include <span.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <test/data/bigint_exp_tests.json.h>
#include <test/data/bigint_mod_tests.json.h>
#include <test/data/bigint_mul_tests.json.h>
#include <test/data/bigint_shift_tests.json.h>
#include <test/data/bigint_sum_tests.json.h>
#include <test/data/bigint_test_vectors.json.h>
#include <test/jsonutil.h>
#include <test/scriptnum10.h>
#include <test/util.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>
#include <ios>
#include <ostream>
#include <sstream>
#include <string_view>
#include <type_traits>

// to be removed once Boost 1.59+ is minimum version.
#ifndef BOOST_TEST_CONTEXT
#define BOOST_TEST_CONTEXT(x)
#endif

// Allows for literals e.g. "f00fb33f"_v to auto-parse to std::vector<uint8_t>
static std::vector<uint8_t> operator""_v(const char *hex, size_t) { return ParseHex(hex); }

// Stream support for byte vectors.. this is so that BOOST_CHECK_EQUAL on vectors works
static std::ostream &operator<< [[maybe_unused]] (std::ostream &os, const std::vector<uint8_t> &v) {
    return os << HexStr(v);
}

#if HAVE_INT128
using int128_t = BigInt::int128_t;
using uint128_t = BigInt::uint128_t;
static std::ostream &operator<< [[maybe_unused]] (std::ostream &os, const int128_t i) {
    Span<const uint8_t> sp{reinterpret_cast<const uint8_t*>(&i), sizeof(i)};
    return os << "(int128_t hex) " << HexStr(sp);
}
static std::ostream &operator<< [[maybe_unused]] (std::ostream &os, const uint128_t i) {
    Span<const uint8_t> sp{reinterpret_cast<const uint8_t*>(&i), sizeof(i)};
    return os << "(uint128_t hex) " << HexStr(sp);
}
#endif

// Hack to make BOOST be able to print vectors and (u)int128_t
namespace boost {
namespace test_tools {
namespace tt_detail {
    template<> struct print_log_value<std::vector<uint8_t>> {
        std::ostream & operator()(std::ostream& os, std::vector<uint8_t> const& ts) { return ::operator<<(os,ts); }
    };
    template<> struct print_log_value<BigInt> {
        std::ostream & operator()(std::ostream& os, BigInt const& ts) { return os << ts; }
    };
#if HAVE_INT128
    template<> struct print_log_value<int128_t> {
        std::ostream & operator()(std::ostream& os, int128_t ts) { return ::operator<<(os, ts); }
    };
    template<> struct print_log_value<uint128_t> {
        std::ostream & operator()(std::ostream& os, uint128_t ts) { return ::operator<<(os, ts); }
    };
#endif
} // namespace tt_detail
} // namespace test_tools
} // namespace boost

BOOST_FIXTURE_TEST_SUITE(bigint_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(construction) {
    // basic default c'tor
    {
        BigInt bi;
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 0);
        BOOST_CHECK(bi.serialize() == ""_v);
        BOOST_CHECK_EQUAL(bi.ToString(), "0");
    }
    // string-based c'tor
    {
        BigInt bi("-9223372036854775808"); // INT64_MIN (requires 9 bytes to serialize)
        BOOST_REQUIRE(bi.getInt());
        BOOST_REQUIRE(!bi.getUInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), std::numeric_limits<int64_t>::min());
        // special-case when serializing in CScriptNum notation -- requires 9 bytes
        BOOST_CHECK_EQUAL(bi.serialize(), "000000000000008080"_v);

        // operator""_bi (uses string-based c'tor)
        auto bi2 = "-9223372036854775808"_bi;
        BOOST_CHECK(bi == bi2);
        BOOST_CHECK_EQUAL(bi2.serialize(), "000000000000008080"_v);
    }
    {
        // auto-detect base
        BigInt bi("0xb3eff00d"); // base16
        BOOST_REQUIRE(bi.getInt());
        BOOST_REQUIRE(bi.getUInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 0xb3eff00d);
        BOOST_CHECK_EQUAL(*bi.getUInt(), 0xb3eff00d);
        BOOST_CHECK_EQUAL(bi.serialize(), "0df0efb300"_v);
        BOOST_CHECK_EQUAL(bi.serialize(), CScriptNum::fromIntUnchecked(*bi.getInt()).getvch());

        bi = "0b10110011111011111111000000001101"_bi; // binary repr of 0xb3eff00d
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 0xb3eff00d);
        BOOST_CHECK_EQUAL(bi.serialize(), "0df0efb300"_v);

        bi = "026373770015"_bi; // octal repr of 0xb3eff00d
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 0xb3eff00d);
        BOOST_CHECK_EQUAL(bi.serialize(), "0df0efb300"_v);
    }
    {
        // failure to parse
        BigInt bi("7bad");
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 0);
        BOOST_CHECK( ! BigInt::FromString("7bad"));
        // empty string should fail to parse
        bi = ""_bi;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK( ! BigInt::FromString(""));
        // leading whitespace ignored
        bi = " 7"_bi;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 7);
        // trailing whitespace ignored
        bi = "7 "_bi;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 7);
        // quirk: in-between whitespace gets trimmed so "7 0" -> 70
        bi = "7 0"_bi;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 70);
    }
    {
        BigInt bi("9223372036854775808"); // INT64_MAX+1 (requires 9 bytes to serialize)
        BOOST_REQUIRE(!bi.getInt());
        BOOST_REQUIRE(bi.getUInt());
#if HAVE_INT128
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), int128_t(std::numeric_limits<int64_t>::max()) + 1);
#endif
        BOOST_CHECK_EQUAL(*bi.getUInt(), uint64_t(std::numeric_limits<int64_t>::max()) + 1u);
        // special-case when serializing in CScriptNum notation -- requires 9 bytes
        BOOST_CHECK_EQUAL(bi.serialize(), "000000000000008000"_v);
    }
    {
        BigInt bi("-9223372036854775807"); // -INT64_MIN + 1
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), std::numeric_limits<int64_t>::min() + 1);
        BOOST_CHECK_EQUAL(bi.serialize(), "ffffffffffffffff"_v);

        // operator""_bi (uses string-based c'tor)
        auto bi2 = "-9223372036854775807"_bi;
        BOOST_CHECK(bi == bi2);
        BOOST_CHECK_EQUAL(bi2.serialize(), "ffffffffffffffff"_v);
    }
    {
        BigInt bi("9223372036854775807"); // INT64_MAX
        BOOST_REQUIRE(bi.getInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), std::numeric_limits<int64_t>::max());
        BOOST_CHECK_EQUAL(bi.serialize(), "ffffffffffffff7f"_v);
    }
    {
        BigInt bi("-9223372036854775809"); // INT64_MIN - 1 (requires 9 bytes)
        BOOST_REQUIRE(!bi.getInt());
#if HAVE_INT128
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), int128_t(std::numeric_limits<int64_t>::min()) - 1);
#endif
        BOOST_CHECK_EQUAL(bi.serialize(), "010000000000008080"_v);

        // operator""_bi (uses string-based c'tor)
        auto bi2 = "-9223372036854775809"_bi;
        BOOST_CHECK(bi == bi2);
        BOOST_CHECK_EQUAL(bi2.serialize(), "010000000000008080"_v);
        // alternate form of _bi literal (no quotes)
        bi2 = 0; BOOST_CHECK_EQUAL(bi2, 0);
        bi2 = -9223372036854775809_bi;
        BOOST_CHECK_EQUAL(bi2, bi);
        BOOST_CHECK_EQUAL(bi2.serialize(), "010000000000008080"_v);
    }
    // int64_t-based c'tor
    {
        BigInt bi(int64_t{1234567});
        BOOST_REQUIRE(bi.getInt());
        BOOST_REQUIRE(bi.getUInt());
        BOOST_CHECK_EQUAL(*bi.getInt(), 1234567);
        BOOST_CHECK_EQUAL(*bi.getUInt(), 1234567u);
        BOOST_CHECK_EQUAL(bi.serialize(), "87d612"_v);

        BigInt bi2(int64_t{-1234567});
        BOOST_REQUIRE(bi2.getInt());
        BOOST_REQUIRE( ! bi2.getUInt());
        BOOST_CHECK_EQUAL(*bi2.getInt(), -1234567);
        BOOST_CHECK_EQUAL(bi2.serialize(), "87d692"_v);
    }
#if HAVE_INT128
    // int128_t-based c'tor
    {
        constexpr auto val = int128_t(uint128_t{0xffffffffffffffffULL} * int128_t{0x7fffffffffffffffLL});
        static_assert(val > 0);
        BigInt bi(val);
        BOOST_REQUIRE(!bi.getInt());
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), val);
        BOOST_CHECK_EQUAL(bi.serialize(), "0100000000000080feffffffffffff7f"_v);

        BigInt bi2(int128_t{-1234567});
        BOOST_REQUIRE(bi2.getInt());
        BOOST_REQUIRE(!bi2.getUInt());
        BOOST_REQUIRE(bi2.getInt128());
        BOOST_CHECK_EQUAL(*bi2.getInt(), -1234567);
        BOOST_CHECK_EQUAL(*bi2.getInt128(), -1234567);
        BOOST_CHECK_EQUAL(bi2.serialize(), "87d692"_v);
    }
    // operator""_bi (uses string-based c'tor)
    {
        auto bi = "-170141183460469231731687303715884105728"_bi; // INT128_MIN edge case (17 bytes to serialize)
        BOOST_REQUIRE(!bi.getInt());
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), std::numeric_limits<int128_t>::min());
        BOOST_CHECK_EQUAL(bi.serialize(), "0000000000000000000000000000008080"_v);
    }
    // test assignment (128-bit ints)
    {
        BigInt bi;

        bi = int128_t(-123456);
        BOOST_REQUIRE(bi.getInt());
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), -123456);
        BOOST_CHECK_EQUAL(bi.serialize(), CScriptNum::fromIntUnchecked(*bi.getInt()).getvch());

        bi = std::numeric_limits<uint128_t>::max();
        BOOST_REQUIRE(!bi.getInt());
        BOOST_REQUIRE(!bi.getInt128());
        BOOST_REQUIRE(bi.getUInt128());
        BOOST_CHECK_EQUAL(*bi.getUInt128(), std::numeric_limits<uint128_t>::max());
        BOOST_CHECK_EQUAL(bi.serialize(), "ffffffffffffffffffffffffffffffff00"_v);
    }
    {
        auto bi = "170141183460469231731687303715884105727"_bi; // INT128_MAX edge case (16 bytes to serialize)
        BOOST_REQUIRE(!bi.getInt());
        BOOST_REQUIRE(bi.getInt128());
        BOOST_CHECK_EQUAL(*bi.getInt128(), std::numeric_limits<int128_t>::max());
        BOOST_CHECK_EQUAL(bi.serialize(), "ffffffffffffffffffffffffffffff7f"_v);
    }
#endif

    // copy c'tor and copy-assign
    {
        // copy c'tor
        BigInt bi(42);
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(bi.getUInt().value_or(-1), 42u);
        BigInt bi2(bi);
        BOOST_CHECK_EQUAL(bi2.getInt().value_or(-1), 42);
        BOOST_CHECK(bi == bi2);
        // copy-assign
        BigInt bi3;
        BOOST_CHECK_EQUAL(bi3.getInt().value_or(-1), 0);
        bi3 = bi2;
        BOOST_CHECK_EQUAL(bi3.getInt().value_or(-1), 42);
        BOOST_CHECK(bi3 == bi2 && bi3 == bi);
    }
    // move c'tor and move-assign
    {
        // move c'tor
        BigInt bi(42);
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 42);
        BigInt bi2(std::move(bi));
        BOOST_CHECK_EQUAL(bi2.getInt().value_or(-1), 42);
        BOOST_CHECK(bi != bi2);
        BOOST_CHECK(bi.getInt().value_or(-1) == 0); // moved-from value is 0
        // move-assign
        BigInt bi3;
        BOOST_CHECK_EQUAL(bi3.getInt().value_or(-1), 0);
        bi3 = std::move(bi2);
        BOOST_CHECK_EQUAL(bi3.getInt().value_or(-1), 42);
        BOOST_CHECK(bi2.getInt().value_or(-1) == 0); // moved-from value is 0
        BOOST_CHECK(bi3 != bi2 && bi3 != bi);
    }
    // C++ int types should be unambiguously resolved; except: `unsigned long` which may be bigger than int64_t
    {
        BOOST_CHECK_EQUAL(BigInt(char{42}).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(int{42}).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(short{42}).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(long{42}).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(unsigned{42}).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(static_cast<unsigned char>(42)).getInt().value_or(-1), 42);
        BOOST_CHECK_EQUAL(BigInt(static_cast<unsigned short>(42)).getInt().value_or(-1), 42);

        BigInt bi;
        BOOST_CHECK_EQUAL((bi = char{42}).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = int{42}).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = short{42}).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = long{42}).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = unsigned{42}).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = static_cast<unsigned char>(42)).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL((bi = static_cast<unsigned short>(42)).getInt().value_or(-1), 42);
        bi = 0;
        BOOST_CHECK_EQUAL(bi.getInt().value_or(-1), 0);
    }
}

BOOST_AUTO_TEST_CASE(misc) {
    {
        // swap
        BigInt a(123), b(345);
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 123);
        BOOST_CHECK_EQUAL(b.getInt().value_or(-1), 345);
        a.swap(b);
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 345);
        BOOST_CHECK_EQUAL(b.getInt().value_or(-1), 123);
    }
    {
        // Negate
        auto a = "123456"_bi;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 123456);
        a.negate();
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), -123456);
        a.negate();
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 123456);
        a = -a;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), -123456);
        a = -a;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 123456);
    }
    {
        // sign & isNegative
        auto a = "123456"_bi;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 123456);
        BOOST_CHECK_EQUAL(a.sign(), 1);
        BOOST_CHECK(!a.isNegative());
        a = 0;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL(a.sign(), 0);
        BOOST_CHECK(!a.isNegative());
        a = -42;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), -42);
        BOOST_CHECK_EQUAL(a.sign(), -1);
        BOOST_CHECK(a.isNegative());
    }
    {
        // setInt* and get*Int* and pre/post-increment and pre/post-decrement and absValNumBits and abs
        BigInt a;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 0);
        BOOST_CHECK_EQUAL(a.absValNumBits(), 1);
        BOOST_CHECK_EQUAL(a--.getInt().value_or(99), 0);
        BOOST_CHECK_EQUAL(a.getInt().value_or(99), -1);
        BOOST_CHECK_EQUAL(a.absValNumBits(), 1);
        BOOST_CHECK_EQUAL(a.ToString(), "-1");
        BOOST_CHECK_EQUAL(a++.getInt().value_or(99), -1);
        BOOST_CHECK_EQUAL(a.getInt().value_or(99), 0);
        BOOST_CHECK_EQUAL(a.ToString(), "0");
        a.setInt(16);
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), 16);
        BOOST_CHECK_EQUAL(a.getUInt().value_or(-1), 16);
        BOOST_CHECK_EQUAL(a.absValNumBits(), 5);
        BOOST_CHECK_EQUAL(a.abs().getUInt().value_or(1), 16);
        --a;
        BOOST_CHECK_EQUAL(a.absValNumBits(), 4);
        a.setInt(std::numeric_limits<int64_t>::max());
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), std::numeric_limits<int64_t>::max());
        BOOST_CHECK_EQUAL(a.getUInt().value_or(1), uint64_t(std::numeric_limits<int64_t>::max()));
        BOOST_CHECK_EQUAL(a.absValNumBits(), 63);
        ++a;
        BOOST_CHECK(!a.getInt());
        BOOST_CHECK_EQUAL(a.getUInt().value_or(1), uint64_t(std::numeric_limits<int64_t>::max()) + 1u);
        BOOST_CHECK_EQUAL(a.absValNumBits(), 64);
        --a;
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), std::numeric_limits<int64_t>::max());
        BOOST_CHECK_EQUAL(a.getUInt().value_or(1), uint64_t(std::numeric_limits<int64_t>::max()));
        BOOST_CHECK_EQUAL(a.absValNumBits(), 63);
        a.setInt(-42);
        BOOST_CHECK_EQUAL(a.getInt().value_or(-1), -42);
        BOOST_CHECK_EQUAL(a.abs().getInt().value_or(1), 42);
        BOOST_CHECK(!a.getUInt());
        BOOST_CHECK_EQUAL(a.absValNumBits(), 6);
        BOOST_CHECK_EQUAL(BigInt{}.getInt().value(), 0); // corner case with null m_p
        BOOST_CHECK_EQUAL((++BigInt(-1)).getInt().value(), 0); // corner case where m_p is not null but it stores 0
        BOOST_CHECK_EQUAL((++BigInt(-1)).getUInt().value(), 0);
#if HAVE_INT128
        a.setInt(std::numeric_limits<uint64_t>::max());
        BOOST_CHECK(!a.getInt());
        BOOST_CHECK_EQUAL(a.getUInt().value_or(1), std::numeric_limits<uint64_t>::max());
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), int128_t{std::numeric_limits<uint64_t>::max()});
        BOOST_CHECK_EQUAL(a.absValNumBits(), 64);
        ++a;
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), int128_t{std::numeric_limits<uint64_t>::max()} + 1);
        BOOST_CHECK_EQUAL(a.absValNumBits(), 65);
        a.setInt(std::numeric_limits<int128_t>::max());
        BOOST_CHECK(!a.getInt());
        BOOST_CHECK(!a.getUInt());
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), std::numeric_limits<int128_t>::max());
        ++a;
        BOOST_CHECK(!a.getInt128());
        BOOST_CHECK_EQUAL(a.ToString(), "170141183460469231731687303715884105728");
        --a;
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), std::numeric_limits<int128_t>::max());
        a.setInt(std::numeric_limits<int128_t>::min());
        BOOST_CHECK(!a.getInt());
        BOOST_CHECK(!a.getUInt());
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), std::numeric_limits<int128_t>::min());
        BOOST_CHECK_EQUAL(a.ToString(), "-170141183460469231731687303715884105728");
        BOOST_CHECK_EQUAL(a.abs().ToString(), "170141183460469231731687303715884105728");
        --a;
        BOOST_CHECK(!a.getInt());
        BOOST_CHECK(!a.getUInt());
        BOOST_CHECK(!a.getInt128());
        BOOST_CHECK_EQUAL(a.ToString(), "-170141183460469231731687303715884105729");
        ++a;
        BOOST_CHECK_EQUAL(a.getInt128().value_or(1), std::numeric_limits<int128_t>::min());
        BOOST_CHECK_EQUAL(a.absValNumBits(), 128);
#endif
    }
    {
        // sqrt and pow
        BOOST_CHECK_EQUAL(("42"_bi.pow(2).sqrt()).getInt().value_or(1), 42);
        BOOST_CHECK_EQUAL(("42"_bi * "42"_bi).sqrt().getInt().value_or(1), 42);
        auto a = "42"_bi.pow(42);
        BOOST_CHECK_EQUAL(a.ToString(), "150130937545296572356771972164254457814047970568738777235893533016064");
        a = a.pow(2);
        BOOST_CHECK_EQUAL(a.ToString(), "22539298408229739998969300776759130257080980854275852333895157904893661197944366624126022728932809301985081175336480346256876428482052096");
        a = a.sqrt();
        BOOST_CHECK_EQUAL(a.ToString(), "150130937545296572356771972164254457814047970568738777235893533016064");
        // pow 0 & 1
        BOOST_CHECK_EQUAL(a.pow(0), 1_bi);
        BOOST_CHECK_EQUAL(BigInt().pow(0), 1_bi);
        BOOST_CHECK_EQUAL(BigInt().pow(1), 0_bi);
        BOOST_CHECK_EQUAL(a.powMod(0, 2), 1_bi);
        BOOST_CHECK_EQUAL(a.powMod(--BigInt(1), 2), 1_bi);
        BOOST_CHECK_EQUAL(BigInt().powMod(0, 2), 1_bi);
        BOOST_CHECK_EQUAL(BigInt().powMod(0, -2), 1_bi);
        BOOST_CHECK_EQUAL(a.powMod(0, 1), 0_bi);
        BOOST_CHECK_EQUAL(a.powMod(--BigInt(1), 1), 0_bi);
        BOOST_CHECK_EQUAL(BigInt().powMod(0, 1), 0_bi);
        BOOST_CHECK_EQUAL(BigInt().powMod(1, 1), 0_bi);
        BOOST_CHECK_EQUAL(BigInt().powMod(1, 2), 0_bi);
    }
    {
        // various things below should throw

        // div by zero, etc
        BOOST_CHECK_THROW(BigInt(42) / 0, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(42) % 0, std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(42).mathModulo(0), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(42) / --BigInt(1), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(42) % --BigInt(1), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt(42).mathModulo(--BigInt(1)), std::invalid_argument);

        // powMod
        BOOST_CHECK_NO_THROW(BigInt(42).powMod(1, 1));
        BOOST_CHECK_THROW(BigInt(42).powMod(-1, 1), std::invalid_argument); // negative exponent
        BOOST_CHECK_NO_THROW(BigInt(42).powMod(0, 1)); // 0 exponent ok
        BOOST_CHECK_THROW(BigInt(42).powMod(1, 0), std::invalid_argument); // zero mod
        BOOST_CHECK_NO_THROW(BigInt(42).powMod(1, -1)); // negative mod ok
        BOOST_CHECK_NO_THROW(BigInt(42).powMod(0, -1)); // 0 exp and negative mod ok

        // ToString with bad base, edge cases
        BOOST_CHECK_THROW(BigInt().ToString(-1), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt().ToString(0), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt().ToString(1), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt().ToString(-37), std::invalid_argument);
        BOOST_CHECK_THROW(BigInt().ToString(63), std::invalid_argument);
        // below are just inside the acceptable bounds for `base`, so they do not throw
        BOOST_CHECK_NO_THROW(BigInt().ToString(-2));
        BOOST_CHECK_NO_THROW(BigInt().ToString(2));
        BOOST_CHECK_NO_THROW(BigInt().ToString(-36));
        BOOST_CHECK_NO_THROW(BigInt().ToString(62));
    }
    {
        // misc. edge-case bit ops
        BOOST_CHECK_EQUAL(BigInt() & BigInt(42), 0);
        BOOST_CHECK_EQUAL(BigInt() | BigInt(42), 42);
        BOOST_CHECK_EQUAL(BigInt() ^ BigInt(42), 42);
        BOOST_CHECK_EQUAL(BigInt(42) & BigInt(), 0);
        BOOST_CHECK_EQUAL(BigInt(42) | BigInt(), 42);
        BOOST_CHECK_EQUAL(BigInt(42) ^ BigInt(), 42);
        BOOST_CHECK_EQUAL("0xffffffffffffffffff"_bi & "0x42"_bi, "0x42"_bi);
        BOOST_CHECK_EQUAL("0xffffffffffffffffbd"_bi | "0x42"_bi, "0xffffffffffffffffff"_bi);
        BOOST_CHECK_EQUAL("0xffffffffffffffffff"_bi ^ "0x42"_bi, "0xffffffffffffffffbd"_bi);
        BOOST_CHECK_EQUAL("0xffffffffffffffffff"_bi << 1, "0x1fffffffffffffffffe"_bi);
        BOOST_CHECK_EQUAL("0x1fffffffffffffffffe"_bi >> 1, "0xffffffffffffffffff"_bi);
        BOOST_CHECK_EQUAL(-42_bi << 1, -84);
        BOOST_CHECK_EQUAL("-42"_bi << 2, -168);
        BOOST_CHECK_EQUAL("-42"_bi >> 1, -21);
        // Ensure right-shift behaves like C++
        BOOST_CHECK_EQUAL("-42"_bi >> 4, -42 >> 4);
        BOOST_CHECK_EQUAL("-42"_bi >> 5, -42 >> 5);
        BOOST_CHECK_EQUAL("-42"_bi >> 6, -42 >> 6);
    }
    {
        // serialize
        BOOST_CHECK_EQUAL("0"_bi.serialize(), ""_v);
        BOOST_CHECK_EQUAL("-0"_bi.serialize(), ""_v);
        BOOST_CHECK_EQUAL("42"_bi.serialize(), "2a"_v);
        BOOST_CHECK_EQUAL("-42"_bi.serialize(), "aa"_v);
        BOOST_CHECK_EQUAL("127"_bi.serialize(), "7f"_v);
        BOOST_CHECK_EQUAL("-127"_bi.serialize(), "ff"_v);
        BOOST_CHECK_EQUAL("128"_bi.serialize(), "8000"_v); // edge case for CScriptNum to distinguish positive from negative
        BOOST_CHECK_EQUAL("-128"_bi.serialize(), "8080"_v); // edge case for CScriptNum to distinguish positive from negative
        // unserialize
        BigInt a;
        a.unserialize("2a"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), 42);
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
        a.unserialize("aa"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), -42);
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
        a.unserialize("7f"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), 127);
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
        a.unserialize("ff"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), -127);
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
        a.unserialize("8000"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), 128); // edge case for CScriptNum to distinguish positive from negative
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
        a.unserialize("8080"_v); BOOST_CHECK_EQUAL(a.getInt().value_or(9999), -128); // edge case for CScriptNum to distinguish positive from negative
        BOOST_CHECK_EQUAL(CScriptNum::fromIntUnchecked(a.getInt().value_or(9999)).getvch(), a.serialize());
    }
    {
        // other assorted edge cases
        BOOST_CHECK_EQUAL(ScriptBigInt::bigIntConsensusMin() % -1, 0);
        BOOST_CHECK_EQUAL(ScriptBigInt::bigIntConsensusMax() % -1, 0);
        BOOST_CHECK_EQUAL(ScriptBigInt::bigIntConsensusMin() / -1, ScriptBigInt::bigIntConsensusMax());
        BOOST_CHECK_EQUAL(ScriptBigInt::bigIntConsensusMax() / -1, ScriptBigInt::bigIntConsensusMin());
    }
}

BOOST_AUTO_TEST_CASE(int_interop) {
    long li = -42; int i = -42; short si = -42; long long lli = -42; char c = 42; signed char sc = -42;
    unsigned long uli = 42; int ui = 42; unsigned short us = 42; unsigned long long ulli = 42; unsigned char uc = 42;
    bool b = 42;
#if HAVE_INT128
    int128_t i128 = -42; uint128_t u128 = 42;
#endif
    BigInt bi;

    // various C++ types should all be assignable ...
    bi =   li; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi =    i; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi =   si; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi =  lli; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi =    c; BOOST_CHECK_EQUAL(bi,  42); bi = 0; // it is platform-specific which overload is used for `char`
    bi =   sc; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi =  uli; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
    bi =   ui; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
    bi =   us; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
    bi = ulli; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
    bi =   uc; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
    bi =    b; BOOST_CHECK_EQUAL(bi,   1); bi = 0; // bool resolves to int
#if HAVE_INT128
    bi = i128; BOOST_CHECK_EQUAL(bi, -42); bi = 0;
    bi = u128; BOOST_CHECK_EQUAL(bi,  42); bi = 0;
#endif

    // ... and constructible
    BOOST_CHECK_EQUAL(BigInt(li),  -42);
    BOOST_CHECK_EQUAL(BigInt(i),   -42);
    BOOST_CHECK_EQUAL(BigInt(si),  -42);
    BOOST_CHECK_EQUAL(BigInt(lli), -42);
    BOOST_CHECK_EQUAL(BigInt(c),    42); // it is platform-specific which overload is used for `char`
    BOOST_CHECK_EQUAL(BigInt(sc),  -42);
    BOOST_CHECK_EQUAL(BigInt(uli),  42);
    BOOST_CHECK_EQUAL(BigInt(ui),   42);
    BOOST_CHECK_EQUAL(BigInt(us),   42);
    BOOST_CHECK_EQUAL(BigInt(ulli), 42);
    BOOST_CHECK_EQUAL(BigInt(uc),   42);
    BOOST_CHECK_EQUAL(BigInt(b),     1); // bool resolves to int
#if HAVE_INT128
    BOOST_CHECK_EQUAL(BigInt(i128), -42);
    BOOST_CHECK_EQUAL(BigInt(u128),  42);
#endif

    // ... and comparable (use various forms... default c'tor'd, explicit c'tor'd, etc)
    for (const auto &bi2 : {BigInt(), BigInt(0), BigInt(-1), BigInt(1), BigInt(true), BigInt(false)}) {
        BOOST_CHECK_GT(bi2, li);
        BOOST_CHECK_GT(bi2, i);
        BOOST_CHECK_GT(bi2, si);
        BOOST_CHECK_GT(bi2, lli);
        BOOST_CHECK_LT(bi2, c); // it is platform-specific which overload is used for `char`
        BOOST_CHECK_GT(bi2, sc);
        BOOST_CHECK_LT(bi2, uli);
        BOOST_CHECK_LT(bi2, ui);
        BOOST_CHECK_LT(bi2, us);
        BOOST_CHECK_LT(bi2, ulli);
        BOOST_CHECK_LT(bi2, uc);
        // check bool comparison (behaves like C++ comparison of int vs bool)
        BOOST_CHECK_EQUAL(bi2 < b, bi2.getInt().value() < b);
        BOOST_CHECK_EQUAL(bi2 > b, bi2.getInt().value() > b);
        BOOST_CHECK_EQUAL(bi2 == b, bi2.getInt().value() == b);
        BOOST_CHECK_EQUAL(bi2 != b, bi2.getInt().value() != b);
        BOOST_CHECK_EQUAL(static_cast<bool>(bi2), bool(bi2.getInt().value()));
#if HAVE_INT128
        BOOST_CHECK_GT(bi2, i128);
        BOOST_CHECK_LT(bi2, u128);
#endif
    }
}

// Check std stream operator<< behaves as expected
static void CheckStreamOp(const BigInt &a) {
    BigInt c;
    std::ostringstream os;
    os << BigInt();
    BOOST_CHECK_EQUAL(os.str(), "0");
    c = BigInt(os.str()); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, 0);
    os.str({});
    os << a;
    BOOST_CHECK_EQUAL(os.str(), a.ToString());
    c = BigInt(os.str()); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, a);
    os.str({});
    os << std::hex << a;
    BOOST_CHECK_EQUAL(os.str(), a.ToString(16));
    c = BigInt(os.str(), 16); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, a);
    os.str({});
    os << std::oct << a;
    BOOST_CHECK_EQUAL(os.str(), a.ToString(8));
    c = BigInt(os.str(), 8); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, a);
    os.str({});
    os << std::showbase << std::hex << a << std::noshowbase;
    if (auto str = a.ToString(16); a.isNegative()) {
        str.insert(1, "0x");
        BOOST_CHECK_EQUAL(os.str(), str);
    } else {
        BOOST_CHECK_EQUAL(os.str(), "0x" + str);
    }
    c = BigInt(os.str()); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, a);
    os.str({});
    os << std::showbase << std::oct << a << std::noshowbase;
    if (auto str = a.ToString(8); a.isNegative()) {
        str.insert(1, "0");
        BOOST_CHECK_EQUAL(os.str(), str);
    } else {
        BOOST_CHECK_EQUAL(os.str(), (a ? "0" : "") + str);
    }
    c = BigInt(os.str()); // test that we can parse what we wrote via operator<<
    BOOST_CHECK_EQUAL(c, a);
}

template<typename Int, typename UInt>
static void CheckIntSerUnserRoundTrip(Int s, UInt u) {
    static_assert(std::is_integral_v<Int> && std::is_integral_v<UInt>);
    static_assert(std::is_same_v<std::make_unsigned_t<Int>, UInt>);
    static_assert(std::is_same_v<std::make_signed_t<UInt>, Int>);
    static_assert(std::is_signed_v<Int> && std::is_unsigned_v<UInt>);
    BigInt a, b;

    auto GetExpectedBytes = [](UInt le, bool neg) {
        std::vector<uint8_t> expected(sizeof(le));
        std::memcpy(expected.data(), &le, sizeof(le));
        // pop MSB zeroes
        while (!expected.empty() && !expected.back()) {
            expected.pop_back();
        }
        // ensure no sign bit conflict
        if (!expected.empty()) {
            if (expected.back() & 0x80u) {
                expected.push_back(neg ? 0x80 : 0x00);
            } else if (neg) expected.back() |= 0x80;
        }
        return expected;
    };

    // do it for signed
    a = s;
    if constexpr (sizeof(s) <= 8u) {
        BOOST_CHECK_EQUAL(a.getInt().value_or(s ^ 12345), s);
        BOOST_CHECK_EQUAL(b.getInt().value_or(s ^ 12345), 0);
        b.unserialize(a.serialize());
        BOOST_CHECK_EQUAL(a.getInt().value_or(s ^ 12345), s);
        BOOST_CHECK_EQUAL(b.getInt().value_or(s ^ 12345), s);

        // Check that it matches CScriptNum serialization
        if (auto optcsn = CScriptNum::fromInt(s)) {
            BOOST_CHECK_EQUAL(optcsn->getvch(), a.serialize());
        } else {
            // Must be this forbidden value if this branch is taken
            BOOST_CHECK_EQUAL(s, std::numeric_limits<int64_t>::min());
        }
    } else {
        BOOST_CHECK_EQUAL(a.getInt128().value_or(s ^ 12345), s);
        BOOST_CHECK_EQUAL(b.getInt128().value_or(s ^ 12345), 0);
        b.unserialize(a.serialize());
        BOOST_CHECK_EQUAL(a.getInt128().value_or(s ^ 12345), s);
        BOOST_CHECK_EQUAL(b.getInt128().value_or(s ^ 12345), s);
    }
    BOOST_CHECK(a == b);
    if (s >= std::numeric_limits<int64_t>::min() && s <= std::numeric_limits<int64_t>::max()) {
        // strprintf only works with int64_t at most ...
        BOOST_CHECK(a.ToString() == strprintf("%i", static_cast<int64_t>(s)));
        BOOST_CHECK(b.ToString() == strprintf("%i", static_cast<int64_t>(s)));
    }
    auto ToLE = [](UInt x) {
        if (const unsigned i = 1; *reinterpret_cast<const uint8_t *>(&i) != 1) {
            // not already little endian, reverse x
            auto *begin = reinterpret_cast<unsigned char *>(&x);
            auto *end = begin + sizeof(x);
            std::reverse(begin, end);
        }
        return x;
    };
    if (s < 0) {
        BOOST_CHECK(! a.getUInt());
#if HAVE_INT128
        BOOST_CHECK(! a.getUInt128());
#endif
        if (s == std::numeric_limits<Int>::min()) {
            // special case
            std::vector<uint8_t> vec(sizeof(UInt) + 1u);
            vec[vec.size()-1u] = 0x80u;
            vec[vec.size()-2u] = 0x80u;
            BOOST_CHECK_EQUAL(a.serialize(), vec);
        } else {
            const auto expected = GetExpectedBytes(ToLE(UInt(-s)), true);
            BOOST_CHECK_EQUAL(a.serialize(), expected);
        }
    }

    // Check operator<<
    CheckStreamOp(a);

    // do what we did above for unsigned
    b = a = 0;
    a = u;
    if constexpr (sizeof(u) <= 8) {
        BOOST_CHECK_EQUAL(a.getUInt().value_or(u ^ 12345u), u);
        BOOST_CHECK_EQUAL(b.getUInt().value_or(u ^ 12345), 0);
        b.unserialize(a.serialize());
        BOOST_CHECK_EQUAL(a.getUInt().value_or(u ^ 12345), u);
        BOOST_CHECK_EQUAL(b.getUInt().value_or(u ^ 12345), u);
    } else {
        BOOST_CHECK_EQUAL(a.getUInt128().value_or(u ^ 12345u), u);
        BOOST_CHECK_EQUAL(b.getUInt128().value_or(u ^ 12345), 0);
        b.unserialize(a.serialize());
        BOOST_CHECK_EQUAL(a.getUInt128().value_or(u ^ 12345), u);
        BOOST_CHECK_EQUAL(b.getUInt128().value_or(u ^ 12345), u);
    }
    BOOST_CHECK(a == b);
    if (u >= std::numeric_limits<uint64_t>::min() && u <= std::numeric_limits<uint64_t>::max()) {
        // strprintf only works with uint64_t at most ...
        BOOST_CHECK(a.ToString() == strprintf("%u", static_cast<uint64_t>(u)));
        BOOST_CHECK(b.ToString() == strprintf("%u", static_cast<uint64_t>(u)));
    }
    if (u > UInt(std::numeric_limits<int64_t>::max())) {
        BOOST_CHECK(! a.getInt());
    }
    BigInt c;
#if HAVE_INT128
    if (u > uint128_t(std::numeric_limits<int128_t>::max())) {
        BOOST_CHECK(! a.getInt128());
    }
    // test setInt (u128)
    BOOST_CHECK(c == 0);
    c.setInt(static_cast<uint128_t>(u));
    BOOST_CHECK(a == c && b == c);
    BOOST_CHECK_EQUAL(c.ToString(), a.ToString());
    c = 0;
#endif
    // test setInt (unsigned)
    BOOST_CHECK(c == 0);
    c.setInt(u);
    BOOST_CHECK(a == c && b == c);
    BOOST_CHECK_EQUAL(c.ToString(), a.ToString());
    c = 0;
    // Test ser is what we expect
    const auto expected = GetExpectedBytes(ToLE(u), false);
    BOOST_CHECK_EQUAL(a.serialize(), expected);
    // Check operator<<
    CheckStreamOp(a);
}

BOOST_AUTO_TEST_CASE(ser_unser_round_trip) {
    // Check serialize()/unserialize() rount-trip + ToString()
    FastRandomContext ctx;
    // check edge cases
    CheckIntSerUnserRoundTrip(int64_t{0}, uint64_t{0u});
    CheckIntSerUnserRoundTrip(std::numeric_limits<int64_t>::min(), std::numeric_limits<uint64_t>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int64_t>::min(), std::numeric_limits<uint64_t>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int64_t>::max(), std::numeric_limits<uint64_t>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int64_t>::max(), std::numeric_limits<uint64_t>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int>::min(), std::numeric_limits<unsigned>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int>::min(), std::numeric_limits<unsigned>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int>::max(), std::numeric_limits<unsigned>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int>::max(), std::numeric_limits<unsigned>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<short>::min(), std::numeric_limits<unsigned short>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<short>::min(), std::numeric_limits<unsigned short>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<short>::max(), std::numeric_limits<unsigned short>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<short>::max(), std::numeric_limits<unsigned short>::max());
#if HAVE_INT128
    CheckIntSerUnserRoundTrip(int128_t{0}, uint128_t{0u});
    CheckIntSerUnserRoundTrip(std::numeric_limits<int128_t>::min(), std::numeric_limits<uint128_t>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int128_t>::min(), std::numeric_limits<uint128_t>::max());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int128_t>::max(), std::numeric_limits<uint128_t>::min());
    CheckIntSerUnserRoundTrip(std::numeric_limits<int128_t>::max(), std::numeric_limits<uint128_t>::max());
#endif
    for (size_t i = 0; i < 25'000u; ++i) {
        // Run through random tries of numbers in the uint64_t range, serializing then unserializing and ensuring
        // same value is preserved.
        {
            const uint64_t u = ctx.rand64();
            int64_t s;
            std::memcpy(&s, &u, sizeof(s));
            // Do test
            CheckIntSerUnserRoundTrip(s, u);
        }
#if HAVE_INT128
        // Also do this for 128-bit numbers, if the compiler supports such numbers
        {
            uint128_t u;
            int128_t s;
            // build unsigned 128-bit int by reading 2 64-bit words from the random context
            {
                unsigned char *p = reinterpret_cast<unsigned char *>(&u);
                const uint64_t w1 = ctx.rand64(), w2 = ctx.rand64();
                static_assert(sizeof(u) == sizeof(w1) + sizeof(w2));
                std::memcpy(p, &w1, sizeof(w1));
                p += sizeof(w1);
                std::memcpy(p, &w2, sizeof(w2));
            }
            std::memcpy(&s, &u, sizeof(s)); // copy bytes also to signed repr
            // Do test
            CheckIntSerUnserRoundTrip(s, u);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(compare) {
    FastRandomContext ctx;
    int64_t sprev{};
    uint64_t uprev{};
    int32_t sprev32{};
    uint32_t uprev32{};
    int16_t sprev16{};
    uint16_t uprev16{};
#if HAVE_INT128
    int128_t sprev128{};
    uint128_t uprev128{};
#endif
    for (size_t i = 0; i < 25'000u; ++i) {
        const uint64_t u = ctx.rand64();
        int64_t s;
        std::memcpy(&s, &u, sizeof(s));

        const uint32_t u32 = ctx.rand32();
        int32_t s32;
        std::memcpy(&s32, &u32, sizeof(s32));

        uint16_t u16;
        int16_t s16;
        std::memcpy(&u16, &u32, sizeof(u16));
        std::memcpy(&s16, &s32, sizeof(s16));

        auto DoTest = [](auto val1, auto val2) {
            const auto as = std::min(val1, val2), bs = std::max(val1, val2);

            // default c'tord BigInt vs as
            BOOST_CHECK_EQUAL(BigInt().compare(as), as < 0 ? 1 : (as ? -1 : 0));
            BOOST_CHECK_EQUAL(BigInt() < as, 0 < as);
            BOOST_CHECK_EQUAL(BigInt() <= as, 0 <= as);
            BOOST_CHECK_EQUAL(BigInt() == as, 0 == as);
            BOOST_CHECK_EQUAL(BigInt() != as, 0 != as);
            BOOST_CHECK_EQUAL(BigInt() >= as, 0 >= as);
            BOOST_CHECK_EQUAL(BigInt() > as, 0 > as);
            BOOST_CHECK_EQUAL(BigInt().compare(BigInt(as)), as < 0 ? 1 : (as ? -1 : 0));
            // compare apples to apples (both BigInt)
            BOOST_CHECK_EQUAL(BigInt() < BigInt(as), 0 < as);
            BOOST_CHECK_EQUAL(BigInt() <= BigInt(as), 0 <= as);
            BOOST_CHECK_EQUAL(BigInt() == BigInt(as), 0 == as);
            BOOST_CHECK_EQUAL(BigInt() != BigInt(as), 0 != as);
            BOOST_CHECK_EQUAL(BigInt() >= BigInt(as), 0 >= as);
            BOOST_CHECK_EQUAL(BigInt() > BigInt(as), 0 > as);
            // as vs default c'tord BigInt
            BOOST_CHECK_EQUAL(BigInt(as).compare(BigInt()), as < 0 ? -1 : (as ? 1 : 0));
            BOOST_CHECK_EQUAL(BigInt(as) < BigInt(), as < 0);
            BOOST_CHECK_EQUAL(BigInt(as) <= BigInt(), as <= 0);
            BOOST_CHECK_EQUAL(BigInt(as) == BigInt(), as == 0);
            BOOST_CHECK_EQUAL(BigInt(as) != BigInt(), as != 0);
            BOOST_CHECK_EQUAL(BigInt(as) >= BigInt(), as >= 0);
            BOOST_CHECK_EQUAL(BigInt(as) > BigInt(), as > 0);
            // default c'tord BigInt vs bs
            BOOST_CHECK_EQUAL(BigInt().compare(bs), bs < 0 ? 1 : (bs ? -1 : 0));
            BOOST_CHECK_EQUAL(BigInt() < bs, 0 < bs);
            BOOST_CHECK_EQUAL(BigInt() <= bs, 0 <= bs);
            BOOST_CHECK_EQUAL(BigInt() == bs, 0 == bs);
            BOOST_CHECK_EQUAL(BigInt() != bs, 0 != bs);
            BOOST_CHECK_EQUAL(BigInt() >= bs, 0 >= bs);
            BOOST_CHECK_EQUAL(BigInt() > bs, 0 > bs);
            // bs vs default c'tord BigInt
            BOOST_CHECK_EQUAL(BigInt(bs).compare(BigInt()), bs < 0 ? -1 : (bs ? 1 : 0));
            BOOST_CHECK_EQUAL(BigInt(bs) < BigInt(), bs < 0);
            BOOST_CHECK_EQUAL(BigInt(bs) <= BigInt(), bs <= 0);
            BOOST_CHECK_EQUAL(BigInt(bs) == BigInt(), bs == 0);
            BOOST_CHECK_EQUAL(BigInt(bs) != BigInt(), bs != 0);
            BOOST_CHECK_EQUAL(BigInt(bs) >= BigInt(), bs >= 0);
            BOOST_CHECK_EQUAL(BigInt(bs) > BigInt(), bs > 0);
            // compare apples to apples (both BigInt)
            BOOST_CHECK_EQUAL(BigInt().compare(BigInt(bs)), bs < 0 ? 1 : (bs ? -1 : 0));
            BOOST_CHECK_EQUAL(BigInt() < BigInt(bs), 0 < bs);
            BOOST_CHECK_EQUAL(BigInt() <= BigInt(bs), 0 <= bs);
            BOOST_CHECK_EQUAL(BigInt() == BigInt(bs), 0 == bs);
            BOOST_CHECK_EQUAL(BigInt() != BigInt(bs), 0 != bs);
            BOOST_CHECK_EQUAL(BigInt() >= BigInt(bs), 0 >= bs);
            BOOST_CHECK_EQUAL(BigInt() > BigInt(bs), 0 > bs);

            if (as < bs) {
                BOOST_CHECK_EQUAL(BigInt(as).compare(BigInt(bs)), -1);
                BOOST_CHECK_EQUAL(BigInt(bs).compare(BigInt(as)), 1);

                BOOST_CHECK_EQUAL(BigInt(as).compare(bs), -1);
                BOOST_CHECK_EQUAL(BigInt(bs).compare(as), 1);

                BOOST_CHECK(BigInt(as) < BigInt(bs));
                BOOST_CHECK(BigInt(as) <= BigInt(bs));
                BOOST_CHECK(!(BigInt(as) == BigInt(bs)));
                BOOST_CHECK(!(BigInt(as) > BigInt(bs)));
                BOOST_CHECK(!(BigInt(as) >= BigInt(bs)));
                BOOST_CHECK(BigInt(as) != BigInt(bs));

                BOOST_CHECK(BigInt(as) < bs);
                BOOST_CHECK(BigInt(as) <= bs);
                BOOST_CHECK(!(BigInt(as) == bs));
                BOOST_CHECK(!(BigInt(as) > bs));
                BOOST_CHECK(!(BigInt(as) >= bs));
                BOOST_CHECK(BigInt(as) != bs);

                BOOST_CHECK(!(BigInt(bs) < BigInt(as)));
                BOOST_CHECK(!(BigInt(bs) <= BigInt(as)));
                BOOST_CHECK(!(BigInt(bs) == BigInt(as)));
                BOOST_CHECK(BigInt(bs) > BigInt(as));
                BOOST_CHECK(BigInt(bs) >= BigInt(as));
                BOOST_CHECK(BigInt(bs) != BigInt(as));

                BOOST_CHECK(!(BigInt(bs) < as));
                BOOST_CHECK(!(BigInt(bs) <= as));
                BOOST_CHECK(!(BigInt(bs) == as));
                BOOST_CHECK(BigInt(bs) > as);
                BOOST_CHECK(BigInt(bs) >= as);
                BOOST_CHECK(BigInt(bs) != as);
            } else if (as == bs) {
                BOOST_CHECK(!(BigInt(as) < bs));
                BOOST_CHECK(BigInt(as) <= bs);
                BOOST_CHECK(BigInt(as) == bs);
                BOOST_CHECK(!(BigInt(as) > bs));
                BOOST_CHECK(BigInt(as) >= bs);
                BOOST_CHECK(!(BigInt(as) != bs));
                BOOST_CHECK_EQUAL(BigInt(as).compare(bs), 0);
                BOOST_CHECK_EQUAL(BigInt(bs).compare(as), 0);

                BOOST_CHECK_EQUAL(BigInt(as).compare(BigInt(bs)), 0);
                BOOST_CHECK_EQUAL(BigInt(bs).compare(BigInt(as)), 0);
                BOOST_CHECK(!(BigInt(as) < BigInt(bs)));
                BOOST_CHECK(BigInt(as) <= BigInt(bs));
                BOOST_CHECK(!(BigInt(as) > BigInt(bs)));
                BOOST_CHECK(BigInt(as) >= BigInt(bs));
                BOOST_CHECK(BigInt(as) == BigInt(bs));
                BOOST_CHECK(!(BigInt(as) != BigInt(bs)));

                BOOST_CHECK(!(BigInt(as) < bs));
                BOOST_CHECK(BigInt(as) <= bs);
                BOOST_CHECK(!(BigInt(as) > bs));
                BOOST_CHECK(BigInt(as) >= bs);
                BOOST_CHECK(BigInt(as) == bs);
                BOOST_CHECK(!(BigInt(as) != bs));

                BOOST_CHECK(!(BigInt(bs) < BigInt(as)));
                BOOST_CHECK(BigInt(bs) <= BigInt(as));
                BOOST_CHECK(!(BigInt(bs) > BigInt(as)));
                BOOST_CHECK(BigInt(bs) >= BigInt(as));
                BOOST_CHECK(BigInt(bs) == BigInt(as));
                BOOST_CHECK(!(BigInt(bs) != BigInt(as)));

                BOOST_CHECK(!(BigInt(bs) < as));
                BOOST_CHECK(BigInt(bs) <= as);
                BOOST_CHECK(!(BigInt(bs) > as));
                BOOST_CHECK(BigInt(bs) >= as);
                BOOST_CHECK(BigInt(bs) == as);
                BOOST_CHECK(!(BigInt(bs) != as));
            } else {
                assert(false);
            }
        };
        DoTest(s, sprev);
        DoTest(u, uprev);

        DoTest(s32, sprev32);
        DoTest(u32, uprev32);

        DoTest(s16, sprev16);
        DoTest(u16, uprev16);

        sprev = s;
        uprev = u;
        sprev32 = s32;
        uprev32 = u32;
        sprev16 = s16;
        uprev16 = uprev;

#if HAVE_INT128
        const uint128_t u128 = uint128_t(ctx.rand64()) | (uint128_t(ctx.rand64()) << 64);
        int128_t s128;
        std::memcpy(&s128, &u128, sizeof(s128));

        DoTest(s128, sprev128);
        DoTest(u128, uprev128);

        sprev128 = s128;
        uprev128 = u128;
#endif
    }
}

enum WhichTestVectors {
    TV_DEFAULT = 0, // from bigint_test_vectors.json

    // The below all come from openssl git: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/
    TV_EXP,   // from bigint_exp_tests.json
    TV_MOD,   // from bigint_mod_tests.json
    TV_MUL,   // from bigint_mul_tests.json
    TV_SHIFT, // from bigint_shift_tests.json
    TV_SUM,   // from bigint_sum_tests.json

    TV_INVALID
};

template<WhichTestVectors TV = TV_DEFAULT>
std::conditional_t<TV == TV_DEFAULT, UniValue::Object, UniValue::Array>
/* UniValue::Object|Array */ GetTestVectors() {
    static_assert(TV >= TV_DEFAULT && TV < TV_INVALID);

    if constexpr (TV == TV_DEFAULT) {
        UniValue uv;
        auto r = uv.read(UncompressStr(json_tests::bigint_test_vectors, json_tests::bigint_test_vectors_uncompressed_size));
        BOOST_REQUIRE(r);

        return std::move(uv.get_obj());
    } else {
        auto UncompressJson = [](Span<const uint8_t> bytes, const size_t uncompSz) {
            return read_json(UncompressStr(bytes, uncompSz));
        };
        switch (TV) {
            case TV_EXP: return UncompressJson(json_tests::bigint_exp_tests, json_tests::bigint_exp_tests_uncompressed_size);
            case TV_MOD: return UncompressJson(json_tests::bigint_mod_tests, json_tests::bigint_mod_tests_uncompressed_size);
            case TV_MUL: return UncompressJson(json_tests::bigint_mul_tests, json_tests::bigint_mul_tests_uncompressed_size);
            case TV_SHIFT: return UncompressJson(json_tests::bigint_shift_tests, json_tests::bigint_shift_tests_uncompressed_size);
            case TV_SUM: return UncompressJson(json_tests::bigint_sum_tests, json_tests::bigint_sum_tests_uncompressed_size);
            default: throw std::invalid_argument("This should never happen");
        }
    }
}

BOOST_AUTO_TEST_CASE(json_test_vectors) {
    const UniValue::Object obj = GetTestVectors();
    const auto &numbers = obj.at("numbers").get_array();
    BOOST_REQUIRE(!numbers.empty());

    auto DoBinaryOp = [](std::string_view oper, const BigInt &op1, const BigInt &op2) -> BigInt {
        if (oper == "+") return op1 + op2;
        if (oper == "-") return op1 - op2;
        if (oper == "*") return op1 * op2;
        if (oper == "/") return op1 / op2;
        if (oper == "%") return op1 % op2;
        if (oper == "&") return op1 & op2;
        if (oper == "|") return op1 | op2;
        if (oper == "^") return op1 ^ op2;
        assert(!"Invalid operation passed to DoBinaryOp!");
        return 0; // not reached
    };

    auto DoUnaryOp = [](std::string_view oper, const BigInt &op1, const BigInt &op2) -> BigInt {
        BigInt result(op1);
        BOOST_CHECK_EQUAL(result.ToString(), op1.ToString());
        if (oper == "+") return result += op2;
        if (oper == "-") return result -= op2;
        if (oper == "*") return result *= op2;
        if (oper == "/") return result /= op2;
        if (oper == "%") return result %= op2;
        if (oper == "&") return result &= op2;
        if (oper == "|") return result |= op2;
        if (oper == "^") return result ^= op2;
        assert(!"Invalid operation passed to DoUnaryOp!");
        return 0; // not reached
    };

    for (const std::string oper : {"+", "-", "*", "/", "%", "&", "|", "^"}) {
        // Do oper
        const auto &tupList = obj.at(oper).get_array();
        BOOST_REQUIRE(!tupList.empty());
        size_t itemNum = 0u;
        for (const auto &uvitem : tupList) {
            const auto &tuple = uvitem.get_array();
            BOOST_REQUIRE_EQUAL(tuple.size(), 3);
            const std::string &op1Str = numbers.at(tuple.at(0).get_int64()).get_str();
            const std::string &op2Str = numbers.at(tuple.at(1).get_int64()).get_str();
            const std::string &expectedResultStr = tuple.at(2).get_str();

            const auto ctxStr = strprintf("op: \"%s\", itemNum: %i, op1: %s, op2: %s, expectedResult: %s",
                                          oper, itemNum, op1Str, op2Str, expectedResultStr);
            BOOST_TEST_CONTEXT(ctxStr) {

                BigInt op1(op1Str), op2(op2Str), result, unaryResult;
                // Sanity check that it parsed ok
                BOOST_CHECK_EQUAL(op1.ToString(), op1Str);
                BOOST_CHECK_EQUAL(op2.ToString(), op2Str);
                // Do the op
                try {
                    result = DoBinaryOp(oper, op1, op2);
                    // Check result is ok
                    BOOST_CHECK_EQUAL(result.ToString(), expectedResultStr);
                } catch (const std::invalid_argument &e) {
                    if (expectedResultStr != "exception") {
                        BOOST_ERROR(strprintf("Unexpected exception: %s", e.what()));
                        throw;
                    }
                    // otherwise, this was expected, so continue...
                }

                // Check unary version, e.g: +=
                try {
                    unaryResult = DoUnaryOp(oper, op1, op2);
                    BOOST_CHECK_EQUAL(unaryResult.ToString(), expectedResultStr);
                } catch (const std::invalid_argument &e) {
                    if (expectedResultStr != "exception") {
                        BOOST_ERROR(strprintf("Unexpected exception: %s", e.what()));
                        throw;
                    }
                    // otherwise, this was expected, so continue...
                }
            }

            ++itemNum;
        }
    }

    // Do <=>
    {
        const auto &tupList = obj.at("<=>").get_array();
        BOOST_REQUIRE(!tupList.empty());
        size_t itemNum = 0u;
        for (const auto &uvitem : tupList) {
            const auto &tuple = uvitem.get_array();
            BOOST_REQUIRE_EQUAL(tuple.size(), 3);
            const std::string &op1Str = numbers.at(tuple.at(0).get_int64()).get_str();
            const std::string &op2Str = numbers.at(tuple.at(1).get_int64()).get_str();
            const int cmp = tuple.at(2).get_int64();

            const auto ctxStr = strprintf("<=> comparison ops for itemNum: %i, op1: %s, op2: %s, cmp: %i",
                                          itemNum, op1Str, op2Str, cmp);
            BOOST_TEST_CONTEXT(ctxStr) {
                const BigInt a(op1Str), b(op2Str);

                BOOST_CHECK_EQUAL(a.compare(b), cmp);

                BOOST_CHECK((a == b) == (cmp == 0));
                BOOST_CHECK((b == a) == (cmp == 0));

                BOOST_CHECK((a != b) == (cmp != 0));
                BOOST_CHECK((b != a) == (cmp != 0));

                BOOST_CHECK((a < b) == (cmp < 0));
                BOOST_CHECK((b < a) == (cmp > 0));

                BOOST_CHECK((a <= b) == (cmp <= 0));
                BOOST_CHECK((b <= a) == (cmp >= 0));

                BOOST_CHECK((a > b) == (cmp > 0));
                BOOST_CHECK((b > a) == (cmp < 0));

                BOOST_CHECK((a >= b) == (cmp >= 0));
                BOOST_CHECK((b >= a) == (cmp <= 0));

                // do it for second operand as bare int64 (if it fits)
                if (auto optval = b.getInt()) {
                    const int64_t bb = *optval;
                    BOOST_CHECK((a == bb) == (cmp == 0));
                    BOOST_CHECK((a != bb) == (cmp != 0));
                    BOOST_CHECK((a < bb) == (cmp < 0));
                    BOOST_CHECK((a <= bb) == (cmp <= 0));
                    BOOST_CHECK((a > bb) == (cmp > 0));
                    BOOST_CHECK((a >= bb) == (cmp >= 0));
                }
#if HAVE_INT128
                if (auto optval = b.getInt128()) {
                    const int128_t bb = *optval;
                    BOOST_CHECK((a == bb) == (cmp == 0));
                    BOOST_CHECK((a != bb) == (cmp != 0));
                    BOOST_CHECK((a < bb) == (cmp < 0));
                    BOOST_CHECK((a <= bb) == (cmp <= 0));
                    BOOST_CHECK((a > bb) == (cmp > 0));
                    BOOST_CHECK((a >= bb) == (cmp >= 0));
                }
#endif
            }
            ++itemNum;
        }
    }
    // Do <<
    {
        const auto &tupList = obj.at("<<").get_array();
        BOOST_REQUIRE(!tupList.empty());
        size_t itemNum = 0u;
        for (const auto &uvitem : tupList) {
            const auto &tuple = uvitem.get_array();
            BOOST_REQUIRE_EQUAL(tuple.size(), 3);
            const std::string &op1Str = numbers.at(tuple.at(0).get_int64()).get_str();
            const int op2 = tuple.at(1).get_int();
            const std::string &expectedResultStr = tuple.at(2).get_str();

            const auto ctxStr = strprintf("<< (left-shift) ops for itemNum: %i, op1: %s, op2: %d, expectedResult: %s",
                                          itemNum, op1Str, op2, expectedResultStr);
            BOOST_TEST_CONTEXT(ctxStr) {
                BigInt op1(op1Str);

                BOOST_CHECK_EQUAL(op1.ToString(), op1Str);
                const BigInt res = op1 << op2;
                BOOST_CHECK_EQUAL(res.ToString(), expectedResultStr);
                // do unary version
                op1 <<= op2;
                BOOST_CHECK_EQUAL(op1.ToString(), expectedResultStr);
                BOOST_CHECK(op1 == res);
            }
            ++itemNum;
        }
    }
    // Do >>
    {
        const auto &tupList = obj.at(">>").get_array();
        BOOST_REQUIRE(!tupList.empty());
        size_t itemNum = 0u;
        for (const auto &uvitem : tupList) {
            const auto &tuple = uvitem.get_array();
            BOOST_REQUIRE_EQUAL(tuple.size(), 3);
            const std::string &op1Str = numbers.at(tuple.at(0).get_int64()).get_str();
            const int op2 = tuple.at(1).get_int();
            const std::string &expectedResultStr = tuple.at(2).get_str();

            const auto ctxStr = strprintf(">> (right-shift) ops for itemNum: %i, op1: %s, op2: %d, expectedResult: %s",
                                          itemNum, op1Str, op2, expectedResultStr);
            BOOST_TEST_CONTEXT(ctxStr) {
                BigInt op1(op1Str);

                BOOST_CHECK_EQUAL(op1.ToString(), op1Str);
                const BigInt res = op1 >> op2;
                BOOST_CHECK_EQUAL(res.ToString(), expectedResultStr);
                // do unary version
                op1 >>= op2;
                BOOST_CHECK_EQUAL(op1.ToString(), expectedResultStr);
                BOOST_CHECK(op1 == res);
            }
            ++itemNum;
        }
    }
    // Do ++ and --
    for (const std::string oper : {"++", "--"}) {
        const auto &tupList = obj.at(oper).get_array();
        BOOST_REQUIRE(!tupList.empty());
        size_t itemNum = 0u;
        for (const auto &uvitem : tupList) {
            const auto &tuple = uvitem.get_array();
            BOOST_REQUIRE_EQUAL(tuple.size(), 2);
            const std::string &opStr = numbers.at(tuple.at(0).get_int64()).get_str();
            const std::string &expectedResultStr = tuple.at(1).get_str();

            const auto ctxStr = strprintf("%s ops for itemNum: %i, operand: %s, expectedResult: %s",
                                          oper, itemNum, opStr, expectedResultStr);
            BOOST_TEST_CONTEXT(ctxStr) {
                const BigInt op(opStr);

                BOOST_CHECK_EQUAL(op.ToString(), opStr);

                if (oper == "++") {
                    BigInt a, r;
                    // post-increment
                    a = op;
                    BOOST_CHECK_EQUAL(a.ToString(), opStr);
                    r = a++;
                    BOOST_CHECK_EQUAL(r.ToString(), opStr);
                    BOOST_CHECK_EQUAL(a.ToString(), expectedResultStr);
                    // pre-increment
                    a = op;
                    BOOST_CHECK_EQUAL(a.ToString(), opStr);
                    r = ++a;
                    BOOST_CHECK_EQUAL(r.ToString(), expectedResultStr);
                    BOOST_CHECK_EQUAL(a.ToString(), expectedResultStr);
                } else if (oper == "--") {
                    BigInt a, r;
                    // post-decrement
                    a = op;
                    BOOST_CHECK_EQUAL(a.ToString(), opStr);
                    r = a--;
                    BOOST_CHECK_EQUAL(r.ToString(), opStr);
                    BOOST_CHECK_EQUAL(a.ToString(), expectedResultStr);
                    // pre-decrement
                    a = op;
                    BOOST_CHECK_EQUAL(a.ToString(), opStr);
                    r = --a;
                    BOOST_CHECK_EQUAL(r.ToString(), expectedResultStr);
                    BOOST_CHECK_EQUAL(a.ToString(), expectedResultStr);
                } else {
                    // This is not reached.
                    BOOST_ERROR("Unkown operation!");
                }
            }
            ++itemNum;
        }
    }
    // Do unary negation opeator-(), also check that .negate(), .sign(), .abs(), isNegative() behave as expected
    {
        size_t n0{}, nNeg{}, nPos{}, ni64{};
        [[maybe_unused]] size_t ni128{};
        for (const auto &numuv : numbers) {
            const std::string &numStr = numuv.get_str();
            BOOST_REQUIRE(!numStr.empty());
            const BigInt n(numStr);
            BOOST_CHECK_EQUAL(n.ToString(), numStr);
            int numStrSign;
            std::string expectedNegStr;
            if (numStr == "0") {
                numStrSign = 0;
                expectedNegStr = numStr;
            } else if (numStr[0] == '-') {
                numStrSign = -1;
                expectedNegStr = numStr.substr(1);
            } else {
                numStrSign = 1;
                expectedNegStr = "-" + numStr;
            }
            const BigInt neg = -n;
            BOOST_CHECK_EQUAL(neg.ToString(), expectedNegStr);
            BOOST_CHECK_EQUAL(neg + n, 0);
            BOOST_CHECK_EQUAL(n + neg, 0);
            BOOST_CHECK_EQUAL(-neg, n);
            // check against basic int64 (if the operand fits)
            if (auto opti64 = n.getInt()) {
                const int64_t i64 = *opti64;
                if (i64 != std::numeric_limits<int64_t>::min()) { // avoid ub for -i64 in this corner case
                    ++ni64;
                    BOOST_CHECK_EQUAL(neg, -i64);
                    BOOST_CHECK_EQUAL(neg.getInt().value(), -i64);
                }
            }
#if HAVE_INT128
            if (auto opti128 = n.getInt128()) {
                const int128_t i128 = *opti128;
                if (i128 != std::numeric_limits<int128_t>::min()) { // avoid ub for -i128 in this corner case
                    ++ni128;
                    BOOST_CHECK_EQUAL(neg, -i128);
                    BOOST_CHECK_EQUAL(neg.getInt128().value(), -i128);
                }
            }
#endif
            // and that the self-modifying .negate() works as expected
            {
                BigInt negCpy(neg);
                BOOST_CHECK_EQUAL(negCpy, neg);
                negCpy.negate();
                BOOST_CHECK_EQUAL(negCpy, n);
                negCpy.negate();
                BOOST_CHECK_EQUAL(negCpy, neg);
            }
            // test .sign()
            BOOST_CHECK_EQUAL(n.sign(), numStrSign);
            BOOST_CHECK_EQUAL(neg.sign(), -numStrSign);
            // test .abs() & .isNegative()
            switch (numStrSign) {
                case 0:
                    ++n0;
                    BOOST_CHECK(!neg.isNegative());
                    BOOST_CHECK(!n.isNegative());
                    BOOST_CHECK_EQUAL(neg, n);
                    BOOST_CHECK_EQUAL(neg.abs(), neg);
                    BOOST_CHECK_EQUAL(n, 0);
                    BOOST_CHECK_EQUAL(neg, 0);
                    BOOST_CHECK_EQUAL(n, BigInt{});
                    BOOST_CHECK_EQUAL(neg, BigInt{});
                    BOOST_CHECK_EQUAL(BigInt{}, n);
                    BOOST_CHECK_EQUAL(BigInt{}, neg);
                    // belt-and-suspenders checks on throw for divide-by-0
                    BOOST_CHECK_THROW(42_bi / n, std::invalid_argument);
                    BOOST_CHECK_THROW(42_bi % n, std::invalid_argument);
                    BOOST_CHECK_THROW((42_bi).mathModulo(n), std::invalid_argument);
                    // check powMod behaving as we expect in the 0 case
                    BOOST_CHECK_NO_THROW((42_bi).powMod(n, 2));
                    BOOST_CHECK_EQUAL((42_bi).powMod(n, 1), 0);
                    BOOST_CHECK_EQUAL((42_bi).powMod(n, 2), 1);
                    BOOST_CHECK_EQUAL((42_bi).powMod(n, -2), 1);
                    BOOST_CHECK_EQUAL((42_bi).powMod(n, 221331), 1);
                    break;
                case 1:
                    ++nPos;
                    BOOST_CHECK(neg.isNegative());
                    BOOST_CHECK(!n.isNegative());
                    BOOST_CHECK_NE(neg, n);
                    BOOST_CHECK_NE(neg.abs(), neg);
                    BOOST_CHECK_EQUAL(neg.abs(), n);
                    BOOST_CHECK_LT(neg, 0);
                    BOOST_CHECK_GT(n, 0);
                    // check powMod throwing when we expect if `exp` is <0, not throwing if >0
                    BOOST_CHECK_THROW((42_bi).powMod(neg, 2), std::invalid_argument);
                    BOOST_CHECK_NO_THROW((42_bi).powMod(n, 2));
                    break;
                case -1:
                    ++nNeg;
                    BOOST_CHECK(!neg.isNegative());
                    BOOST_CHECK(n.isNegative());
                    BOOST_CHECK_NE(neg, n);
                    BOOST_CHECK_EQUAL(neg.abs(), neg);
                    BOOST_CHECK_NE(neg.abs(), n);
                    BOOST_CHECK_GT(neg, 0);
                    BOOST_CHECK_LT(n, 0);
                    // check powMod throwing when we expect
                    BOOST_CHECK_THROW((42_bi).powMod(n, 2), std::invalid_argument);
                    BOOST_CHECK_NO_THROW((42_bi).powMod(neg, 2));
                    break;
                default: throw std::runtime_error("This should never happen");
            }
        }
        BOOST_CHECK_GT(n0, 0u);
        BOOST_CHECK_GT(nNeg, 0u);
        BOOST_CHECK_GT(nPos, 0u);
        BOOST_CHECK_GT(ni64, 0u);
#if HAVE_INT128
        BOOST_CHECK_GT(ni128, 0u);
#endif
    }
}

// For all of the numbers in the json test vectors file, test serializing/unserializing round-trip to/from ScriptBigNum
// and other ScriptBigNum-associated checks.
BOOST_AUTO_TEST_CASE(scriptnum_checks) {
    const UniValue::Object obj = GetTestVectors();
    const auto &nums = obj.at("numbers").get_array();
    BOOST_REQUIRE(!nums.empty());

    size_t seen_1_past_max_bi{}, seen_1_under_min_bi{}, seen_outside_i64{}, seen_inside_i64{}, seen_1_under_min_i64{},
           seen_1_under_min_i32{}, seen_min_bi{}, seen_max_bi{};

    for (const auto &num : nums) {
        const auto &numStr = num.get_str();
        BOOST_TEST_CONTEXT(strprintf("Testing number vs ScriptBigNum: %s", numStr)) {
            const BigInt bi(numStr);
            BOOST_CHECK_EQUAL(bi.ToString(), numStr);
            auto res = ScriptBigInt::fromInt(bi);
            BOOST_CHECK_EQUAL(ScriptBigInt::validRange(bi), bool(res));
            if (!res) {
                // If it doesn't work with fromInt(), it is outside the consensus range, ensure that is the case, and skip
                BOOST_CHECK_GT(bi.serialize().size(), ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT);
                // Ensure that this c'tor throws in this case
                BOOST_CHECK_THROW(ScriptBigInt(bi.serialize(), true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT),
                                  scriptnum_error);
                // Check edge cases, if we slip back to the boundary condition, sizes should be at the threshold again
                if (bi + 1 == ScriptBigInt::bigIntConsensusMin()) {
                    ++seen_1_under_min_bi;
                    auto res2 = ScriptBigInt::fromInt(bi + 1);
                    BOOST_REQUIRE(bool(res2));
                    BOOST_CHECK_EQUAL(res2->getvch().size(), ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT);
                } else if (bi - 1 == ScriptBigInt::bigIntConsensusMax()) {
                    ++seen_1_past_max_bi;
                    auto res2 = ScriptBigInt::fromInt(bi - 1);
                    BOOST_REQUIRE(bool(res2));
                    BOOST_CHECK_EQUAL(res2->getvch().size(), ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT);
                }
                // Check that ser/unser round-trip is always ok, even for out-of-range nums
                BigInt bi2;
                bi2.unserialize(bi.serialize());
                BOOST_CHECK_EQUAL(bi, bi2);
                BOOST_CHECK_EQUAL(bi2.ToString(), numStr);
                // Now, just proceed to the next number; we cannot continue with the checks after this `if` block...
                continue;
            } else {
                // It's in consensus; sanity check to ensure that is the case
                BOOST_CHECK_LE(bi.serialize().size(), ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT);
                seen_min_bi += (bi == ScriptBigInt::bigIntConsensusMin());
                seen_max_bi += (bi == ScriptBigInt::bigIntConsensusMax());
                BOOST_CHECK_NO_THROW(ScriptBigInt(res->getvch(), true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT));
            }

            BOOST_CHECK(bi == res->getBigInt());

            if (auto opti64 = res->getint64(); !opti64) {
                // Doesn't fit in an int64_t -- the below must be true
                ++seen_outside_i64;
                BOOST_CHECK(bi < std::numeric_limits<int64_t>::min() || bi > std::numeric_limits<int64_t>::max());
                BOOST_CHECK(*res < std::numeric_limits<int64_t>::min() || *res > std::numeric_limits<int64_t>::max());
                BOOST_CHECK_THROW(ScriptBigInt(res->getvch(), true, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT),
                                  scriptnum_error);
                BOOST_CHECK_THROW(ScriptBigInt(res->getvch(), true, 4u /* legacy limit, no longer used */),
                                  scriptnum_error);
            } else {
                // Does fit in an int64_t -- the below must be true
                ++seen_inside_i64;
                BOOST_CHECK(*res == *opti64);
                BOOST_CHECK(bi == *opti64);
                BOOST_CHECK(bi >= std::numeric_limits<int64_t>::min() && bi <= std::numeric_limits<int64_t>::max());
                BOOST_CHECK(*res >= std::numeric_limits<int64_t>::min() && *res <= std::numeric_limits<int64_t>::max());
                if (*res < (std::numeric_limits<int32_t>::min() + 1) || *res > std::numeric_limits<int32_t>::max()) {
                    BOOST_CHECK_THROW(ScriptBigInt(res->getvch(), true, 4u /* legacy limit, no longer used */),
                                      scriptnum_error);
                } else {
                    BOOST_CHECK(ScriptBigInt(res->getvch(), true, 4u /* legacy limit, no longer used */) == bi);
                }
                // Check it serializes as we expect versus legacy CScriptNum implementations
                BOOST_CHECK_EQUAL(res->getvch(), CScriptNum::fromIntUnchecked(*opti64).getvch());
                BOOST_CHECK_EQUAL(res->getvch(), CScriptNum10(*opti64).getvch());
            }
            if (*res == std::numeric_limits<int64_t>::min()) { // serializes to 9 bytes so, must fail with this c'tor
                ++seen_1_under_min_i64;
                BOOST_CHECK_THROW(ScriptBigInt(res->getvch(), true, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT),
                                  scriptnum_error);
            }
            if (*res == std::numeric_limits<int32_t>::min()) { // serializes to 5 bytes so, must fail with this c'tor
                ++seen_1_under_min_i32;
                BOOST_CHECK_THROW(ScriptBigInt(res->getvch(), true, 4u /* legacy limit, no longer used */),
                                  scriptnum_error);
            }
            auto b2 = ScriptBigInt(res->getvch(), true, ScriptBigInt::MAXIMUM_ELEMENT_SIZE_BIG_INT);
            BOOST_CHECK(b2 == *res);
            BOOST_CHECK_EQUAL(b2.getvch(), bi.serialize());

            BigInt bi2;
            bi2.unserialize(b2.getvch());
            BOOST_CHECK(bi == bi2);
        }
    }

    // Check that our test vectors exercised the branches we wanted.
    BOOST_CHECK_GT(seen_1_past_max_bi, 0u);
    BOOST_CHECK_GT(seen_1_under_min_bi, 0u);
    BOOST_CHECK_GT(seen_outside_i64, 0u);
    BOOST_CHECK_GT(seen_inside_i64, 0u);
    BOOST_CHECK_GT(seen_1_under_min_i64, 0u);
    BOOST_CHECK_GT(seen_1_under_min_i32, 0u);
    BOOST_CHECK_GT(seen_min_bi, 0u);
    BOOST_CHECK_GT(seen_max_bi, 0u);
}

// Trim leading 0's except for the last one
static std::string Trim0s(std::string_view s) {
    while (s.size() > 1 && s.front() == '0') s = s.substr(1);
    return std::string{s};
}

// Test vectors obtained from the openssl lib: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/bnexp.txt
BOOST_AUTO_TEST_CASE(json_exp_tests) {
    const auto arr = GetTestVectors<TV_EXP>();
    BOOST_REQUIRE( ! arr.empty());
    size_t nTests = 0u;

    for (const auto &uv : arr) {
        if (!uv.isObject()) {
            // may be a "comment" in the vector, skip
            continue;
        }
        const auto &obj = uv.get_obj();
        const UniValue *pExp, *pA, *pE;
        pExp = obj.locate("Exp");
        BOOST_REQUIRE(pExp != nullptr && pExp->isStr());
        pA = obj.locate("A");
        BOOST_REQUIRE(pA != nullptr && pA->isStr());
        pE = obj.locate("E");
        BOOST_REQUIRE(pE != nullptr && pE->isStr());

        const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
        BOOST_CHECK_EQUAL(a.ToString(16), pA->get_str());

        const BigInt e = BigInt::FromString(pE->get_str(), 16).value();
        BOOST_CHECK_EQUAL(e.ToString(16), pE->get_str());

        const BigInt exp = BigInt::FromString(pExp->get_str(), 16).value();
        BOOST_CHECK_EQUAL(exp.ToString(16), pExp->get_str());

        const auto optUInt = e.getUInt();
        BOOST_REQUIRE(optUInt);
        const auto e_int = optUInt.value();
        BOOST_REQUIRE(e_int <= std::numeric_limits<unsigned long>::max());

        const BigInt exp2 = a.pow(e_int);

        BOOST_CHECK_EQUAL(exp2, exp);
        BOOST_CHECK_EQUAL(exp2.ToString(16), pExp->get_str());

        ++nTests;
    }

    BOOST_CHECK_GT(nTests, 0u);
}

// Test vectors obtained from the openssl lib: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/bnmod.txt
BOOST_AUTO_TEST_CASE(json_mod_tests) {
    const auto arr = GetTestVectors<TV_MOD>();
    BOOST_REQUIRE( ! arr.empty());
    size_t nModMulTests = 0u, nModExpTests = 0u, nModSqrtTests = 0u;

    for (const auto &uv : arr) {
        if (!uv.isObject()) {
            // may be a "comment" in the vector, skip
            continue;
        }
        const auto &obj = uv.get_obj();
        const UniValue *pMod;

        // ModMul tests, must satisfy: A * B = ModMul (mod M) and 0 <= ModMul < M.
        if ((pMod = obj.locate("ModMul"))) {
            BOOST_REQUIRE(pMod->isStr());
            const BigInt modMul = BigInt::FromString(pMod->get_str(), 16).value();
            BOOST_CHECK_EQUAL(modMul.ToString(16), pMod->get_str());

            const UniValue *pA, *pB, *pM;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pB = obj.locate("B");
            BOOST_REQUIRE(pB != nullptr && pB->isStr());
            pM = obj.locate("M");
            BOOST_REQUIRE(pM != nullptr && pM->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), pA->get_str());
            const BigInt b = BigInt::FromString(pB->get_str(), 16).value();
            BOOST_CHECK_EQUAL(b.ToString(16), pB->get_str());
            const BigInt m = BigInt::FromString(pM->get_str(), 16).value();
            BOOST_CHECK_EQUAL(m.ToString(16), pM->get_str());

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", B = " << b.ToString(16) << ", M = "
                                      << m.ToString(16) << ", ModMul = " << modMul.ToString(16)
                                      << "; must satisfy: (A * B) mod M = ModMul") {
                BOOST_CHECK(BigInt{0} <= modMul);
                BOOST_CHECK(modMul < m);
                BOOST_CHECK_EQUAL((a * b).mathModulo(m), modMul);
            }
            ++nModMulTests;
        }

        // ModExp tests, must satisfy: A ^ E = ModExp (mod M) and 0 <= ModExp < M.
        else if ((pMod = obj.locate("ModExp"))) {
            BOOST_REQUIRE(pMod->isStr());
            const BigInt modExp = BigInt::FromString(pMod->get_str(), 16).value();
            BOOST_CHECK_EQUAL(modExp.ToString(16), Trim0s(pMod->get_str()));

            const UniValue *pA, *pE, *pM;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pE = obj.locate("E");
            BOOST_REQUIRE(pE != nullptr && pE->isStr());
            pM = obj.locate("M");
            BOOST_REQUIRE(pM != nullptr && pM->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt e = BigInt::FromString(pE->get_str(), 16).value();
            BOOST_CHECK_EQUAL(e.ToString(16), Trim0s(pE->get_str()));
            const BigInt m = BigInt::FromString(pM->get_str(), 16).value();
            BOOST_CHECK_EQUAL(m.ToString(16), Trim0s(pM->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", E = " << e.ToString(16) << ", M = "
                                      << m.ToString(16) << ", ModExp = " << modExp.ToString(16)
                                      << "; must satisfy: (A ^ E) mod M = ModExp") {
                BOOST_CHECK(BigInt{0} <= modExp);
                BOOST_CHECK(modExp < m);
                BOOST_CHECK_EQUAL(a.powMod(e, m), modExp);
            }

            ++nModExpTests;
        }

        // ModExp tests, must satisfy: (ModSqrt * ModSqrt) mod P = A mod P with P a prime; ModSqrt is in [0, (P-1)/2].
        else if ((pMod = obj.locate("ModSqrt"))) {
            BOOST_REQUIRE(pMod->isStr());
            const BigInt modSqrt = BigInt::FromString(pMod->get_str(), 16).value();
            BOOST_CHECK_EQUAL(modSqrt.ToString(16), Trim0s(pMod->get_str()));

            const UniValue *pA, *pP;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pP = obj.locate("P");
            BOOST_REQUIRE(pP != nullptr && pP->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt p = BigInt::FromString(pP->get_str(), 16).value();
            BOOST_CHECK_EQUAL(p.ToString(16), Trim0s(pP->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", P = " << p.ToString(16)
                                      << ", ModSqrt = " << modSqrt.ToString(16)
                                      << "; must satisfy: (ModSqrt * ModSqrt) mod P = A mod P with P a prime") {
                if (modSqrt < 0 || modSqrt > (p -1) / 2) continue; // skip invalid tests
                BOOST_CHECK_EQUAL((modSqrt * modSqrt).mathModulo(p), a.mathModulo(p));
            }
            ++nModSqrtTests;
        }
    }

    BOOST_CHECK_GT(nModMulTests, 0u);
    BOOST_CHECK_GT(nModExpTests, 0u);
    BOOST_CHECK_GT(nModSqrtTests, 0u);
}

// Test vectors obtained from the openssl lib: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/bnmul.txt
BOOST_AUTO_TEST_CASE(json_mul_tests) {
    const auto arr = GetTestVectors<TV_MUL>();
    BOOST_REQUIRE( ! arr.empty());
    size_t nSquareTests = 0u, nProductTests = 0u, nQuotientTests = 0u;

    for (const auto &uv : arr) {
        if (!uv.isObject()) {
            // may be a "comment" in the vector, skip
            continue;
        }
        const auto &obj = uv.get_obj();
        const UniValue *pVal;

        if ((pVal = obj.locate("Square"))) {
            ++nSquareTests;

            const BigInt square = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(square.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pA;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", Square = " << square.ToString(16)
                                      << "; must satisfy: A * A = Square") {
                BOOST_CHECK_EQUAL(a * a, square);
                BigInt sqrt = square.sqrt();
                if (a.isNegative()) sqrt.negate();
                BOOST_CHECK_EQUAL(sqrt, a);
            }
        }

        else if ((pVal = obj.locate("Product"))) {
            ++nProductTests;

            const BigInt product = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(product.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pA, *pB;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pB = obj.locate("B");
            BOOST_REQUIRE(pB != nullptr && pB->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt b = BigInt::FromString(pB->get_str(), 16).value();
            BOOST_CHECK_EQUAL(b.ToString(16), Trim0s(pB->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", B = " << b.ToString(16) << ", Product = " << product.ToString(16)
                                      << "; must satisfy: A * B = Product") {
                BOOST_CHECK_EQUAL(a * b, product);
                BOOST_CHECK_EQUAL(product / b, a);
                BOOST_CHECK_EQUAL(product / a, b);
            }
        }

        else if ((pVal = obj.locate("Quotient"))) {
            ++nQuotientTests;

            const BigInt quotient = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(quotient.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pRem, *pA, *pB;
            pRem = obj.locate("Remainder");
            BOOST_REQUIRE(pRem != nullptr && pRem->isStr());
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pB = obj.locate("B");
            BOOST_REQUIRE(pB != nullptr && pB->isStr());

            const BigInt rem = BigInt::FromString(pRem->get_str(), 16).value();
            BOOST_CHECK_EQUAL(rem.ToString(16), Trim0s(pRem->get_str()));
            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt b = BigInt::FromString(pB->get_str(), 16).value();
            BOOST_CHECK_EQUAL(b.ToString(16), Trim0s(pB->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", B = " << b.ToString(16) << ", Quotient = " << quotient.ToString(16)
                                      << ", Remainder = " << rem.ToString(16)
                                      << "; must satisfy: A / B = Quotient with rem Remainder") {
                BOOST_CHECK_EQUAL(a / b, quotient);
                BOOST_CHECK_EQUAL(a % b, rem);
                BOOST_CHECK_EQUAL(b * quotient + rem, a);
            }
        }
    }

    BOOST_CHECK_GT(nSquareTests, 0u);
    BOOST_CHECK_GT(nProductTests, 0u);
    BOOST_CHECK_GT(nQuotientTests, 0u);
}

// Test vectors obtained from the openssl lib: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/bnshift.txt
BOOST_AUTO_TEST_CASE(json_shift_tests) {
    const auto arr = GetTestVectors<TV_SHIFT>();
    BOOST_REQUIRE( ! arr.empty());
    size_t nLShift1Tests = 0u, nLShiftTests = 0u, nRShiftTests = 0u;

    for (const auto &uv : arr) {
        if (!uv.isObject()) {
            // may be a "comment" in the vector, skip
            continue;
        }
        const auto &obj = uv.get_obj();
        const UniValue *pVal;

        if ((pVal = obj.locate("LShift1"))) {
            ++nLShift1Tests;

            const BigInt lshift1 = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(lshift1.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pA;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", LShift1 = " << lshift1.ToString(16)
                                      << "; must satisfy: A * 2 = LShift1") {
                BOOST_CHECK_EQUAL(a * 2, lshift1);
                BOOST_CHECK_EQUAL(a << 1, lshift1);
            }
        }

        else if ((pVal = obj.locate("LShift"))) {
            ++nLShiftTests;

            const BigInt lshift = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(lshift.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pA, *pN;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pN = obj.locate("N");
            BOOST_REQUIRE(pN != nullptr && pN->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt n = BigInt::FromString(pN->get_str(), 16).value();
            BOOST_CHECK_EQUAL(n.ToString(16), Trim0s(pN->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", N = " << n.ToString(16) << ", LShift = " << lshift.ToString(16)
                                      << "; must satisfy: A * 2^N = LShift") {
                const auto n_uint = n.getUInt().value();
                BOOST_REQUIRE_LE(n_uint, unsigned(std::numeric_limits<int>::max()));
                BOOST_CHECK_EQUAL(a * BigInt(2).pow(n_uint), lshift);
                BOOST_CHECK_EQUAL(a << n_uint, lshift);
            }
        }

        else if ((pVal = obj.locate("RShift"))) {
            ++nRShiftTests;

            const BigInt rshift = BigInt::FromString(pVal->get_str(), 16).value();
            BOOST_CHECK_EQUAL(rshift.ToString(16), Trim0s(pVal->get_str()));

            const UniValue *pA, *pN;
            pA = obj.locate("A");
            BOOST_REQUIRE(pA != nullptr && pA->isStr());
            pN = obj.locate("N");
            BOOST_REQUIRE(pN != nullptr && pN->isStr());

            const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
            BOOST_CHECK_EQUAL(a.ToString(16), Trim0s(pA->get_str()));
            const BigInt n = BigInt::FromString(pN->get_str(), 16).value();
            BOOST_CHECK_EQUAL(n.ToString(16), Trim0s(pN->get_str()));

            BOOST_TEST_CONTEXT("A = " << a.ToString(16) << ", N = " << n.ToString(16) << ", RShift = " << rshift.ToString(16)
                                      << "; must satisfy: A / 2^N = RShift") {
                const auto n_uint = n.getUInt().value();
                BOOST_REQUIRE_LE(n_uint, unsigned(std::numeric_limits<int>::max()));
                BOOST_CHECK_EQUAL(a / BigInt(2).pow(n_uint), rshift);
                BOOST_CHECK_EQUAL(a >> n_uint, rshift);
            }
        }
    }

    BOOST_CHECK_GT(nLShift1Tests, 0u);
    BOOST_CHECK_GT(nLShiftTests, 0u);
    BOOST_CHECK_GT(nRShiftTests, 0u);
}

// Test vectors obtained from the openssl lib: https://github.com/openssl/openssl/blob/master/test/recipes/10-test_bn_data/bnsum.txt
BOOST_AUTO_TEST_CASE(json_sum_tests) {
    const auto arr = GetTestVectors<TV_SUM>();
    BOOST_REQUIRE( ! arr.empty());
    size_t nTests = 0u;

    for (const auto &uv : arr) {
        if (!uv.isObject()) {
            // may be a "comment" in the vector, skip
            continue;
        }
        const auto &obj = uv.get_obj();
        const UniValue *pSum, *pA, *pB;
        pSum = obj.locate("Sum");
        BOOST_REQUIRE(pSum != nullptr && pSum->isStr());
        pA = obj.locate("A");
        BOOST_REQUIRE(pA != nullptr && pA->isStr());
        pB = obj.locate("B");
        BOOST_REQUIRE(pB != nullptr && pB->isStr());

        const BigInt a = BigInt::FromString(pA->get_str(), 16).value();
        BOOST_CHECK_EQUAL(a.ToString(16), pA->get_str());

        const BigInt b = BigInt::FromString(pB->get_str(), 16).value();
        BOOST_CHECK_EQUAL(b.ToString(16), pB->get_str());

        const BigInt sum = a + b;
        BOOST_CHECK_EQUAL(sum.ToString(16), pSum->get_str());

        ++nTests;
    }

    BOOST_CHECK_GT(nTests, 0u);
}

BOOST_AUTO_TEST_SUITE_END()
