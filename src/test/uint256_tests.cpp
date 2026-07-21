// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <uint256.h>

#include <arith_uint256.h>
#include <crypto/common.h> // ReadLE64
#include <random.h>
#include <streams.h>
#include <version.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <limits>
#include <new> // for std::launder
#include <sstream>
#include <string>
#include <utility>

BOOST_FIXTURE_TEST_SUITE(uint256_tests, BasicTestingSetup)

const uint8_t R1Array[] =
    "\x9c\x52\x4a\xdb\xcf\x56\x11\x12\x2b\x29\x12\x5e\x5d\x35\xd2\xd2"
    "\x22\x81\xaa\xb5\x33\xf0\x08\x32\xd5\x56\xb1\xf9\xea\xe5\x1d\x7d";
const char R1ArrayHex[] =
    "7D1DE5EAF9B156D53208F033B5AA8122D2d2355d5e12292b121156cfdb4a529c";
const uint256 R1L = uint256(std::vector<uint8_t>(R1Array, R1Array + 32));
const uint160 R1S = uint160(std::vector<uint8_t>(R1Array, R1Array + 20));

const uint8_t R2Array[] =
    "\x70\x32\x1d\x7c\x47\xa5\x6b\x40\x26\x7e\x0a\xc3\xa6\x9c\xb6\xbf"
    "\x13\x30\x47\xa3\x19\x2d\xda\x71\x49\x13\x72\xf0\xb4\xca\x81\xd7";
const uint256 R2L = uint256(std::vector<uint8_t>(R2Array, R2Array + 32));
const uint160 R2S = uint160(std::vector<uint8_t>(R2Array, R2Array + 20));

const uint8_t ZeroArray[] =
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const uint256 ZeroL = uint256(std::vector<uint8_t>(ZeroArray, ZeroArray + 32));
const uint160 ZeroS = uint160(std::vector<uint8_t>(ZeroArray, ZeroArray + 20));

const uint8_t OneArray[] =
    "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const uint256 OneL = uint256(std::vector<uint8_t>(OneArray, OneArray + 32));
const uint160 OneS = uint160(std::vector<uint8_t>(OneArray, OneArray + 20));

const uint8_t MaxArray[] =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
const uint256 MaxL = uint256(std::vector<uint8_t>(MaxArray, MaxArray + 32));
const uint160 MaxS = uint160(std::vector<uint8_t>(MaxArray, MaxArray + 20));

static std::string ArrayToString(const uint8_t A[], unsigned int width) {
    std::stringstream Stream;
    Stream << std::hex;
    for (unsigned int i = 0; i < width; ++i) {
        Stream << std::setw(2) << std::setfill('0')
               << (unsigned int)A[width - i - 1];
    }
    return Stream.str();
}

// constructors, equality, inequality
BOOST_AUTO_TEST_CASE(basics) {
    BOOST_CHECK(1 == 0 + 1);
    // constructor uint256(vector<char>):
    BOOST_CHECK(R1L.ToString() == ArrayToString(R1Array, 32));
    BOOST_CHECK(R1S.ToString() == ArrayToString(R1Array, 20));
    BOOST_CHECK(R2L.ToString() == ArrayToString(R2Array, 32));
    BOOST_CHECK(R2S.ToString() == ArrayToString(R2Array, 20));
    BOOST_CHECK(ZeroL.ToString() == ArrayToString(ZeroArray, 32));
    BOOST_CHECK(ZeroS.ToString() == ArrayToString(ZeroArray, 20));
    BOOST_CHECK(OneL.ToString() == ArrayToString(OneArray, 32));
    BOOST_CHECK(OneS.ToString() == ArrayToString(OneArray, 20));
    BOOST_CHECK(MaxL.ToString() == ArrayToString(MaxArray, 32));
    BOOST_CHECK(MaxS.ToString() == ArrayToString(MaxArray, 20));
    BOOST_CHECK(OneL.ToString() != ArrayToString(ZeroArray, 32));
    BOOST_CHECK(OneS.ToString() != ArrayToString(ZeroArray, 20));

    // .GetUint64
    for (int i = 0; i < 4; ++i) {
        if (i < 2) BOOST_CHECK(R1L.GetUint64(i) == R1S.GetUint64(i));
        const uint64_t val = ReadLE64(R1Array + i*8);
        BOOST_CHECK_EQUAL(R1L.GetUint64(i), val);
    }

    // == and !=
    BOOST_CHECK(R1L != R2L && R1S != R2S);
    BOOST_CHECK(ZeroL != OneL && ZeroS != OneS);
    BOOST_CHECK(OneL != ZeroL && OneS != ZeroS);
    BOOST_CHECK(MaxL != ZeroL && MaxS != ZeroS);

    // String Constructor and Copy Constructor
    BOOST_CHECK(uint256S("0x" + R1L.ToString()) == R1L);
    BOOST_CHECK(uint256S("0x" + R2L.ToString()) == R2L);
    BOOST_CHECK(uint256S("0x" + ZeroL.ToString()) == ZeroL);
    BOOST_CHECK(uint256S("0x" + OneL.ToString()) == OneL);
    BOOST_CHECK(uint256S("0x" + MaxL.ToString()) == MaxL);
    BOOST_CHECK(uint256S(R1L.ToString()) == R1L);
    BOOST_CHECK(uint256S("   0x" + R1L.ToString() + "   ") == R1L);
    BOOST_CHECK(uint256S("") == ZeroL);
    BOOST_CHECK(R1L == uint256S(R1ArrayHex));
    BOOST_CHECK(uint256(R1L) == R1L);
    BOOST_CHECK(uint256(ZeroL) == ZeroL);
    BOOST_CHECK(uint256(OneL) == OneL);

    BOOST_CHECK(uint160S("0x" + R1S.ToString()) == R1S);
    BOOST_CHECK(uint160S("0x" + R2S.ToString()) == R2S);
    BOOST_CHECK(uint160S("0x" + ZeroS.ToString()) == ZeroS);
    BOOST_CHECK(uint160S("0x" + OneS.ToString()) == OneS);
    BOOST_CHECK(uint160S("0x" + MaxS.ToString()) == MaxS);
    BOOST_CHECK(uint160S(R1S.ToString()) == R1S);
    BOOST_CHECK(uint160S("   0x" + R1S.ToString() + "   ") == R1S);
    BOOST_CHECK(uint160S("") == ZeroS);
    BOOST_CHECK(R1S == uint160S(R1ArrayHex));

    BOOST_CHECK(uint160(R1S) == R1S);
    BOOST_CHECK(uint160(ZeroS) == ZeroS);
    BOOST_CHECK(uint160(OneS) == OneS);

    // ensure a string with a short, odd number of hex digits parses ok, and clears remaining bytes ok
    const std::string oddHex = "12a4507c9";
    uint256 oddHexL;
    uint160 oddHexS;
    GetRandBytes(oddHexL.begin(), 32);
    GetRandBytes(oddHexS.begin(), 20);
    oddHexL.SetHex(oddHex);
    oddHexS.SetHex(oddHex);
    BOOST_CHECK_EQUAL(oddHexL.ToString(), std::string(64 - oddHex.size(), '0') + oddHex);
    BOOST_CHECK_EQUAL(oddHexS.ToString(), std::string(40 - oddHex.size(), '0') + oddHex);
    // also test GetUint64
    BOOST_CHECK_EQUAL(oddHexL.GetUint64(0), 5004134345ull);
    BOOST_CHECK_EQUAL(oddHexS.GetUint64(0), 5004134345ull);
}

static void CheckComparison(const uint256 &a, const uint256 &b) {
    BOOST_CHECK(a < b);
    BOOST_CHECK(a <= b);
    BOOST_CHECK(b > a);
    BOOST_CHECK(b >= a);
}

static void CheckComparison(const uint160 &a, const uint160 &b) {
    BOOST_CHECK(a < b);
    BOOST_CHECK(a <= b);
    BOOST_CHECK(b > a);
    BOOST_CHECK(b >= a);
}

// <= >= < >
BOOST_AUTO_TEST_CASE(comparison) {
    uint256 LastL;
    for (int i = 0; i < 256; i++) {
        uint256 TmpL;
        *(TmpL.begin() + (i >> 3)) |= 1 << (i & 7);
        CheckComparison(LastL, TmpL);
        LastL = TmpL;
        BOOST_CHECK(LastL <= LastL);
        BOOST_CHECK(LastL >= LastL);
    }

    CheckComparison(ZeroL, R1L);
    CheckComparison(R1L, R2L);
    CheckComparison(ZeroL, OneL);
    CheckComparison(OneL, MaxL);
    CheckComparison(R1L, MaxL);
    CheckComparison(R2L, MaxL);

    uint160 LastS;
    for (int i = 0; i < 160; i++) {
        uint160 TmpS;
        *(TmpS.begin() + (i >> 3)) |= 1 << (i & 7);
        CheckComparison(LastS, TmpS);
        LastS = TmpS;
        BOOST_CHECK(LastS <= LastS);
        BOOST_CHECK(LastS >= LastS);
    }

    CheckComparison(ZeroS, R1S);
    CheckComparison(R2S, R1S);
    CheckComparison(ZeroS, OneS);
    CheckComparison(OneS, MaxS);
    CheckComparison(R1S, MaxS);
    CheckComparison(R2S, MaxS);
}

// GetHex SetHex begin() end() size() GetLow64 GetSerializeSize, Serialize,
// Unserialize
BOOST_AUTO_TEST_CASE(methods) {
    BOOST_CHECK(R1L.GetHex() == R1L.ToString());
    BOOST_CHECK(R2L.GetHex() == R2L.ToString());
    BOOST_CHECK(OneL.GetHex() == OneL.ToString());
    BOOST_CHECK(MaxL.GetHex() == MaxL.ToString());
    uint256 TmpL(R1L);
    BOOST_CHECK(TmpL == R1L);
    BOOST_CHECK(!TmpL.IsNull());
    TmpL.SetHex(R2L.ToString());
    BOOST_CHECK(TmpL == R2L);
    TmpL.SetHex(ZeroL.ToString());
    BOOST_CHECK(TmpL == uint256());
    BOOST_CHECK(TmpL.IsNull());

    TmpL.SetHex(R1L.ToString());
    BOOST_CHECK(std::memcmp(R1L.begin(), R1Array, 32) == 0);
    BOOST_CHECK(std::memcmp(TmpL.begin(), R1Array, 32) == 0);
    BOOST_CHECK(std::memcmp(R2L.begin(), R2Array, 32) == 0);
    BOOST_CHECK(std::memcmp(ZeroL.begin(), ZeroArray, 32) == 0);
    BOOST_CHECK(std::memcmp(OneL.begin(), OneArray, 32) == 0);
    BOOST_CHECK(R1L.size() == sizeof(R1L));
    BOOST_CHECK(sizeof(R1L) == 32);
    BOOST_CHECK(R1L.size() == 32);
    BOOST_CHECK(R2L.size() == 32);
    BOOST_CHECK(ZeroL.size() == 32);
    BOOST_CHECK(MaxL.size() == 32);
    BOOST_CHECK(R1L.begin() + 32 == R1L.end());
    BOOST_CHECK(R2L.begin() + 32 == R2L.end());
    BOOST_CHECK(OneL.begin() + 32 == OneL.end());
    BOOST_CHECK(MaxL.begin() + 32 == MaxL.end());
    BOOST_CHECK(TmpL.begin() + 32 == TmpL.end());
    BOOST_CHECK(GetSerializeSize(R1L, PROTOCOL_VERSION) == 32);
    BOOST_CHECK(GetSerializeSize(ZeroL, PROTOCOL_VERSION) == 32);

    CDataStream ss(0, PROTOCOL_VERSION);
    ss << R1L;
    BOOST_CHECK(ss.str() == std::string(R1Array, R1Array + 32));
    ss >> TmpL;
    BOOST_CHECK(R1L == TmpL);
    ss.clear();
    ss << ZeroL;
    BOOST_CHECK(ss.str() == std::string(ZeroArray, ZeroArray + 32));
    ss >> TmpL;
    BOOST_CHECK(ZeroL == TmpL);
    ss.clear();
    ss << MaxL;
    BOOST_CHECK(ss.str() == std::string(MaxArray, MaxArray + 32));
    ss >> TmpL;
    BOOST_CHECK(MaxL == TmpL);
    ss.clear();

    BOOST_CHECK(R1S.GetHex() == R1S.ToString());
    BOOST_CHECK(R2S.GetHex() == R2S.ToString());
    BOOST_CHECK(OneS.GetHex() == OneS.ToString());
    BOOST_CHECK(MaxS.GetHex() == MaxS.ToString());
    uint160 TmpS(R1S);
    BOOST_CHECK(TmpS == R1S);
    BOOST_CHECK(!TmpS.IsNull());
    TmpS.SetHex(R2S.ToString());
    BOOST_CHECK(TmpS == R2S);
    BOOST_CHECK(!TmpS.IsNull());
    TmpS.SetHex(ZeroS.ToString());
    BOOST_CHECK(TmpS == uint160());
    BOOST_CHECK(TmpS.IsNull());

    TmpS.SetHex(R1S.ToString());
    BOOST_CHECK(std::memcmp(R1S.begin(), R1Array, 20) == 0);
    BOOST_CHECK(std::memcmp(TmpS.begin(), R1Array, 20) == 0);
    BOOST_CHECK(std::memcmp(R2S.begin(), R2Array, 20) == 0);
    BOOST_CHECK(std::memcmp(ZeroS.begin(), ZeroArray, 20) == 0);
    BOOST_CHECK(std::memcmp(OneS.begin(), OneArray, 20) == 0);
    BOOST_CHECK(R1S.size() == sizeof(R1S));
    BOOST_CHECK(sizeof(R1S) == 20);
    BOOST_CHECK(R1S.size() == 20);
    BOOST_CHECK(R2S.size() == 20);
    BOOST_CHECK(ZeroS.size() == 20);
    BOOST_CHECK(MaxS.size() == 20);
    BOOST_CHECK(R1S.begin() + 20 == R1S.end());
    BOOST_CHECK(R2S.begin() + 20 == R2S.end());
    BOOST_CHECK(OneS.begin() + 20 == OneS.end());
    BOOST_CHECK(MaxS.begin() + 20 == MaxS.end());
    BOOST_CHECK(TmpS.begin() + 20 == TmpS.end());
    BOOST_CHECK(GetSerializeSize(R1S, PROTOCOL_VERSION) == 20);
    BOOST_CHECK(GetSerializeSize(ZeroS, PROTOCOL_VERSION) == 20);

    ss << R1S;
    BOOST_CHECK(ss.str() == std::string(R1Array, R1Array + 20));
    ss >> TmpS;
    BOOST_CHECK(R1S == TmpS);
    ss.clear();
    ss << ZeroS;
    BOOST_CHECK(ss.str() == std::string(ZeroArray, ZeroArray + 20));
    ss >> TmpS;
    BOOST_CHECK(ZeroS == TmpS);
    ss.clear();
    ss << MaxS;
    BOOST_CHECK(ss.str() == std::string(MaxArray, MaxArray + 20));
    ss >> TmpS;
    BOOST_CHECK(MaxS == TmpS);
    ss.clear();

    // Check that '0x' or '0X', and leading spaces are correctly skipped in
    // SetHex
    const auto baseHexstring{uint256S(
        "0x7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c")};
    const auto hexstringWithCharactersToSkip{uint256S(
        " 0X7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c")};
    const auto wrongHexstringWithCharactersToSkip{uint256S(
        " 0X7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529d")};

    BOOST_CHECK(baseHexstring.GetHex() == "7d1de5eaf9b156d53208f033b5aa8122d2d2355d5e12292b121156cfdb4a529c");
    BOOST_CHECK(baseHexstring == hexstringWithCharactersToSkip);
    BOOST_CHECK(baseHexstring != wrongHexstringWithCharactersToSkip);

    // Test IsNull, SetNull, operator==, operator!=, and size()
    auto hexCpy = baseHexstring;
    BOOST_CHECK(hexCpy != ZeroL);
    BOOST_CHECK(ZeroL.IsNull());
    BOOST_CHECK(!hexCpy.IsNull());
    hexCpy.SetNull();
    BOOST_CHECK(hexCpy.IsNull());
    BOOST_CHECK(hexCpy == ZeroL);
    BOOST_CHECK(0 == std::memcmp(hexCpy.begin(), ZeroL.begin(), hexCpy.size()));
    BOOST_CHECK(0 == std::memcmp(hexCpy.begin(), ZeroArray, hexCpy.size()));
    BOOST_CHECK(hexCpy.size() == 32);
    BOOST_CHECK(uint160::size() == 20);

    // check the uninitilized vs initialized constructor
    constexpr size_t wordSize = sizeof(void *);
    constexpr size_t dataSize = sizeof(uint256) + wordSize;
    std::array<uint8_t, dataSize> rawBuf;
    uint8_t *alignedPtr = rawBuf.data();
    // ensure aligned data pointer
    if (std::size_t(alignedPtr) % wordSize) {
        // not aligned, move forward by wordSize bytes, then back by the unaligned bytes
        const auto unaligned = std::size_t(alignedPtr) + wordSize;
        alignedPtr = reinterpret_cast<uint8_t *>(unaligned - unaligned % wordSize);
    }
    // check sanity of align code above
    const bool alignedOk = std::size_t(alignedPtr) % wordSize == 0
                           && rawBuf.end() - alignedPtr >= std::ptrdiff_t(sizeof(uint256))
                           && alignedPtr >= rawBuf.begin();
    BOOST_CHECK(alignedOk);
    if (alignedOk) {
        constexpr uint8_t uninitializedByte = 0xfa;
        const auto end = alignedPtr + sizeof(uint256);
        // 1. check that the Uninitialized constructor in fact does not initialize memory
        std::fill(alignedPtr, end, uninitializedByte); // set memory area to clearly uninitialized data
        // the below line prevents the above std::fill from being optimized away
        BOOST_CHECK(end > alignedPtr && *alignedPtr == uninitializedByte && end[-1] == uninitializedByte);
/* GCC 8.3.x warns here if compiling with -O3 -- but the warning is a false positive. We intentionally
 * are testing the uninitialized case here.  So we suppress the warning.
 * Note that clang doesn't know about -Wmaybe-uninitialized so we limit this pragma to GNUC only. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
        {
            // Note: this pointer is to data on the stack and should not be freed!
            uint256 *uninitialized = new (alignedPtr) uint256(uint256::Uninitialized); // explicitly does not initialize the data
            BOOST_CHECK(uninitialized->data() == alignedPtr);
            uninitialized->~uint256(); // end object lifetime immediately
            alignedPtr = std::launder(alignedPtr);
            unsigned uninitializedCtr = 0;
            // ensure the uninitialized c'tor left the data buffer unmolested
            for (size_t i = 0; i < uint256::size(); ++i) {
                uninitializedCtr += unsigned(alignedPtr[i] == uninitializedByte); // false = 0, true = 1
            }
            BOOST_CHECK(uninitializedCtr == uint256::size());
        }
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
        // 2. while we are here, check the default constructor zeroes out data
        std::fill(alignedPtr, end, uninitializedByte); // set memory area to clearly uninitialized data
        // the below line prevents the above std::fill from being optimized away
        BOOST_CHECK(end > alignedPtr && *alignedPtr == uninitializedByte && end[-1] == uninitializedByte);
        {
            // Note: this pointer is to data on the stack and should not be freed!
            uint256 *initialized = new (alignedPtr) uint256(); // implicitly zero-initializes the data
            unsigned initializedCtr = 0;
            // ensure the regular default c'tor zero-initialized the very same buffer
            for (const auto ch : *initialized) {
                initializedCtr += unsigned(ch == 0x0); // false = 0, true = 1
            }
            initialized->~uint256(); // end object lifetime politely
            BOOST_CHECK(initializedCtr == uint256::size());
        }
    }
}

BOOST_AUTO_TEST_CASE(conversion) {
    BOOST_CHECK(ArithToUint256(UintToArith256(ZeroL)) == ZeroL);
    BOOST_CHECK(ArithToUint256(UintToArith256(OneL)) == OneL);
    BOOST_CHECK(ArithToUint256(UintToArith256(R1L)) == R1L);
    BOOST_CHECK(ArithToUint256(UintToArith256(R2L)) == R2L);
    BOOST_CHECK(UintToArith256(ZeroL) == 0);
    BOOST_CHECK(UintToArith256(OneL) == 1);
    BOOST_CHECK(ArithToUint256(0) == ZeroL);
    BOOST_CHECK(ArithToUint256(1) == OneL);
    BOOST_CHECK(arith_uint256(R1L.GetHex()) == UintToArith256(R1L));
    BOOST_CHECK(arith_uint256(R2L.GetHex()) == UintToArith256(R2L));
    BOOST_CHECK(R1L.GetHex() == UintToArith256(R1L).GetHex());
    BOOST_CHECK(R2L.GetHex() == UintToArith256(R2L).GetHex());
}

// Use *& to remove self-assign warning.
#define SELF(x) (*&(x))

BOOST_AUTO_TEST_CASE(operator_with_self) {
    arith_uint256 v = UintToArith256(uint256S("02"));
    v *= SELF(v);
    BOOST_CHECK(v == UintToArith256(uint256S("04")));
    v /= SELF(v);
    BOOST_CHECK(v == UintToArith256(uint256S("01")));
    v += SELF(v);
    BOOST_CHECK(v == UintToArith256(uint256S("02")));
    v -= SELF(v);
    BOOST_CHECK(v == UintToArith256(uint256S("0")));
}

BOOST_AUTO_TEST_CASE(isnull_fuzz) {
    // Test 100 separate default-constructed instances and ensure they are IsNull()
    for (auto & [u256, u160] : std::vector<std::pair<uint256, uint160>>(100)) {
        BOOST_CHECK(u256.IsNull());
        BOOST_CHECK(u160.IsNull());

        // Next, randomly pick an index to set to nonzero for both u256 and u160, and IsNull should become false
        uint8_t randNonZeroByte;
        do {
            randNonZeroByte = InsecureRandRange(std::numeric_limits<uint8_t>::max()) + 1u;
        } while (!randNonZeroByte);
        // u256
        size_t idx = InsecureRandRange(u256.size());
        BOOST_REQUIRE(idx < u256.size());
        u256.data()[idx] = randNonZeroByte;
        BOOST_CHECK(!u256.IsNull());
        // u160
        BOOST_REQUIRE(u160.size() > 0);
        idx = InsecureRandRange(u160.size());
        BOOST_REQUIRE(idx < u160.size());
        u160.data()[idx] = randNonZeroByte;
        BOOST_CHECK(!u160.IsNull());
    }

    // Next, construct 100 uint256's and uint160's from random data and ensure they are not IsNull()
    for (size_t i = 0; i < 100; ++i) {
        const uint256 u256 = InsecureRand256();
        BOOST_CHECK(!u256.IsNull());

        uint160 u160{uint160::Uninitialized};
        const auto rb = g_insecure_rand_ctx.randbytes(u160.size());
        BOOST_REQUIRE(rb.size() == u160.size());
        std::copy(rb.begin(), rb.end(), u160.begin());
        BOOST_CHECK(!u160.IsNull());
    }
}

BOOST_AUTO_TEST_SUITE_END()
