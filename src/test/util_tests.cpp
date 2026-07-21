// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/system.h>

#include <clientversion.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/bit_cast.h>
#include <util/defer.h>
#include <util/hwaccel.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/overloaded.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#ifndef WIN32
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#endif

BOOST_FIXTURE_TEST_SUITE(util_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(util_criticalsection) {
    RecursiveMutex cs;

    do {
        LOCK(cs);
        break;

        BOOST_ERROR("break was swallowed!");
    } while (0);

    do {
        TRY_LOCK(cs, lockTest);
        if (lockTest) {
            // Needed to suppress "Test case [...] did not check any assertions"
            BOOST_CHECK(true);
            break;
        }

        BOOST_ERROR("break was swallowed!");
    } while (0);
}

static const uint8_t ParseHex_expected[65] = {
    0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67,
    0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0,
    0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6,
    0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04,
    0xe5, 0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b,
    0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f};
BOOST_AUTO_TEST_CASE(util_ParseHex) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> expected(
        ParseHex_expected, ParseHex_expected + sizeof(ParseHex_expected));
    // Basic test vector
    result = ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0"
                      "ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d"
                      "578a4c702b6bf11d5f");
    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                  expected.begin(), expected.end());

    // Spaces between bytes must be supported
    result = ParseHex("12 34 56 78");
    BOOST_CHECK(result.size() == 4 && result[0] == 0x12 && result[1] == 0x34 &&
                result[2] == 0x56 && result[3] == 0x78);

    // Leading space must be supported (used in BerkeleyEnvironment::Salvage)
    result = ParseHex(" 89 34 56 78");
    BOOST_CHECK(result.size() == 4 && result[0] == 0x89 && result[1] == 0x34 &&
                result[2] == 0x56 && result[3] == 0x78);

    // Stop parsing at invalid value
    result = ParseHex("1234 invalid 1234");
    BOOST_CHECK(result.size() == 2 && result[0] == 0x12 && result[1] == 0x34);
}

BOOST_AUTO_TEST_CASE(util_HexStr) {
    BOOST_CHECK_EQUAL(HexStr(ParseHex_expected),
                      "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0"
                      "ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d"
                      "578a4c702b6bf11d5f");

    BOOST_CHECK_EQUAL(HexStr(Span<const uint8_t>(ParseHex_expected).first(5), true), "04 67 8a fd b0");

    BOOST_CHECK_EQUAL(HexStr(Span<const uint8_t>(ParseHex_expected).last(0)), "");

    BOOST_CHECK_EQUAL(HexStr(Span<const uint8_t>(ParseHex_expected).last(0), true), "");

    BOOST_CHECK_EQUAL(HexStr(Span<const uint8_t>(ParseHex_expected).first(0)), "");

    BOOST_CHECK_EQUAL(HexStr(Span<const uint8_t>(ParseHex_expected).first(0), true), "");

    std::vector<uint8_t> ParseHex_vec(ParseHex_expected, ParseHex_expected + 5);

    BOOST_CHECK_EQUAL(HexStr(ParseHex_vec, true), "04 67 8a fd b0");

    BOOST_CHECK_EQUAL(HexStr(ParseHex_vec.rbegin(), ParseHex_vec.rend()),
                      "b0fd8a6704");

    BOOST_CHECK_EQUAL(HexStr(ParseHex_vec.rbegin(), ParseHex_vec.rend(), true),
                      "b0 fd 8a 67 04");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected)),
        "");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected), true),
        "");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected + 1),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected)),
        "04");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected + 1),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected), true),
        "04");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected + 5),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected)),
        "b0fd8a6704");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected + 5),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected), true),
        "b0 fd 8a 67 04");

    BOOST_CHECK_EQUAL(
        HexStr(std::reverse_iterator<const uint8_t *>(ParseHex_expected + 65),
               std::reverse_iterator<const uint8_t *>(ParseHex_expected)),
        "5f1df16b2b704c8a578d0bbaf74d385cde12c11ee50455f3c438ef4c3fbcf649b6de61"
        "1feae06279a60939e028a8d65c10b73071a6f16719274855feb0fd8a6704");

    // check that if begin > end, empty string is returned
    BOOST_CHECK_EQUAL(HexStr(ParseHex_expected + 10, ParseHex_expected + 1, true), "");
}

/// Test string utility functions: trim
BOOST_AUTO_TEST_CASE(util_TrimString, *boost::unit_test::timeout(5)) {
    static const std::string pattern = " \t\r\n";
    BOOST_CHECK_EQUAL(TrimString(" \t asdf \t fdsa\r \n", pattern), std::string{"asdf \t fdsa"});
    BOOST_CHECK_EQUAL(TrimString("\t\t\t asdf \t fdsa\r\r\r ", pattern), std::string{"asdf \t fdsa"});
    BOOST_CHECK_EQUAL(TrimString("", pattern), std::string{""});
    BOOST_CHECK_EQUAL(TrimString("\t\t\t", pattern), std::string{""});
    BOOST_CHECK_EQUAL(TrimString("\t\t\tA", pattern), std::string{"A"});
    BOOST_CHECK_EQUAL(TrimString("A\t\t\tA", pattern), std::string{"A\t\t\tA"});
    BOOST_CHECK_EQUAL(TrimString("A\t\t\t", pattern), std::string{"A"});
    BOOST_CHECK_EQUAL(TrimString(" \f\n\r\t\vasdf fdsa \f\n\r\t\v"), std::string{"asdf fdsa"}); // test default parameters
}

/// Test string utility functions: join
BOOST_AUTO_TEST_CASE(util_Join, *boost::unit_test::timeout(5)) {
    // Normal version
    BOOST_CHECK_EQUAL(Join({}, ", "), "");
    BOOST_CHECK_EQUAL(Join({"foo"}, ", "), "foo");
    BOOST_CHECK_EQUAL(Join({"foo", "bar"}, ", "), "foo, bar");

    // Version with unary operator
    const auto op_upper = [](const std::string &s) { return ToUpper(s); };
    BOOST_CHECK_EQUAL(Join<std::string>({}, ", ", op_upper), "");
    BOOST_CHECK_EQUAL(Join<std::string>({"foo"}, ", ", op_upper), "FOO");
    BOOST_CHECK_EQUAL(Join<std::string>({"foo", "bar"}, ", ", op_upper), "FOO, BAR");
}

static void SplitWrapper(std::vector<std::string> &result, std::string_view str,
                         std::optional<std::string_view> delims = std::nullopt, bool tokenCompress = false) {
    std::set<std::string> set;

    if (delims) {
        Split(result, str, *delims, tokenCompress);
        Split(set, str, *delims, tokenCompress);
    } else {
        // this is so that this test doesn't have to keep track of whatever the default delim arg is for Split()
        Split(result, str);
        Split(set, str);
    }

    // check that using std::set produces correct results as compared to the std::vector version.
    BOOST_CHECK(set == std::set<std::string>(result.begin(), result.end()));
}

/// Test string utility functions: split
BOOST_AUTO_TEST_CASE(util_Split, *boost::unit_test::timeout(5)) {
    std::vector<std::string> result;

    SplitWrapper(result, "", " \n");
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK(result[0].empty());

    SplitWrapper(result, "   ", " ");
    BOOST_CHECK_EQUAL(result.size(), 4);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[3].empty());

    SplitWrapper(result, "  .", " .");
    BOOST_CHECK_EQUAL(result.size(), 4);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[3].empty());

    SplitWrapper(result, "word", " \n");
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK_EQUAL(result[0], "word");

    SplitWrapper(result, "simple\ntest", " .\n");
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK_EQUAL(result[0], "simple");
    BOOST_CHECK_EQUAL(result[1], "test");

    SplitWrapper(result, "This is a test.", " .");
    BOOST_CHECK_EQUAL(result.size(), 5);
    BOOST_CHECK_EQUAL(result[0], "This");
    BOOST_CHECK_EQUAL(result[3], "test");
    BOOST_CHECK(result[4].empty());

    SplitWrapper(result, "This is a test...", " .");
    BOOST_CHECK_EQUAL(result.size(), 7);
    BOOST_CHECK_EQUAL(result[0], "This");
    BOOST_CHECK_EQUAL(result[3], "test");
    BOOST_CHECK(result[4].empty());

    SplitWrapper(result, " \f\n\r\t\vasdf fdsa \f\n\r\t\v"); // test default parameters
    BOOST_CHECK_EQUAL(result.size(), 14);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK_EQUAL(result[6], "asdf");
    BOOST_CHECK_EQUAL(result[7], "fdsa");
    BOOST_CHECK(result[3].empty());

    SplitWrapper(result, "", " \n", true);
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK(result[0].empty());

    SplitWrapper(result, "   ", " ", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());

    SplitWrapper(result, "  .", " .", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());

    SplitWrapper(result, "word", " \n", true);
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK_EQUAL(result[0], "word");

    SplitWrapper(result, "simple\ntest", " .\n", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK_EQUAL(result[0], "simple");
    BOOST_CHECK_EQUAL(result[1], "test");

    SplitWrapper(result, "This is a test.", " .", true);
    BOOST_CHECK_EQUAL(result.size(), 5);
    BOOST_CHECK_EQUAL(result[0], "This");
    BOOST_CHECK_EQUAL(result[3], "test");
    BOOST_CHECK(result[4].empty());

    SplitWrapper(result, "This is a test...", " .", true); // the same token should merge
    BOOST_CHECK_EQUAL(result.size(), 5);
    BOOST_CHECK_EQUAL(result[0], "This");
    BOOST_CHECK_EQUAL(result[3], "test");
    BOOST_CHECK(result[4].empty());

    SplitWrapper(result, " \f\n\r\t\vasdf fdsa \f\n\r\t\v", " \f\n\r\t\v", true);
    BOOST_CHECK_EQUAL(result.size(), 4);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK_EQUAL(result[1], "asdf");
    BOOST_CHECK_EQUAL(result[2], "fdsa");
    BOOST_CHECK(result[3].empty());

    // empty separator string should yield the same string again both for compressed and uncompressed version
    SplitWrapper(result, "i lack separators, compressed", "", true);
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK_EQUAL(result[0], "i lack separators, compressed");
    SplitWrapper(result, "i lack separators, uncompressed", "", false);
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK_EQUAL(result[0], "i lack separators, uncompressed");

    // nothing, with compression is 1 empty token
    SplitWrapper(result, "", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK(result[0].empty());
    // nothing, without compression is still 1 empty token
    SplitWrapper(result, "", ",");
    BOOST_CHECK_EQUAL(result.size(), 1);
    BOOST_CHECK(result[0].empty());

    // 2 empty fields, compressed, is 2 empty tokens
    SplitWrapper(result, ",", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    // 2 empty fields, not compressed is also 2 empty tokens
    SplitWrapper(result, ",", ",");
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());

    // 3 empty fields, compressed is 2 empty tokens
    SplitWrapper(result, ",,", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    // 3 empty fields, not compressed is 3 empty tokens
    SplitWrapper(result, ",,", ",");
    BOOST_CHECK_EQUAL(result.size(), 3);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());

    // N empty fields, compressed, is always 2 empty tokens
    SplitWrapper(result, ",,,,,", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    // N empty fields, not compressed, is N empty tokens
    SplitWrapper(result, ",,,,,", ",");
    BOOST_CHECK_EQUAL(result.size(), 6);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());
    BOOST_CHECK(result[3].empty());
    BOOST_CHECK(result[4].empty());
    BOOST_CHECK(result[5].empty());

    // an odd number of empty fields, plus a non-empty is 2 tokens
    SplitWrapper(result, ",,,hello", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK_EQUAL(result[1], "hello");
    // uncompressed: expect 4 tokens, 3 empty, 1 with "hello"
    SplitWrapper(result, ",,,hello", ",");
    BOOST_CHECK_EQUAL(result.size(), 4);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());
    BOOST_CHECK_EQUAL(result[3], "hello");

    // an even number of empty fields plus a non-empty is 2 tokens
    SplitWrapper(result, ",,,,hello", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK_EQUAL(result[1], "hello");
    // uncompressed: expect 5 tokens, 4 empty, 1 with "hello"
    SplitWrapper(result, ",,,,hello", ",");
    BOOST_CHECK_EQUAL(result.size(), 5);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());
    BOOST_CHECK(result[3].empty());
    BOOST_CHECK_EQUAL(result[4], "hello");

    // a non-empty, a bunch of empties, and a non-empty is 2 tokens
    SplitWrapper(result, "1,,,,hello", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 2);
    BOOST_CHECK_EQUAL(result[0], "1");
    BOOST_CHECK_EQUAL(result[1], "hello");
    // uncompressed: 5 tokens
    SplitWrapper(result, "1,,,,hello", ",", false);
    BOOST_CHECK_EQUAL(result.size(), 5);
    BOOST_CHECK_EQUAL(result[0], "1");
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());
    BOOST_CHECK(result[3].empty());
    BOOST_CHECK_EQUAL(result[4], "hello");

    // compressed: a bunch of empties, a non-empty, a bunch of empties
    SplitWrapper(result, ",,,1,,,,hello", ",", true);
    BOOST_CHECK_EQUAL(result.size(), 3);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK_EQUAL(result[1], "1");
    BOOST_CHECK_EQUAL(result[2], "hello");
    // uncompressed: it's 8 tokens
    SplitWrapper(result, ",,,1,,,,hello", ",", false);
    BOOST_CHECK_EQUAL(result.size(), 8);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1].empty());
    BOOST_CHECK(result[2].empty());
    BOOST_CHECK_EQUAL(result[3], "1");
    BOOST_CHECK(result[4].empty());
    BOOST_CHECK(result[5].empty());
    BOOST_CHECK(result[6].empty());
    BOOST_CHECK_EQUAL(result[7], "hello");
}

/// Test string utility functions: replace all
BOOST_AUTO_TEST_CASE(util_ReplaceAll, *boost::unit_test::timeout(5)) {
    auto test_replaceall = [](std::string const &input,
                              std::string const &search,
                              std::string const &format,
                              std::string const &expected){
        std::string input_copy{input};
        ReplaceAll(input_copy, search, format);
        BOOST_CHECK_EQUAL(input_copy, expected);
    };

    // adapted and expanded from boost unit tests for replace_all and erase_all
    test_replaceall("1abc3abc2", "abc", "YYY", "1YYY3YYY2");
    test_replaceall("1abc3abc2", "/", "\\", "1abc3abc2");
    test_replaceall("1abc3abc2", "abc", "Z", "1Z3Z2");
    test_replaceall("1abc3abc2", "abc", "XXXX", "1XXXX3XXXX2");
    test_replaceall("1abc3abc2", "XXXX", "", "1abc3abc2");
    test_replaceall("1abc3abc2", "", "XXXX", "1abc3abc2");
    test_replaceall("1abc3abc2", "", "", "1abc3abc2");
    test_replaceall("1abc3abc2", "abc", "", "132");
    test_replaceall("1abc3abc2", "", "", "1abc3abc2");
    test_replaceall("aaaBBaaaBBaa", "BB", "cBBc", "aaacBBcaaacBBcaa");
    test_replaceall("", "abc", "XXXX", "");
    test_replaceall("", "abc", "", "");
    test_replaceall("", "", "XXXX", "");
    test_replaceall("", "", "", "");
}

/// Test string utility functions: validate
BOOST_AUTO_TEST_CASE(util_ValidAsCString, *boost::unit_test::timeout(5)) {
    using namespace std::string_literals; // since C++14 using std::string literals allows us to embed null characters
    BOOST_CHECK(ValidAsCString("valid"));
    BOOST_CHECK(ValidAsCString(std::string{"valid"}));
    BOOST_CHECK(ValidAsCString(std::string{"valid"s}));
    BOOST_CHECK(ValidAsCString("valid"s));
    BOOST_CHECK(!ValidAsCString("invalid\0"s));
    BOOST_CHECK(!ValidAsCString("\0invalid"s));
    BOOST_CHECK(!ValidAsCString("inv\0alid"s));
    BOOST_CHECK(ValidAsCString(""s));
    BOOST_CHECK(!ValidAsCString("\0"s));
}

BOOST_AUTO_TEST_CASE(util_FormatParseISO8601DateTime) {
    BOOST_CHECK_EQUAL(FormatISO8601DateTime(1317425777),
                      "2011-09-30T23:36:17Z");
    BOOST_CHECK_EQUAL(FormatISO8601DateTime(0), "1970-01-01T00:00:00Z");

    BOOST_CHECK_EQUAL(ParseISO8601DateTime("1970-01-01T00:00:00Z"), 0);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("1960-01-01T00:00:00Z"), 0);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("2011-09-30T23:36:17Z"), 1317425777);

    auto time = GetSystemTimeInSeconds();
    BOOST_CHECK_EQUAL(ParseISO8601DateTime(FormatISO8601DateTime(time)), time);
}

BOOST_AUTO_TEST_CASE(util_FormatISO8601Date) {
    BOOST_CHECK_EQUAL(FormatISO8601Date(1317425777), "2011-09-30");
}

struct TestArgsManager : public ArgsManager {
    TestArgsManager() { m_network_only_args.clear(); }
    std::map<std::string, std::vector<std::string>> &GetOverrideArgs() {
        return m_override_args;
    }
    std::map<std::string, std::vector<std::string>> &GetConfigArgs() {
        return m_config_args;
    }
    void ReadConfigString(const std::string str_config) {
        std::istringstream streamConfig(str_config);
        {
            LOCK(cs_args);
            m_config_args.clear();
            m_config_sections.clear();
        }
        std::string error;
        BOOST_REQUIRE(ReadConfigStream(streamConfig, "", error));
    }
    void SetNetworkOnlyArg(const std::string arg) {
        LOCK(cs_args);
        m_network_only_args.insert(arg);
    }
    void
    SetupArgs(const std::vector<std::pair<std::string, unsigned int>> &args) {
        for (const auto &arg : args) {
            AddArg(arg.first, "", arg.second, OptionsCategory::OPTIONS);
        }
    }
    using ArgsManager::cs_args;
    using ArgsManager::m_network;
    using ArgsManager::ReadConfigStream;
};

BOOST_AUTO_TEST_CASE(util_ParseParameters) {
    TestArgsManager testArgs;
    const auto a = std::make_pair("-a", ArgsManager::ALLOW_ANY);
    const auto b = std::make_pair("-b", ArgsManager::ALLOW_ANY);
    const auto ccc = std::make_pair("-ccc", ArgsManager::ALLOW_ANY);
    const auto d = std::make_pair("-d", ArgsManager::ALLOW_ANY);

    const char *argv_test[] = {"-ignored",      "-a", "-b",  "-ccc=argument",
                               "-ccc=multiple", "f",  "-d=e"};

    std::string error;
    testArgs.SetupArgs({a, b, ccc, d});

    BOOST_CHECK(testArgs.ParseParameters(1, (char **)argv_test, error));
    BOOST_CHECK(testArgs.GetOverrideArgs().empty() &&
                testArgs.GetConfigArgs().empty());

    BOOST_CHECK(testArgs.ParseParameters(7, (char **)argv_test, error));
    // expectation: -ignored is ignored (program name argument),
    // -a, -b and -ccc end up in map, -d ignored because it is after
    // a non-option argument (non-GNU option parsing)
    BOOST_CHECK(testArgs.GetOverrideArgs().size() == 3 &&
                testArgs.GetConfigArgs().empty());
    BOOST_CHECK(testArgs.IsArgSet("-a") && testArgs.IsArgSet("-b") &&
                testArgs.IsArgSet("-ccc") && !testArgs.IsArgSet("f") &&
                !testArgs.IsArgSet("-d"));
    BOOST_CHECK(testArgs.GetOverrideArgs().count("-a") &&
                testArgs.GetOverrideArgs().count("-b") &&
                testArgs.GetOverrideArgs().count("-ccc") &&
                !testArgs.GetOverrideArgs().count("f") &&
                !testArgs.GetOverrideArgs().count("-d"));

    BOOST_CHECK(testArgs.GetOverrideArgs()["-a"].size() == 1);
    BOOST_CHECK(testArgs.GetOverrideArgs()["-a"].front() == "");
    BOOST_CHECK(testArgs.GetOverrideArgs()["-ccc"].size() == 2);
    BOOST_CHECK(testArgs.GetOverrideArgs()["-ccc"].front() == "argument");
    BOOST_CHECK(testArgs.GetOverrideArgs()["-ccc"].back() == "multiple");
    BOOST_CHECK(testArgs.GetArgs("-ccc").size() == 2);
}

BOOST_AUTO_TEST_CASE(util_ParseKeyValue) {
    {
        std::string key = "badarg";
        std::string value;
        BOOST_CHECK(!ParseKeyValue(key, value));
    }
    {
        std::string key = "badarg=v";
        std::string value;
        BOOST_CHECK(!ParseKeyValue(key, value));
    }
    {
        std::string key = "-a";
        std::string value;
        BOOST_CHECK(ParseKeyValue(key, value));
        BOOST_CHECK_EQUAL(key, "-a");
        BOOST_CHECK_EQUAL(value, "");
    }
    {
        std::string key = "-a=1";
        std::string value;
        BOOST_CHECK(ParseKeyValue(key, value));
        BOOST_CHECK_EQUAL(key, "-a");
        BOOST_CHECK_EQUAL(value, "1");
    }
    {
        std::string key = "--b";
        std::string value;
        BOOST_CHECK(ParseKeyValue(key, value));
        BOOST_CHECK_EQUAL(key, "-b");
        BOOST_CHECK_EQUAL(value, "");
    }
    {
        std::string key = "--b=abc";
        std::string value;
        BOOST_CHECK(ParseKeyValue(key, value));
        BOOST_CHECK_EQUAL(key, "-b");
        BOOST_CHECK_EQUAL(value, "abc");
    }
}

BOOST_AUTO_TEST_CASE(util_GetBoolArg) {
    TestArgsManager testArgs;
    const auto a = std::make_pair("-a", ArgsManager::ALLOW_BOOL);
    const auto b = std::make_pair("-b", ArgsManager::ALLOW_BOOL);
    const auto c = std::make_pair("-c", ArgsManager::ALLOW_BOOL);
    const auto d = std::make_pair("-d", ArgsManager::ALLOW_BOOL);
    const auto e = std::make_pair("-e", ArgsManager::ALLOW_BOOL);
    const auto f = std::make_pair("-f", ArgsManager::ALLOW_BOOL);

    const char *argv_test[] = {"ignored", "-a",       "-nob",   "-c=0",
                               "-d=1",    "-e=false", "-f=true"};
    std::string error;
    testArgs.SetupArgs({a, b, c, d, e, f});
    BOOST_CHECK(testArgs.ParseParameters(7, (char **)argv_test, error));

    // Each letter should be set.
    for (const char opt : "abcdef") {
        BOOST_CHECK(testArgs.IsArgSet({'-', opt}) || !opt);
    }

    // Nothing else should be in the map
    BOOST_CHECK(testArgs.GetOverrideArgs().size() == 6 &&
                testArgs.GetConfigArgs().empty());

    // The -no prefix should get stripped on the way in.
    BOOST_CHECK(!testArgs.IsArgSet("-nob"));

    // The -b option is flagged as negated, and nothing else is
    BOOST_CHECK(testArgs.IsArgNegated("-b"));
    BOOST_CHECK(!testArgs.IsArgNegated("-a"));

    // Check expected values.
    BOOST_CHECK(testArgs.GetBoolArg("-a", false) == true);
    BOOST_CHECK(testArgs.GetBoolArg("-b", true) == false);
    BOOST_CHECK(testArgs.GetBoolArg("-c", true) == false);
    BOOST_CHECK(testArgs.GetBoolArg("-d", false) == true);
    BOOST_CHECK(testArgs.GetBoolArg("-e", true) == false);
    BOOST_CHECK(testArgs.GetBoolArg("-f", true) == false);
}

BOOST_AUTO_TEST_CASE(util_GetBoolArgEdgeCases) {
    // Test some awful edge cases that hopefully no user will ever exercise.
    TestArgsManager testArgs;

    // Params test
    const auto foo = std::make_pair("-foo", ArgsManager::ALLOW_BOOL);
    const auto bar = std::make_pair("-bar", ArgsManager::ALLOW_BOOL);
    const char *argv_test[] = {"ignored", "-nofoo", "-foo", "-nobar=0"};
    testArgs.SetupArgs({foo, bar});
    std::string error;
    BOOST_CHECK(testArgs.ParseParameters(4, (char **)argv_test, error));

    // This was passed twice, second one overrides the negative setting.
    BOOST_CHECK(!testArgs.IsArgNegated("-foo"));
    BOOST_CHECK(testArgs.GetArg("-foo", "xxx") == "");

    // A double negative is a positive, and not marked as negated.
    BOOST_CHECK(!testArgs.IsArgNegated("-bar"));
    BOOST_CHECK(testArgs.GetArg("-bar", "xxx") == "1");

    // Config test
    const char *conf_test = "nofoo=1\nfoo=1\nnobar=0\n";
    BOOST_CHECK(testArgs.ParseParameters(1, (char **)argv_test, error));
    testArgs.ReadConfigString(conf_test);

    // This was passed twice, second one overrides the negative setting,
    // and the value.
    BOOST_CHECK(!testArgs.IsArgNegated("-foo"));
    BOOST_CHECK(testArgs.GetArg("-foo", "xxx") == "1");

    // A double negative is a positive, and does not count as negated.
    BOOST_CHECK(!testArgs.IsArgNegated("-bar"));
    BOOST_CHECK(testArgs.GetArg("-bar", "xxx") == "1");

    // Combined test
    const char *combo_test_args[] = {"ignored", "-nofoo", "-bar"};
    const char *combo_test_conf = "foo=1\nnobar=1\n";
    BOOST_CHECK(testArgs.ParseParameters(3, (char **)combo_test_args, error));
    testArgs.ReadConfigString(combo_test_conf);

    // Command line overrides, but doesn't erase old setting
    BOOST_CHECK(testArgs.IsArgNegated("-foo"));
    BOOST_CHECK(testArgs.GetArg("-foo", "xxx") == "0");
    BOOST_CHECK(testArgs.GetArgs("-foo").size() == 0);

    // Command line overrides, but doesn't erase old setting
    BOOST_CHECK(!testArgs.IsArgNegated("-bar"));
    BOOST_CHECK(testArgs.GetArg("-bar", "xxx") == "");
    BOOST_CHECK(testArgs.GetArgs("-bar").size() == 1 &&
                testArgs.GetArgs("-bar").front() == "");
}

BOOST_AUTO_TEST_CASE(util_ReadConfigStream) {
    const char *str_config = "a=\n"
                             "b=1\n"
                             "ccc=argument\n"
                             "ccc=multiple\n"
                             "d=e\n"
                             "nofff=1\n"
                             "noggg=0\n"
                             "h=1\n"
                             "noh=1\n"
                             "noi=1\n"
                             "i=1\n"
                             "sec1.ccc=extend1\n"
                             "\n"
                             "[sec1]\n"
                             "ccc=extend2\n"
                             "d=eee\n"
                             "h=1\n"
                             "[sec2]\n"
                             "ccc=extend3\n"
                             "iii=2\n";

    TestArgsManager test_args;
    const auto a = std::make_pair("-a", ArgsManager::ALLOW_BOOL);
    const auto b = std::make_pair("-b", ArgsManager::ALLOW_BOOL);
    const auto ccc = std::make_pair("-ccc", ArgsManager::ALLOW_STRING);
    const auto d = std::make_pair("-d", ArgsManager::ALLOW_STRING);
    const auto e = std::make_pair("-e", ArgsManager::ALLOW_ANY);
    const auto fff = std::make_pair("-fff", ArgsManager::ALLOW_BOOL);
    const auto ggg = std::make_pair("-ggg", ArgsManager::ALLOW_BOOL);
    const auto h = std::make_pair("-h", ArgsManager::ALLOW_BOOL);
    const auto i = std::make_pair("-i", ArgsManager::ALLOW_BOOL);
    const auto iii = std::make_pair("-iii", ArgsManager::ALLOW_INT);
    test_args.SetupArgs({a, b, ccc, d, e, fff, ggg, h, i, iii});

    test_args.ReadConfigString(str_config);
    // expectation: a, b, ccc, d, fff, ggg, h, i end up in map
    // so do sec1.ccc, sec1.d, sec1.h, sec2.ccc, sec2.iii

    BOOST_CHECK(test_args.GetOverrideArgs().empty());
    BOOST_CHECK(test_args.GetConfigArgs().size() == 13);

    BOOST_CHECK(test_args.GetConfigArgs().count("-a") &&
                test_args.GetConfigArgs().count("-b") &&
                test_args.GetConfigArgs().count("-ccc") &&
                test_args.GetConfigArgs().count("-d") &&
                test_args.GetConfigArgs().count("-fff") &&
                test_args.GetConfigArgs().count("-ggg") &&
                test_args.GetConfigArgs().count("-h") &&
                test_args.GetConfigArgs().count("-i"));
    BOOST_CHECK(test_args.GetConfigArgs().count("-sec1.ccc") &&
                test_args.GetConfigArgs().count("-sec1.h") &&
                test_args.GetConfigArgs().count("-sec2.ccc") &&
                test_args.GetConfigArgs().count("-sec2.iii"));

    BOOST_CHECK(test_args.IsArgSet("-a") && test_args.IsArgSet("-b") &&
                test_args.IsArgSet("-ccc") && test_args.IsArgSet("-d") &&
                test_args.IsArgSet("-fff") && test_args.IsArgSet("-ggg") &&
                test_args.IsArgSet("-h") && test_args.IsArgSet("-i") &&
                !test_args.IsArgSet("-zzz") && !test_args.IsArgSet("-iii"));

    BOOST_CHECK(test_args.GetArg("-a", "xxx") == "" &&
                test_args.GetArg("-b", "xxx") == "1" &&
                test_args.GetArg("-ccc", "xxx") == "argument" &&
                test_args.GetArg("-d", "xxx") == "e" &&
                test_args.GetArg("-fff", "xxx") == "0" &&
                test_args.GetArg("-ggg", "xxx") == "1" &&
                test_args.GetArg("-h", "xxx") == "0" &&
                test_args.GetArg("-i", "xxx") == "1" &&
                test_args.GetArg("-zzz", "xxx") == "xxx" &&
                test_args.GetArg("-iii", "xxx") == "xxx");

    for (const bool def : {false, true}) {
        BOOST_CHECK(test_args.GetBoolArg("-a", def) &&
                    test_args.GetBoolArg("-b", def) &&
                    !test_args.GetBoolArg("-ccc", def) &&
                    !test_args.GetBoolArg("-d", def) &&
                    !test_args.GetBoolArg("-fff", def) &&
                    test_args.GetBoolArg("-ggg", def) &&
                    !test_args.GetBoolArg("-h", def) &&
                    test_args.GetBoolArg("-i", def) &&
                    test_args.GetBoolArg("-zzz", def) == def &&
                    test_args.GetBoolArg("-iii", def) == def);
    }

    BOOST_CHECK(test_args.GetArgs("-a").size() == 1 &&
                test_args.GetArgs("-a").front() == "");
    BOOST_CHECK(test_args.GetArgs("-b").size() == 1 &&
                test_args.GetArgs("-b").front() == "1");
    BOOST_CHECK(test_args.GetArgs("-ccc").size() == 2 &&
                test_args.GetArgs("-ccc").front() == "argument" &&
                test_args.GetArgs("-ccc").back() == "multiple");
    BOOST_CHECK(test_args.GetArgs("-fff").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-nofff").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-ggg").size() == 1 &&
                test_args.GetArgs("-ggg").front() == "1");
    BOOST_CHECK(test_args.GetArgs("-noggg").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-h").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-noh").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-i").size() == 1 &&
                test_args.GetArgs("-i").front() == "1");
    BOOST_CHECK(test_args.GetArgs("-noi").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-zzz").size() == 0);

    BOOST_CHECK(!test_args.IsArgNegated("-a"));
    BOOST_CHECK(!test_args.IsArgNegated("-b"));
    BOOST_CHECK(!test_args.IsArgNegated("-ccc"));
    BOOST_CHECK(!test_args.IsArgNegated("-d"));
    BOOST_CHECK(test_args.IsArgNegated("-fff"));
    BOOST_CHECK(!test_args.IsArgNegated("-ggg"));
    // last setting takes precedence
    BOOST_CHECK(test_args.IsArgNegated("-h"));
    // last setting takes precedence
    BOOST_CHECK(!test_args.IsArgNegated("-i"));
    BOOST_CHECK(!test_args.IsArgNegated("-zzz"));

    // Test sections work
    test_args.SelectConfigNetwork("sec1");

    // same as original
    BOOST_CHECK(test_args.GetArg("-a", "xxx") == "" &&
                test_args.GetArg("-b", "xxx") == "1" &&
                test_args.GetArg("-fff", "xxx") == "0" &&
                test_args.GetArg("-ggg", "xxx") == "1" &&
                test_args.GetArg("-zzz", "xxx") == "xxx" &&
                test_args.GetArg("-iii", "xxx") == "xxx");
    // d is overridden
    BOOST_CHECK(test_args.GetArg("-d", "xxx") == "eee");
    // section-specific setting
    BOOST_CHECK(test_args.GetArg("-h", "xxx") == "1");
    // section takes priority for multiple values
    BOOST_CHECK(test_args.GetArg("-ccc", "xxx") == "extend1");
    // check multiple values works
    const std::vector<std::string> sec1_ccc_expected = {"extend1", "extend2",
                                                        "argument", "multiple"};
    const auto &sec1_ccc_res = test_args.GetArgs("-ccc");
    BOOST_CHECK_EQUAL_COLLECTIONS(sec1_ccc_res.begin(), sec1_ccc_res.end(),
                                  sec1_ccc_expected.begin(),
                                  sec1_ccc_expected.end());

    test_args.SelectConfigNetwork("sec2");

    // same as original
    BOOST_CHECK(test_args.GetArg("-a", "xxx") == "" &&
                test_args.GetArg("-b", "xxx") == "1" &&
                test_args.GetArg("-d", "xxx") == "e" &&
                test_args.GetArg("-fff", "xxx") == "0" &&
                test_args.GetArg("-ggg", "xxx") == "1" &&
                test_args.GetArg("-zzz", "xxx") == "xxx" &&
                test_args.GetArg("-h", "xxx") == "0");
    // section-specific setting
    BOOST_CHECK(test_args.GetArg("-iii", "xxx") == "2");
    // section takes priority for multiple values
    BOOST_CHECK(test_args.GetArg("-ccc", "xxx") == "extend3");
    // check multiple values works
    const std::vector<std::string> sec2_ccc_expected = {"extend3", "argument",
                                                        "multiple"};
    const auto &sec2_ccc_res = test_args.GetArgs("-ccc");
    BOOST_CHECK_EQUAL_COLLECTIONS(sec2_ccc_res.begin(), sec2_ccc_res.end(),
                                  sec2_ccc_expected.begin(),
                                  sec2_ccc_expected.end());

    // Test section only options

    test_args.SetNetworkOnlyArg("-d");
    test_args.SetNetworkOnlyArg("-ccc");
    test_args.SetNetworkOnlyArg("-h");

    test_args.SelectConfigNetwork(CBaseChainParams::MAIN);
    BOOST_CHECK(test_args.GetArg("-d", "xxx") == "e");
    BOOST_CHECK(test_args.GetArgs("-ccc").size() == 2);
    BOOST_CHECK(test_args.GetArg("-h", "xxx") == "0");

    test_args.SelectConfigNetwork("sec1");
    BOOST_CHECK(test_args.GetArg("-d", "xxx") == "eee");
    BOOST_CHECK(test_args.GetArgs("-d").size() == 1);
    BOOST_CHECK(test_args.GetArgs("-ccc").size() == 2);
    BOOST_CHECK(test_args.GetArg("-h", "xxx") == "1");

    test_args.SelectConfigNetwork("sec2");
    BOOST_CHECK(test_args.GetArg("-d", "xxx") == "xxx");
    BOOST_CHECK(test_args.GetArgs("-d").size() == 0);
    BOOST_CHECK(test_args.GetArgs("-ccc").size() == 1);
    BOOST_CHECK(test_args.GetArg("-h", "xxx") == "0");
}

BOOST_AUTO_TEST_CASE(util_GetArg) {
    TestArgsManager testArgs;
    testArgs.GetOverrideArgs().clear();
    testArgs.GetOverrideArgs()["strtest1"] = {"string..."};
    // strtest2 undefined on purpose
    testArgs.GetOverrideArgs()["inttest1"] = {"12345"};
    testArgs.GetOverrideArgs()["inttest2"] = {"81985529216486895"};
    // inttest3 undefined on purpose
    testArgs.GetOverrideArgs()["booltest1"] = {""};
    // booltest2 undefined on purpose
    testArgs.GetOverrideArgs()["booltest3"] = {"0"};
    testArgs.GetOverrideArgs()["booltest4"] = {"1"};

    // priorities
    testArgs.GetOverrideArgs()["pritest1"] = {"a", "b"};
    testArgs.GetConfigArgs()["pritest2"] = {"a", "b"};
    testArgs.GetOverrideArgs()["pritest3"] = {"a"};
    testArgs.GetConfigArgs()["pritest3"] = {"b"};
    testArgs.GetOverrideArgs()["pritest4"] = {"a", "b"};
    testArgs.GetConfigArgs()["pritest4"] = {"c", "d"};

    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest1", -1), 12345);
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest2", -1), 81985529216486895LL);
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest3", -1), -1);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", false), true);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest2", false), false);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest3", false), false);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest4", false), true);

    BOOST_CHECK_EQUAL(testArgs.GetArg("pritest1", "default"), "b");
    BOOST_CHECK_EQUAL(testArgs.GetArg("pritest2", "default"), "a");
    BOOST_CHECK_EQUAL(testArgs.GetArg("pritest3", "default"), "a");
    BOOST_CHECK_EQUAL(testArgs.GetArg("pritest4", "default"), "b");
}

BOOST_AUTO_TEST_CASE(util_ClearArg) {
    TestArgsManager testArgs;

    // Clear single string arg
    testArgs.GetOverrideArgs()["strtest1"] = {"string..."};
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "string...");
    testArgs.ClearArg("strtest1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "default");

    // Clear boolean arg
    testArgs.GetOverrideArgs()["booltest1"] = {"1"};
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", false), true);
    testArgs.ClearArg("booltest1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("booltest1", false), false);

    // Clear config args only
    testArgs.GetConfigArgs()["strtest2"].push_back("string...");
    testArgs.GetConfigArgs()["strtest2"].push_back("...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 2);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").back(), "...gnirts");
    testArgs.ClearArg("strtest2");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 0);

    // Clear both cli args and config args
    testArgs.GetOverrideArgs()["strtest3"].push_back("cli string...");
    testArgs.GetOverrideArgs()["strtest3"].push_back("...gnirts ilc");
    testArgs.GetConfigArgs()["strtest3"].push_back("string...");
    testArgs.GetConfigArgs()["strtest3"].push_back("...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest3", "default"), "...gnirts ilc");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest3").size(), 4);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest3").front(), "cli string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest3").back(), "...gnirts");
    testArgs.ClearArg("strtest3");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest3", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest3").size(), 0);
}

BOOST_AUTO_TEST_CASE(util_SetArg) {
    TestArgsManager testArgs;

    // SoftSetArg
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.SoftSetArg("strtest1", "string..."), true);
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest1").size(), 1);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest1").front(), "string...");
    BOOST_CHECK_EQUAL(testArgs.SoftSetArg("strtest1", "...gnirts"), false);
    testArgs.ClearArg("strtest1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.SoftSetArg("strtest1", "...gnirts"), true);
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "...gnirts");

    // SoftSetBoolArg
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", false), false);
    BOOST_CHECK_EQUAL(testArgs.SoftSetBoolArg("booltest1", true), true);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", false), true);
    BOOST_CHECK_EQUAL(testArgs.SoftSetBoolArg("booltest1", false), false);
    testArgs.ClearArg("booltest1");
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", true), true);
    BOOST_CHECK_EQUAL(testArgs.SoftSetBoolArg("booltest1", false), true);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", true), false);

    // ForceSetArg
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "default");
    testArgs.ForceSetArg("strtest2", "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 1);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "string...");
    testArgs.ForceSetArg("strtest2", "...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 1);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "...gnirts");

    // ForceSetMultiArg
    testArgs.ForceSetMultiArg("strtest2", "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 2);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").back(), "string...");
    testArgs.ClearArg("strtest2");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 0);
    testArgs.ForceSetMultiArg("strtest2", "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 1);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "string...");
    testArgs.ForceSetMultiArg("strtest2", "one more thing...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"),
                      "one more thing...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 2);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").back(), "one more thing...");
    // If there are multi args, ForceSetArg should erase them
    testArgs.ForceSetArg("strtest2", "...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "...gnirts");
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").size(), 1);
    BOOST_CHECK_EQUAL(testArgs.GetArgs("strtest2").front(), "...gnirts");
}

BOOST_AUTO_TEST_CASE(util_GetChainName) {
    TestArgsManager test_args;
    const auto testnet = std::make_pair("-testnet", ArgsManager::ALLOW_BOOL);
    const auto regtest = std::make_pair("-regtest", ArgsManager::ALLOW_BOOL);
    test_args.SetupArgs({testnet, regtest});

    const char *argv_testnet[] = {"cmd", "-testnet"};
    const char *argv_regtest[] = {"cmd", "-regtest"};
    const char *argv_test_no_reg[] = {"cmd", "-testnet", "-noregtest"};
    const char *argv_both[] = {"cmd", "-testnet", "-regtest"};

    // equivalent to "-testnet"
    // regtest in testnet section is ignored
    const char *testnetconf = "testnet=1\nregtest=0\n[test]\nregtest=1";
    std::string error;

    BOOST_CHECK(test_args.ParseParameters(0, (char **)argv_testnet, error));
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "main");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_testnet, error));
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_regtest, error));
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "regtest");

    BOOST_CHECK(test_args.ParseParameters(3, (char **)argv_test_no_reg, error));
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(3, (char **)argv_both, error));
    BOOST_CHECK_THROW(test_args.GetChainName(), std::runtime_error);

    BOOST_CHECK(test_args.ParseParameters(0, (char **)argv_testnet, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_testnet, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_regtest, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_THROW(test_args.GetChainName(), std::runtime_error);

    BOOST_CHECK(test_args.ParseParameters(3, (char **)argv_test_no_reg, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(3, (char **)argv_both, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_THROW(test_args.GetChainName(), std::runtime_error);

    // check setting the network to test (and thus making
    // [test] regtest=1 potentially relevant) doesn't break things
    test_args.SelectConfigNetwork("test");

    BOOST_CHECK(test_args.ParseParameters(0, (char **)argv_testnet, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_testnet, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_regtest, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_THROW(test_args.GetChainName(), std::runtime_error);

    BOOST_CHECK(test_args.ParseParameters(2, (char **)argv_test_no_reg, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_EQUAL(test_args.GetChainName(), "test");

    BOOST_CHECK(test_args.ParseParameters(3, (char **)argv_both, error));
    test_args.ReadConfigString(testnetconf);
    BOOST_CHECK_THROW(test_args.GetChainName(), std::runtime_error);
}

// Test different ways settings can be merged, and verify results. This test can
// be used to confirm that updates to settings code don't change behavior
// unintentionally.
//
// The test covers:
//
// - Combining different setting actions. Possible actions are: configuring a
//   setting, negating a setting (adding "-no" prefix), and configuring/negating
//   settings in a network section (adding "main." or "test." prefixes).
//
// - Combining settings from command line arguments and a config file.
//
// - Combining SoftSet and ForceSet calls.
//
// - Testing "main" and "test" network values to make sure settings from network
//   sections are applied and to check for mainnet-specific behaviors like
//   inheriting settings from the default section.
//
// - Testing network-specific settings like "-wallet", that may be ignored
//   outside a network section, and non-network specific settings like "-server"
//   that aren't sensitive to the network.
//
struct SettingsMergeTestingSetup : public BasicTestingSetup {
    //! Max number of actions to sequence together. Can decrease this when
    //! debugging to make test results easier to understand.
    static constexpr int MAX_ACTIONS = 3;

    enum Action { SET = 0, NEGATE, SECTION_SET, SECTION_NEGATE, END };
    using ActionList = Action[MAX_ACTIONS];

    //! Enumerate all possible test configurations.
    template <typename Fn> void ForEachMergeSetup(Fn &&fn) {
        ForEachActionList([&](const ActionList &arg_actions) {
            ForEachActionList([&](const ActionList &conf_actions) {
                for (bool soft_set : {false, true}) {
                    for (bool force_set : {false, true}) {
                        for (const std::string &section :
                             {CBaseChainParams::MAIN,
                              CBaseChainParams::TESTNET,
                              CBaseChainParams::TESTNET4,
                              CBaseChainParams::SCALENET,
                              CBaseChainParams::CHIPNET}) {
                            for (const std::string &network :
                                 {CBaseChainParams::MAIN,
                                  CBaseChainParams::TESTNET,
                                  CBaseChainParams::TESTNET4,
                                  CBaseChainParams::SCALENET,
                                  CBaseChainParams::CHIPNET}) {
                                for (bool net_specific : {false, true}) {
                                    fn(arg_actions, conf_actions, soft_set,
                                       force_set, section, network,
                                       net_specific);
                                }
                            }
                        }
                    }
                }
            });
        });
    }

    //! Enumerate interesting combinations of actions.
    template <typename Fn> void ForEachActionList(Fn &&fn) {
        ActionList actions = {SET};
        for (bool done = false; !done;) {
            int prev_action = -1;
            bool skip_actions = false;
            for (Action action : actions) {
                if ((prev_action == END && action != END) ||
                    (prev_action != END && action == prev_action)) {
                    // To cut down list of enumerated settings, skip enumerating
                    // settings with ignored actions after an END, and settings
                    // that repeat the same action twice in a row.
                    skip_actions = true;
                    break;
                }
                prev_action = action;
            }
            if (!skip_actions) {
                fn(actions);
            }
            done = true;
            for (Action &action : actions) {
                action = Action(action < END ? action + 1 : 0);
                if (action) {
                    done = false;
                    break;
                }
            }
        }
    }

    //! Translate actions into a list of <key>=<value> setting strings.
    std::vector<std::string> GetValues(const ActionList &actions,
                                       const std::string &section,
                                       const std::string &name,
                                       const std::string &value_prefix) {
        std::vector<std::string> values;
        int suffix = 0;
        for (Action action : actions) {
            if (action == END) {
                break;
            }
            std::string prefix;
            if (action == SECTION_SET || action == SECTION_NEGATE) {
                prefix = section + ".";
            }
            if (action == SET || action == SECTION_SET) {
                for (int i = 0; i < 2; ++i) {
                    values.push_back(prefix + name + "=" + value_prefix +
                                     std::to_string(++suffix));
                }
            }
            if (action == NEGATE || action == SECTION_NEGATE) {
                values.push_back(prefix + "no" + name + "=1");
            }
        }
        return values;
    }
};

// Regression test covering different ways config settings can be merged. The
// test parses and merges settings, representing the results as strings that get
// compared against an expected hash. To debug, the result strings can be dumped
// to a file (see below).
BOOST_FIXTURE_TEST_CASE(util_SettingsMerge, SettingsMergeTestingSetup) {
    CHash256 out_sha;
    FILE *out_file = nullptr;
    if (const char *out_path = std::getenv("SETTINGS_MERGE_TEST_OUT")) {
        out_file = fsbridge::fopen(out_path, "w");
        if (!out_file) {
            throw std::system_error(errno, std::generic_category(),
                                    "fopen failed");
        }
    }
    Defer fileCloser([&]{
        if (out_file) {
            if (std::fclose(out_file)) {
                throw std::system_error(errno, std::generic_category(),
                                        "fclose failed");
            }
            out_file = nullptr;
        }
    });

    ForEachMergeSetup([&](const ActionList &arg_actions,
                          const ActionList &conf_actions, bool soft_set,
                          bool force_set, const std::string &section,
                          const std::string &network, bool net_specific) {
        TestArgsManager parser;
        LOCK(parser.cs_args);

        std::string desc = "net=";
        desc += network;
        parser.m_network = network;

        const std::string &name = net_specific ? "server" : "wallet";
        const std::string key = "-" + name;
        parser.AddArg(key, name, ArgsManager::ALLOW_ANY,
                      OptionsCategory::OPTIONS);
        if (net_specific) {
            parser.SetNetworkOnlyArg(key);
        }

        auto args = GetValues(arg_actions, section, name, "a");
        std::vector<const char *> argv = {"ignored"};
        for (auto &arg : args) {
            arg.insert(0, "-");
            desc += " ";
            desc += arg;
            argv.push_back(arg.c_str());
        }
        std::string error;
        BOOST_CHECK(parser.ParseParameters(argv.size(), argv.data(), error));
        BOOST_CHECK_EQUAL(error, "");

        std::string conf;
        for (auto &conf_val : GetValues(conf_actions, section, name, "c")) {
            desc += " ";
            desc += conf_val;
            conf += conf_val;
            conf += "\n";
        }
        std::istringstream conf_stream(conf);
        BOOST_CHECK(parser.ReadConfigStream(conf_stream, "filepath", error));
        BOOST_CHECK_EQUAL(error, "");

        if (soft_set) {
            desc += " soft";
            parser.SoftSetArg(key, "soft1");
            parser.SoftSetArg(key, "soft2");
        }

        if (force_set) {
            desc += " force";
            parser.ForceSetArg(key, "force1");
            parser.ForceSetArg(key, "force2");
        }

        desc += " || ";

        if (!parser.IsArgSet(key)) {
            desc += "unset";
            BOOST_CHECK(!parser.IsArgNegated(key));
            BOOST_CHECK_EQUAL(parser.GetArg(key, "default"), "default");
            BOOST_CHECK(parser.GetArgs(key).empty());
        } else if (parser.IsArgNegated(key)) {
            desc += "negated";
            BOOST_CHECK_EQUAL(parser.GetArg(key, "default"), "0");
            BOOST_CHECK(parser.GetArgs(key).empty());
        } else {
            desc += parser.GetArg(key, "default");
            desc += " |";
            for (const auto &arg : parser.GetArgs(key)) {
                desc += " ";
                desc += arg;
            }
        }

        std::set<std::string> ignored = parser.GetUnsuitableSectionOnlyArgs();
        if (!ignored.empty()) {
            desc += " | ignored";
            for (const auto &arg : ignored) {
                desc += " ";
                desc += arg;
            }
        }

        desc += "\n";

        out_sha.Write(MakeUInt8Span(desc));
        if (out_file) {
            BOOST_REQUIRE(std::fwrite(desc.data(), 1, desc.size(), out_file) ==
                          desc.size());
        }
    });

    uint8_t out_sha_bytes[CSHA256::OUTPUT_SIZE];
    out_sha.Finalize(out_sha_bytes);
    std::string out_sha_hex = HexStr(out_sha_bytes);

    // If check below fails, should manually dump the results with:
    //
    //   SETTINGS_MERGE_TEST_OUT=results.txt src/test/test_bitcoin
    //   --run_test=util_tests/util_SettingsMerge
    //
    // And verify diff against previous results to make sure the changes are
    // expected.
    //
    // Results file is formatted like:
    //
    //   <input> || <IsArgSet/IsArgNegated/GetArg output> | <GetArgs output> |
    //   <GetUnsuitable output>
    BOOST_CHECK_EQUAL(
        out_sha_hex,
        "c90958b09fa4c1a4b13b4561d07c7ab8a95bd094d0f97cd76eaec336f74ab158");
}

BOOST_AUTO_TEST_CASE(util_FormatMoney) {
    BOOST_CHECK_EQUAL(FormatMoney(Amount::zero()), "0.00");
    BOOST_CHECK_EQUAL(FormatMoney(123456789 * (COIN / 10000)), "12345.6789");
    BOOST_CHECK_EQUAL(FormatMoney(-1 * COIN), "-1.00");

    BOOST_CHECK_EQUAL(FormatMoney(100000000 * COIN), "100000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(10000000 * COIN), "10000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(1000000 * COIN), "1000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(100000 * COIN), "100000.00");
    BOOST_CHECK_EQUAL(FormatMoney(10000 * COIN), "10000.00");
    BOOST_CHECK_EQUAL(FormatMoney(1000 * COIN), "1000.00");
    BOOST_CHECK_EQUAL(FormatMoney(100 * COIN), "100.00");
    BOOST_CHECK_EQUAL(FormatMoney(10 * COIN), "10.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN), "1.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 10), "0.10");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 100), "0.01");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 1000), "0.001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 10000), "0.0001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 100000), "0.00001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 1000000), "0.000001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 10000000), "0.0000001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN / 100000000), "0.00000001");
}

BOOST_AUTO_TEST_CASE(util_ParseMoney) {
    Amount ret = Amount::zero();
    BOOST_CHECK(ParseMoney("0.0", ret));
    BOOST_CHECK_EQUAL(ret, Amount::zero());

    BOOST_CHECK(ParseMoney("12345.6789", ret));
    BOOST_CHECK_EQUAL(ret, 123456789 * (COIN / 10000));

    BOOST_CHECK(ParseMoney("100000000.00", ret));
    BOOST_CHECK_EQUAL(ret, 100000000 * COIN);
    BOOST_CHECK(ParseMoney("10000000.00", ret));
    BOOST_CHECK_EQUAL(ret, 10000000 * COIN);
    BOOST_CHECK(ParseMoney("1000000.00", ret));
    BOOST_CHECK_EQUAL(ret, 1000000 * COIN);
    BOOST_CHECK(ParseMoney("100000.00", ret));
    BOOST_CHECK_EQUAL(ret, 100000 * COIN);
    BOOST_CHECK(ParseMoney("10000.00", ret));
    BOOST_CHECK_EQUAL(ret, 10000 * COIN);
    BOOST_CHECK(ParseMoney("1000.00", ret));
    BOOST_CHECK_EQUAL(ret, 1000 * COIN);
    BOOST_CHECK(ParseMoney("100.00", ret));
    BOOST_CHECK_EQUAL(ret, 100 * COIN);
    BOOST_CHECK(ParseMoney("10.00", ret));
    BOOST_CHECK_EQUAL(ret, 10 * COIN);
    BOOST_CHECK(ParseMoney("1.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN);
    BOOST_CHECK(ParseMoney("1", ret));
    BOOST_CHECK_EQUAL(ret, COIN);
    BOOST_CHECK(ParseMoney("0.1", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 10);
    BOOST_CHECK(ParseMoney("0.01", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 100);
    BOOST_CHECK(ParseMoney("0.001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 1000);
    BOOST_CHECK(ParseMoney("0.0001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 10000);
    BOOST_CHECK(ParseMoney("0.00001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 100000);
    BOOST_CHECK(ParseMoney("0.000001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 1000000);
    BOOST_CHECK(ParseMoney("0.0000001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 10000000);
    BOOST_CHECK(ParseMoney("0.00000001", ret));
    BOOST_CHECK_EQUAL(ret, COIN / 100000000);

    // Attempted 63 bit overflow should fail
    BOOST_CHECK(!ParseMoney("92233720368.54775808", ret));

    // Parsing negative amounts must fail
    BOOST_CHECK(!ParseMoney("-1", ret));
}

BOOST_AUTO_TEST_CASE(util_IsHex) {
    BOOST_CHECK(IsHex("00"));
    BOOST_CHECK(IsHex("00112233445566778899aabbccddeeffAABBCCDDEEFF"));
    BOOST_CHECK(IsHex("ff"));
    BOOST_CHECK(IsHex("FF"));

    BOOST_CHECK(!IsHex(""));
    BOOST_CHECK(!IsHex("0"));
    BOOST_CHECK(!IsHex("a"));
    BOOST_CHECK(!IsHex("eleven"));
    BOOST_CHECK(!IsHex("00xx00"));
    BOOST_CHECK(!IsHex("0x0000"));
}

BOOST_AUTO_TEST_CASE(util_IsHexNumber) {
    BOOST_CHECK(IsHexNumber("0x0"));
    BOOST_CHECK(IsHexNumber("0"));
    BOOST_CHECK(IsHexNumber("0x10"));
    BOOST_CHECK(IsHexNumber("10"));
    BOOST_CHECK(IsHexNumber("0xff"));
    BOOST_CHECK(IsHexNumber("ff"));
    BOOST_CHECK(IsHexNumber("0xFfa"));
    BOOST_CHECK(IsHexNumber("Ffa"));
    BOOST_CHECK(IsHexNumber("0x00112233445566778899aabbccddeeffAABBCCDDEEFF"));
    BOOST_CHECK(IsHexNumber("00112233445566778899aabbccddeeffAABBCCDDEEFF"));

    BOOST_CHECK(!IsHexNumber(""));      // empty string not allowed
    BOOST_CHECK(!IsHexNumber("0x"));    // empty string after prefix not allowed
    BOOST_CHECK(!IsHexNumber("0x0 "));  // no spaces at end,
    BOOST_CHECK(!IsHexNumber(" 0x0"));  // or beginning,
    BOOST_CHECK(!IsHexNumber("0x 0"));  // or middle,
    BOOST_CHECK(!IsHexNumber(" "));     // etc.
    BOOST_CHECK(!IsHexNumber("0x0ga")); // invalid character
    BOOST_CHECK(!IsHexNumber("x0"));    // broken prefix
    BOOST_CHECK(!IsHexNumber("0x0x00")); // two prefixes not allowed
}

BOOST_AUTO_TEST_CASE(util_seed_insecure_rand) {
    SeedInsecureRand(true);
    for (int mod = 2; mod < 11; mod++) {
        int mask = 1;
        // Really rough binomial confidence approximation.
        int err =
            30 * 10000. / mod * sqrt((1. / mod * (1 - 1. / mod)) / 10000.);
        // mask is 2^ceil(log2(mod))-1
        while (mask < mod - 1) {
            mask = (mask << 1) + 1;
        }

        int count = 0;
        // How often does it get a zero from the uniform range [0,mod)?
        for (int i = 0; i < 10000; i++) {
            uint32_t rval;
            do {
                rval = InsecureRand32() & mask;
            } while (rval >= uint32_t(mod));
            count += rval == 0;
        }
        BOOST_CHECK(count <= 10000 / mod + err);
        BOOST_CHECK(count >= 10000 / mod - err);
    }
}

BOOST_AUTO_TEST_CASE(util_TimingResistantEqual) {
    BOOST_CHECK(TimingResistantEqual(std::string(""), std::string("")));
    BOOST_CHECK(!TimingResistantEqual(std::string("abc"), std::string("")));
    BOOST_CHECK(!TimingResistantEqual(std::string(""), std::string("abc")));
    BOOST_CHECK(!TimingResistantEqual(std::string("a"), std::string("aa")));
    BOOST_CHECK(!TimingResistantEqual(std::string("aa"), std::string("a")));
    BOOST_CHECK(TimingResistantEqual(std::string("abc"), std::string("abc")));
    BOOST_CHECK(!TimingResistantEqual(std::string("abc"), std::string("aba")));
}

/* Test strprintf formatting directives.
 * Put a string before and after to ensure sanity of element sizes on stack. */
#define B "check_prefix"
#define E "check_postfix"
BOOST_AUTO_TEST_CASE(strprintf_numbers) {
    int64_t s64t = -9223372036854775807LL;   /* signed 64 bit test value */
    uint64_t u64t = 18446744073709551615ULL; /* unsigned 64 bit test value */
    BOOST_CHECK(strprintf("%s %d %s", B, s64t, E) == B
                " -9223372036854775807 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, u64t, E) == B
                " 18446744073709551615 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, u64t, E) == B " ffffffffffffffff " E);

    size_t st = 12345678;    /* unsigned size_t test value */
    ssize_t sst = -12345678; /* signed size_t test value */
    BOOST_CHECK(strprintf("%s %d %s", B, sst, E) == B " -12345678 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, st, E) == B " 12345678 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, st, E) == B " bc614e " E);

    ptrdiff_t pt = 87654321;   /* positive ptrdiff_t test value */
    ptrdiff_t spt = -87654321; /* negative ptrdiff_t test value */
    BOOST_CHECK(strprintf("%s %d %s", B, spt, E) == B " -87654321 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, pt, E) == B " 87654321 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, pt, E) == B " 5397fb1 " E);

    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, 12345.6789f, E), B " 12345.678711 " E); // float - expect loss of precision
    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, 12345.6789, E), B " 12345.678900 " E); // double - no loss of precision
    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, -12345.6789f, E), B " -12345.678711 " E); // negative float
    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, -12345.6789, E), B " -12345.678900 " E); // negative double
    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, 16777216u, E), B " 16777216 " E); // float representation of unsigned integer
    BOOST_CHECK_EQUAL(strprintf("%s %f %s", B, -16777216, E), B " -16777216 " E); // float representation of negative integer
}
#undef B
#undef E

/* Check for mingw/wine issue #3494
 * Remove this test before time.ctime(0xffffffff) == 'Sun Feb  7 07:28:15 2106'
 */
BOOST_AUTO_TEST_CASE(gettime) {
    BOOST_CHECK((GetTime() & ~0xFFFFFFFFLL) == 0);
}

BOOST_AUTO_TEST_CASE(util_time_GetTime) {
    SetMockTime(111);
    // Check that mock time does not change after a sleep
    for (const auto &num_sleep : {0, 1}) {
        MilliSleep(num_sleep);
        BOOST_CHECK_EQUAL(111, GetTime()); // Deprecated time getter
        BOOST_CHECK_EQUAL(111, GetTime<std::chrono::seconds>().count());
        BOOST_CHECK_EQUAL(111000, GetTime<std::chrono::milliseconds>().count());
        BOOST_CHECK_EQUAL(111000000,
                          GetTime<std::chrono::microseconds>().count());
    }

    SetMockTime(0);
    // Check that system time changes after a sleep
    const auto ms_0 = GetTime<std::chrono::milliseconds>();
    const auto us_0 = GetTime<std::chrono::microseconds>();
    MilliSleep(1);
    BOOST_CHECK(ms_0 < GetTime<std::chrono::milliseconds>());
    BOOST_CHECK(us_0 < GetTime<std::chrono::microseconds>());
}

BOOST_AUTO_TEST_CASE(test_IsDigit) {
    BOOST_CHECK_EQUAL(IsDigit('0'), true);
    BOOST_CHECK_EQUAL(IsDigit('1'), true);
    BOOST_CHECK_EQUAL(IsDigit('8'), true);
    BOOST_CHECK_EQUAL(IsDigit('9'), true);

    BOOST_CHECK_EQUAL(IsDigit('0' - 1), false);
    BOOST_CHECK_EQUAL(IsDigit('9' + 1), false);
    BOOST_CHECK_EQUAL(IsDigit(0), false);
    BOOST_CHECK_EQUAL(IsDigit(1), false);
    BOOST_CHECK_EQUAL(IsDigit(8), false);
    BOOST_CHECK_EQUAL(IsDigit(9), false);
}

BOOST_AUTO_TEST_CASE(test_ParseInt32) {
    int32_t n;
    // Valid values
    BOOST_CHECK(ParseInt32("1234", nullptr));
    BOOST_CHECK(ParseInt32("0", &n) && n == 0);
    BOOST_CHECK(ParseInt32("1234", &n) && n == 1234);
    BOOST_CHECK(ParseInt32("01234", &n) && n == 1234); // no octal
    BOOST_CHECK(ParseInt32("2147483647", &n) && n == 2147483647);
    // (-2147483647 - 1) equals INT_MIN
    BOOST_CHECK(ParseInt32("-2147483648", &n) && n == (-2147483647 - 1));
    BOOST_CHECK(ParseInt32("-1234", &n) && n == -1234);
    // Invalid values
    BOOST_CHECK(!ParseInt32("", &n));
    BOOST_CHECK(!ParseInt32(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseInt32("1 ", &n));
    BOOST_CHECK(!ParseInt32("1a", &n));
    BOOST_CHECK(!ParseInt32("aap", &n));
    BOOST_CHECK(!ParseInt32("0x1", &n)); // no hex
    BOOST_CHECK(!ParseInt32("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseInt32(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseInt32("-2147483649", nullptr));
    BOOST_CHECK(!ParseInt32("2147483648", nullptr));
    BOOST_CHECK(!ParseInt32("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseInt32("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseInt64) {
    int64_t n;
    // Valid values
    BOOST_CHECK(ParseInt64("1234", nullptr));
    BOOST_CHECK(ParseInt64("0", &n) && n == 0LL);
    BOOST_CHECK(ParseInt64("1234", &n) && n == 1234LL);
    BOOST_CHECK(ParseInt64("01234", &n) && n == 1234LL); // no octal
    BOOST_CHECK(ParseInt64("2147483647", &n) && n == 2147483647LL);
    BOOST_CHECK(ParseInt64("-2147483648", &n) && n == -2147483648LL);
    BOOST_CHECK(ParseInt64("9223372036854775807", &n) &&
                n == (int64_t)9223372036854775807);
    BOOST_CHECK(ParseInt64("-9223372036854775808", &n) &&
                n == (int64_t)-9223372036854775807 - 1);
    BOOST_CHECK(ParseInt64("-1234", &n) && n == -1234LL);
    // Invalid values
    BOOST_CHECK(!ParseInt64("", &n));
    BOOST_CHECK(!ParseInt64(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseInt64("1 ", &n));
    BOOST_CHECK(!ParseInt64("1a", &n));
    BOOST_CHECK(!ParseInt64("aap", &n));
    BOOST_CHECK(!ParseInt64("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseInt64(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseInt64("-9223372036854775809", nullptr));
    BOOST_CHECK(!ParseInt64("9223372036854775808", nullptr));
    BOOST_CHECK(!ParseInt64("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseInt64("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseUInt32) {
    uint32_t n;
    // Valid values
    BOOST_CHECK(ParseUInt32("1234", nullptr));
    BOOST_CHECK(ParseUInt32("0", &n) && n == 0);
    BOOST_CHECK(ParseUInt32("1234", &n) && n == 1234);
    BOOST_CHECK(ParseUInt32("01234", &n) && n == 1234); // no octal
    BOOST_CHECK(ParseUInt32("2147483647", &n) && n == 2147483647);
    BOOST_CHECK(ParseUInt32("2147483648", &n) && n == (uint32_t)2147483648);
    BOOST_CHECK(ParseUInt32("4294967295", &n) && n == (uint32_t)4294967295);
    // Invalid values
    BOOST_CHECK(!ParseUInt32("", &n));
    BOOST_CHECK(!ParseUInt32(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseUInt32(" -1", &n));
    BOOST_CHECK(!ParseUInt32("1 ", &n));
    BOOST_CHECK(!ParseUInt32("1a", &n));
    BOOST_CHECK(!ParseUInt32("aap", &n));
    BOOST_CHECK(!ParseUInt32("0x1", &n)); // no hex
    BOOST_CHECK(!ParseUInt32("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseUInt32(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseUInt32("-2147483648", &n));
    BOOST_CHECK(!ParseUInt32("4294967296", &n));
    BOOST_CHECK(!ParseUInt32("-1234", &n));
    BOOST_CHECK(!ParseUInt32("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseUInt32("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseUInt64) {
    uint64_t n;
    // Valid values
    BOOST_CHECK(ParseUInt64("1234", nullptr));
    BOOST_CHECK(ParseUInt64("0", &n) && n == 0LL);
    BOOST_CHECK(ParseUInt64("1234", &n) && n == 1234LL);
    BOOST_CHECK(ParseUInt64("01234", &n) && n == 1234LL); // no octal
    BOOST_CHECK(ParseUInt64("2147483647", &n) && n == 2147483647LL);
    BOOST_CHECK(ParseUInt64("9223372036854775807", &n) &&
                n == 9223372036854775807ULL);
    BOOST_CHECK(ParseUInt64("9223372036854775808", &n) &&
                n == 9223372036854775808ULL);
    BOOST_CHECK(ParseUInt64("18446744073709551615", &n) &&
                n == 18446744073709551615ULL);
    // Invalid values
    BOOST_CHECK(!ParseUInt64("", &n));
    BOOST_CHECK(!ParseUInt64(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseUInt64(" -1", &n));
    BOOST_CHECK(!ParseUInt64("1 ", &n));
    BOOST_CHECK(!ParseUInt64("1a", &n));
    BOOST_CHECK(!ParseUInt64("aap", &n));
    BOOST_CHECK(!ParseUInt64("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseUInt64(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseUInt64("-9223372036854775809", nullptr));
    BOOST_CHECK(!ParseUInt64("18446744073709551616", nullptr));
    BOOST_CHECK(!ParseUInt64("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseUInt64("-2147483648", &n));
    BOOST_CHECK(!ParseUInt64("-9223372036854775808", &n));
    BOOST_CHECK(!ParseUInt64("-1234", &n));
}

BOOST_AUTO_TEST_CASE(test_ParseDouble) {
    double n;
    // Valid values
    BOOST_CHECK(ParseDouble("1234", nullptr));
    BOOST_CHECK(ParseDouble("0", &n) && n == 0.0);
    BOOST_CHECK(ParseDouble("1234", &n) && n == 1234.0);
    BOOST_CHECK(ParseDouble("01234", &n) && n == 1234.0); // no octal
    BOOST_CHECK(ParseDouble("2147483647", &n) && n == 2147483647.0);
    BOOST_CHECK(ParseDouble("-2147483648", &n) && n == -2147483648.0);
    BOOST_CHECK(ParseDouble("-1234", &n) && n == -1234.0);
    BOOST_CHECK(ParseDouble("1e6", &n) && n == 1e6);
    BOOST_CHECK(ParseDouble("-1e6", &n) && n == -1e6);
    // Invalid values
    BOOST_CHECK(!ParseDouble("", &n));
    BOOST_CHECK(!ParseDouble(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseDouble("1 ", &n));
    BOOST_CHECK(!ParseDouble("1a", &n));
    BOOST_CHECK(!ParseDouble("aap", &n));
    BOOST_CHECK(!ParseDouble("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseDouble(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseDouble("-1e10000", nullptr));
    BOOST_CHECK(!ParseDouble("1e10000", nullptr));
}

BOOST_AUTO_TEST_CASE(test_FormatParagraph) {
    BOOST_CHECK_EQUAL(FormatParagraph("", 79, 0), "");
    BOOST_CHECK_EQUAL(FormatParagraph("test", 79, 0), "test");
    BOOST_CHECK_EQUAL(FormatParagraph(" test", 79, 0), " test");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 79, 0), "test test");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 4, 0), "test\ntest");
    BOOST_CHECK_EQUAL(FormatParagraph("testerde test", 4, 0), "testerde\ntest");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 4, 4), "    test\n    test");

    // Make sure we don't indent a fully-new line following a too-long line
    // ending
    BOOST_CHECK_EQUAL(FormatParagraph("test test\nabc", 4, 4),
                      "    test\n    test\n    abc");

    BOOST_CHECK_EQUAL(
        FormatParagraph("This_is_a_very_long_test_string_without_any_spaces_so_"
                        "it_should_just_get_returned_as_is_despite_the_length "
                        "until it gets here",
                        79),
        "This_is_a_very_long_test_string_without_any_spaces_so_it_should_just_"
        "get_returned_as_is_despite_the_length\nuntil it gets here");

    // Test wrap length is exact
    BOOST_CHECK_EQUAL(
        FormatParagraph("a b c d e f g h i j k l m n o p q r s t u v w x y z 1 "
                        "2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p",
                        79),
        "a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 "
        "a b c de\nf g h i j k l m n o p");
    BOOST_CHECK_EQUAL(
        FormatParagraph("x\na b c d e f g h i j k l m n o p q r s t u v w x y "
                        "z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p",
                        79),
        "x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 "
        "8 9 a b c de\nf g h i j k l m n o p");
    // Indent should be included in length of lines
    BOOST_CHECK_EQUAL(
        FormatParagraph("x\na b c d e f g h i j k l m n o p q r s t u v w x y "
                        "z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p q "
                        "r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 a b c d e fg h "
                        "i j k",
                        79, 4),
        "    x\n    a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 "
        "8 9 a b c\n    de f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 "
        "5 6 7 8 9 a b c d e\n    fg h i j k");

    BOOST_CHECK_EQUAL(
        FormatParagraph("This is a very long test string. This is a second "
                        "sentence in the very long test string.",
                        79),
        "This is a very long test string. This is a second sentence in the "
        "very long\ntest string.");
    BOOST_CHECK_EQUAL(
        FormatParagraph("This is a very long test string.\nThis is a second "
                        "sentence in the very long test string. This is a "
                        "third sentence in the very long test string.",
                        79),
        "This is a very long test string.\nThis is a second sentence in the "
        "very long test string. This is a third\nsentence in the very long "
        "test string.");
    BOOST_CHECK_EQUAL(
        FormatParagraph("This is a very long test string.\n\nThis is a second "
                        "sentence in the very long test string. This is a "
                        "third sentence in the very long test string.",
                        79),
        "This is a very long test string.\n\nThis is a second sentence in the "
        "very long test string. This is a third\nsentence in the very long "
        "test string.");
    BOOST_CHECK_EQUAL(
        FormatParagraph(
            "Testing that normal newlines do not get indented.\nLike here.",
            79),
        "Testing that normal newlines do not get indented.\nLike here.");
}

BOOST_AUTO_TEST_CASE(test_FormatSubVersion) {
    std::vector<std::string> comments;
    comments.push_back(std::string("comment1"));
    std::vector<std::string> comments2;
    comments2.push_back(std::string("comment1"));
    // Semicolon is discouraged but not forbidden by BIP-0014
    comments2.push_back(SanitizeString(
        std::string("Comment2; .,_?@-; !\"#$%&'()*+/<=>[]\\^`{|}~"),
        SAFE_CHARS_UA_COMMENT));
    BOOST_CHECK_EQUAL(
        FormatSubVersion("Test", 99900, std::vector<std::string>()),
        std::string("/Test:0.9.99/"));
    BOOST_CHECK_EQUAL(FormatSubVersion("Test", 99900, comments),
                      std::string("/Test:0.9.99(comment1)/"));
    BOOST_CHECK_EQUAL(
        FormatSubVersion("Test", 99900, comments2),
        std::string("/Test:0.9.99(comment1; Comment2; .,_?@-; )/"));
}

BOOST_AUTO_TEST_CASE(test_ParseFixedPoint) {
    int64_t amount = 0;
    BOOST_CHECK(ParseFixedPoint("0", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 0LL);
    BOOST_CHECK(ParseFixedPoint("1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000LL);
    BOOST_CHECK(ParseFixedPoint("0.0", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 0LL);
    BOOST_CHECK(ParseFixedPoint("-0.1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -10000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 110000000LL);
    BOOST_CHECK(ParseFixedPoint("1.10000000000000000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 110000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1e1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1100000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1e-1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 11000000LL);
    BOOST_CHECK(ParseFixedPoint("1000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000000LL);
    BOOST_CHECK(ParseFixedPoint("-1000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -100000000000LL);
    BOOST_CHECK(ParseFixedPoint("0.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1LL);
    BOOST_CHECK(ParseFixedPoint("0.0000000100000000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1LL);
    BOOST_CHECK(ParseFixedPoint("-0.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -1LL);
    BOOST_CHECK(ParseFixedPoint("1000000000.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000000000001LL);
    BOOST_CHECK(ParseFixedPoint("9999999999.99999999", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 999999999999999999LL);
    BOOST_CHECK(ParseFixedPoint("-9999999999.99999999", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -999999999999999999LL);

    BOOST_CHECK(!ParseFixedPoint("", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("a-1000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-a1000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-1000a", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-01000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("00.1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint(".1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("--0.1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("0.000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-0.000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("0.00000001000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000009", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000009", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-99999999999.99999999", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("99999909999.09999999", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("92233720368.54775807", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("92233720368.54775808", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-92233720368.54775808", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-92233720368.54775809", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.1e", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.1e-", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.", 8, &amount));
}

static void TestOtherThread(const fs::path &dirname, const std::string &lockname,
                            bool *result) {
    *result = LockDirectory(dirname, lockname);
}

#ifndef WIN32 // Cannot do this test on WIN32 due to lack of fork()
static constexpr char LockCommand = 'L';
static constexpr char UnlockCommand = 'U';
static constexpr char ExitCommand = 'X';

static void TestOtherProcess(const fs::path &dirname, const std::string &lockname, int fd) {
    char ch;
    while (true) {
        // Wait for command
        int rv = read(fd, &ch, 1);
        assert(rv == 1);
        switch (ch) {
            case LockCommand:
                ch = LockDirectory(dirname, lockname);
                rv = write(fd, &ch, 1);
                assert(rv == 1);
                break;
            case UnlockCommand:
                ReleaseDirectoryLocks();
                ch = true; // Always succeeds
                rv = write(fd, &ch, 1);
                assert(rv == 1);
                break;
            case ExitCommand:
                close(fd);
                // As an alternative to exit() which runs the exit handlers
                // (which seem to be flakey with Boost test suite with JUNIT
                // logging in a forked process), just vanish this process as
                // fast as possible. `quick_exit()` would also work, but it is
                // not available on all non glibc platforms.
                // Using exec also stops valgrind from thinking it needs to
                // analyze the memory leaks in this forked process.
                execlp("true", "true", (char *)NULL);
                break;
            default:
                assert(0);
                break;
        }
    }
}
#endif

BOOST_AUTO_TEST_CASE(test_LockDirectory) {
    fs::path dirname = SetDataDir("test_LockDirectory") / fs::unique_path();
    const std::string lockname = ".lock";
#ifndef WIN32
    // Revert SIGCHLD to default, otherwise boost.test will catch and fail on
    // it: there is BOOST_TEST_IGNORE_SIGCHLD but that only works when defined
    // at build-time of the boost library
    void (*old_handler)(int) = signal(SIGCHLD, SIG_DFL);

    // Fork another process for testing before creating the lock, so that we
    // won't fork while holding the lock (which might be undefined, and is not
    // relevant as test case as that is avoided with -daemonize).
    int fd[2];
    BOOST_CHECK_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, fd), 0);
    pid_t pid = fork();
    if (!pid) {
        BOOST_CHECK_EQUAL(close(fd[1]), 0); // Child: close parent end
        TestOtherProcess(dirname, lockname, fd[0]);
    }
    BOOST_CHECK_EQUAL(close(fd[0]), 0); // Parent: close child end
#endif
    // Lock on non-existent directory should fail
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname), false);

    fs::create_directories(dirname);

    // Probing lock on new directory should succeed
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname, true), true);

    // Persistent lock on new directory should succeed
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname), true);

    // Another lock on the directory from the same thread should succeed
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname), true);

    // Another lock on the directory from a different thread within the same
    // process should succeed
    bool threadresult;
    std::thread thr(TestOtherThread, dirname, lockname, &threadresult);
    thr.join();
    BOOST_CHECK_EQUAL(threadresult, true);
#ifndef WIN32
    // Try to acquire lock in child process while we're holding it, this should
    // fail.
    char ch;
    BOOST_CHECK_EQUAL(write(fd[1], &LockCommand, 1), 1);
    BOOST_CHECK_EQUAL(read(fd[1], &ch, 1), 1);
    BOOST_CHECK_EQUAL((bool)ch, false);

    // Give up our lock
    ReleaseDirectoryLocks();
    // Probing lock from our side now should succeed, but not hold on to the
    // lock.
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname, true), true);

    // Try to acquire the lock in the child process, this should be successful.
    BOOST_CHECK_EQUAL(write(fd[1], &LockCommand, 1), 1);
    BOOST_CHECK_EQUAL(read(fd[1], &ch, 1), 1);
    BOOST_CHECK_EQUAL((bool)ch, true);

    // When we try to probe the lock now, it should fail.
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname, true), false);

    // Unlock the lock in the child process
    BOOST_CHECK_EQUAL(write(fd[1], &UnlockCommand, 1), 1);
    BOOST_CHECK_EQUAL(read(fd[1], &ch, 1), 1);
    BOOST_CHECK_EQUAL((bool)ch, true);

    // When we try to probe the lock now, it should succeed.
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname, true), true);

    // Re-lock the lock in the child process, then wait for it to exit, check
    // successful return. After that, we check that exiting the process
    // has released the lock as we would expect by probing it.
    int processstatus;
    BOOST_CHECK_EQUAL(write(fd[1], &LockCommand, 1), 1);
    BOOST_CHECK_EQUAL(write(fd[1], &ExitCommand, 1), 1);
    BOOST_CHECK_EQUAL(waitpid(pid, &processstatus, 0), pid);
    BOOST_CHECK_EQUAL(processstatus, 0);
    BOOST_CHECK_EQUAL(LockDirectory(dirname, lockname, true), true);

    // Restore SIGCHLD
    signal(SIGCHLD, old_handler);
    BOOST_CHECK_EQUAL(close(fd[1]), 0); // Close our side of the socketpair
#endif
    // Clean up
    ReleaseDirectoryLocks();
    fs::remove_all(dirname);
}

BOOST_AUTO_TEST_CASE(test_DirIsWritable) {
    // Should be able to write to the data dir.
    fs::path tmpdirname = SetDataDir("test_DirIsWritable");
    BOOST_CHECK_EQUAL(DirIsWritable(tmpdirname), true);

    // Should not be able to write to a non-existent dir.
    tmpdirname = tmpdirname / fs::unique_path();
    BOOST_CHECK_EQUAL(DirIsWritable(tmpdirname), false);

    fs::create_directory(tmpdirname);
    // Should be able to write to it now.
    BOOST_CHECK_EQUAL(DirIsWritable(tmpdirname), true);
    fs::remove(tmpdirname);
}

template <size_t F, size_t T, typename InT = uint8_t, typename OutT = uint8_t>
static void CheckConvertBits(const std::vector<InT> &in,
                             const std::vector<OutT> &expected) {
    std::vector<OutT> outpad;
    bool ret = ConvertBits<F, T, true>([&](OutT c) { outpad.push_back(c); },
                                       in.begin(), in.end());
    BOOST_CHECK(ret);
    BOOST_CHECK(outpad == expected);

    const bool dopad = (in.size() * F) % T;
    std::vector<OutT> outnopad;
    ret = ConvertBits<F, T, false>([&](OutT c) { outnopad.push_back(c); },
                                   in.begin(), in.end());
    BOOST_CHECK(ret != (dopad && !outpad.empty() && outpad.back()));

    if (dopad) {
        // We should have skipped the last digit.
        outnopad.push_back(expected.back());
    }

    BOOST_CHECK(outnopad == expected);

    // Check the other way around.
    // Check with padding. We may get an extra 0 in that case.
    std::vector<InT> origpad;
    ret = ConvertBits<T, F, true>([&](InT c) { origpad.push_back(c); },
                                  expected.begin(), expected.end());
    BOOST_CHECK(ret);

    std::vector<InT> orignopad;
    ret = ConvertBits<T, F, false>([&](InT c) { orignopad.push_back(c); },
                                   expected.begin(), expected.end());
    BOOST_CHECK(ret != ((expected.size() * T) % F && !origpad.empty() &&
                        origpad.back()));
    BOOST_CHECK(orignopad == in);

    if (dopad) {
        BOOST_CHECK_EQUAL(origpad.back(), 0);
        origpad.pop_back();
    }

    BOOST_CHECK(origpad == in);
}

BOOST_AUTO_TEST_CASE(test_ConvertBits) {
    CheckConvertBits<8, 5>({}, {});
    CheckConvertBits<8, 5>({0xff}, {0x1f, 0x1c});
    CheckConvertBits<8, 5>({0xff, 0xff}, {0x1f, 0x1f, 0x1f, 0x10});
    CheckConvertBits<8, 5>({0xff, 0xff, 0xff}, {0x1f, 0x1f, 0x1f, 0x1f, 0x1e});
    CheckConvertBits<8, 5>({0xff, 0xff, 0xff, 0xff},
                           {0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x18});
    CheckConvertBits<8, 5>({0xff, 0xff, 0xff, 0xff, 0xff},
                           {0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f});
    CheckConvertBits<8, 5>({0xff, 0xff, 0xff, 0xff, 0xff},
                           {0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f});
    CheckConvertBits<8, 5>({0xff, 0xff, 0xff, 0xff, 0xff},
                           {0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f});
    CheckConvertBits<8, 5>({0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
                           {0x00, 0x04, 0x11, 0x14, 0x0a, 0x19, 0x1c, 0x09,
                            0x15, 0x0f, 0x06, 0x1e, 0x1e});
    CheckConvertBits<8, 5>({0x00}, {0x00, 0x00});
    CheckConvertBits<8, 5>({0xf8}, {0x1f, 0x00});
    CheckConvertBits<8, 5>({0x00, 0x00}, {0x00, 0x00, 0x00, 0x00});

    // Test operation on values beyond the 8-bit range.
    CheckConvertBits<12, 16, uint16_t, uint16_t>({0xf2c, 0x486, 0xc8f, 0xafb, 0xfcf, 0xd98, 0x761, 0x010},
                                                 {0xf2c4, 0x86c8, 0xfafb, 0xfcfd, 0x9876, 0x1010});
    if constexpr (sizeof(size_t) >= 8) {
        // 64-bit case, we can go beyond 31 bits
        CheckConvertBits<16, 32, uint16_t, uint32_t>({0xf2c4, 0x86c8, 0xfafb, 0xfcfd, 0x9876, 0x1},
                                                     {0xf2c486c8, 0xfafbfcfd, 0x98760001});
    }
}

BOOST_AUTO_TEST_CASE(test_ToLower) {
    BOOST_CHECK_EQUAL(ToLower('@'), '@');
    BOOST_CHECK_EQUAL(ToLower('A'), 'a');
    BOOST_CHECK_EQUAL(ToLower('Z'), 'z');
    BOOST_CHECK_EQUAL(ToLower('['), '[');
    BOOST_CHECK_EQUAL(ToLower(0), 0);
    BOOST_CHECK_EQUAL(ToLower(255), 255);

    BOOST_CHECK_EQUAL(ToLower(""), "");
    BOOST_CHECK_EQUAL(ToLower("#HODL"), "#hodl");
    BOOST_CHECK_EQUAL(ToLower("\x00\xfe\xff"), "\x00\xfe\xff");
}

BOOST_AUTO_TEST_CASE(test_ToUpper) {
    BOOST_CHECK_EQUAL(ToUpper('`'), '`');
    BOOST_CHECK_EQUAL(ToUpper('a'), 'A');
    BOOST_CHECK_EQUAL(ToUpper('z'), 'Z');
    BOOST_CHECK_EQUAL(ToUpper('{'), '{');
    BOOST_CHECK_EQUAL(ToUpper(0), 0);
    BOOST_CHECK_EQUAL(ToUpper(255), 255);

    BOOST_CHECK_EQUAL(ToUpper(""), "");
    BOOST_CHECK_EQUAL(ToUpper("#hodl"), "#HODL");
    BOOST_CHECK_EQUAL(ToUpper("\x00\xfe\xff"), "\x00\xfe\xff");
}

BOOST_AUTO_TEST_CASE(test_Capitalize) {
    BOOST_CHECK_EQUAL(Capitalize(""), "");
    BOOST_CHECK_EQUAL(Capitalize("bitcoin"), "Bitcoin");
    BOOST_CHECK_EQUAL(Capitalize("\x00\xfe\xff"), "\x00\xfe\xff");
}

BOOST_AUTO_TEST_CASE(test_GetPerfTimeNanos) {
    // Basic test to just check sanity of the GetPerfTimeNanos() call that it actually increses along with system clock.
    // We would like to test things with more precision than this but it's very tricky to compare two distinct clocks.
    for (int i = 0; i < 100; ++i) {
        const int64_t sleeptime_msec = (i+1) * 7;
        const int64_t before = GetPerfTimeNanos();
        MilliSleep(sleeptime_msec);
        const int64_t after = GetPerfTimeNanos();
        constexpr int64_t fuzz =
#ifdef _WIN32
                500'000; // round up to nearest millisecond on Windows due to lack of scheduler granularity
#else
                1'000; // other platforms: fudge up by 1 usec in case of drift
#endif
        BOOST_CHECK_GE((after - before) + fuzz, sleeptime_msec * 1'000'000);
    }
}

BOOST_AUTO_TEST_CASE(test_Tic) {
    Tic tic;
    // freshly constructed Tic timer should not have elapsed much. 100ms arbitrarily chosen as a "safe" value.
    BOOST_CHECK_LT(tic.msec(), 100);
    int64_t cum_time = 0;
    for (int i = 0; i < 100; ++i) {
        const int64_t sleeptime_msec = (i+1) * 7;
        MilliSleep(sleeptime_msec);
        cum_time += sleeptime_msec;
        // we expect that tic must have measured at least as much time as we slept
        BOOST_CHECK_GE(tic.msec() + 1 /* fudge to guard against drift */, cum_time);
    }
    // freeze clock
    tic.fin();
    const auto frozen_nsec = tic.nsec();
    for (int i = 0; i < 10; ++i) {
        MilliSleep(10);
        // ensure frozen times remain frozen
        BOOST_CHECK_EQUAL(tic.nsec(), frozen_nsec);
        BOOST_CHECK_EQUAL(tic.usec(), frozen_nsec / 1'000);
        BOOST_CHECK_EQUAL(tic.msec(), frozen_nsec / 1'000'000);
        BOOST_CHECK_EQUAL(tic.secs<int64_t>(), frozen_nsec / 1'000'000'000);
    }

    // ensure the clock string values correspond to what we expect
    BOOST_CHECK_EQUAL(tic.secsStr(3), strprintf("%1.3f", tic.secs<double>()));
    BOOST_CHECK_EQUAL(tic.msecStr(3), strprintf("%1.3f", tic.msec<double>()));
    BOOST_CHECK_EQUAL(tic.usecStr(3), strprintf("%1.3f", tic.usec<double>()));
    BOOST_CHECK_EQUAL(tic.nsecStr(), strprintf("%i", tic.nsec()));
}

BOOST_AUTO_TEST_CASE(test_bit_cast) {
    // convert double to uint64 via bit_cast and back should yield roughly the same value
    // (we allow for fuzz because floats can be imprecise)
    BOOST_CHECK_LE(std::abs(bit_cast<double>(bit_cast<uint64_t>(19880124.0)) - 19880124.0),
                   std::numeric_limits<double>::epsilon());

    // next, use bit_cast with some structs that have similar common members
    struct S1 {
        char s[16];
        int i;
    };

    struct S2 {
        char s[16];
        int i;
        float f;
        char s2[32];
    };

    S2 s2{"hello", 42, 3.14f, "foo"};

    S1 s1 = bit_cast<S1>(s2);
    BOOST_CHECK_EQUAL(std::strncmp(s1.s, s2.s, sizeof(s1.s)), 0);
    BOOST_CHECK_EQUAL(s1.i, s2.i);

    // convert from a larger array should work
    const char zeros[sizeof(s2)]{};

    BOOST_CHECK_NE(s1.s[0], 0);
    BOOST_CHECK_NE(s1.i, 0);
    s1 = bit_cast<S1>(zeros);
    BOOST_CHECK_EQUAL(s1.s[0], 0);
    BOOST_CHECK_EQUAL(s1.i, 0);

    struct Padded {
        S1 s1;
        char padding[sizeof(s2) - sizeof(s1) + sizeof(void *)];
    };
    Padded pad{};

    BOOST_CHECK_EQUAL(int(pad.s1.i), 0); // sanity check: ensure was 0-initted
    BOOST_CHECK_NE(int(s2.f), 0);
    s2 = bit_cast_unsafe<S2>(pad.s1); // bit_case_unsafe required for a smaller struct to a larger one
    BOOST_CHECK_EQUAL(int(s2.f), 0);
}

namespace {

struct Tracker {
    //! Points to the original object (possibly itself) we moved/copied from
    const Tracker *origin;
    //! How many copies where involved between the original object and this one (moves are not counted)
    int copies;

    Tracker() noexcept : origin(this), copies(0) {}
    Tracker(const Tracker &t) noexcept : origin(t.origin), copies(t.copies + 1) {}
    Tracker(Tracker &&t) noexcept : origin(t.origin), copies(t.copies) {}
    Tracker &operator=(const Tracker &t) noexcept {
        origin = t.origin;
        copies = t.copies + 1;
        return *this;
    }
    Tracker &operator=(Tracker &&t) noexcept {
        origin = t.origin;
        copies = t.copies;
        return *this;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(test_tracked_vector) {
    Tracker t1;
    Tracker t2;
    Tracker t3;

    BOOST_CHECK(t1.origin == &t1);
    BOOST_CHECK(t2.origin == &t2);
    BOOST_CHECK(t3.origin == &t3);

    auto v1 = Vector(t1);
    BOOST_CHECK_EQUAL(v1.size(), 1);
    BOOST_CHECK(v1[0].origin == &t1);
    BOOST_CHECK_EQUAL(v1[0].copies, 1);

    auto v2 = Vector(std::move(t2));
    BOOST_CHECK_EQUAL(v2.size(), 1);
    BOOST_CHECK(v2[0].origin == &t2);
    BOOST_CHECK_EQUAL(v2[0].copies, 0);

    auto v3 = Vector(t1, std::move(t2));
    BOOST_CHECK_EQUAL(v3.size(), 2);
    BOOST_CHECK(v3[0].origin == &t1);
    BOOST_CHECK(v3[1].origin == &t2);
    BOOST_CHECK_EQUAL(v3[0].copies, 1);
    BOOST_CHECK_EQUAL(v3[1].copies, 0);

    auto v4 = Vector(std::move(v3[0]), v3[1], std::move(t3));
    BOOST_CHECK_EQUAL(v4.size(), 3);
    BOOST_CHECK(v4[0].origin == &t1);
    BOOST_CHECK(v4[1].origin == &t2);
    BOOST_CHECK(v4[2].origin == &t3);
    BOOST_CHECK_EQUAL(v4[0].copies, 1);
    BOOST_CHECK_EQUAL(v4[1].copies, 1);
    BOOST_CHECK_EQUAL(v4[2].copies, 0);

    auto v5 = Cat(v1, v4);
    BOOST_CHECK_EQUAL(v5.size(), 4);
    BOOST_CHECK(v5[0].origin == &t1);
    BOOST_CHECK(v5[1].origin == &t1);
    BOOST_CHECK(v5[2].origin == &t2);
    BOOST_CHECK(v5[3].origin == &t3);
    BOOST_CHECK_EQUAL(v5[0].copies, 2);
    BOOST_CHECK_EQUAL(v5[1].copies, 2);
    BOOST_CHECK_EQUAL(v5[2].copies, 2);
    BOOST_CHECK_EQUAL(v5[3].copies, 1);

    auto v6 = Cat(std::move(v1), v3);
    BOOST_CHECK_EQUAL(v6.size(), 3);
    BOOST_CHECK(v6[0].origin == &t1);
    BOOST_CHECK(v6[1].origin == &t1);
    BOOST_CHECK(v6[2].origin == &t2);
    BOOST_CHECK_EQUAL(v6[0].copies, 1);
    BOOST_CHECK_EQUAL(v6[1].copies, 2);
    BOOST_CHECK_EQUAL(v6[2].copies, 1);

    auto v7 = Cat(v2, std::move(v4));
    BOOST_CHECK_EQUAL(v7.size(), 4);
    BOOST_CHECK(v7[0].origin == &t2);
    BOOST_CHECK(v7[1].origin == &t1);
    BOOST_CHECK(v7[2].origin == &t2);
    BOOST_CHECK(v7[3].origin == &t3);
    BOOST_CHECK_EQUAL(v7[0].copies, 1);
    BOOST_CHECK_EQUAL(v7[1].copies, 1);
    BOOST_CHECK_EQUAL(v7[2].copies, 1);
    BOOST_CHECK_EQUAL(v7[3].copies, 0);

    auto v8 = Cat(std::move(v2), std::move(v3));
    BOOST_CHECK_EQUAL(v8.size(), 3);
    BOOST_CHECK(v8[0].origin == &t2);
    BOOST_CHECK(v8[1].origin == &t1);
    BOOST_CHECK(v8[2].origin == &t2);
    BOOST_CHECK_EQUAL(v8[0].copies, 0);
    BOOST_CHECK_EQUAL(v8[1].copies, 1);
    BOOST_CHECK_EQUAL(v8[2].copies, 0);
}

BOOST_AUTO_TEST_CASE(test_overloaded_visitor) {
    std::variant<std::monostate, bool, std::string, double, int64_t> var;
    std::string which = "";

    auto visitor = util::Overloaded{
        [&which](std::monostate) { which = "monostate"; },
        [&which](bool b) { which = strprintf("bool: %d", b); },
        [&which](const std::string &s) { which = strprintf("string: %s", s); },
        [&which](double d) { which = strprintf("double: %g", d); },
        [&which](int64_t i) { which = strprintf("int64_t: %i", i); },
    };

    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "monostate");

    var = false;
    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "bool: 0");
    var = true;
    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "bool: 1");

    var = std::string{"foo"};
    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "string: foo");

    var = 3.14;
    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "double: 3.14");

    var = int64_t(42);
    std::visit(visitor, var);
    BOOST_CHECK_EQUAL(which, "int64_t: 42");
}

/* Check for overflow */
template <typename T>
static void TestAddMulMatrixOverflow() {
    constexpr T MAXI{std::numeric_limits<T>::max()};

    // add
    BOOST_CHECK(!CheckedAdd(T{1}, MAXI));
    BOOST_CHECK(!CheckedAdd(MAXI, MAXI));

    BOOST_CHECK_EQUAL(0, CheckedAdd(T{0}, T{0}).value());
    BOOST_CHECK_EQUAL(MAXI, CheckedAdd(T{0}, MAXI).value());
    BOOST_CHECK_EQUAL(MAXI, CheckedAdd(T{1}, MAXI - 1).value());
    BOOST_CHECK_EQUAL(MAXI - 1, CheckedAdd(T{1}, MAXI - 2).value());

    // mul
    BOOST_CHECK(!CheckedMul(MAXI, T{2}));
    BOOST_CHECK(!CheckedMul(MAXI / T{2}, T{3}));
    BOOST_CHECK(!CheckedMul(MAXI, MAXI));
    BOOST_CHECK_EQUAL((MAXI >> 1) << 1, CheckedMul(MAXI / 2, T{2}).value());
}

/* Check for overflow or underflow */
template <typename T>
static void TestAddSubMulMatrix() {
    TestAddMulMatrixOverflow<T>();
    constexpr T MINI{std::numeric_limits<T>::min()};
    constexpr T MAXI{std::numeric_limits<T>::max()};
    BOOST_CHECK(!CheckedAdd(T{-1}, MINI));
    BOOST_CHECK(!CheckedAdd(MINI, MINI));

    BOOST_CHECK_EQUAL(MINI, CheckedAdd(T{0}, MINI).value());
    BOOST_CHECK_EQUAL(MINI, CheckedAdd(T{-1}, MINI + 1).value());
    BOOST_CHECK_EQUAL(-1, CheckedAdd(MINI, MAXI).value());
    BOOST_CHECK_EQUAL(MINI + 1, CheckedAdd(T{-1}, MINI + 2).value());

    // sub
    BOOST_CHECK(!CheckedSub(MINI, T{1}));
    BOOST_CHECK(!CheckedSub(MINI + 2, 3));
    BOOST_CHECK_EQUAL(MINI + 1, CheckedSub(MINI + 3, 2).value());
    BOOST_CHECK_EQUAL(T{1}, CheckedSub(T{3}, T{2}).value());
    BOOST_CHECK(!CheckedSub(MINI, MAXI));
    BOOST_CHECK_EQUAL(1, CheckedSub(MINI + 1, MINI).value());
}

BOOST_AUTO_TEST_CASE(util_overflow) {
    TestAddMulMatrixOverflow<unsigned>();
    TestAddSubMulMatrix<signed>();
}

BOOST_AUTO_TEST_CASE(test_LogEscapeMessageInPlace) {
    std::string str;
    // ASCII and UTF-8 must pass through unaltered.
    str = "Valid log message貓";
    BOOST_CHECK(not BCLog::LogEscapeMessageInPlace(str));
    BOOST_CHECK_EQUAL(str, "Valid log message貓");
    // A more fancy and complex UTF-8 string also should be unaltered.
    str = "Smileys: 😀 😂 😊 😎, Fruit: 🍇 🍊 🍏 🥝, Phoenican: 𐤀 𐤁 𐤂 𐤃, Colored: ⌚⏰🟥🟩";
    BOOST_CHECK(not BCLog::LogEscapeMessageInPlace(str));
    BOOST_CHECK_EQUAL(str, "Smileys: 😀 😂 😊 😎, Fruit: 🍇 🍊 🍏 🥝, Phoenican: 𐤀 𐤁 𐤂 𐤃, Colored: ⌚⏰🟥🟩");
    // Newlines must pass through unaltered.
    str = "Message\n with newlines\n";
    BOOST_CHECK(not BCLog::LogEscapeMessageInPlace(str));
    BOOST_CHECK_EQUAL(str, "Message\n with newlines\n");
    // Other control characters are escaped in C syntax.
    str = "\x01\x7f Corrupted log message\x0d";
    BOOST_CHECK(BCLog::LogEscapeMessageInPlace(str));
    BOOST_CHECK_EQUAL(str, R"(\x01\x7f Corrupted log message\x0d)");
    // Embedded NULL characters are escaped too.
    str.assign("O\x00O", 3);
    BOOST_CHECK(BCLog::LogEscapeMessageInPlace(str));
    BOOST_CHECK_EQUAL(str, R"(O\x00O)");
}

// Correctness test for the hwaccel::IsAllZeros() function
BOOST_AUTO_TEST_CASE(test_IsAllZeros) {
    FastRandomContext rng;
    // Buffer with room for misalignment offsets.
    std::vector<uint8_t> buf(16 + 10000 + 16);
    size_t ncases = 0;

    // Reference implementation: direct byte-wise check for all zeros
    auto bytewiseRefImpl = [](const std::span<const uint8_t> &bytes) {
        return std::none_of(bytes.begin(), bytes.end(), [](auto b) { return b != 0; });
    };

    auto check = [&](const std::span<const uint8_t> &bytes) {
        const bool expect = bytewiseRefImpl(bytes);
        BOOST_CHECK_EQUAL(hwaccel::IsAllZeros(bytes), expect);
        // also check vs non-SIMD version
        BOOST_CHECK_EQUAL(hwaccel::detail::IsAllZerosPortable(std::as_bytes(bytes)), expect);
        ++ncases;
    };

    std::vector<size_t> sizes;
    for (size_t n = 0; n <= 320; ++n) {
        sizes.push_back(n);
    }
    for (size_t n : {size_t(511), size_t(512), size_t(513), size_t(1000), size_t(4095),
                     size_t(4096), size_t(4097), size_t(9998), size_t(9999), size_t(10000)}) {
        sizes.push_back(n);
    }

    for (size_t offset : {0, 1, 7, 13}) {
        uint8_t *base = buf.data() + offset;
        for (const size_t n : sizes) {
            // all zeros
            std::fill(base, base + n, 0);
            check({base, n});
            if (n >= 1) {
                // single nonzero at various positions/values
                for (size_t pos : {size_t(0), n / 2, n - 1}) {
                    for (uint8_t v : {0x01, 0x80, 0xff}) {
                        base[pos] = v;
                        check({base, n});
                        base[pos] = 0;
                    }
                }
                // nonzero early
                if (n >= 2) {
                    base[0] = 1;
                    check({base, n});
                    base[0] = 0;
                }
            }
            // random, zero-biased
            for (int r = 0; r < (n <= 320 ? 10 : 3); ++r) {
                for (size_t i = 0; i < n; ++i) {
                    uint64_t x = rng.rand64();
                    base[i] = (x & 0xF) ? 0 : uint8_t(x >> 32); // ~94% zeros
                }
                check({base, n});
            }
        }
    }
    BOOST_CHECK(ncases > 0);
}

BOOST_AUTO_TEST_SUITE_END()
