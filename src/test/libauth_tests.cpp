// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <config.h>
#include <consensus/activation.h>
#include <util/system.h>
#include <validation.h>

#include <test/libauth_testing_setup.h>
#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <optional>
#include <string>

namespace {

/// Test fixture that can force-enable or disable upgrade9 (cashtokens)
struct Upgrade9OverrideTestingSetup : LibauthTestingSetup {
    std::optional<int32_t> upgrade9OriginalOverride;
    bool touchedUpgrade9{};

    Upgrade9OverrideTestingSetup() {
        upgrade9OriginalOverride = g_Upgrade9HeightOverride;
    }

    ~Upgrade9OverrideTestingSetup() override {
        if (touchedUpgrade9) {
            g_Upgrade9HeightOverride = upgrade9OriginalOverride;
        }
    }

    /// Activates or deactivates upgrade 9 by setting the activation height in the past or future respectively
    void SetUpgrade9Active(bool active) {
        const auto currentHeight = []{
            LOCK(cs_main);
            return ::ChainActive().Tip()->nHeight;
        }();
        auto activationHeight = active ? currentHeight - 1 : currentHeight + 1;
        g_Upgrade9HeightOverride = activationHeight;
        touchedUpgrade9 = true;
    }
};


/// Test fixture that can force-enable or disable upgrade 11 (vmlimits + bigint) as well as upgrade9 (cashtokens)
struct Upgrade11OverrideTestingSetup : Upgrade9OverrideTestingSetup {
    std::optional<int32_t> upgrade11OriginalOverride;
    bool touchedUpgrade11 = false;

    Upgrade11OverrideTestingSetup() {
        upgrade11OriginalOverride = g_Upgrade11HeightOverride;
    }

    ~Upgrade11OverrideTestingSetup() override {
        if (touchedUpgrade11) {
            g_Upgrade11HeightOverride = upgrade11OriginalOverride;
        }
    }

    /// Activates or deactivates upgrade 11 by setting the activation height in the past or future respectively
    void SetUpgrade11Active(bool active) {
        const auto currentHeight = []{
            LOCK(cs_main);
            return ::ChainActive().Tip()->nHeight;
        }();
        auto activationHeight = active ? currentHeight - 1 : currentHeight + 1;
        g_Upgrade11HeightOverride = activationHeight;
        touchedUpgrade11 = true;
    }
};

/// Test fixture that can force-enable or disable upgrade 12 (may2026), as well as upgrade 9 & 11
struct Upgrade12OverrideTestingSetup : Upgrade11OverrideTestingSetup {
    std::optional<int32_t> upgrade12OriginalOverride;
    bool touchedUpgrade12 = false;

    Upgrade12OverrideTestingSetup() {
        upgrade12OriginalOverride = g_Upgrade12HeightOverride;
    }

    ~Upgrade12OverrideTestingSetup() override {
        if (touchedUpgrade12) {
            g_Upgrade12HeightOverride = upgrade12OriginalOverride;
        }
    }

    /// Activates or deactivates upgrade 12 by setting the activation time in the past or future respectively
    void SetUpgrade12Active(bool active) {
        const auto currentHeight = []{
            LOCK(cs_main);
            return ::ChainActive().Tip()->nHeight;
        }();
        auto activationHeight = active ? currentHeight - 1 : currentHeight + 1;
        g_Upgrade12HeightOverride = activationHeight;
        touchedUpgrade12 = true;
    }
};

bool ran2022 = false, ran2023 = false, ran2025 = false, ran2026 = false;

} // namespace


BOOST_AUTO_TEST_SUITE(libauth_tests)

BOOST_FIXTURE_TEST_CASE(regression_2022, Upgrade12OverrideTestingSetup) {
    SetUpgrade9Active(false); // needs to be forced off for this series of tests
    SetUpgrade11Active(false); // also need to ensure upgrade11 is not activated for this series of tests
    SetUpgrade12Active(false); // also need to ensure upgrade12 is not activated for this series of tests
    RunTestPack("2022");
    ran2022 = true;
}

BOOST_FIXTURE_TEST_CASE(regression_2023, Upgrade12OverrideTestingSetup) {
    SetUpgrade11Active(false); // need to ensure upgrade11 is not activated for this series of tests
    SetUpgrade12Active(false); // need to ensure upgrade12 is not activated for this series of tests
    RunTestPack("2023");
    ran2023 = true;
}

BOOST_FIXTURE_TEST_CASE(upgrade11_2025, Upgrade12OverrideTestingSetup) {
    SetUpgrade11Active(true); // force Upgrade11 (vmlimts + bigint) to be active
    SetUpgrade12Active(false); // need to ensure upgrade12 is not activated for this series of tests
    RunTestPack("2025");
    ran2025 = true;
}

BOOST_FIXTURE_TEST_CASE(upgrade12_2026, Upgrade12OverrideTestingSetup) {
    SetUpgrade11Active(true); // ensure Upgrade11 (vmlimts + bigint) is active
    SetUpgrade12Active(true); // ensure Upgrade12 (may2026) is active
    RunTestPack("2026");
    ran2026 = true;
}

// Precondition: This test *requires* that all Libauth test packs have previously completed as part of this
// test_bitcoin run.
BOOST_FIXTURE_TEST_CASE(test_lookup_table, TestingSetup) {
    BOOST_REQUIRE(ran2022 && ran2023 && ran2025 && ran2026);
    LibauthTestingSetup::ProcessExpectedReasonsTable();
    LibauthTestingSetup::ProcessExpectedMetricsTable();
}
BOOST_AUTO_TEST_SUITE_END()
