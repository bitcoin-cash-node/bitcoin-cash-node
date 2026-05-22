// Copyright (c) 2019-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/activation.h>
#include <sync.h>
#include <util/defer.h>
#include <util/system.h>
#include <validation.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(activation_tests, BasicTestingSetup)

static void SetMTP(std::array<CBlockIndex, 12> &blocks, int64_t mtp) {
    size_t len = blocks.size();

    for (size_t i = 0; i < len; ++i) {
        blocks[i].nTime = mtp + (i - (len / 2));
        blocks[i].ClearCachedMTPValue();
    }

    BOOST_CHECK_EQUAL(blocks.back().GetMedianTimePast(), mtp);
}

BOOST_AUTO_TEST_CASE(isgravitonenabled) {
    const auto params = CreateChainParams(CBaseChainParams::MAIN);
    const auto &consensus = params->GetConsensus();

    BOOST_CHECK(!IsGravitonEnabled(consensus, nullptr));

    std::array<CBlockIndex, 4> blocks;
    blocks[0].nHeight = consensus.gravitonHeight - 2;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = blocks[i - 1].nHeight + 1;
    }
    BOOST_CHECK(!IsGravitonEnabled(consensus, &blocks[0]));
    BOOST_CHECK(!IsGravitonEnabled(consensus, &blocks[1]));
    BOOST_CHECK(IsGravitonEnabled(consensus, &blocks[2]));
    BOOST_CHECK(IsGravitonEnabled(consensus, &blocks[3]));
}

BOOST_AUTO_TEST_CASE(isphononenabled) {
    const Consensus::Params &consensus = Params().GetConsensus();
    BOOST_CHECK(!IsPhononEnabled(consensus, nullptr));

    std::array<CBlockIndex, 4> blocks;
    blocks[0].nHeight = consensus.phononHeight - 2;

    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = blocks[i - 1].nHeight + 1;
    }
    BOOST_CHECK(!IsPhononEnabled(consensus, &blocks[0]));
    BOOST_CHECK(!IsPhononEnabled(consensus, &blocks[1]));
    BOOST_CHECK(IsPhononEnabled(consensus, &blocks[2]));
    BOOST_CHECK(IsPhononEnabled(consensus, &blocks[3]));
}

BOOST_AUTO_TEST_CASE(isaxionenabled) {
    // first, test chains with no hard-coded activation height (activation based on MTP)
    {
        const auto pparams = CreateChainParams(CBaseChainParams::SCALENET);
        const Consensus::Params &params = pparams->GetConsensus();
        const auto activation =
            gArgs.GetArg("-axionactivationtime", params.axionActivationTime);
        SetMockTime(activation - 1000000);

        BOOST_CHECK(!IsAxionEnabled(params, nullptr));

        std::array<CBlockIndex, 12> blocks;
        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
        }
        BOOST_CHECK(!IsAxionEnabled(params, &blocks.back()));

        SetMTP(blocks, activation - 1);
        BOOST_CHECK(!IsAxionEnabled(params, &blocks.back()));

        SetMTP(blocks, activation);
        BOOST_CHECK(IsAxionEnabled(params, &blocks.back()));

        SetMTP(blocks, activation + 1);
        BOOST_CHECK(IsAxionEnabled(params, &blocks.back()));
    }

    // next, test chains with height-based activation
    {
        const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
        const auto &params = pparams->GetConsensus();
        const auto axionHeight = params.asertAnchorParams->nHeight;

        std::array<CBlockIndex, 4> blocks;
        blocks[0].nHeight = axionHeight - 2;
        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
            blocks[i].nHeight = blocks[i - 1].nHeight + 1;
        }
        BOOST_CHECK(!IsAxionEnabled(params, &blocks[0]));
        BOOST_CHECK(!IsAxionEnabled(params, &blocks[1]));
        BOOST_CHECK(IsAxionEnabled(params, &blocks[2]));
        BOOST_CHECK(IsAxionEnabled(params, &blocks[3]));
    }
}

BOOST_AUTO_TEST_CASE(isupgrade8enabled) {
    const Consensus::Params &consensus = Params().GetConsensus();
    BOOST_CHECK(!IsUpgrade8Enabled(consensus, nullptr));

    std::array<CBlockIndex, 4> blocks;
    blocks[0].nHeight = consensus.upgrade8Height - 2;

    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = blocks[i - 1].nHeight + 1;
    }
    BOOST_CHECK(!IsUpgrade8Enabled(consensus, &blocks[0]));
    BOOST_CHECK(!IsUpgrade8Enabled(consensus, &blocks[1]));
    BOOST_CHECK(IsUpgrade8Enabled(consensus, &blocks[2]));
    BOOST_CHECK(IsUpgrade8Enabled(consensus, &blocks[3]));
}

BOOST_AUTO_TEST_CASE(isupgrade9enabled) {
    // test with hard-coded activation height, also test the upgrade height override mechanism
    Defer d([orig_override = g_Upgrade9HeightOverride] { g_Upgrade9HeightOverride = orig_override; });
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();

    // check with no override (params.upgrade9height), and with a bunch of overrides spanning the int32 range ...
    for (const int32_t override : {-1, 0, 1000, 1'000'000, 1'000'000'000 }) {
        if (override < 0) {
            // no override, use consensus params
            g_Upgrade9HeightOverride.reset();
            BOOST_CHECK_EQUAL(GetUpgrade9ActivationHeight(params), params.upgrade9Height);
        } else {
            // with override
            g_Upgrade9HeightOverride = override;
            BOOST_CHECK_EQUAL(GetUpgrade9ActivationHeight(params), override);
        }
        const int32_t activation_height = GetUpgrade9ActivationHeight(params);

        BOOST_CHECK(!IsUpgrade9Enabled(params, nullptr));

        std::array<CBlockIndex, 4> blocks;
        blocks[0].nHeight = activation_height - 2;

        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
            blocks[i].nHeight = blocks[i - 1].nHeight + 1;
        }
        BOOST_CHECK(!IsUpgrade9Enabled(params, &blocks[0]));
        BOOST_CHECK(!IsUpgrade9Enabled(params, &blocks[1]));
        BOOST_CHECK(IsUpgrade9Enabled(params, &blocks[2]));
        BOOST_CHECK(IsUpgrade9Enabled(params, &blocks[3]));

        // Check the *ForHeightPrev style API
        BOOST_CHECK(!IsUpgrade9EnabledForHeightPrev(params, blocks[0].nHeight));
        BOOST_CHECK(!IsUpgrade9EnabledForHeightPrev(params, blocks[1].nHeight));
        BOOST_CHECK(IsUpgrade9EnabledForHeightPrev(params, blocks[2].nHeight));
        BOOST_CHECK(IsUpgrade9EnabledForHeightPrev(params, blocks[3].nHeight));
    }
}

BOOST_AUTO_TEST_CASE(isupgrade10enabled) {
    // test with hard-coded activation height, also test the upgrade height override mechanism
    Defer d([orig_override = g_Upgrade10HeightOverride] { g_Upgrade10HeightOverride = orig_override; });
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();

    // check with no override (params.upgrade10height), and with a bunch of overrides spanning the int32 range ...
    for (const int32_t override : {-1, 0, 1000, 1'000'000, 1'000'000'000 }) {
        if (override < 0) {
            // no override, use consensus params
            g_Upgrade10HeightOverride.reset();
            BOOST_CHECK_EQUAL(GetUpgrade10ActivationHeight(params), params.upgrade10Height);
        } else {
            // with override
            g_Upgrade10HeightOverride = override;
            BOOST_CHECK_EQUAL(GetUpgrade10ActivationHeight(params), override);
        }
        const int32_t activation_height = GetUpgrade10ActivationHeight(params);

        BOOST_CHECK(!IsUpgrade10Enabled(params, nullptr));

        std::array<CBlockIndex, 4> blocks;
        blocks[0].nHeight = activation_height - 2;

        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
            blocks[i].nHeight = blocks[i - 1].nHeight + 1;
        }
        BOOST_CHECK(!IsUpgrade10Enabled(params, &blocks[0]));
        BOOST_CHECK(!IsUpgrade10Enabled(params, &blocks[1]));
        BOOST_CHECK(IsUpgrade10Enabled(params, &blocks[2]));
        BOOST_CHECK(IsUpgrade10Enabled(params, &blocks[3]));
    }
}

BOOST_AUTO_TEST_CASE(isupgrade11enabled) {
    // test with hard-coded activation height, also test the upgrade height override mechanism
    Defer d([orig_override = g_Upgrade11HeightOverride] { g_Upgrade11HeightOverride = orig_override; });
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();

    // check with no override (params.upgrade11height), and with a bunch of overrides spanning the int32 range ...
    for (const int32_t override : {-1, 0, 1000, 1'000'000, 1'000'000'000 }) {
        if (override < 0) {
            // no override, use consensus params
            g_Upgrade11HeightOverride.reset();
            BOOST_CHECK_EQUAL(GetUpgrade11ActivationHeight(params), params.upgrade11Height);
        } else {
            // with override
            g_Upgrade11HeightOverride = override;
            BOOST_CHECK_EQUAL(GetUpgrade11ActivationHeight(params), override);
        }
        const int32_t activation_height = GetUpgrade11ActivationHeight(params);

        BOOST_CHECK(!IsUpgrade11Enabled(params, nullptr));

        std::array<CBlockIndex, 4> blocks;
        blocks[0].nHeight = activation_height - 2;

        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
            blocks[i].nHeight = blocks[i - 1].nHeight + 1;
        }
        BOOST_CHECK(!IsUpgrade11Enabled(params, &blocks[0]));
        BOOST_CHECK(!IsUpgrade11Enabled(params, &blocks[1]));
        BOOST_CHECK(IsUpgrade11Enabled(params, &blocks[2]));
        BOOST_CHECK(IsUpgrade11Enabled(params, &blocks[3]));
    }
}

BOOST_AUTO_TEST_CASE(isupgrade12enabled) {
    // test with hard-coded activation height, also test the upgrade height override mechanism
    Defer d([orig_override = g_Upgrade12HeightOverride] { g_Upgrade12HeightOverride = orig_override; });
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();

    // check with no override (params.upgrade12height), and with a bunch of overrides spanning the int32 range ...
    for (const int32_t override : {-1, 0, 1000, 1'000'000, 1'000'000'000 }) {
        if (override < 0) {
            // no override, use consensus params
            g_Upgrade12HeightOverride.reset();
            BOOST_CHECK_EQUAL(GetUpgrade12ActivationHeight(params), params.upgrade12Height);
        } else {
            // with override
            g_Upgrade12HeightOverride = override;
            BOOST_CHECK_EQUAL(GetUpgrade12ActivationHeight(params), override);
        }
        const int32_t activation_height = GetUpgrade12ActivationHeight(params);

        BOOST_CHECK(!IsUpgrade12Enabled(params, nullptr));

        std::array<CBlockIndex, 4> blocks;
        blocks[0].nHeight = activation_height - 2;

        for (size_t i = 1; i < blocks.size(); ++i) {
            blocks[i].pprev = &blocks[i - 1];
            blocks[i].nHeight = blocks[i - 1].nHeight + 1;
        }
        BOOST_CHECK(!IsUpgrade12Enabled(params, &blocks[0]));
        BOOST_CHECK(!IsUpgrade12Enabled(params, &blocks[1]));
        BOOST_CHECK(IsUpgrade12Enabled(params, &blocks[2]));
        BOOST_CHECK(IsUpgrade12Enabled(params, &blocks[3]));
    }
}

BOOST_AUTO_TEST_CASE(isupgrade2027enabled) {
    // test with no hard-coded activation height (activation based on MTP)
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();
    const auto activation = gArgs.GetArg("-upgrade2027activationtime", params.upgrade2027ActivationTime);
    const auto origMockTime = GetMockTime();
    Defer d([origMockTime] { SetMockTime(origMockTime); });
    SetMockTime(activation - 1000000);

    BOOST_CHECK(!IsUpgrade2027Enabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
    }
    BOOST_CHECK(!IsUpgrade2027Enabled(params, &blocks.back()));

    SetMTP(blocks, activation - 1);
    BOOST_CHECK(!IsUpgrade2027Enabled(params, &blocks.back()));

    SetMTP(blocks, activation);
    BOOST_CHECK(IsUpgrade2027Enabled(params, &blocks.back()));

    SetMTP(blocks, activation + 1);
    BOOST_CHECK(IsUpgrade2027Enabled(params, &blocks.back()));
}

// Test that the upgrade2027 activation height tracker mechanism works, even if examining blocks that are not the
// active chain.
BOOST_AUTO_TEST_CASE(test_upgrade2027_activation_block_tracking) {
    LOCK(cs_main); // needed to access the g_upgrade2027_block_tracker and ::ChainActive()
    CBlockIndex * const origTip = ::ChainActive().Tip();
    const auto pparams = CreateChainParams(CBaseChainParams::MAIN);
    const Consensus::Params &params = pparams->GetConsensus();
    const auto activation = gArgs.GetArg("-upgrade2027activationtime", params.upgrade2027ActivationTime);
    const auto origMockTime = GetMockTime();
    SetMockTime(activation - 1000000);
    Defer d([&] {
        LOCK(cs_main); // to suppress warnings
        SetMockTime(origMockTime);
        ::ChainActive().SetTip(origTip);
        g_upgrade2027_block_tracker.ResetActivationBlockCache();
    });

    BOOST_CHECK(!IsUpgrade2027Enabled(params, nullptr));

    std::array<CBlockIndex, 12> blocks, blocks2, blocksFork;
    for (size_t i = 1; i < blocks.size(); ++i) {
        blocks[i].pprev = &blocks[i - 1];
        blocks2[i].pprev = &blocks2[i - 1];
        blocksFork[i].pprev = &blocksFork[i - 1];
        if (i > 1) {
            blocks[i].pskip = &blocks[i - 2];
            blocks2[i].pskip = &blocks2[i - 2];
            blocksFork[i].pskip = &blocksFork[i - 2];
        }
    }

    SetMTP(blocks, activation + 3);
    SetMTP(blocks2, activation + 1);

    blocksFork[0].pprev = &blocks[6]; // fork at block 6 (1 past the activation block)
    blocksFork[0].nTime = blocksFork[0].pprev->nTime + 1;
    blocksFork[0].ClearCachedMTPValue();
    for (size_t i = 1; i < blocksFork.size(); ++i) {
        blocksFork[i].nTime = blocksFork[i-1].nTime + 1;
        blocksFork[i].ClearCachedMTPValue();
    }

    BOOST_CHECK(IsUpgrade2027Enabled(params, &blocks.back()));
    BOOST_CHECK(IsUpgrade2027Enabled(params, &blocks2.back()));

    // test that it returns what we expect when the active chain is `blocks`
    ::ChainActive().SetTip(&blocks.back());

    auto *block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks.back(), params);
    BOOST_CHECK(block == &blocks[5]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks2.back(), params);
    BOOST_CHECK(block == &blocks2[9]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocksFork.back(), params); // check fork
    BOOST_CHECK(block == &blocks[5]); // the chain we forked off of is still the activation block
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));


    // switch to another tip
    ::ChainActive().SetTip(origTip);

    // both should still work even if non-main chain and if the upgrade is not activated!
    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks.back(), params);
    BOOST_CHECK(block == &blocks[5]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks2.back(), params);
    BOOST_CHECK(block == &blocks2[9]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocksFork.back(), params); // check fork
    BOOST_CHECK(block == &blocks[5]); // the chain we forked off of is still the activation block
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));


    // switch to another tip
    ::ChainActive().SetTip(&blocks2.back());

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks.back(), params);
    BOOST_CHECK(block == &blocks[5]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks2.back(), params);
    BOOST_CHECK(block == &blocks2[9]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocksFork.back(), params); // check fork
    BOOST_CHECK(block == &blocks[5]); // the chain we forked off of is still the activation block
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    // switch to the fork tip
    ::ChainActive().SetTip(&blocksFork.back());

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks.back(), params);
    BOOST_CHECK(block == &blocks[5]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocks2.back(), params);
    BOOST_CHECK(block == &blocks2[9]);
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocksFork.back(), params); // check fork
    BOOST_CHECK(block == &blocks[5]); // the chain we forked off of is still the activation block
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));

    // Call it again against another block to test caching works
    block = g_upgrade2027_block_tracker.GetActivationBlock(&blocksFork[5], params); // check fork
    BOOST_CHECK(block == &blocks[5]); // the chain we forked off of is still the activation block
    BOOST_CHECK(IsUpgrade2027Enabled(params, block) && !IsUpgrade2027Enabled(params, block->pprev));
}

BOOST_AUTO_TEST_SUITE_END()
