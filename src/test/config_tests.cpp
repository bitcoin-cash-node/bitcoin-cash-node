// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config.h>

#include <chainparams.h>
#include <consensus/consensus.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(config_tests, BasicTestingSetup)

static void CheckDefaultBlockSize(const Config &config) {
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), config.GetChainParams().GetConsensus().nDefaultConsensusBlockSize);
}

BOOST_AUTO_TEST_CASE(chain_params) {
    GlobalConfig config;

    // Global config is consistent with params.
    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);

    SelectParams(CBaseChainParams::TESTNET);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);

    SelectParams(CBaseChainParams::TESTNET4);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);

    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);

    SelectParams(CBaseChainParams::SCALENET);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);

    SelectParams(CBaseChainParams::CHIPNET);
    BOOST_CHECK_EQUAL(&Params(), &config.GetChainParams());
    CheckDefaultBlockSize(config);
}

BOOST_AUTO_TEST_CASE(generated_block_size_percent) {
    GlobalConfig config;

    // Default constructed should be at the default consensus blocksize
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), DEFAULT_CONSENSUS_BLOCK_SIZE);

    // Default to equal the max block size.
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), config.GetGeneratedBlockSize(DEFAULT_CONSENSUS_BLOCK_SIZE));

    // Out of range
    BOOST_CHECK(!config.SetGeneratedBlockSizePercent(-0.01));
    BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(DEFAULT_CONSENSUS_BLOCK_SIZE), config.GetDefaultConsensusBlockSize());
    BOOST_CHECK(!config.SetGeneratedBlockSizePercent(100.1));
    BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(DEFAULT_CONSENSUS_BLOCK_SIZE), config.GetDefaultConsensusBlockSize());

    BOOST_CHECK(config.SetGeneratedBlockSizePercent(0.0));
    BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(DEFAULT_CONSENSUS_BLOCK_SIZE), 0);

    BOOST_CHECK(config.SetGeneratedBlockSizePercent(100.0));
    BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(DEFAULT_CONSENSUS_BLOCK_SIZE), config.GetDefaultConsensusBlockSize());
    BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(64 * ONE_MEGABYTE), 64 * ONE_MEGABYTE);

    // try various percentages and they should be what we expect
    for (double percent = 0.0; percent <= 100.0; percent += 0.1) {
        const uint64_t size_override = 64 * ONE_MEGABYTE;
        const uint64_t expected = config.GetDefaultConsensusBlockSize() * (percent / 100.0);
        const uint64_t expected_override = size_override * (percent / 100.0);
        BOOST_CHECK(config.SetGeneratedBlockSizePercent(percent));
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(config.GetDefaultConsensusBlockSize()), expected);
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(size_override), expected_override);
    }
}

BOOST_AUTO_TEST_CASE(lookahead_guess) {
    GlobalConfig config;

    BOOST_REQUIRE_EQUAL(config.GetDefaultConsensusBlockSize(), DEFAULT_CONSENSUS_BLOCK_SIZE);

    size_t branch1{}, branch2{}, branch3{};
    for (uint64_t size = 0; size <= MAX_CONSENSUS_BLOCK_SIZE + ONE_MEGABYTE; size += ONE_MEGABYTE / 10) {
        config.NotifyMaxBlockSizeLookAheadGuessChanged(size);
        if (size <= config.GetDefaultConsensusBlockSize()) {
            // the max blocksize lookahead guess can never be smaller than the default consensus blocksize
            BOOST_CHECK_EQUAL(config.GetMaxBlockSizeLookAheadGuess(), config.GetDefaultConsensusBlockSize());
            ++branch1;
        } else if (size <= MAX_CONSENSUS_BLOCK_SIZE) {
            // however if it is set to larger, the lookahead guess should be verbatim what was set by
            // NotifyMaxBlockSizeLookAheadGuessChanged() above
            BOOST_CHECK_EQUAL(config.GetMaxBlockSizeLookAheadGuess(), size);
            ++branch2;
        } else {
            // except the lookahead guess should never exceed MAX_CONSENSUS_BLOCK_SIZE
            BOOST_CHECK_EQUAL(config.GetMaxBlockSizeLookAheadGuess(), MAX_CONSENSUS_BLOCK_SIZE);
            ++branch3;
        }
    }
    // Sanity check to ensure all 3 branches above were taken at least once
    BOOST_REQUIRE(branch1 && branch2 && branch3);
}

BOOST_AUTO_TEST_CASE(blocksize_override) {
    GlobalConfig config;

    // paranoia: for the below test to be ok this must hold
    BOOST_REQUIRE(DEFAULT_CONSENSUS_BLOCK_SIZE != MAX_CONSENSUS_BLOCK_SIZE
                  && DEFAULT_CONSENSUS_BLOCK_SIZE != ONE_MEGABYTE + 1);

    // Default constructed should be at the default consensus blocksize
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), DEFAULT_CONSENSUS_BLOCK_SIZE);

    // Disallow small values
    BOOST_CHECK(!config.SetBlockSizeOverride(1000));
    BOOST_CHECK(!config.SetBlockSizeOverride(ONE_MEGABYTE - 1));
    BOOST_CHECK(!config.SetBlockSizeOverride(ONE_MEGABYTE));
    // Disallow huge values
    BOOST_CHECK(!config.SetBlockSizeOverride(MAX_CONSENSUS_BLOCK_SIZE + 1));

    // Ensure nothing changed
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), DEFAULT_CONSENSUS_BLOCK_SIZE);

    // Allow > ONE_MEGABYTE
    BOOST_CHECK(config.SetBlockSizeOverride(ONE_MEGABYTE + 1));
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), ONE_MEGABYTE + 1);
    // Allow at limit
    BOOST_CHECK(config.SetBlockSizeOverride(MAX_CONSENSUS_BLOCK_SIZE));
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), MAX_CONSENSUS_BLOCK_SIZE);

    // Clear and check again
    BOOST_CHECK(config.SetBlockSizeOverride(std::nullopt));
    BOOST_CHECK_EQUAL(config.GetDefaultConsensusBlockSize(), DEFAULT_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_SUITE_END()
