// Copyright (c) 2018-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockvalidity.h>
#include <chain.h>
#include <consensus/abla.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(blockindex_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(get_block_header) {
    const int32_t expectedVersion = 4;
    const uint256 expectedMerkleRoot = uint256();
    const uint32_t expectedBlockTime = 123;
    const uint32_t expectedDifficultyBits = 234;
    const uint32_t expectedNonce = 345;

    CBlockHeader header;
    header.nVersion = expectedVersion;
    header.hashMerkleRoot = expectedMerkleRoot;
    header.nTime = expectedBlockTime;
    header.nBits = expectedDifficultyBits;
    header.nNonce = expectedNonce;

    const CBlockIndex index(header);

    CBlockHeader checkHeader = index.GetBlockHeader();
    BOOST_CHECK(checkHeader.nVersion == expectedVersion);
    BOOST_CHECK(checkHeader.hashMerkleRoot == expectedMerkleRoot);
    BOOST_CHECK(checkHeader.nTime == expectedBlockTime);
    BOOST_CHECK(checkHeader.nBits == expectedDifficultyBits);
    BOOST_CHECK(checkHeader.nNonce == expectedNonce);
}

BOOST_AUTO_TEST_CASE(get_disk_positions) {
    // Test against all validity values
    std::set<BlockValidity> validityValues{
        BlockValidity::UNKNOWN, BlockValidity::HEADER,
        BlockValidity::TREE,    BlockValidity::TRANSACTIONS,
        BlockValidity::CHAIN,   BlockValidity::SCRIPTS};
    for (BlockValidity validity : validityValues) {
        // Test against all combinations of data and undo flags
        for (int flags = 0; flags <= 0x03; flags++) {
            // Generate some values to test against
            const int expectedFile = flags * 123;
            const unsigned int expectedDataPosition = flags * 234;
            const unsigned int expectedUndoPosition = flags * 345;

            CBlockIndex index;
            index.nStatus = index.nStatus.withValidity(BlockValidity(validity));

            // All combinations of data and undo
            if (flags & 0x01) {
                index.nStatus = index.nStatus.withData();
                index.nFile = expectedFile;
                index.nDataPos = expectedDataPosition;
            }
            if (flags & 0x02) {
                index.nStatus = index.nStatus.withUndo();
                index.nFile = expectedFile;
                index.nUndoPos = expectedUndoPosition;
            }

            // Data and undo positions should be unmodified
            FlatFilePos dataPosition = index.GetBlockPos();
            if (flags & 0x01) {
                BOOST_CHECK(dataPosition.nFile == expectedFile);
                BOOST_CHECK(dataPosition.nPos == expectedDataPosition);
            } else {
                BOOST_CHECK(dataPosition == FlatFilePos());
            }

            FlatFilePos undoPosition = index.GetUndoPos();
            if (flags & 0x02) {
                BOOST_CHECK(undoPosition.nFile == expectedFile);
                BOOST_CHECK(undoPosition.nPos == expectedUndoPosition);
            } else {
                BOOST_CHECK(undoPosition == FlatFilePos());
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(get_block_hash) {
    CBlockIndex index{};

    /* Test with all 0 hash */
    const BlockHash zeroHash = BlockHash();
    index.phashBlock = &zeroHash;
    BlockHash hash = index.GetBlockHash();
    BOOST_CHECK(hash == zeroHash);

    /* Test with a random hash */
    uint256 hashBytes;
    std::generate(hashBytes.begin(), hashBytes.end(),
                  []() { return uint8_t(rand() % 255); });

    const BlockHash randomHash = BlockHash(hashBytes);
    index.phashBlock = &randomHash;
    hash = index.GetBlockHash();
    BOOST_CHECK(hash == randomHash);
}

BOOST_AUTO_TEST_CASE(received_time) {
    // Set to UINT32_MAX because that's the maximum value header.nTime can hold
    const int64_t expectedBlockTime = std::numeric_limits<uint32_t>::max();

    CBlockHeader header;
    header.nTime = uint32_t(expectedBlockTime);

    CBlockIndex index(header);

    // nTimeReceived defaults to 0
    BOOST_CHECK_EQUAL(index.nTimeReceived, 0);

    // nTimeReceived can be updated to the actual received time, which may
    // be before or after the miner's time.
    for (int64_t receivedTime = expectedBlockTime - 10;
         // Make sure that receivedTime is tested beyond 32-bit values.
         receivedTime <= expectedBlockTime + 10; receivedTime++) {
        index.nTimeReceived = receivedTime;
        BOOST_CHECK_EQUAL(index.GetBlockTime(), expectedBlockTime);
        BOOST_CHECK_EQUAL(index.GetHeaderReceivedTime(), receivedTime);
        BOOST_CHECK_EQUAL(index.GetReceivedTimeDiff(),
                          receivedTime - expectedBlockTime);
    }
}

BOOST_AUTO_TEST_CASE(median_time_past) {
    std::array<CBlockIndex, 12> indices;

    // times in this test are pairs of <blockTime, MTP>

    // Check that MTP is correctly calculated for all cases when block times
    // are consecutive and greater than previous block times:
    // 1) All cases where the number of blocks is < 11
    // 2) The case where the number of blocks is exactly 11
    // 3) The case where the number of blocks is > 11 (but only 11 are used to
    //    calculate MTP.
    std::array<std::pair<int, int>, 12> times = {{{0, 0},
                                                  {1, 1},
                                                  {2, 1},
                                                  {4, 2},
                                                  {4, 2},
                                                  {5, 4},
                                                  {7, 4},
                                                  {10, 4},
                                                  {12, 4},
                                                  {14, 5},
                                                  {17, 5},
                                                  {20, 7}}};
    for (size_t i = 0; i < indices.size(); i++) {
        indices[i].nTime = times[i].first;
        if (i > 0) {
            indices[i].pprev = &indices[i - 1];
        }

        BOOST_CHECK(indices[i].GetMedianTimePast() == times[i].second);
    }

    // Test against non-consecutive block times
    std::array<std::pair<int, int>, 12> times2 = {{{0, 0},
                                                   {0, 0},
                                                   {1, 0},
                                                   {3, 1},
                                                   {2, 1},
                                                   {3, 2},
                                                   {4, 2},
                                                   {5, 3},
                                                   {6, 3},
                                                   {7, 3},
                                                   {8, 3},
                                                   {9, 4}}};
    for (size_t i = 0; i < indices.size(); i++) {
        indices[i].nTime = times2[i].first;
        indices[i].ClearCachedMTPValue();
        BOOST_CHECK(indices[i].GetMedianTimePast() == times2[i].second);
    }
}

BOOST_AUTO_TEST_CASE(to_string) {
    CBlockHeader header = CBlockHeader();
    header.hashMerkleRoot = uint256();

    CBlockIndex index(header);
    const BlockHash hashBlock = BlockHash();
    index.phashBlock = &hashBlock;
    index.nHeight = 123;

    CBlockIndex indexPrev{};

    std::string expectedString = "";
    std::string indexString = "";

    /* CASE 1 : pprev is null */
    expectedString = strprintf(
        "CBlockIndex(pprev=%p, nHeight=123, "
        "merkle="
        "0000000000000000000000000000000000000000000000000000000000000000, "
        "hashBlock="
        "0000000000000000000000000000000000000000000000000000000000000000)",
        (void *)(nullptr));
    index.pprev = nullptr;
    indexString = index.ToString();
    BOOST_CHECK_EQUAL(indexString, expectedString);

    /* CASE 2 : pprev is indexPrev */
    expectedString = strprintf(
        "CBlockIndex(pprev=%p, nHeight=123, "
        "merkle="
        "0000000000000000000000000000000000000000000000000000000000000000, "
        "hashBlock="
        "0000000000000000000000000000000000000000000000000000000000000000)",
        &indexPrev);
    index.pprev = &indexPrev;
    indexString = index.ToString();
    BOOST_CHECK_EQUAL(indexString, expectedString);

    /* CASE 3 : height is max(int) */
    expectedString = strprintf(
        "CBlockIndex(pprev=%p, nHeight=2147483647, "
        "merkle="
        "0000000000000000000000000000000000000000000000000000000000000000, "
        "hashBlock="
        "0000000000000000000000000000000000000000000000000000000000000000)",
        &indexPrev);
    index.nHeight = INT32_MAX;
    indexString = index.ToString();
    BOOST_CHECK_EQUAL(indexString, expectedString);

    /* CASE 4 : set some Merkle root hash */
    expectedString = strprintf(
        "CBlockIndex(pprev=%p, nHeight=2147483647, "
        "merkle="
        "0000000000000000000000000000000000000000000000000123456789abcdef, "
        "hashBlock="
        "0000000000000000000000000000000000000000000000000000000000000000)",
        &indexPrev);
    index.hashMerkleRoot = uint256S("0123456789ABCDEF");
    indexString = index.ToString();
    BOOST_CHECK_EQUAL(indexString, expectedString);

    /* CASE 5 : set some block hash */
    expectedString = strprintf(
        "CBlockIndex(pprev=%p, nHeight=2147483647, "
        "merkle="
        "0000000000000000000000000000000000000000000000000123456789abcdef, "
        "hashBlock="
        "000000000000000000000000000000000000000000000000fedcba9876543210)",
        &indexPrev);
    const BlockHash emptyHashBlock = BlockHash::fromHex("FEDCBA9876543210");
    index.phashBlock = &emptyHashBlock;
    indexString = index.ToString();
    BOOST_CHECK_EQUAL(indexString, expectedString);
}

BOOST_AUTO_TEST_CASE(index_validity_tests) {
    CBlockIndex index;

    // Test against all validity values
    std::set<BlockValidity> validityValues{
        BlockValidity::UNKNOWN, BlockValidity::HEADER,
        BlockValidity::TREE,    BlockValidity::TRANSACTIONS,
        BlockValidity::CHAIN,   BlockValidity::SCRIPTS};
    std::set<bool> boolValues = {false, true};
    for (BlockValidity validity : validityValues) {
        for (bool withFailed : boolValues) {
            for (bool withFailedParent : boolValues) {
                index.nStatus = BlockStatus()
                                    .withValidity(validity)
                                    .withFailed(withFailed)
                                    .withFailedParent(withFailedParent);

                for (BlockValidity validUpTo : validityValues) {
                    // Test isValidity()
                    bool isValid = index.IsValid(validUpTo);
                    if (validUpTo <= validity && !withFailed &&
                        !withFailedParent) {
                        BOOST_CHECK(isValid);
                    } else {
                        BOOST_CHECK(!isValid);
                    }

                    // Test RaiseValidity()
                    CBlockIndex indexRaiseValidity;
                    for (BlockValidity validFrom : validityValues) {
                        indexRaiseValidity.nStatus =
                            BlockStatus()
                                .withValidity(validFrom)
                                .withFailed(withFailed)
                                .withFailedParent(withFailedParent);

                        bool raisedValidity =
                            indexRaiseValidity.RaiseValidity(validUpTo);
                        if (validFrom < validUpTo && !withFailed &&
                            !withFailedParent) {
                            BOOST_CHECK(raisedValidity);
                            BOOST_CHECK(
                                indexRaiseValidity.nStatus.getValidity() ==
                                validUpTo);
                        } else {
                            BOOST_CHECK(!raisedValidity);
                            BOOST_CHECK(
                                indexRaiseValidity.nStatus.getValidity() ==
                                validFrom);
                        }
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(index_ancestors) {
    std::array<CBlockIndex, 256> indexes; //! all instances are default constructed here

    /* Check the skip pointer don't build when there is no precedence */
    for (size_t i = 0; i < indexes.size(); i++) {
        indexes[i].nHeight = i;

        indexes[i].pprev = nullptr;
        indexes[i].pskip = nullptr;

        indexes[i].BuildSkip();

        /* Check that skip not rebuilt if there is no preceding index */
        BOOST_CHECK(indexes[i].pskip == nullptr);
    }

    for (size_t i = 0; i < indexes.size(); i++) {
        if (i > 0) {
            indexes[i].pprev = &indexes[i - 1];
            indexes[i].BuildSkip();

            /* Check that skip is built */
            BOOST_CHECK(indexes[i].pskip != nullptr);

            /*
             * Starting from height 2, pskip should be more efficient that
             * pprev.
             * Ensure pskip.nHeight < pprev.nHeight
             */
            if (i > 1) {
                BOOST_CHECK(indexes[i].pskip->nHeight <
                            indexes[i].pprev->nHeight);
            }

            /* Find an ancestor 16 indexes behind */
            if (i > 16) {
                CBlockIndex *ancestor =
                    indexes[i].GetAncestor(indexes[i].nHeight - 16);
                BOOST_CHECK(ancestor != nullptr);
                BOOST_CHECK(ancestor->nHeight == (indexes[i].nHeight - 16));
            }
        }
    }

    /*
     * Reorder these indexes to setup multiple branches:
     *
     *                                     (248)->(...)->(255)
     *                                    /
     *                 (128)->(...)->(191)->(...)->(247)
     *                /
     * (0)->(...)->(63)->(...)->(127)
     */
    for (size_t i = 0; i < indexes.size(); i++) {
        /* Build the tree */
        indexes[i].pskip = nullptr;
        if (i > 0) {
            indexes[i].pprev = &indexes[i - 1];
        }
        if (i < 128) {
            indexes[i].nHeight = i;
        } else if (i < 248) {
            /* Branch at 128 */
            if (i == 128) {
                indexes[i].pprev = &indexes[63];
            }
            indexes[i].nHeight = i - 64;
        } else {
            /* Branch at 248 */
            if (i == 248) {
                indexes[i].pprev = &indexes[191];
            }
            indexes[i].nHeight = i - 128 + 8;
        }

        /* Build and test skip pointer */
        if (i > 0) {
            indexes[i].BuildSkip();

            /* Check that skip is built */
            BOOST_CHECK(indexes[i].pskip != nullptr);

            /*
             * Starting from height 2, pskip should be more efficient that
             * pprev.
             * Ensure pskip.nHeight < pprev.nHeight
             */
            if (i > 1) {
                BOOST_CHECK(indexes[i].pskip->nHeight <
                            indexes[i].pprev->nHeight);
            }
        }

        /* Find an ancestor 37 indexes behind */
        if (i > 37) {
            CBlockIndex *ancestor =
                indexes[i].GetAncestor(indexes[i].nHeight - 37);
            BOOST_CHECK(ancestor != nullptr);
            BOOST_CHECK(ancestor->nHeight == (indexes[i].nHeight - 37));
        }
    }
}

BOOST_AUTO_TEST_CASE(abla_state_packing) {
    const auto u64max = std::numeric_limits<uint64_t>::max();
    const uint64_t maxPackable = u64max >> 1;

    CBlockIndex index;
    BOOST_CHECK(!index.GetAblaStateOpt());

    // A state survives the packed representation unchanged. blockSize gets one bit fewer than
    // the other two members, since the engaged flag steals one. Descending order so that a
    // store which fails to clear bits set by the previous one is visible here.
    for (const uint64_t blockSize : {maxPackable, uint64_t(1000), uint64_t(0)}) {
        const auto state = abla::State::FromTuple({blockSize, u64max, u64max});
        index.SetAblaStateOpt(state);
        const auto readBack = index.GetAblaStateOpt();
        BOOST_REQUIRE(readBack);
        BOOST_CHECK_EQUAL(readBack->GetBlockSize(), blockSize);
        BOOST_CHECK_EQUAL(readBack->GetControlBlockSize(), u64max);
        BOOST_CHECK_EQUAL(readBack->GetElasticBufferSize(), u64max);
        BOOST_CHECK(*readBack == state);
    }

    // The engaged flag is distinct from a zeroed state: both must be representable.
    index.SetAblaStateOpt(abla::State{});
    BOOST_REQUIRE(index.GetAblaStateOpt());
    BOOST_CHECK(*index.GetAblaStateOpt() == abla::State{});
    index.SetAblaStateOpt(std::nullopt);
    BOOST_CHECK(!index.GetAblaStateOpt());

    // GetAblaStateOr must not evaluate the fallback when a state is present: its only caller
    // reads a block from disk in that lambda.
    const auto fallback = abla::State::FromTuple({7, 7, 7});
    size_t calls = 0;
    const auto countingFallback = [&] { ++calls; return fallback; };
    BOOST_CHECK(index.GetAblaStateOr(countingFallback) == fallback);
    BOOST_CHECK_EQUAL(calls, 1u);
    const auto real = abla::State::FromTuple({1, 2, 3});
    index.SetAblaStateOpt(real);
    BOOST_CHECK(index.GetAblaStateOr(countingFallback) == real);
    BOOST_CHECK_EQUAL(calls, 1u);

    // CanPack is the boundary the serialization code relies on.
    BOOST_CHECK(AblaStateMixin::CanPack(std::nullopt));
    BOOST_CHECK(AblaStateMixin::CanPack(abla::State::FromTuple({maxPackable, 0, 0})));
    BOOST_CHECK(!AblaStateMixin::CanPack(abla::State::FromTuple({maxPackable + 1, 0, 0})));
}

BOOST_AUTO_TEST_CASE(abla_state_disk_serialization) {
    CBlockIndex index;
    index.nHeight = 700000;
    index.nStatus = index.nStatus.withData().withUndo();
    index.nTx = 5;
    index.nFile = 1;
    index.nDataPos = 123;
    index.nUndoPos = 456;
    index.nVersion = 4;
    index.nTime = 1700000000;
    index.nBits = 0x1d00ffff;
    index.nNonce = 42;
    const auto state = abla::State::FromTuple({1000, 32000000, 1000000});
    index.SetAblaStateOpt(state);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CDiskBlockIndex(&index);

    // Sanity: a well-formed record round-trips.
    {
        CDataStream in(ss);
        CDiskBlockIndex read;
        in >> read;
        BOOST_REQUIRE(read.GetAblaStateOpt());
        BOOST_CHECK(*read.GetAblaStateOpt() == state);
    }

    // Splice in a state whose blockSize does not fit the packed representation, as disk
    // corruption could produce. Serializing it directly is fine: only the CBlockIndex setter
    // packs. This assumes the abla state is the last thing CDiskBlockIndex writes; if a field
    // is ever appended after it, the tail check below is what will complain.
    const auto unpackable = abla::State::FromTuple({uint64_t(1) << 63, 32000000, 1000000});
    BOOST_REQUIRE(!AblaStateMixin::CanPack(unpackable));
    CDataStream goodTailStream(SER_DISK, CLIENT_VERSION), badTailStream(SER_DISK, CLIENT_VERSION);
    goodTailStream << std::optional<abla::State>{state};
    badTailStream << std::optional<abla::State>{unpackable};
    const std::vector<uint8_t> goodTail(goodTailStream.begin(), goodTailStream.end());
    const std::vector<uint8_t> badTail(badTailStream.begin(), badTailStream.end());

    std::vector<uint8_t> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_GT(bytes.size(), goodTail.size());
    const auto tailBegin = bytes.end() - goodTail.size();
    BOOST_TEST_INFO("record tail " << HexStr(tailBegin, bytes.end())
                    << ", expected abla state " << HexStr(goodTail));
    BOOST_REQUIRE_MESSAGE(std::equal(goodTail.begin(), goodTail.end(), tailBegin),
                          "the abla state is no longer the last field of CDiskBlockIndex");
    bytes.resize(bytes.size() - goodTail.size());
    bytes.insert(bytes.end(), badTail.begin(), badTail.end());

    // Must be reported as a stream failure, which callers turn into "Error loading block
    // database", rather than tripping an assert or silently truncating blockSize.
    CDataStream corrupt(bytes, SER_DISK, CLIENT_VERSION);
    CDiskBlockIndex read;
    BOOST_CHECK_EXCEPTION(corrupt >> read, std::ios_base::failure,
                          HasReason("exceeds packed representation"));
}

BOOST_AUTO_TEST_CASE(abla_state_truncated_record) {
    // A record that ends before the abla state is tolerated and read as "no state", which is
    // how block indices written before the field existed are loaded.
    CBlockIndex index;
    index.nHeight = 42;
    index.nTx = 1;
    index.nVersion = 4;
    index.nTime = 1700000000;
    index.nBits = 0x1d00ffff;
    index.SetAblaStateOpt(abla::State::FromTuple({1000, 32000000, 1000000}));

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CDiskBlockIndex(&index);

    CDataStream tailStream(SER_DISK, CLIENT_VERSION);
    tailStream << index.GetAblaStateOpt();
    std::vector<uint8_t> bytes(ss.begin(), ss.end());
    BOOST_REQUIRE_GT(bytes.size(), tailStream.size());
    bytes.resize(bytes.size() - tailStream.size());

    CDataStream truncated(bytes, SER_DISK, CLIENT_VERSION);
    CDiskBlockIndex read;
    BOOST_CHECK_NO_THROW(truncated >> read);
    BOOST_CHECK(!read.GetAblaStateOpt());
}

BOOST_AUTO_TEST_SUITE_END()
