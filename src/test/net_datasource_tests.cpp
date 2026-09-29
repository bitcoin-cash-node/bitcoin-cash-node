// Copyright (c) 2026-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_datasource.h>

#include <clientversion.h>
#include <fs.h>
#include <streams.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <ios>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

// Writes `size` bytes of a simple deterministic pattern and returns them.
std::vector<uint8_t> WritePatternFile(const fs::path &path, const size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 7u + 3u) & 0xffu);
    }
    std::FILE *f = fsbridge::fopen(path, "wb");
    BOOST_REQUIRE(f != nullptr);
    BOOST_REQUIRE_EQUAL(std::fwrite(data.data(), 1, data.size(), f), data.size());
    BOOST_REQUIRE_EQUAL(std::fclose(f), 0);
    return data;
}

std::vector<uint8_t> Slice(const std::vector<uint8_t> &v, const size_t offset, const size_t count) {
    return {v.begin() + offset, v.begin() + offset + count};
}

// Reads the whole source in RecommendedChunkSize() pieces, the way CConnman::SocketSendData does.
std::vector<uint8_t> ReadAll(SerializedDataSource &ds) {
    std::vector<uint8_t> out, tmp;
    const size_t chunk = ds.RecommendedChunkSize();
    for (size_t pos = 0; pos < ds.size();) {
        const size_t n = std::min(chunk, ds.size() - pos);
        const auto sp = ds.GetBytes(pos, n, tmp);
        out.insert(out.end(), sp.begin(), sp.end());
        pos += n;
    }
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(net_datasource_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(file_backed_serves_the_requested_range) {
    const auto dir = SetDataDir("net_datasource");
    const auto path = dir / "blk.dat";
    constexpr size_t FILE_SIZE = 200'000;
    constexpr size_t OFFSET = 12'345;
    constexpr size_t LENGTH = 150'001; // > 2 chunks, not a multiple of the chunk size
    const auto file = WritePatternFile(path, FILE_SIZE);
    const auto expected = Slice(file, OFFSET, LENGTH);

    SerializedDataSource ds(path, OFFSET, LENGTH, nullptr);
    BOOST_CHECK(ReadAll(ds) == expected);

    // Random access, out of order, so seek() is exercised in both directions.
    std::vector<uint8_t> tmp;
    for (const size_t pos : {size_t{100'000}, size_t{0}, size_t{LENGTH - 1}, size_t{65'536}, size_t{7}}) {
        const auto sp = ds.GetBytes(pos, 1, tmp);
        BOOST_REQUIRE_EQUAL(sp.size(), 1u);
        BOOST_CHECK_EQUAL(sp[0], expected[pos]);
    }

    // The checksum of a file-backed range is the checksum of those bytes.
    SerializedDataSource vec(std::vector<uint8_t>{expected});
    BOOST_CHECK(ds.CalculateCheckSum() == vec.CalculateCheckSum());
}

BOOST_AUTO_TEST_CASE(reused_file_handle_serves_the_named_range) {
    const auto dir = SetDataDir("net_datasource");
    const auto path = dir / "blk.dat";
    constexpr size_t OFFSET = 1'000;
    constexpr size_t LENGTH = 50'000;
    const auto file = WritePatternFile(path, 100'000);

    // The supplied handle may start at an unrelated position.
    CAutoFile autoFile(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    BOOST_REQUIRE(!autoFile.IsNull());
    BOOST_REQUIRE_EQUAL(std::fseek(autoFile.Get(), 77'777, SEEK_SET), 0);

    SerializedDataSource ds(path, OFFSET, LENGTH, nullptr, &autoFile);
    BOOST_CHECK(autoFile.IsNull());
    BOOST_CHECK(ReadAll(ds) == Slice(file, OFFSET, LENGTH));
}

BOOST_AUTO_TEST_CASE(reads_past_the_end_throw_without_wrapping) {
    const auto dir = SetDataDir("net_datasource");
    const auto path = dir / "blk.dat";
    constexpr size_t LENGTH = 1'000;
    const auto bytes = WritePatternFile(path, LENGTH);
    constexpr size_t MAX = std::numeric_limits<size_t>::max();

    SerializedDataSource file(path, 0, LENGTH, nullptr);
    SerializedDataSource vec{std::vector<uint8_t>{bytes}};
    std::vector<uint8_t> tmp;

    for (SerializedDataSource *ds : {&file, &vec}) {
        const auto last = ds->GetBytes(LENGTH - 1, 1, tmp);
        BOOST_REQUIRE_EQUAL(last.size(), 1u);
        BOOST_CHECK_EQUAL(last[0], bytes.back());
        BOOST_CHECK(ds->GetBytes(LENGTH, 0, tmp).empty());
        BOOST_CHECK_THROW(ds->GetBytes(LENGTH, 1, tmp), std::invalid_argument);
        BOOST_CHECK_THROW(ds->GetBytes(LENGTH + 1, 0, tmp), std::invalid_argument);
        // `offset + count` wraps to a small number here; the check must not be fooled by that.
        BOOST_CHECK_THROW(ds->GetBytes(MAX, 2, tmp), std::invalid_argument);
        BOOST_CHECK_THROW(ds->GetBytes(2, MAX, tmp), std::invalid_argument);
    }
}

BOOST_AUTO_TEST_CASE(failed_read_does_not_poison_later_reads) {
    const auto dir = SetDataDir("net_datasource");
    const auto path = dir / "blk.dat";
    constexpr size_t FILE_SIZE = 10'000;
    constexpr size_t CLAIMED = 20'000;
    const auto file = WritePatternFile(path, FILE_SIZE);

    SerializedDataSource ds(path, 0, CLAIMED, nullptr);
    std::vector<uint8_t> tmp;

    // The advertised range extends beyond the file.
    BOOST_CHECK_THROW(ds.GetBytes(FILE_SIZE - 10, 100, tmp), std::ios_base::failure);

    // Retrying at the same offset must return the bytes before EOF, not reuse the failed read's position.
    const auto sp = ds.GetBytes(FILE_SIZE - 10, 10, tmp);
    BOOST_CHECK(std::vector<uint8_t>(sp.begin(), sp.end()) == Slice(file, FILE_SIZE - 10, 10));
}

BOOST_AUTO_TEST_SUITE_END()
