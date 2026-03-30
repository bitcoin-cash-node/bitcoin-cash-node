// Copyright (c) 2019-2025 The Bitcoin Core developers
// Copyright (c) 2025-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>

#include <clientversion.h>
#include <primitives/transaction.h>
#include <scheduler.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/string.h>
#include <util/system.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <string>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static std::vector<std::string> ReadDebugLogLines() {
    std::vector<std::string> lines;
    std::ifstream ifs{LogInstance().m_file_path.string()};
    for (std::string line; std::getline(ifs, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

struct ScopedScheduler {
    CScheduler scheduler;
    bool did_set_limiter = false;

    ScopedScheduler() {
        scheduler.serviceThread = std::thread([this] { scheduler.serviceQueue(); });
    }
    ~ScopedScheduler() {
        if (did_set_limiter) LogInstance().DisableRateLimiting();
        scheduler.stop();
    }
    void MockForwardAndSync(std::chrono::seconds duration) {
        scheduler.MockForward(duration);
        std::promise<void> promise;
        scheduler.scheduleFromNow([&promise] { promise.set_value(); }, 0ms);
        promise.get_future().wait();
    }
    std::weak_ptr<BCLog::LogRateLimiter> MakeLimiter(size_t max_bytes, std::chrono::seconds window) {
        auto weak_limiter = LogInstance().SetRateLimiting(max_bytes, window);
        did_set_limiter = true;
        scheduler.scheduleEvery([weak_limiter]{
            if (auto limiter = weak_limiter.lock()) {
                limiter->Reset();
                return true;
            }
            return false;
        }, window);
        return weak_limiter;
    }
};

BOOST_AUTO_TEST_CASE(logging_log_rate_limiter) {
    const uint64_t max_bytes = 1024;
    const auto reset_window = 1min;
    ScopedScheduler scheduler;
    const auto plimiter = scheduler.MakeLimiter(max_bytes, reset_window).lock();
    BOOST_REQUIRE(plimiter != nullptr);
    BCLog::LogRateLimiter &limiter = *plimiter;

    using Status = BCLog::LogRateLimiter::Status;
    const auto source_loc_1 = std::source_location::current();
    const auto source_loc_2 = std::source_location::current();

    // A fresh limiter should not have any suppressions
    BOOST_CHECK(!limiter.SuppressionsActive());

    // Resetting an unused limiter is fine
    limiter.Reset();
    BOOST_CHECK(!limiter.SuppressionsActive());

    // No suppression should happen until more than max_bytes have been consumed
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes - 1, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::UNSUPPRESSED);
    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::STILL_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // Location 2  should not be affected by location 1's suppression
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // After reset_window time has passed, all suppressions should be cleared.
    scheduler.MockForwardAndSync(reset_window);

    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
}

BOOST_AUTO_TEST_CASE(logging_log_limit_stats) {
    BCLog::LogRateLimiter::Stats stats(BCLog::RATELIMIT_MAX_BYTES);

    // Check that counter gets initialized correctly.
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    const uint64_t MESSAGE_SIZE{BCLog::RATELIMIT_MAX_BYTES / 2};
    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE * 2);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    // Consuming more bytes after already having consumed RATELIMIT_MAX_BYTES should fail.
    BOOST_CHECK(!stats.Consume(500));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, uint64_t{0});
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{500});
}

struct LogSetup : BasicTestingSetup {
    const fs::path prev_log_path;
    const bool prev_reopen_file;
    const bool prev_print_to_console;
    const bool prev_print_to_file;
    const bool prev_log_timestamps;
    const bool prev_log_time_micros;
    const bool prev_log_threadnames;
    const uint32_t prev_category_mask;

    LogSetup() : prev_log_path{LogInstance().m_file_path},
                 prev_reopen_file{LogInstance().m_reopen_file},
                 prev_print_to_console{LogInstance().m_print_to_console},
                 prev_print_to_file{LogInstance().m_print_to_file},
                 prev_log_timestamps{LogInstance().m_log_timestamps},
                 prev_log_time_micros{LogInstance().m_log_time_micros},
                 prev_log_threadnames{LogInstance().m_log_threadnames},
                 prev_category_mask{LogInstance().GetCategoryMask()} {
        auto tmp_log_path = SetDataDir("logging_tests_setup") / "tmp_debug.log";
        BCLog::ReconstructLogInstance();
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_console = false;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().DisableRateLimiting();
        LogInstance().OpenDebugLog();
    }

    ~LogSetup() {
        BCLog::ReconstructLogInstance();
        LogInstance().DisableRateLimiting();
        LogInstance().m_file_path = prev_log_path;
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_print_to_console = prev_print_to_console;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_time_micros = prev_log_time_micros;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().EnableCategory(static_cast<BCLog::LogFlags>(prev_category_mask));
    }
};

namespace {

enum class Location {
    INFO_1,
    INFO_2,
    DEBUG_LOG,
    INFO_NOLIMIT,
};

void LogFromLocation(Location location, const std::string& message) {
    switch (location) {
        case Location::INFO_1:
            LogPrintf("%s\n", message);
            return;
        case Location::INFO_2:
            LogPrintf("%s\n", message);
            return;
        case Location::DEBUG_LOG:
            LogPrint(BCLog::LogFlags::HTTP, "%s\n", message);
            return;
        case Location::INFO_NOLIMIT:
            LogPrintfNoRateLimit("%s\n", message);
            return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/**
 * For a given `location` and `message`, ensure that the on-disk debug log behaviour resembles what
 * we'd expect it to be for `status` and `suppressions_active`.
 */
void TestLogFromLocation(Location location, const std::string& message,
                         BCLog::LogRateLimiter::Status status, bool suppressions_active,
                         std::source_location source = std::source_location::current()) {
    BOOST_TEST_INFO_SCOPE("TestLogFromLocation called from " << source.file_name() << ":" << source.line());
    using Status = BCLog::LogRateLimiter::Status;
    if (!suppressions_active) assert(status == Status::UNSUPPRESSED); // developer error

    std::ofstream ofs(LogInstance().m_file_path.string(), std::ios::out | std::ios::trunc); // clear debug log
    LogFromLocation(location, message);
    auto log_lines = ReadDebugLogLines();
    BOOST_TEST_INFO_SCOPE(log_lines.size() << " log_lines read: \n" << Join(log_lines, "\n"));

    if (status == Status::STILL_SUPPRESSED) {
        BOOST_CHECK_EQUAL(log_lines.size(), 0);
        return;
    }

    BOOST_REQUIRE_EQUAL(log_lines.size(), 1);

    if (status == Status::NEWLY_SUPPRESSED) {
        BOOST_CHECK(log_lines[0].starts_with("[*] Excessive logging detected"));
    }
    auto& payload{log_lines.back()};
    BOOST_CHECK(payload.find(message) != std::string::npos);
    BOOST_CHECK_EQUAL(suppressions_active, payload.starts_with("[*] "));
}

} // namespace

BOOST_FIXTURE_TEST_CASE(logging_filesize_rate_limit, LogSetup) {
    using Status = BCLog::LogRateLimiter::Status;
    LogInstance().m_log_timestamps = false;
    LogInstance().m_log_threadnames = false;
    LogInstance().EnableCategory(BCLog::LogFlags::HTTP);

    constexpr int64_t line_length = 1024;
    constexpr int64_t num_lines = 10;
    constexpr int64_t bytes_quota = line_length * num_lines;
    constexpr auto time_window = 30min;

    ScopedScheduler scheduler;
    scheduler.MakeLimiter(bytes_quota, time_window);

    const std::string log_message(line_length - 1, 'a'); // subtract one for newline

    for (int i = 0; i < num_lines; ++i) {
        TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    }
    TestLogFromLocation(Location::INFO_1, "a", Status::NEWLY_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_1, "b", Status::STILL_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_2, "c", Status::UNSUPPRESSED, /*suppressions_active=*/true);
    {
        scheduler.MockForwardAndSync(time_window);
        auto lines = ReadDebugLogLines();
        BOOST_REQUIRE(not lines.empty());
        BOOST_CHECK(lines.back().find("Restarting logging from") != std::string::npos);
    }
    // Check that logging from previously suppressed location is unsuppressed again.
    TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    // Check that conditional logging, and unconditional logging with should_ratelimit=false is
    // not being ratelimited.
    for (Location location : {Location::DEBUG_LOG, Location::INFO_NOLIMIT}) {
        for (int i = 0; i < num_lines + 2; ++i) {
            TestLogFromLocation(location, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
