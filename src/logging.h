// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <crypto/siphash.h>
#include <fs.h>
#include <sync.h>
#include <tinyformat.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

inline constexpr bool DEFAULT_LOGTIMEMICROS = false;
inline constexpr bool DEFAULT_LOGIPS = false;
inline constexpr bool DEFAULT_LOGTIMESTAMPS = true;
inline constexpr bool DEFAULT_LOGTHREADNAMES = false;

extern bool fLogIPs;
extern const char *const DEFAULT_DEBUGLOGFILE;

struct CLogCategoryActive {
    std::string category;
    bool active;
};

namespace BCLog {

using namespace std::chrono_literals;

inline constexpr bool DEFAULT_LOGRATELIMIT = true;
inline constexpr uint64_t RATELIMIT_MAX_BYTES = 1024 * 1024; // maximum number of bytes per source location that can be logged within the RATELIMIT_WINDOW
inline constexpr auto RATELIMIT_WINDOW = 1h; // time window after which log ratelimit stats are reset

//! Fixed window rate limiter for logging.
class LogRateLimiter {
public:
    //! Keeps track of an individual source location and how many available bytes are left for logging from it.
    struct Stats {
        //! Remaining bytes
        uint64_t m_available_bytes = 0;
        //! Number of bytes that were consumed but didn't fit in the available bytes.
        uint64_t m_dropped_bytes = 0;

        Stats(uint64_t max_bytes) : m_available_bytes{max_bytes} {}
        //! Updates internal accounting and returns true if enough available_bytes were remaining
        bool Consume(uint64_t bytes);
    };

private:
    mutable Mutex m_mutex;

    struct SourceLocationEqual {
        bool operator()(const std::source_location& lhs, const std::source_location& rhs) const noexcept {
            return lhs.line() == rhs.line() && 0 == std::strcmp(lhs.file_name(), rhs.file_name());
        }
    };

    struct SourceLocationHasher {
        size_t operator()(const std::source_location& s) const noexcept {
            // Use CSipHasher(0, 0) as a simple way to get uniform distribution.
            return static_cast<size_t>(CSipHasher(0, 0)
                                           .Write(s.line())
                                           .Write(std::as_bytes(std::span{std::string_view{s.file_name()}}))
                                           .Finalize());
        }
    };

    using SourceLocationsMap = std::unordered_map<std::source_location, Stats, SourceLocationHasher, SourceLocationEqual>;
    //! Stats for each source location that has attempted to log something.
    SourceLocationsMap m_source_locations GUARDED_BY(m_mutex);
    //! Whether any log locations are suppressed. Cached view on m_source_locations for performance reasons.
    std::atomic_bool m_suppression_active = false;

public:
    //! Maximum number of bytes logged per location per window.
    const uint64_t m_max_bytes;
    //! Interval after which the window is reset.
    const std::chrono::seconds m_reset_window;

    /**
     * @param max_bytes         Maximum number of bytes that can be logged for each source location per time window.
     * @param reset_window      Time window after which the stats are reset to 0 for all source locations.
     */
    LogRateLimiter(uint64_t max_bytes, std::chrono::seconds reset_window)
        : m_max_bytes{max_bytes}, m_reset_window{reset_window} {}

    //! Suppression status of a source log location.
    enum class Status {
        UNSUPPRESSED,     // string fits within the limit
        NEWLY_SUPPRESSED, // suppression has started since this string
        STILL_SUPPRESSED, // suppression is still ongoing
    };
    //! Consumes `source_loc`'s available bytes corresponding to the size of the (formatted)
    //! `str` and returns its status.
    [[nodiscard]] Status Consume(const std::source_location& source_loc, const std::string& str) LOCKS_EXCLUDED(m_mutex);
    //! Resets all usage to zero. Called periodically by the scheduler.
    void Reset() LOCKS_EXCLUDED(m_mutex);
    //! Returns true if any log locations are currently being suppressed.
    bool SuppressionsActive() const { return m_suppression_active; }
};

enum LogFlags : uint32_t {
    NONE = 0,
    NET = (1 << 0),
    TOR = (1 << 1),
    MEMPOOL = (1 << 2),
    HTTP = (1 << 3),
    BENCH = (1 << 4),
    ZMQ = (1 << 5),
    DB = (1 << 6),
    RPC = (1 << 7),
    ESTIMATEFEE = (1 << 8),
    ADDRMAN = (1 << 9),
    SELECTCOINS = (1 << 10),
    REINDEX = (1 << 11),
    CMPCTBLOCK = (1 << 12),
    RAND = (1 << 13),
    PRUNE = (1 << 14),
    PROXY = (1 << 15),
    MEMPOOLREJ = (1 << 16),
    LIBEVENT = (1 << 17),
    COINDB = (1 << 18),
    QT = (1 << 19),
    LEVELDB = (1 << 20),
    FINALIZATION = (1 << 21),
    PARKING = (1 << 22),
    DSPROOF = (1 << 23),

    //! Log *all* httpserver request and response data transferred to/from the
    //! client. Note: Unlike all the other categories, to avoid logs from
    //! filling up (and from revealing potentially sensitive data), this is
    //! NOT enabled automatically if using ALL. It must be enabled explicitly.
    HTTPTRACE = (1 << 24),

    //! For the adjustable blocksize limit algorithm (consensu/abla.*)
    ABLA = (1 << 25),

    ALL = ~uint32_t(0) & ~uint32_t(HTTPTRACE),
};

class Logger {
    Mutex m_cs;
    FILE *m_fileout GUARDED_BY(m_cs) = nullptr;
    std::list<std::string> m_msgs_before_open GUARDED_BY(m_cs);

    std::shared_ptr<LogRateLimiter> m_limiter GUARDED_BY(m_cs);

    /**
     * m_started_new_line is a state variable that will suppress printing of the
     * timestamp when multiple calls are made that don't end in a newline.
     */
    std::atomic_bool m_started_new_line{true};

    /**
     * Log categories bitfield.
     */
    std::atomic_uint32_t m_categories{0};

    void PrependTimestampStr(std::string &str);

public:
    // Note: The below members are not guarded by any mutex and should only be written-to before threads are started
    bool m_print_to_console = false;
    bool m_print_to_file = false;

    bool m_log_timestamps = DEFAULT_LOGTIMESTAMPS;
    bool m_log_time_micros = DEFAULT_LOGTIMEMICROS;
    bool m_log_threadnames = DEFAULT_LOGTHREADNAMES;

    fs::path m_file_path;
    std::atomic_bool m_reopen_file{false};

    ~Logger();

    /** Send a string to the log output */
    void LogPrintStr(std::string &&str, std::source_location &&sloc, bool should_rate_limit);
    void LogPrintStr(std::string_view str, std::source_location &&sloc, bool should_rate_limit) {
        LogPrintStr(std::string{str}, std::move(sloc), should_rate_limit);
    }

    /** Returns whether logs will be written to any output */
    bool Enabled() const { return m_print_to_console || m_print_to_file; }

    bool OpenDebugLog();
    void ShrinkDebugFile();

    uint32_t GetCategoryMask() const { return m_categories.load(); }

    void EnableCategory(LogFlags category);
    bool EnableCategory(const std::string &str);
    void DisableCategory(LogFlags category);
    bool DisableCategory(const std::string &str);

    /** Return true if log accepts specified category */
    bool WillLogCategory(LogFlags category) const;

    /** Default for whether ShrinkDebugFile should be run */
    bool DefaultShrinkDebugFile() const;

    std::weak_ptr<LogRateLimiter> SetRateLimiting(uint64_t max_bytes, std::chrono::seconds reset_window) LOCKS_EXCLUDED(m_cs) {
        LOCK(m_cs);
        return m_limiter = std::make_shared<LogRateLimiter>(max_bytes, reset_window);
    }

    void DisableRateLimiting() LOCKS_EXCLUDED(m_cs) {
        LOCK(m_cs);
        m_limiter.reset();
    }
};

/** Belt and suspenders: make sure outgoing log messages don't contain
 * potentially suspicious characters, such as terminal control codes.
 *
 * This escapes control characters except newline ('\n') in C syntax.
 * It escapes instead of removes them to still allow for troubleshooting
 * issues where they accidentally end up in strings.
 *
 * This function is used internally but is exposed here for unit tests.
 * @returns true if `str` was modified, false otherwise.
 */
bool LogEscapeMessageInPlace(std::string &str);

/** Delete and re-create the LogInstance. Used by tests. */
void ReconstructLogInstance();

} // namespace BCLog

BCLog::Logger &LogInstance();

/** Return true if log accepts specified category */
static inline bool LogAcceptCategory(BCLog::LogFlags category) {
    return LogInstance().WillLogCategory(category);
}

/** Returns a string with the log categories. */
std::string ListLogCategories();

/** Returns a vector of the active log categories. */
std::vector<CLogCategoryActive> ListActiveLogCategories();

/** Return true if str parses as a log category and set the flag */
bool GetLogCategory(BCLog::LogFlags &flag, const std::string &str);

// App-global logging. Uses basic rate limiting to mitigate disk filling attacks.
// Be conservative when using functions that unconditionally log to debug.log!
// It should not be the case that an inbound peer can fill up a user's storage
// with debug.log entries.
template <typename... Args>
static inline void LogPrintfInternal(std::source_location &&sloc, bool should_rate_limit, const char *fmt, const Args &... args) {
    if (LogInstance().Enabled()) {
        std::string log_msg;
        try {
            log_msg = tfm::format(fmt, args...);
        } catch (const tinyformat::format_error &fmterr) {
            /**
             * Original format string will have newline so don't add one here
             */
            log_msg = "Error \"" + std::string(fmterr.what()) + "\" while formatting log message: " + fmt;
        }
        LogInstance().LogPrintStr(std::move(log_msg), std::move(sloc), should_rate_limit);
    }
}

#define LogPrintf(fmt, ...)            LogPrintfInternal(std::source_location::current(), true, (fmt) __VA_OPT__(,) __VA_ARGS__)
#define LogPrintfNoRateLimit(fmt, ...) LogPrintfInternal(std::source_location::current(), false, (fmt) __VA_OPT__(,) __VA_ARGS__)

// Use a macro instead of a function for conditional logging to prevent
// evaluating arguments when logging for the category is not enabled.
#define LogPrint(category, fmt, ...)                                           \
    do {                                                                       \
        if (LogAcceptCategory((category))) {                                   \
            LogPrintfNoRateLimit((fmt) __VA_OPT__(,) __VA_ARGS__);             \
        }                                                                      \
    } while (0)

/**
 * These are aliases used to explicitly state that the message should not end
 * with a newline character. It allows for detecting the missing newlines that
 * could make the logs hard to read.
 */
#define LogPrintfToBeContinued LogPrintf
#define LogPrintToBeContinued LogPrint
