// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>

#include <util/threadnames.h>
#include <util/time.h>

#include <cstdio>
#include <memory>

bool fLogIPs = DEFAULT_LOGIPS;
const char *const DEFAULT_DEBUGLOGFILE = "debug.log";

BCLog::Logger &LogInstance() {
    /**
     * NOTE: the logger instance is leaked on exit. This is ugly, but will be
     * cleaned up by the OS/libc. Defining a logger as a global object doesn't
     * work since the order of destruction of static/global objects is
     * undefined. Consider if the logger gets destroyed, and then some later
     * destructor calls LogPrintf, maybe indirectly, and you get a core dump at
     * shutdown trying to access the logger. When the shutdown sequence is fully
     * audited and tested, explicit destruction of these objects can be
     * implemented by changing this from a raw pointer to a std::unique_ptr.
     * Since the destructor is never called, the logger and all its members must
     * have a trivial destructor.
     *
     * This method of initialization was originally introduced in
     * ee3374234c60aba2cc4c5cd5cac1c0aefc2d817c.
     */
    static BCLog::Logger *g_logger{new BCLog::Logger()};
    return *g_logger;
}

void BCLog::ReconstructLogInstance() {
    auto &instance = LogInstance();
    std::destroy_at(&instance);
    std::construct_at(&instance);
}

static int FileWriteStr(const std::string &str, FILE *fp) {
    return std::fwrite(str.data(), 1, str.size(), fp);
}

bool BCLog::Logger::OpenDebugLog() {
    LOCK(m_cs);

    assert(m_fileout == nullptr);
    assert(!m_file_path.empty());

    m_fileout = fsbridge::fopen(m_file_path, "a");
    if (!m_fileout) {
        return false;
    }

    // Unbuffered.
    std::setbuf(m_fileout, nullptr);
    // Dump buffered messages from before we opened the log.
    while (!m_msgs_before_open.empty()) {
        FileWriteStr(m_msgs_before_open.front(), m_fileout);
        m_msgs_before_open.pop_front();
    }

    return true;
}

struct CLogCategoryDesc {
    BCLog::LogFlags flag;
    std::string category;
};

const CLogCategoryDesc LogCategories[] = {
    {BCLog::NONE, "0"},
    {BCLog::NONE, "none"},
    {BCLog::NET, "net"},
    {BCLog::TOR, "tor"},
    {BCLog::MEMPOOL, "mempool"},
    {BCLog::HTTP, "http"},
    {BCLog::BENCH, "bench"},
    {BCLog::ZMQ, "zmq"},
    {BCLog::DB, "db"},
    {BCLog::RPC, "rpc"},
    {BCLog::ESTIMATEFEE, "estimatefee"},
    {BCLog::ADDRMAN, "addrman"},
    {BCLog::SELECTCOINS, "selectcoins"},
    {BCLog::REINDEX, "reindex"},
    {BCLog::CMPCTBLOCK, "cmpctblock"},
    {BCLog::RAND, "rand"},
    {BCLog::PRUNE, "prune"},
    {BCLog::PROXY, "proxy"},
    {BCLog::MEMPOOLREJ, "mempoolrej"},
    {BCLog::LIBEVENT, "libevent"},
    {BCLog::COINDB, "coindb"},
    {BCLog::QT, "qt"},
    {BCLog::LEVELDB, "leveldb"},
    {BCLog::FINALIZATION, "finalization"},
    {BCLog::PARKING, "parking"},
    {BCLog::DSPROOF, "dsproof"},
    {BCLog::HTTPTRACE, "httptrace"},
    {BCLog::ABLA, "abla"},
    {BCLog::ALL, "1"},
    {BCLog::ALL, "all"},
};

bool GetLogCategory(BCLog::LogFlags &flag, const std::string &str) {
    if (str == "") {
        flag = BCLog::ALL;
        return true;
    }
    for (const CLogCategoryDesc &category_desc : LogCategories) {
        if (category_desc.category == str) {
            flag = category_desc.flag;
            return true;
        }
    }
    return false;
}

std::string ListLogCategories() {
    std::string ret;
    int outcount = 0;
    for (const CLogCategoryDesc &category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE &&
            category_desc.flag != BCLog::ALL) {
            if (outcount != 0) {
                ret += ", ";
            }
            ret += category_desc.category;
            outcount++;
        }
    }
    return ret;
}

std::vector<CLogCategoryActive> ListActiveLogCategories() {
    std::vector<CLogCategoryActive> ret;
    for (const CLogCategoryDesc &category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE &&
            category_desc.flag != BCLog::ALL) {
            CLogCategoryActive catActive;
            catActive.category = category_desc.category;
            catActive.active = LogAcceptCategory(category_desc.flag);
            ret.push_back(catActive);
        }
    }
    return ret;
}

BCLog::Logger::~Logger() {
    if (m_fileout) {
        std::fclose(m_fileout);
    }
}

void BCLog::Logger::PrependTimestampStr(std::string &str) {
    if (!m_log_timestamps || !m_started_new_line)
        return;

    const int64_t nTimeMicros = GetTimeMicros();
    std::string tmpStr = FormatISO8601DateTime(nTimeMicros / 1000000);
    if (m_log_time_micros) {
        tmpStr.pop_back(); // pop off the trailing Z
        tmpStr += strprintf(".%06dZ", nTimeMicros % 1000000);
    }
    const int64_t mocktime = GetMockTime();
    if (mocktime) {
        tmpStr +=
            " (mocktime: " + FormatISO8601DateTime(mocktime) + ")";
    }
    // reserve space in tmp buffer for appending: ' ' + str
    tmpStr.reserve(tmpStr.size() + 1 + str.size());
    tmpStr += ' ';
    tmpStr += str; // finally, add the log line after having prepended the timestamp
    str = std::move(tmpStr);  // move line buffer back onto out value
}

void BCLog::Logger::LogPrintStr(std::string &&str, std::source_location &&sloc, const bool should_rate_limit)
{
    if (!m_print_to_console && !m_print_to_file)
        return; // Nothing to do!

    LogEscapeMessageInPlace(str);

    bool rateLimit = false;
    bool suppressionActive = false;
    {
        LOCK(m_cs);

        if (m_limiter && should_rate_limit) {
            const auto status = m_limiter->Consume(sloc, str);
            if (status == LogRateLimiter::Status::NEWLY_SUPPRESSED) {
                str.insert(0, strprintf("Excessive logging detected from %s:%d (%s): >%d bytes logged during "
                                        "the last time window of %is. Suppressing logging to disk from this "
                                        "source location until time window resets. Console logging "
                                        "unaffected. Last log entry: ", sloc.file_name(), sloc.line(),
                                        sloc.function_name(), m_limiter->m_max_bytes,
                                        std::chrono::seconds(m_limiter->m_reset_window).count()));
            } else if (status == LogRateLimiter::Status::STILL_SUPPRESSED) {
                rateLimit = true;
            }
        }

        suppressionActive = m_limiter && m_limiter->SuppressionsActive();
    }

    // To avoid confusion caused by dropped log messages when debugging an issue,
    // we prefix log message contents with "[*] " when there are any suppressions active.
    if (suppressionActive && m_started_new_line) {
        str.insert(0, "[*] ");
    }

    if (m_log_threadnames && m_started_new_line) {
        // below does: str = "[" + threadName + "] " + str; (but with less copying)
        std::string tmp;
        const auto &threadName = util::ThreadGetInternalName();
        tmp.reserve(str.size() + threadName.size() + 3); // reserve space
        tmp += '[';
        tmp += threadName;
        tmp += "] ";
        tmp += str;
        str = std::move(tmp); // move tmp back onto str for efficiency
    }

    const bool hadNL = !str.empty() && str.back() == '\n';

    PrependTimestampStr(str);

    m_started_new_line = hadNL;

    if (m_print_to_console) {
        // print to console
        FileWriteStr(str, stdout);
        std::fflush(stdout);
    }

    if (m_print_to_file && !rateLimit) {
        LOCK(m_cs);

        // Buffer if we haven't opened the log yet.
        if (m_fileout == nullptr) {
            m_msgs_before_open.emplace_back(std::move(str));
        } else {
            // Reopen the log file, if requested.
            if (m_reopen_file) {
                m_reopen_file = false;
                FILE *new_fileout = fsbridge::fopen(m_file_path, "a");
                if (new_fileout) {
                    std::setbuf(new_fileout, nullptr); // unbuffered.
                    std::fclose(m_fileout);
                    m_fileout = new_fileout;
                }
            }
            FileWriteStr(str, m_fileout);
        }
    }
}

void BCLog::Logger::ShrinkDebugFile() {
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;

    assert(!m_file_path.empty());

    // Scroll debug.log if it's getting too big.
    FILE *file = fsbridge::fopen(m_file_path, "r");

    // Special files (e.g. device nodes) may not have a size.
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (const fs::filesystem_error &) {
    }

    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes.
    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10)) {
        // Restart the file with some of the end.
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        if (std::fseek(file, -((long)vch.size()), SEEK_END)) {
            LogPrintf("Failed to shrink debug log file: fseek(...) failed\n");
            std::fclose(file);
            return;
        }
        const size_t nBytes = std::fread(vch.data(), 1, vch.size(), file);
        std::fclose(file);

        file = fsbridge::fopen(m_file_path, "w");
        if (file) {
            std::fwrite(vch.data(), 1, nBytes, file);
            std::fclose(file);
        }
    } else if (file != nullptr) {
        std::fclose(file);
    }
}

void BCLog::Logger::EnableCategory(LogFlags category) {
    m_categories |= category;
}

bool BCLog::Logger::EnableCategory(const std::string &str) {
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) {
        return false;
    }
    EnableCategory(flag);
    return true;
}

void BCLog::Logger::DisableCategory(LogFlags category) {
    m_categories &= ~category;
}

bool BCLog::Logger::DisableCategory(const std::string &str) {
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) {
        return false;
    }
    DisableCategory(flag);
    return true;
}

bool BCLog::Logger::WillLogCategory(LogFlags category) const {
    // ALL is not meant to be used as a logging category, but only as a mask
    // representing all categories.
    if (category == BCLog::NONE || category == BCLog::ALL) {
        LogPrintf("Error trying to log using a category mask instead of an "
                  "explicit category.\n");
        return true;
    }

    return (m_categories.load(std::memory_order_relaxed) & category) != 0;
}

bool BCLog::Logger::DefaultShrinkDebugFile() const {
    return m_categories != BCLog::NONE;
}

bool BCLog::LogEscapeMessageInPlace(std::string &str) {
    // Returns true if the character is "mundane" or acceptable to print to log as-is, false otherwise.
    auto IsMundaneChar = [](const char ch_in) {
        const uint8_t ch = static_cast<uint8_t>(ch_in);
        return ch != 0x7fu && (ch >= 32u || ch_in == '\n'); // Note that we accept UTF-8 control chars >= 0x80, etc
    };
    // Returns the input character as a 4-char string of the form: "\xNN" where NN is the hex code for the character.
    auto EscapeChar = [](const uint8_t ch) { return strprintf("\\x%02x", ch); };
    // First, loop through all chars and find the first non-acceptable char, if any.
    const size_t strsz = str.size();
    size_t i;
    for (i = 0; i != strsz && IsMundaneChar(str[i]); ++i) { /**/ }
    // If all chars are acceptable, return early, doing no work, no allocations, etc
    if (i == strsz) [[likely]] {
        return false; // indicate str was unmodified
    }
    // If we get here, at least one character needs to be replaced
    std::string tmp;
    tmp.reserve(strsz + 3u); // reserve space for known string size plus at least 1 replacement char
    // Copy the chars we accepted already above
    tmp.append(str.data(), i);
    // Escape the first known bad char
    tmp.append(EscapeChar(str[i++]));
    // ... and process the rest
    for ( ; i != strsz; ++i) {
        const char ch = str[i];
        if (IsMundaneChar(ch)) {
            tmp.push_back(ch);
        } else {
            tmp.append(EscapeChar(ch));
        }
    }
    str = std::move(tmp);
    return true; // indicate str was modified
}

bool BCLog::LogRateLimiter::Stats::Consume(uint64_t bytes) {
    if (bytes > m_available_bytes) {
        m_dropped_bytes += bytes;
        m_available_bytes = 0;
        return false;
    }

    m_available_bytes -= bytes;
    return true;
}

auto BCLog::LogRateLimiter::Consume(const std::source_location& source_loc, const std::string& str) -> Status {
    LOCK(m_mutex);
    auto& stats = m_source_locations.try_emplace(source_loc, m_max_bytes).first->second;
    Status status = stats.m_dropped_bytes > 0 ? Status::STILL_SUPPRESSED : Status::UNSUPPRESSED;

    if (!stats.Consume(str.size()) && status == Status::UNSUPPRESSED) {
        status = Status::NEWLY_SUPPRESSED;
        m_suppression_active = true;
    }

    return status;
}

void BCLog::LogRateLimiter::Reset() {
    SourceLocationsMap source_locations;
    {
        LOCK(m_mutex);
        source_locations.swap(m_source_locations);
        m_suppression_active = false;
    }
    for (const auto & [sloc, stats] : source_locations) {
        if (stats.m_dropped_bytes == 0) continue;
        // Unconditionally announce to log that we reset the stats for this source location
        LogPrintfNoRateLimit("Restarting logging from %s:%u (%s): %u bytes were dropped during the last %is.\n",
                             sloc.file_name(), sloc.line(), sloc.file_name(), stats.m_dropped_bytes,
                             std::chrono::seconds{m_reset_window}.count());
    }
}
