// Copyright (c) 2026-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_datasource.h>

#include <hash.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <util/overloaded.h>
#include <util/saltedhashers.h>

#include <array>
#include <cstdio>
#include <ios>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#ifdef _WIN32
#include <netbase.h> /* For NetworkErrorString */
#include <windows.h>

static std::string GetErrorReason() {
    // Note that NetworkErrorString, despite the name, can return text for any windows error code from GetLastError()
    return NetworkErrorString(GetLastError());
}
#endif

class SerializedDataSource::FileBacked {
#ifdef _WIN32
    // Note that we *intentionally* use the native win32 file API here so as to not consume any of the limited number of
    // MS C runtime file descriptors which default to 512 (but can be raised to 2048 on msvcrt.dll, 8192 on ucrt).
    // Whereas by using native win32 file handles, we have a limit of ~16.7 million of these, which plenty.
    HANDLE hFile = INVALID_HANDLE_VALUE;
#else
    std::FILE *f = nullptr;
#endif
    std::string fileName; // the file's basename (sans path); used for logging
    size_t offset = 0; // where in the file the data starts
    size_t length = 0; // the length of the data for this data source
    size_t currentReadPos = 0; // the file's current position (optimization to avoid redundant fseek() calls each time)

public:
    const uintptr_t checkSumKey{}; ///< if not zero, will use checkSumCache

    FileBacked(const fs::path &path, size_t o, size_t l, const CBlockIndex *k, CAutoFile *pfileIn)
        : fileName{path.filename().string()}, offset{o}, length{l}, checkSumKey{reinterpret_cast<uintptr_t>(k)} {
        // Open the file now, to ensure it exists and is held around on the system (even if deleted by other code).
#ifdef _WIN32
        // pfileIn cannot be re-used on WIN32 because we need to explicitly open this file with FILE_SHARE_* flags
        if (pfileIn) pfileIn->fclose();
#else
        // on other systems, we will try to re-use `pfileIn`'s underlying `FILE *` (if neither are `nullptr`)
        if (pfileIn && (f = pfileIn->release())) {
            const long pos = std::ftell(f); // figure out where we are in the passed-in file handle
            if (pos >= 0) {
                currentReadPos = pos;
            } else {
                // some unspecified error calling ftell, just close the file and let open(path) try again
                std::fclose(f);
                f = nullptr;
            }
        }
#endif
        // Note that in the !_WIN32 case, where we were given a valid pfileIn, open(path) below may be a no-op
        open(path); // may throw
    }

    ~FileBacked() { cleanup(); }

    FileBacked(const FileBacked &o) = delete; // no copying, no moving
    FileBacked(FileBacked &&o) = delete;
    FileBacked &operator=(const FileBacked &o) = delete;
    FileBacked &operator=(FileBacked &&o) = delete;

    void read(const size_t pos, const std::span<uint8_t> &dest) {
        seek(pos);
        if (dest.empty()) return; // nothing to do
#ifdef _WIN32
        DWORD size = dest.size(), nread = 0;
        if (static_cast<size_t>(size) != dest.size()) [[unlikely]] {
            // Overflow -- DWORD is only a 32-bit value
            throw std::domain_error(strprintf("Specified buffer size %u exceeds maximum for a win32 DWORD!", dest.size()));
        }
        const auto ok = ReadFile(hFile, dest.data(), size, &nread, nullptr);
        if (!ok) [[unlikely]] {
            throw std::ios_base::failure(strprintf("Failed to read %u bytes from %s, error: %s", dest.size(), fileName,
                                                   GetErrorReason()));
        }
        if (nread != size) [[unlikely]] {
            LARGE_INTEGER l; l.QuadPart = static_cast<LONGLONG>(currentReadPos);
            const bool badSeek = !SetFilePointerEx(hFile, l, nullptr, FILE_BEGIN); // restore hFile to a known-good pos
            throw std::ios_base::failure(strprintf("Short read %u != %u bytes from %s%s", nread, size, fileName,
                                                   badSeek ? " (also failed to seek back to old pos)" : ""));
        }
#else
        if (std::fread(dest.data(), 1, dest.size(), f) != dest.size()) {
            const bool badSeek = 0 != std::fseek(f, currentReadPos, SEEK_SET); // restore `f` to a known-good position
            throw std::ios_base::failure(strprintf("Failed to read %u bytes from %s%s", dest.size(), fileName,
                                                   badSeek ? " (also failed to seek back to old pos)" : ""));
        }
#endif
        currentReadPos += dest.size();
    }

    size_t size() const { return length; }

private:
    void cleanup() {
#ifdef _WIN32
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
#else
        if (f) {
            std::fclose(f);
            f = nullptr;
        }
#endif
        fileName = {}; // release mem
        currentReadPos = offset = length = 0;
    }
    void open(const fs::path &path) {
#ifdef _WIN32
        if (hFile == INVALID_HANDLE_VALUE) {
            // Open the file in a specific fashion to allow other code to share this file or delete it while we
            // have it open (if it's deleted while we have it open we can still read from it and it will really go
            // away only after we close the file handle, as on Unix).
            hFile = CreateFileW(path.wstring().c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) [[unlikely]]
                throw std::ios_base::failure("Error opening file: " + path.string() + ", error: " + GetErrorReason());
            currentReadPos = 0;
        }
#else
        if (!f) {
            f = fsbridge::fopen(path, "rb");
            if (!f) [[unlikely]] throw std::ios_base::failure("Error opening file: " + path.string());
            currentReadPos = 0;
        }
#endif
    }
    void seek(const size_t pos) {
#ifdef _WIN32
        Assume(hFile != INVALID_HANDLE_VALUE);
#else
        Assume(f != nullptr);
#endif
        const size_t newPos = offset + pos;
        if (currentReadPos != newPos) {
#ifdef _WIN32
            LARGE_INTEGER l;
            l.QuadPart = static_cast<LONGLONG>(newPos);
            const auto ok = SetFilePointerEx(hFile, l, nullptr, FILE_BEGIN);
            if (!ok) [[unlikely]] {
                throw std::ios_base::failure(strprintf("Error seeking file %s to offset %u, error: %s",
                                                       fileName, newPos, GetErrorReason()));
            }
#else
            const long lpos = static_cast<long>(newPos);
            if (lpos < 0 || static_cast<size_t>(lpos) != newPos) [[unlikely]] {
                throw std::domain_error(strprintf("Desired file position %u is out of bounds of a C++ long value!", lpos));
            }
            if (std::fseek(f, lpos, SEEK_SET) != 0) {
                throw std::ios_base::failure(strprintf("Error seeking file %s to offset %u", fileName, newPos));
            }
#endif
            currentReadPos = newPos;
        }
    }
};

namespace {
// Buffer size used internally
inline constexpr size_t BUF_SIZE = 65'536;

// Cache used to speed up processing for SerializedDataSource::CalculateCheckSum.
using CheckSumCache = std::unordered_map<uintptr_t, CMessageHeader::CheckSum, StdHashWrapper<uintptr_t>>;
static SharedMutex cs_checkSumCache;
static CheckSumCache checkSumCache GUARDED_BY(cs_checkSumCache);
} // namespace

// Vec c'tor
SerializedDataSource::SerializedDataSource() = default;
// Vec c'tor
SerializedDataSource::SerializedDataSource(std::vector<uint8_t> &&data)
    : var(std::in_place_type<Vec>, std::move(data)) {}
// FileBacked c'tor
SerializedDataSource::SerializedDataSource(const fs::path &file, const size_t offset, const size_t length, const CBlockIndex *pindex,
                                           CAutoFile *pfileIn)
    : var(std::in_place_type<FBP>, std::make_unique<FileBacked>(file, offset, length, pindex, pfileIn)) {}
// No copying, only moves.
SerializedDataSource::SerializedDataSource(SerializedDataSource &&o)
    : var{std::move(o.var)} {
    // force non-FBP mode for a moved-from object to avoid `o.var` ever containing a FBP that is nullptr
    o.GetVec();
}
SerializedDataSource & SerializedDataSource::operator=(SerializedDataSource &&o) {
    if (this != &o) {
        var = std::move(o.var);
        // force non-FBP mode for a moved-from object to avoid `o.var` ever containing a FBP that is nullptr
        o.GetVec();
    }
    return *this;
}
// Defined d'tor needed due to private FileBacked class
SerializedDataSource::~SerializedDataSource() = default;

size_t SerializedDataSource::size() const {
    return std::visit(util::Overloaded{
        [](const Vec &v) { return v.size(); },
        [](const FBP &f) { return f->size(); }
    }, var);
}

CMessageHeader::CheckSum SerializedDataSource::CalculateCheckSum() {
    CMessageHeader::CheckSum ret;
    static_assert(uint256::size() >= ret.size());
    std::visit(util::Overloaded{
        [&ret](const Vec &v) {
            const auto hash = Hash(Span{v});
            std::memcpy(ret.data(), hash.data(), ret.size());
        },
        [&ret](FBP &f) {
            if (f->checkSumKey){
                LOCK_SHARED(cs_checkSumCache);
                const auto &cache = std::as_const(checkSumCache);
                if (auto it = cache.find(f->checkSumKey); it != cache.end()) {
                    // cache hit, return cached value
                    ret = it->second;
                    return;
                }
            }
            // cache miss or no checkSumKey specified, hash the entire file and optionally cache the result
            std::array<uint8_t, BUF_SIZE> tmpBuf;
            CHash256 h;
            size_t bytesLeft = f->size();
            size_t pos = 0;
            while (bytesLeft) {
                const std::span sp{tmpBuf.data(), std::min(bytesLeft, tmpBuf.size())};
                f->read(pos, sp);
                h.Write(sp);
                bytesLeft -= sp.size();
                pos += sp.size();
            }
            uint256 hash{uint256::Uninitialized};
            h.Finalize(hash);
            std::memcpy(ret.data(), hash.data(), ret.size());
            if (f->checkSumKey) {
                // cache result (if cache key specified).
                //
                // NB: 2 threads may theoretically enter here at the same time and may have hashed the same data in
                // parallel (because we released the shared lock above); that's not really a problem, however, was just
                // worth noting. (Currently only the msghand thread ever comes through here.)
                LOCK(cs_checkSumCache);
                checkSumCache.try_emplace(f->checkSumKey, ret);
            }
        }
    }, var);
    return ret;
}

std::span<const uint8_t> SerializedDataSource::GetBytes(const size_t offset, const size_t count, Vec &tmpBuffer) {
    static const auto ThrowIfGT = [](const size_t end, const size_t size) {
        if (end > size) [[unlikely]] throw std::invalid_argument("Attempt to read past end of buffer");
    };
    return std::visit(util::Overloaded{
        [offset, count](const Vec &v) {
            ThrowIfGT(offset + count, v.size());
            return std::span{v.data() + offset, count};
        },
        [offset, count, &tmpBuffer](FBP &f) {
            ThrowIfGT(offset + count, f->size());
            tmpBuffer.resize(count);
            f->read(offset, tmpBuffer);
            return std::span<const uint8_t>{tmpBuffer};
        }
    }, var);
}

size_t SerializedDataSource::RecommendedChunkSize() const {
    return std::visit(util::Overloaded{
        [](const Vec &v) { return v.size(); },
        [](const FBP &f) { return std::min<size_t>(BUF_SIZE, f->size()); }
    }, var);
}

auto SerializedDataSource::GetVec() -> Vec & {
    if (auto *vec = std::get_if<Vec>(&var)) return *vec;
    else return var.emplace<Vec>();
}

/* static */
void SerializedDataSource::ClearCheckSumCache() {
    LOCK(cs_checkSumCache);
    checkSumCache = CheckSumCache{}; // clear cache and also release any reserved memory
}
