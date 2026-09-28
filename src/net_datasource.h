// Copyright (c) 2026-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <fs.h>
#include <protocol.h>

#include <cstdint>
#include <memory>
#include <span>
#include <variant>
#include <vector>

class CAutoFile;
class CBlockIndex;

/// A variant type that is possibly file-backed or memory buffer backed. Used by CSerializedNetMsg and CNode::vSendMsg.
///
/// Note that for performance reasons, the file-backed data source as of right now only supports serving up blocks
/// from disk, and the checksum hash is cached using CBlockIndex * pointer values as the key. If assumptions change
/// and CBlockIndex * no longer is an app-stable pointer, or if this class needs to be used for serving up other
/// serialized data from disk, then the CheckSumCache mechanism in net_datasource.cpp will need to be revised.
class SerializedDataSource {
    class FileBacked; ///< Opaque implementation is in .cpp file
    using Vec = std::vector<uint8_t>;
    using FBP = std::unique_ptr<FileBacked>;

    std::variant<Vec, FBP> var;
public:
    // Vec c'tor
    SerializedDataSource();
    // Vec c'tor
    SerializedDataSource(std::vector<uint8_t> &&data);
    /// FileBacked c'tor
    /// @param file - The full file path of the underlying file. Must be valid and be openable for reading.
    /// @param offset - The file offset where the data we are acting as a source for begins.
    /// @param length - The length of the data we are acting as a source for.
    /// @param pindex - Must either be `nullptr` or point to one of the stable global block indexes in `mapBlockIndex`.
    ///                 `pindex` is never derefercened, only its raw pointer value is used as a cache key.
    /// @param pfileIn - If not `nullptr`, performance optimization to re-use the file handle owned by `*pfileIn`. After
    ///                  this call, `*pfileIn` will be `IsNull()`. Pass `nullptr` to have this class open the file itself.
    /// @throw std::runtime_error If the file could not be opened for reading.
    SerializedDataSource(const fs::path &file, const size_t offset, const size_t length, const CBlockIndex *pindex,
                         CAutoFile *pfileIn = nullptr);
    // No copying, only moves.
    SerializedDataSource(SerializedDataSource &&);
    SerializedDataSource &operator=(SerializedDataSource &&);
    SerializedDataSource(const SerializedDataSource &msg) = delete;
    SerializedDataSource &operator=(const SerializedDataSource &) = delete;
    // Separately-defined d'tor needed due to private FileBacked class
    ~SerializedDataSource();

    size_t size() const;

    /// Reads the entire data source over once and calculates its net message checksum, returning it
    /// (used by CConnman::PushMessage).
    ///
    /// Note that if this is a file-backed instance that was constructed with a `checkSumKey` that is not `nullptr`,
    /// then the resulting value is cached and subsequent calls for this or future instances with the same key do not
    /// re-calculate the CheckSum but will return a cached value.
    ///
    /// @throw std::runtime_error If file-backed and the underlying file could not be read to calculate the checksum.
    CMessageHeader::CheckSum CalculateCheckSum();

    /// In file-backed mode, GetBytes() returns a reference to `tmpBuffer`, which should be kept alive for the entire
    /// lifetime of the returned span.  In vector-backed mode, `tmpBuffer` is ignored.
    ///
    /// @throw - `std::invalid_argument` For any attempt to read past the end
    ///          `std::ios_base::failure` For any other low-level I/O error in FileBacked mode
    ///          `std::runtime_error` For various other assorted errors/system errors/etc.
    std::span<const uint8_t> GetBytes(const size_t offset, const size_t count, Vec &tmpBuffer);

    /// Recommended size to pass as the `count` parameter to GetBytes().
    ///
    /// For file-backed mode this will be at most 64KiB, but may be smaller if the file in question is smaller than that.
    /// For vector mode this will be the entire vector's size since it's in memory already.
    size_t RecommendedChunkSize() const;

    /// Get a reference to the underlying vector, if in vector mode. Note that if this instance is in file-backed mode,
    /// this function will modify this object in-place and force it into vector mode, potentially zeoring out its state!
    /// Only use this if you know what you are doing.
    Vec & GetVec();

    /// Returns true iff this instance represents a file-backed data source, false otherwise.
    bool isFileBacked() const { return std::get_if<FBP>(&var) != nullptr; }

    /// Called from validation.cpp `UnloadBlockIndex` to clear the CheckSumCache
    static void ClearCheckSumCache();
};
