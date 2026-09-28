// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2023-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <fs.h>
#include <primitives/blockhash.h>
#include <sync.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <vector>

class CAutoFile;
class CBlock;
class CBlockFileInfo;
class CBlockIndex;
class CBlockUndo;
class CValidationState;
class CChainParams;
class Config;
struct FlatFilePos;
namespace Consensus {
struct Params;
}

/** Default for -stopafterblockimport */
static constexpr bool DEFAULT_STOPAFTERBLOCKIMPORT = false;

/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static constexpr unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static constexpr unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** The maximum size of a blk?????.dat file (since 0.8) */
static constexpr unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB

/** External lock; lives in validation.cpp; used for some of the variables and functions below. */
extern RecursiveMutex cs_main;

extern std::atomic_bool fImporting;
extern std::atomic_bool fReindex;
/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned GUARDED_BY(cs_main);
/** True if we're running in -prune mode. */
extern bool fPruneMode;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;
extern bool fCheckBlockReads;
extern RecursiveMutex cs_LastBlockFile;
extern std::vector<CBlockFileInfo> vinfoBlockFile GUARDED_BY(cs_LastBlockFile);
extern int nLastBlockFile GUARDED_BY(cs_LastBlockFile);
extern bool fCheckForPruning GUARDED_BY(cs_LastBlockFile);
extern std::set<const CBlockIndex*> setDirtyBlockIndex GUARDED_BY(cs_main);
extern std::set<int> setDirtyFileInfo GUARDED_BY(cs_LastBlockFile);

//! Check whether the block associated with this index entry is pruned or not.
bool IsBlockPruned(const CBlockIndex *pblockindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

void CleanupBlockRevFiles();

/**
 * Open a block file (blk?????.dat).
 */
FILE *OpenBlockFile(const FlatFilePos &pos, bool fReadOnly = false);

/** Get block file info entry for one block file */
CBlockFileInfo *GetBlockFileInfo(size_t n);

/**
 * Calculate the amount of disk space the block & undo files currently use.
 */
uint64_t CalculateCurrentUsage();

/**
 * Actually unlink the specified files
 */
void UnlinkPrunedFiles(const std::set<int> &setFilesToPrune);

/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock &block, const FlatFilePos &pos, const Consensus::Params &params,
                       const std::optional<BlockHash> &expectedHash = std::nullopt,
                       uint64_t *pBlockSize = nullptr);
bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &params, uint64_t *pBlockSize = nullptr);
/**
 * Read raw block bytes from disk. Faster than the above, because this function just returns the raw block data without
 * any unserialization. Intended to be used by the net code for low-overhead serving of block data.
 * @param autoFileIn - If not nullptr, use this as the file reader. Note that this *must* be a CAutoFile pointing to the
 *                     correct block file (may be at any position within the file) and opened for at least reading
 *                     binary (i.e. "rb" or "rb+"). The `*autoFileIn` object will be moved-from and will be `IsNull()`
 *                     on `true` return from this call. `false` return leaves `*autoFileIn` in a valid but unspecified
 *                     state.
 * `nType` and `nVersion` parameters are used for `-checkblockreads` sanity checking of the serialized data. */
bool ReadRawBlockFromDisk(std::vector<uint8_t> &rawBlock, const CBlockIndex *pindex, const CChainParams &chainParams,
                          int nType, int nVersion, CAutoFile *autoFileIn = nullptr);

/**
 *  Read just the block size for a given block. This is done by examining the on-disk block file data and is a
 *  relatively quick function to call.  Note that even though the returned value is 64-bit, the actual size
 *  will be bound to MAX_CONSENSUS_BLOCK_SIZE (2GB) until consensus, p2p msg format, and disk file format changes are
 *  made to support 64-bit block sizes.
 *
 *  @param autoFileOut - If not nullptr, and if this function is successful (i.e. return value .has_value()), then
 *                       `*autoFileOut` will be populated with a valid CAutoFile positioned right at the beginning of
 *                       the block's data, otherwise it will remain unchanged.
 *  @return The block's serialized size. An empty optional is returned if the block is not found or if there is a
 *          low-level error.
 */
std::optional<uint64_t> ReadBlockSizeFromDisk(const CBlockIndex *pindex, const CChainParams &chainParams,
                                              fs::path *fileNameOut = nullptr, uint64_t *fileOffsetOut = nullptr,
                                              CAutoFile *autoFileOut = nullptr);

bool UndoReadFromDisk(CBlockUndo &blockundo, const CBlockIndex *pindex);
bool WriteUndoDataForBlock(const CBlockUndo &blockundo, CValidationState &state, CBlockIndex *pindex,
                           const CChainParams &chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/**
 * Store block on disk. If dbp is non-nullptr, the file is known to already
 * reside on disk.
 */
FlatFilePos SaveBlockToDisk(const CBlock &block, int nHeight, const CChainParams &chainparams, const FlatFilePos *dbp)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

void ThreadImport(const Config &config, std::vector<fs::path> vImportFiles);
