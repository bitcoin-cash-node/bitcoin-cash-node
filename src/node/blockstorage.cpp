// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2024-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockstorage.h>

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <config.h>
#include <consensus/validation.h>
#include <dsproof/dsproof.h>
#include <flatfile.h>
#include <fs.h>
#include <pow.h>
#include <hash.h>
#include <shutdown.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <validation.h>

#include <limits>
#include <utility>

std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
bool fHavePruned GUARDED_BY(cs_main) = false;
bool fPruneMode = false;
uint64_t nPruneTarget = 0;
bool fCheckBlockReads = false;

RecursiveMutex cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile GUARDED_BY(cs_LastBlockFile);
int nLastBlockFile GUARDED_BY(cs_LastBlockFile) = 0;
/**
 * Global flag to indicate we should check to see if there are block/undo files
 * that should be deleted. Set on startup or if we allocate more file space when
 * we're in prune mode.
 */
bool fCheckForPruning GUARDED_BY(cs_LastBlockFile) = false;

/** Dirty block index entries. */
std::set<const CBlockIndex *> setDirtyBlockIndex GUARDED_BY(cs_main);

/** Dirty block file entries. */
std::set<int> setDirtyFileInfo GUARDED_BY(cs_LastBlockFile);

static FILE *OpenUndoFile(const FlatFilePos &pos, bool fReadOnly = false);
static FlatFileSeq BlockFileSeq();
static FlatFileSeq UndoFileSeq();

bool IsBlockPruned(const CBlockIndex *pblockindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    return fHavePruned && !pblockindex->nStatus.hasData() && pblockindex->nTx > 0;
}

// If we're using -prune with -reindex, then delete block files that will be
// ignored by the reindex.  Since reindexing works by starting at block file 0
// and looping until a blockfile is missing, do the same here to delete any
// later block files after a gap. Also delete all rev files since they'll be
// rewritten by the reindex anyway. This ensures that vinfoBlockFile is in sync
// with what's actually on disk by the time we start downloading, so that
// pruning works correctly.
void CleanupBlockRevFiles() {
    std::map<std::string, fs::path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for "
              "-reindex with -prune\n");
    const auto directoryIterator = fs::directory_iterator{GetBlocksDir()};
    for (const auto &file : directoryIterator) {
        const auto fileName = file.path().filename().string();
        if (fs::is_regular_file(file) && fileName.length() == 12 &&
            fileName.substr(8, 4) == ".dat") {
            if (fileName.substr(0, 3) == "blk") {
                mapBlockFiles[fileName.substr(3, 5)] = file.path();
            } else if (fileName.substr(0, 3) == "rev") {
                remove(file.path());
            }
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by keeping
    // a separate counter. Once we hit a gap (or if 0 doesn't exist) start
    // removing block files.
    int contiguousCounter = 0;
    for (const auto &item : mapBlockFiles) {
        if (atoi(item.first) == contiguousCounter) {
            contiguousCounter++;
            continue;
        }
        remove(item.second);
    }
}

std::string CBlockFileInfo::ToString() const {
    return strprintf(
        "CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)",
        nBlocks, nSize, nHeightFirst, nHeightLast,
        FormatISO8601DateTime(nTimeFirst), FormatISO8601DateTime(nTimeLast));
}

CBlockFileInfo *GetBlockFileInfo(size_t n) {
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

namespace {
// Constants needed later in this file but appearing here to be close to the logic they represent (in UndoWriteToDisk())
namespace detail {
constexpr size_t kUndoHeaderSize = CMessageHeader::MessageMagic{}.size() + sizeof(unsigned);
constexpr size_t kUndoFooterSize = uint256::size();
} // detail
constexpr size_t kUndoExtraSpaceNeeded = detail::kUndoHeaderSize + detail::kUndoFooterSize;
static_assert(kUndoExtraSpaceNeeded == 40, "Unexpected undo file format change");
} // namespace

static bool UndoWriteToDisk(const CBlockUndo &blockundo, FlatFilePos &pos,
                            const BlockHash &hashBlock, const unsigned nSize,
                            const CMessageHeader::MessageMagic &messageStart) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return error("%s: OpenUndoFile failed", __func__);
    }

    // Write index header
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = std::ftell(fileout.Get());
    if (fileOutPos < 0) {
        return error("%s: ftell failed", __func__);
    } else if (static_cast<uint64_t>(fileOutPos) > std::numeric_limits<unsigned int>::max()) {
        return error("%s: ftell overflowed the size of an unsigned int", __func__);
    }
    pos.nPos = static_cast<unsigned int>(fileOutPos);
    // Write the remaining data using the BufferedWriter which is faster; `fileout` is moved-from beyond this point.
    BufferedWriter writer(std::move(fileout));
    writer << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    writer << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo &blockundo, const CBlockIndex *pindex) {
    FlatFilePos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenUndoFile failed", __func__);
    }
    // We use a buffered reader for better performance; note that `filein` is moved-from beyond this point.
    BufferedReader reader(std::move(filein));

    // Read block
    uint256 hashChecksum;
    // We need a CHashVerifier as reserializing may lose data
    CHashVerifier<decltype(reader)> verifier(&reader);
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        reader >> hashChecksum;
    } catch (const std::exception &e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash()) {
        return error("%s: Checksum mismatch", __func__);
    }

    return true;
}

void FlushBlockFile(bool fFinalize = false) {
    LOCK(cs_LastBlockFile);

    FlatFilePos block_pos_old(nLastBlockFile,
                              vinfoBlockFile[nLastBlockFile].nSize);
    FlatFilePos undo_pos_old(nLastBlockFile,
                             vinfoBlockFile[nLastBlockFile].nUndoSize);

    bool status = true;
    status &= BlockFileSeq().Flush(block_pos_old, fFinalize);
    status &= UndoFileSeq().Flush(undo_pos_old, fFinalize);
    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the "
                  "result of an I/O error.");
    }
}

uint64_t CalculateCurrentUsage() {
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }

    return retval;
}

void UnlinkPrunedFiles(const std::set<int> &setFilesToPrune) {
    for (const int i : setFilesToPrune) {
        FlatFilePos pos(i, 0);
        fs::remove(BlockFileSeq().FileName(pos));
        fs::remove(UndoFileSeq().FileName(pos));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, i);
    }
}

static FlatFileSeq BlockFileSeq() {
    return FlatFileSeq(GetBlocksDir(), "blk", BLOCKFILE_CHUNK_SIZE);
}

static FlatFileSeq UndoFileSeq() {
    return FlatFileSeq(GetBlocksDir(), "rev", UNDOFILE_CHUNK_SIZE);
}

FILE *OpenBlockFile(const FlatFilePos &pos, bool fReadOnly) {
    return BlockFileSeq().Open(pos, fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE *OpenUndoFile(const FlatFilePos &pos, bool fReadOnly) {
    return UndoFileSeq().Open(pos, fReadOnly);
}

static fs::path GetBlockPosFilename(const FlatFilePos &pos) {
    return BlockFileSeq().FileName(pos);
}

static bool FindBlockPos(FlatFilePos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime,
                         bool fKnown = false) {
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize > 0 &&
               vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile,
                      vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown) {
        vinfoBlockFile[nFile].nSize =
            std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    } else {
        vinfoBlockFile[nFile].nSize += nAddSize;
    }

    if (!fKnown) {
        bool out_of_space;
        size_t bytes_allocated =
            BlockFileSeq().Allocate(pos, nAddSize, out_of_space);
        if (out_of_space) {
            return AbortNode("Disk space is low!",
                             _("Error: Disk space is low!"));
        }
        if (bytes_allocated != 0 && fPruneMode) {
            fCheckForPruning = true;
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(CValidationState &state, int nFile, FlatFilePos &pos,
                        unsigned int nAddSize) {
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    bool out_of_space;
    size_t bytes_allocated =
        UndoFileSeq().Allocate(pos, nAddSize, out_of_space);
    if (out_of_space) {
        return AbortNode(state, "Disk space is low!",
                         _("Error: Disk space is low!"));
    }
    if (bytes_allocated != 0 && fPruneMode) {
        fCheckForPruning = true;
    }

    return true;
}

namespace {
// Constant needed later in this file but appearing here to be close to the logic it represents (in WriteBlockToDisk())
constexpr size_t kBlockExtraSpaceNeeded = CMessageHeader::MessageMagic{}.size() + sizeof(unsigned);
static_assert(kBlockExtraSpaceNeeded == 8, "Unexpected block file format change");
} // namespace

static bool WriteBlockToDisk(const CBlock &block, FlatFilePos &pos, const unsigned nSize,
                             const CMessageHeader::MessageMagic &messageStart) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return error("WriteBlockToDisk: OpenBlockFile failed");
    }

    // Write index header
    fileout << messageStart << nSize;

    // Write block
    long fileOutPos = std::ftell(fileout.Get());
    if (fileOutPos < 0) {
        return error("WriteBlockToDisk: ftell failed");
    } else if (static_cast<uint64_t>(fileOutPos) > std::numeric_limits<unsigned int>::max()) {
        return error("%s: ftell overflowed the size of an unsigned int", __func__);
    }

    pos.nPos = static_cast<unsigned int>(fileOutPos);

    // Serialize the rest of the block using the faster BufferedWriter; `fileout` is moved-from beyond this point.
    BufferedWriter writer(std::move(fileout));
    writer << block;

    return true;
}

bool WriteUndoDataForBlock(const CBlockUndo &blockundo, CValidationState &state, CBlockIndex *pindex,
                           const CChainParams &chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        const size_t nSize = ::GetSerializeSize(blockundo, CLIENT_VERSION);
        const size_t spaceNeeded = nSize + kUndoExtraSpaceNeeded;
        // Must assert the below to prevent overflow for both FindUndoPos() and UndoWriteToDisk() which use unsigned int
        assert(std::in_range<unsigned>(spaceNeeded) && spaceNeeded >= nSize && "Overflow check failed");

        FlatFilePos pos;
        if (!FindUndoPos(state, pindex->nFile, pos, spaceNeeded)) {
            return error("ConnectBlock(): FindUndoPos failed");
        }
        if (!UndoWriteToDisk(blockundo, pos, pindex->pprev->GetBlockHash(), nSize, chainparams.DiskMagic())) {
            return AbortNode(state, "Failed to write undo data");
        }

        // update nUndoPos in block index
        pindex->nUndoPos = pos.nPos;
        pindex->nStatus = pindex->nStatus.withUndo();
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

bool ReadBlockFromDisk(CBlock &block, const FlatFilePos &pos, const Consensus::Params &params,
                       const std::optional<BlockHash> &expectedHash) {
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s",
                     pos.ToString());
    }

    // Read block
    try {
        // Note that `filein` is moved-from beyond this point
        BufferedReader(std::move(filein)) >> block;
    } catch (const std::exception &e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__,
                     e.what(), pos.ToString());
    }

    const auto blockHash = block.GetHash();

    // Check the header
    if (!CheckProofOfWork(blockHash, block.nBits, params)) {
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());
    }

    // Optionally check the block hash
    if (expectedHash && *expectedHash != blockHash) {
        return error("GetHash() doesn't match index at %s while reading block (%s != %s)",
                     pos.ToString(), blockHash.ToString(), expectedHash->ToString());
    }

    return true;
}

bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &params) {
    FlatFilePos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    return ReadBlockFromDisk(block, blockPos, params, pindex->GetBlockHash());
}

static std::optional<CAutoFile> ReadBlockSizeCommon(uint64_t &blockSizeOut, const CBlockIndex *pindex,
                                                    const CChainParams &chainParams, FlatFilePos *blockPosOut = nullptr,
                                                    const bool logErrorIfMissing = true) {

    FlatFilePos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }
    if (blockPosOut) *blockPosOut = blockPos;
    if (blockPos.IsNull()) {
        if (logErrorIfMissing) {
            error("%s: Block file missing for block %s (height: %i)", __func__, pindex->GetBlockHash().ToString(),
                  pindex->nHeight);
        }
        return std::nullopt;
    }

    CAutoFile filein(OpenBlockFile(blockPos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s: OpenBlockFile failed for %s", __func__, blockPos.ToString());
        return std::nullopt;
    }

    unsigned int blockSize = 0;
    const size_t headerSize = CMessageHeader::MESSAGE_START_SIZE + sizeof(blockSize);
    if (std::fseek(filein.Get(), -static_cast<long>(headerSize), SEEK_CUR)) {
        error("%s: failed to seek to the block data for %s", __func__, blockPos.ToString());
        return std::nullopt;
    }

    CMessageHeader::MessageMagic magic;
    try {
        // read the disk magic and block size
        filein >> magic >> blockSize;
    } catch (const std::exception &e) {
        error("%s: failed to read block header and size from disk for %s. Original exception: %s",
              __func__, blockPos.ToString(), e.what());
        return std::nullopt;
    }

    // verify disk magic to validate block position inside the file
    if (magic != chainParams.DiskMagic()) {
        error("%s: block DiskMagic verification failed for %s", __func__, blockPos.ToString());
        return std::nullopt;
    }

    // check the block size for sanity
    if (blockSize < BLOCK_HEADER_SIZE || blockSize > MAX_CONSENSUS_BLOCK_SIZE) {
        error("%s: block size verification failed for %s", __func__, blockPos.ToString());
        return std::nullopt;
    }
    blockSizeOut = blockSize;

    return std::optional<CAutoFile>{std::move(filein)};
}

std::optional<uint64_t> ReadBlockSizeFromDisk(const CBlockIndex *pindex, const CChainParams &chainParams) {
    uint64_t blockSize;
    if (!ReadBlockSizeCommon(blockSize, pindex, chainParams, nullptr, /* logErrorIfMissing = */ false)) {
        return std::nullopt;
    }
    return blockSize;
}

bool ReadRawBlockFromDisk(std::vector<uint8_t> &rawBlock, const CBlockIndex *pindex,
                          const CChainParams &chainParams, int nType, int nVersion) {
    uint64_t blockSize;
    FlatFilePos blockPos;
    auto optFile = ReadBlockSizeCommon(blockSize, pindex, chainParams, &blockPos);
    if (!optFile) {
        // error message already generated by ReadBlockSizeCommon() above
        return false;
    }

    try {
        // populate data
        rawBlock.resize(blockSize);
        *optFile >> Span{rawBlock};
    } catch (const std::exception &e) {
        return error("%s: failed to read block data from disk for %s. Original exception: %s",
                     __func__, blockPos.ToString(), e.what());
    }

    if (fCheckBlockReads) {
        // This is normally only enabled for regtest and is provided in order to guarantee additional sanity checks
        // when returning raw blocks in this manner. For real networks, we prefer the performance benefit of not
        // deserializing and not doing these slower checks here.
        Tic elapsed;
        CBlock block;
        std::vector<uint8_t> rawBlock2;
        rawBlock2.reserve(rawBlock.size());

        try {
            VectorReader(nType, nVersion, rawBlock, 0) >> block;
            CVectorWriter(nType, nVersion, rawBlock2, 0) << block;
        } catch (const std::exception &e) {
            return error("%s: Consistency check failed; ser/deser error for block data for %s, exception was: %s",
                         __func__, blockPos.ToString(), e.what());
        }

        // Ensure the block, when re-serialized with nType and nVersion matches what we had on disk. This defends
        // against block serialization being sensitive to the caller's nType/nVersion flags. Block serialization
        // should always be the same irrespective of flags provided, otherwise this ReadRawBlockFromDisk() function
        // cannot be used and caller should be using ReadBlockFromDisk() instead (see net_processing.cpp where this
        // function is called).
        if (rawBlock != rawBlock2) {
            return error("%s: Consistency check failed; block raw data mismatches re-serialized version for block %s at"
                         " %s, nType: %i, nVersion: %i", __func__, pindex->ToString(), blockPos.ToString(), nType,
                         nVersion);
        }
        // Check the header (detects possible corruption; unlikely)
        if (block.GetHash() != pindex->GetBlockHash()) {
            return error("%s: Consistency check failed; GetHash() doesn't match index for %s at %s",
                         __func__, pindex->ToString(), blockPos.ToString());
        }
        LogPrint(BCLog::BENCH, "%s: checks passed for block %s (%i bytes) in %s msec\n", __func__,
                 block.GetHash().ToString(), rawBlock2.size(), elapsed.msecStr());
    }

    return true;
}

FlatFilePos SaveBlockToDisk(const CBlock &block, int nHeight, const CChainParams &chainparams, const FlatFilePos *dbp)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    const size_t blockSize = ::GetSerializeSize(block, CLIENT_VERSION);
    const size_t spaceNeeded = blockSize + kBlockExtraSpaceNeeded;
    // Must assert the below to prevent overflow for both FindBlockPos() and WriteBlockToDisk() which use unsigned int
    assert(std::in_range<unsigned>(spaceNeeded) && spaceNeeded >= blockSize && "Overflow check failed");
    FlatFilePos blockPos;
    if (dbp != nullptr) {
        blockPos = *dbp;
    }
    if (!FindBlockPos(blockPos, spaceNeeded, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return FlatFilePos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, blockSize, chainparams.DiskMagic())) {
            AbortNode("Failed to write block");
            return FlatFilePos();
        }
    }
    return blockPos;
}

struct CImportingNow {
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};

void ThreadImport(const Config &config, std::vector<fs::path> vImportFiles) {
    util::ThreadRename("loadblk");
    ScheduleBatchPriority();

    {
        CImportingNow imp;

        // -reindex
        if (fReindex) {
            int nFile = 0;
            while (true) {
                FlatFilePos pos(nFile, 0);
                if (!fs::exists(GetBlockPosFilename(pos))) {
                    // No block files left to reindex
                    break;
                }
                FILE *file = OpenBlockFile(pos, true);
                if (!file) {
                    // This error is logged in OpenBlockFile
                    break;
                }
                LogPrintf("Reindexing block file blk%05u.dat...\n",
                          (unsigned int)nFile);
                LoadExternalBlockFile(config, file, &pos);
                nFile++;
            }
            pblocktree->WriteReindexing(false);
            fReindex = false;
            LogPrintf("Reindexing finished\n");
            // To avoid ending up in a situation without genesis block, re-try
            // initializing (no-op if reindexing worked):
            LoadGenesisBlock(config.GetChainParams());
        }

        // hardcoded $DATADIR/bootstrap.dat
        fs::path pathBootstrap = GetDataDir() / "bootstrap.dat";
        if (fs::exists(pathBootstrap)) {
            FILE *file = fsbridge::fopen(pathBootstrap, "rb");
            if (file) {
                fs::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
                LogPrintf("Importing bootstrap.dat...\n");
                LoadExternalBlockFile(config, file);
                RenameOver(pathBootstrap, pathBootstrapOld);
            } else {
                LogPrintf("Warning: Could not open bootstrap file %s\n",
                          pathBootstrap.string());
            }
        }

        // -loadblock=
        for (const fs::path &path : vImportFiles) {
            FILE *file = fsbridge::fopen(path, "rb");
            if (file) {
                LogPrintf("Importing blocks file %s...\n", path.string());
                LoadExternalBlockFile(config, file);
            } else {
                LogPrintf("Warning: Could not open blocks file %s\n",
                          path.string());
            }
        }

        // scan for better chains in the block chain database, that are not yet
        // connected in the active best chain
        CValidationState state;
        if (!ActivateBestChain(config, state)) {
            LogPrintf("Failed to connect best block (%s)\n",
                      FormatStateMessage(state));
            StartShutdown();
            return;
        }

        if (gArgs.GetBoolArg("-stopafterblockimport",
                             DEFAULT_STOPAFTERBLOCKIMPORT)) {
            LogPrintf("Stopping after block import\n");
            StartShutdown();
            return;
        }
    } // End scope of CImportingNow

    if (gArgs.GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL)) {
        if (DoubleSpendProof::IsEnabled()) {
            LoadDSProofs(::g_mempool);
        }
        LoadMempool(config, ::g_mempool);
    }
    ::g_mempool.SetIsLoaded(!ShutdownRequested());
}
