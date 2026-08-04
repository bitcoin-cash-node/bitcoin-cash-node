// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/blockdata.h>

#include <bench/data.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <streams.h>
#include <undo.h>
#include <util/system.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

BlockData::BlockData(int blockHeight) {
    std::function<const std::vector<uint8_t>()> GetBlock;
    std::function<const std::vector<uint8_t>()> GetCoinsSpent;
    if (blockHeight == 413567) {
        GetBlock = benchmark::data::Get_block413567;
        GetCoinsSpent = benchmark::data::Get_coins_spent_413567;
    } else if (blockHeight == 556034) {
        GetBlock = benchmark::data::Get_block556034;
        GetCoinsSpent = benchmark::data::Get_coins_spent_556034;
    } else {
        throw std::runtime_error("Unknown block height in BlockData::BlockData(). Expected one of: 413567, 556034");
    }
    assert(bool(GetBlock) && bool(GetCoinsSpent));
    const std::vector<uint8_t> &data = GetBlock();
    const std::vector<uint8_t> &coinsSpent = GetCoinsSpent();
    const CChainParams &chainParams = Params();

    // Fetch the main block data
    VectorReader stream(SER_NETWORK, PROTOCOL_VERSION, data, 0);
    stream >> block;
    blockHash = block.GetHash();
    blockIndex.phashBlock = &blockHash;
    blockIndex.nBits = block.nBits;
    blockIndex.nHeight = blockHeight;

    // Create a blockindex for the previous block
    prevBlockHash = BlockHash();
    prevBlockIndex.phashBlock = &prevBlockHash;
    blockIndex.pprev = &prevBlockIndex;

    // Create undo data for the block
    CBlockUndo blockundo;
    blockundo.vtxundo.resize(block.vtx.size() - 1);
    CCoinsView dummy;
    CCoinsViewCache coinsCache(&dummy);
    std::map<COutPoint, Coin> coinsMap;
    VectorReader(SER_NETWORK, PROTOCOL_VERSION, coinsSpent, 0) >> coinsMap;
    for (const auto & [out, coin] : coinsMap) {
        coinsCache.AddCoin(out, coin, false);
    }
    size_t txIndex = 0;
    for (const auto &ptx : block.vtx) {
        const CTransaction &tx = *ptx;
        if (tx.IsCoinBase()) {
            continue;
        }
        SpendCoins(coinsCache, tx, blockundo.vtxundo.at(txIndex), blockIndex.nHeight);
        ++txIndex;
    }

    // Save block to disk
    FlatFilePos blockPos = SaveBlockToDisk(block, blockIndex.nHeight, chainParams, nullptr);
    if (blockPos.IsNull()) {
        throw std::runtime_error(std::string("Failed to save block to disk."));
    }
    blockIndex.nFile = blockPos.nFile;
    blockIndex.nDataPos = blockPos.nPos;

    // Write the undo data to disk
    CValidationState state;
    WriteUndoDataForBlock(blockundo, state, &blockIndex, chainParams);
    if (!state.IsValid()) {
        throw std::runtime_error(std::string("Failed to save undo data to disk: ") + state.GetRejectReason());
    }
}

BlockData::~BlockData() {
    // Remove the temporary block and undo data files
    FlatFilePos pos(blockIndex.nFile, blockIndex.nDataPos);
    fs::path filePath = FlatFileSeq(GetBlocksDir(), "blk", UNDOFILE_CHUNK_SIZE).FileName(pos);
    fs::remove(filePath);
    pos.nPos = blockIndex.nUndoPos;
    filePath = FlatFileSeq(GetBlocksDir(), "rev", UNDOFILE_CHUNK_SIZE).FileName(pos);
    fs::remove(filePath);
}
