// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <core_io.h>
#include <sync.h>
#include <univalue.h>

#include <cstdint>
#include <vector>

extern RecursiveMutex cs_main;

class CBlock;
class CBlockIndex;
class Config;
class CTxMemPool;
class JSONRPCRequest;
namespace abla { class State; }

UniValue getblockchaininfo(const Config &config, const JSONRPCRequest &request);

static constexpr int NUM_GETBLOCKSTATS_PERCENTILES = 5;

/**
 * Get the required difficulty of the next block w/r/t the given block index.
 *
 * @return A floating point number that is a multiple of the main net minimum
 * difficulty (4295032833 hashes).
 */
double GetDifficulty(const CBlockIndex *blockindex);

/** Callback for when block tip changed. */
void RPCNotifyBlockChange(bool ibd, const CBlockIndex *pindex);

/** Block description to JSON */
UniValue::Object blockToJSON(const Config &config, const CBlock &block, const CBlockIndex *tip,
                             const CBlockIndex *blockindex, const TransactionFormatOptions &txOptions) LOCKS_EXCLUDED(cs_main);

/** Mempool information to JSON */
UniValue::Object MempoolInfoToJSON(const Config &config, const CTxMemPool &pool);

/** Mempool to JSON */
UniValue MempoolToJSON(const CTxMemPool &pool, bool verbose = false);

/** Block header to JSON */
UniValue::Object blockheaderToJSON(const Config &config, const CBlockIndex *tip, const CBlockIndex *blockindex) LOCKS_EXCLUDED(cs_main);

/** ABLA state to JSON */
UniValue::Object ablaStateToJSON(const Config &config, const abla::State &ablaState);

/** Used by getblockstats to get feerates at different percentiles by weight  */
void CalculatePercentilesBySize(Amount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<Amount, int64_t>>& scores, int64_t total_size);
