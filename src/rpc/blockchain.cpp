// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <coins.h>
#include <coinstats.h>
#include <config.h>
#include <consensus/abla.h>
#include <consensus/activation.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <index/coinstatsindex.h>
#include <index/txindex.h>
#include <key_io.h>
#include <net_processing.h> /* for PeerLogicValidation */
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <software_outdated.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <util/check.h>
#include <util/defer.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>

struct CUpdatedBlock {
    uint256 hash;
    int height;
};

static Mutex cs_blockchange;
static std::condition_variable cond_blockchange;
static CUpdatedBlock latestblock;

/**
 * Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex *blockindex) {
    assert(blockindex);

    int nShift = (blockindex->nBits >> 24) & 0xff;
    double dDiff = double(0x0000ffff) / double(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

static int ComputeNextBlockAndDepth(const CBlockIndex *tip,
                                    const CBlockIndex *blockindex,
                                    const CBlockIndex *&next) {
    next = tip->GetAncestor(blockindex->nHeight + 1);
    if (next && next->pprev == blockindex) {
        return tip->nHeight - blockindex->nHeight + 1;
    }
    next = nullptr;
    return blockindex == tip ? 1 : -1;
}

UniValue::Object blockheaderToJSON(const Config &config, const CBlockIndex *tip, const CBlockIndex *blockindex) {
    const CBlockIndex *pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    bool previousblockhash = blockindex->pprev;
    bool nextblockhash = pnext;
    const auto ablaStateOpt = blockindex->GetAblaStateOpt();
    UniValue::Object result;
    result.reserve(13 + previousblockhash + nextblockhash + bool(ablaStateOpt));
    result.emplace_back("hash", blockindex->GetBlockHash().GetHex());
    result.emplace_back("confirmations", confirmations);
    result.emplace_back("height", blockindex->nHeight);
    result.emplace_back("version", blockindex->nVersion);
    result.emplace_back("versionHex", strprintf("%08x", blockindex->nVersion));
    result.emplace_back("merkleroot", blockindex->hashMerkleRoot.GetHex());
    result.emplace_back("time", blockindex->nTime);
    result.emplace_back("mediantime", blockindex->GetMedianTimePast());
    result.emplace_back("nonce", blockindex->nNonce);
    result.emplace_back("bits", strprintf("%08x", blockindex->nBits));
    result.emplace_back("difficulty", GetDifficulty(blockindex));
    result.emplace_back("chainwork", blockindex->nChainWork.GetHex());
    result.emplace_back("nTx", blockindex->nTx);
    if (previousblockhash) {
        result.emplace_back("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    }
    if (nextblockhash) {
        result.emplace_back("nextblockhash", pnext->GetBlockHash().GetHex());
    }
    if (ablaStateOpt) {
        result.emplace_back("ablastate", ablaStateToJSON(config, *ablaStateOpt));
    }
    return result;
}

UniValue::Object blockToJSON(const Config &config, const CBlock &block, const CBlockIndex *tip,
                             const CBlockIndex *blockindex, const TransactionFormatOptions &txOptions) LOCKS_EXCLUDED(cs_main) {
    const CBlockIndex *pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    bool previousblockhash = blockindex->pprev;
    bool nextblockhash = pnext;
    const auto ablaStateOpt = blockindex->GetAblaStateOpt();
    UniValue::Object result;
    result.reserve(15 + previousblockhash + nextblockhash + bool(ablaStateOpt));
    result.emplace_back("hash", blockindex->GetBlockHash().GetHex());
    result.emplace_back("confirmations", confirmations);
    result.emplace_back("size", ::GetSerializeSize(block, PROTOCOL_VERSION));
    result.emplace_back("height", blockindex->nHeight);
    result.emplace_back("version", block.nVersion);
    result.emplace_back("versionHex", strprintf("%08x", block.nVersion));
    result.emplace_back("merkleroot", block.hashMerkleRoot.GetHex());
    UniValue::Array txs;
    txs.reserve(block.vtx.size());

    if (txOptions.block_level.txids_only) {
        // Equivalent to BlockTxVerbosity::SHOW_TXID: only transaction IDs
        for (const auto &tx : block.vtx) {
            txs.emplace_back(tx->GetId().GetHex());
        }
    } else {
        // Detailed serialization with options
        CBlockUndo blockUndo;
        const bool have_undo{WITH_LOCK(::cs_main, return !IsBlockPruned(blockindex) && UndoReadFromDisk(blockUndo, blockindex))};

        for (size_t i = 0u; i < block.vtx.size(); ++i) {
            const CTransactionRef& tx = block.vtx[i];
            // coinbase transaction (i.e. i == 0) doesn't have undo data
            const CTxUndo* txundo = (have_undo && i > 0u) ? &blockUndo.vtxundo.at(i - 1u) : nullptr;
            txs.push_back(TransactionToUniv(config, *tx, txundo, txOptions));
        }
    }

    result.emplace_back("tx", std::move(txs));
    result.emplace_back("time", block.GetBlockTime());
    result.emplace_back("mediantime", blockindex->GetMedianTimePast());
    result.emplace_back("nonce", block.nNonce);
    result.emplace_back("bits", strprintf("%08x", block.nBits));
    result.emplace_back("difficulty", GetDifficulty(blockindex));
    result.emplace_back("chainwork", blockindex->nChainWork.GetHex());
    result.emplace_back("nTx", blockindex->nTx);
    if (previousblockhash) {
        result.emplace_back("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    }
    if (nextblockhash) {
        result.emplace_back("nextblockhash", pnext->GetBlockHash().GetHex());
    }
    if (ablaStateOpt) {
        result.emplace_back("ablastate", ablaStateToJSON(config, *ablaStateOpt));
    }
    return result;
}

UniValue::Object ablaStateToJSON(const Config &config, const abla::State &state) {
    UniValue::Object ret;
    ret.reserve(5);
    ret.emplace_back("epsilon", state.GetControlBlockSize());
    ret.emplace_back("beta", state.GetElasticBufferSize());
    ret.emplace_back("blocksize", state.GetBlockSize());
    // Note that consensus rules are that the max block size is always at least the configured max block size,
    // or what ABLA says, whichever is greater.
    const auto cmbs = config.GetConfiguredMaxBlockSize();
    ret.emplace_back("blocksizelimit", std::max(cmbs, state.GetBlockSizeLimit()));
    ret.emplace_back("nextblocksizelimit", std::max(cmbs, state.GetNextBlockSizeLimit(
                                                              config.GetChainParams().GetConsensus().ablaConfig)));
    return ret;
}

static UniValue getblockcount(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getblockcount",
                "\nReturns the number of blocks in the longest blockchain.\n", {}}
                .ToString() +
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") +
            HelpExampleRpc("getblockcount", ""));
    }

    LOCK(cs_main);
    return ::ChainActive().Height();
}

static UniValue getbestblockhash(const Config &config,
                                 const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getbestblockhash",
                "\nReturns the hash of the best (tip) block in the longest blockchain.\n", {}}
                .ToString() +
            "\nResult:\n"
            "\"hex\"      (string) the block hash hex-encoded\n"
            "\nExamples:\n" +
            HelpExampleCli("getbestblockhash", "") +
            HelpExampleRpc("getbestblockhash", ""));
    }

    LOCK(cs_main);
    return ::ChainActive().Tip()->GetBlockHash().GetHex();
}

UniValue getfinalizedblockhash(const Config &config,
                               const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "getfinalizedblockhash\n"
            "\nReturns the hash of the currently finalized block\n"
            "\nResult:\n"
            "\"hex\"      (string) the block hash hex-encoded\n");
    }

    LOCK(cs_main);
    const CBlockIndex *blockIndexFinalized = GetFinalizedBlock();
    if (blockIndexFinalized) {
        return blockIndexFinalized->GetBlockHash().GetHex();
    }
    return std::string();
}

void RPCNotifyBlockChange(bool ibd, const CBlockIndex *pindex) {
    if (pindex) {
        std::lock_guard<std::mutex> lock(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

static UniValue waitfornewblock(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"waitfornewblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"timeout", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", ""},
                }}
                .ToString() +
            "\nArguments:\n"
            "1. timeout (int, optional, default=0) Time in "
            "milliseconds to wait for a response. 0 indicates "
            "no timeout.\n"
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("waitfornewblock", "1000") +
            HelpExampleRpc("waitfornewblock", "1000"));
    }

    int timeout = 0;
    if (!request.params[0].isNull()) {
        timeout = request.params[0].get_int();
    }

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        block = latestblock;
        if (timeout) {
            cond_blockchange.wait_for(
                lock, std::chrono::milliseconds(timeout), [&block] {
                    return latestblock.height != block.height ||
                           latestblock.hash != block.hash || !IsRPCRunning();
                });
        } else {
            cond_blockchange.wait(lock, [&block] {
                return latestblock.height != block.height ||
                       latestblock.hash != block.hash || !IsRPCRunning();
            });
        }
        block = latestblock;
    }
    UniValue::Object ret;
    ret.reserve(2);
    ret.emplace_back("hash", block.hash.GetHex());
    ret.emplace_back("height", block.height);
    return ret;
}

static UniValue waitforblock(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"waitforblock",
                "\nWaits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0", "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                }}
                .ToString() +
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4"
                                           "570b24c9ed7b4a8c619eb02596f8862\", "
                                           "1000") +
            HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4"
                                           "570b24c9ed7b4a8c619eb02596f8862\", "
                                           "1000"));
    }

    int timeout = 0;

    BlockHash hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull()) {
        timeout = request.params[1].get_int();
    }

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if (timeout) {
            cond_blockchange.wait_for(
                lock, std::chrono::milliseconds(timeout), [&hash] {
                    return latestblock.hash == hash || !IsRPCRunning();
                });
        } else {
            cond_blockchange.wait(lock, [&hash] {
                return latestblock.hash == hash || !IsRPCRunning();
            });
        }
        block = latestblock;
    }

    UniValue::Object ret;
    ret.reserve(2);
    ret.emplace_back("hash", block.hash.GetHex());
    ret.emplace_back("height", block.height);
    return ret;
}

static UniValue waitforblockheight(const Config &config,
                                   const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"waitforblockheight",
                "\nWaits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n",
                {
                    {"height", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0", "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                }}
                .ToString() +
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("waitforblockheight", "\"100\", 1000") +
            HelpExampleRpc("waitforblockheight", "\"100\", 1000"));
    }

    int timeout = 0;

    int height = request.params[0].get_int();

    if (!request.params[1].isNull()) {
        timeout = request.params[1].get_int();
    }

    CUpdatedBlock block;
    {
        WAIT_LOCK(cs_blockchange, lock);
        if (timeout) {
            cond_blockchange.wait_for(
                lock, std::chrono::milliseconds(timeout), [&height] {
                    return latestblock.height >= height || !IsRPCRunning();
                });
        } else {
            cond_blockchange.wait(lock, [&height] {
                return latestblock.height >= height || !IsRPCRunning();
            });
        }
        block = latestblock;
    }
    UniValue::Object ret;
    ret.reserve(2);
    ret.emplace_back("hash", block.hash.GetHex());
    ret.emplace_back("height", block.height);
    return ret;
}

static UniValue
syncwithvalidationinterfacequeue(const Config &config,
                                 const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            RPCHelpMan{"syncwithvalidationinterfacequeue",
                "\nWaits for the validation interface queue to catch up on everything that was there when we entered this function.\n", {}}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
        );
    }
    SyncWithValidationInterfaceQueue();
    return UniValue();
}

static UniValue getdifficulty(const Config& config,
                              const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getdifficulty",
                "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n", {}}
                .ToString() +
            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
            "\nExamples:\n"
            + HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
        );
    }

    LOCK(cs_main);
    return GetDifficulty(::ChainActive().Tip());
}

static std::string EntryDescriptionString() {
    return "    \"size\" : n,             (numeric) transaction size.\n"
           "    \"time\" : n,             (numeric) local time transaction "
           "entered pool in seconds since 1 Jan 1970 GMT\n"
           "    \"fees\" : {\n"
           "        \"base\" : n,         (numeric) transaction fee in " +
           CURRENCY_UNIT +
           "\n"
           "        \"modified\" : n,     (numeric) transaction fee with fee "
           "deltas used for mining priority in " +
           CURRENCY_UNIT +
           "\n"
           "    }\n"
           "    \"depends\" : [           (array) unconfirmed transactions "
           "used as inputs for this transaction\n"
           "        \"transactionid\",    (string) parent transaction id\n"
           "       ... ]\n"
           "    \"spentby\" : [           (array) unconfirmed transactions "
           "spending outputs from this transaction\n"
           "        \"transactionid\",    (string) child transaction id\n"
           "       ... ]\n";
}

static UniValue::Object entryToJSON(const CTxMemPool &pool, const CTxMemPoolEntry &e)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs) {
    AssertLockHeld(pool.cs);

    UniValue::Object info;
    info.reserve(5);

    UniValue::Object fees;
    fees.reserve(2);
    fees.emplace_back("base", ValueFromAmount(e.GetFee()));
    fees.emplace_back("modified", ValueFromAmount(e.GetModifiedFee()));

    info.emplace_back("fees", std::move(fees));
    info.emplace_back("size", e.GetTxSize());
    info.emplace_back("time", e.GetTime());

    const CTransaction &tx = e.GetTx();

    std::set<std::string> setDepends;
    for (const CTxIn &txin : tx.vin) {
        if (pool.exists(txin.prevout.GetTxId())) {
            setDepends.insert(txin.prevout.GetTxId().ToString());
        }
    }
    UniValue::Array depends;
    depends.reserve(setDepends.size());
    for (const std::string &dep : setDepends) {
        depends.emplace_back(dep);
    }
    info.emplace_back("depends", std::move(depends));

    UniValue::Array spent;
    const CTxMemPool::txiter &it = pool.mapTx.find(tx.GetId());
    const CTxMemPool::setEntries &setChildren = pool.GetMemPoolChildren(it);
    spent.reserve(setChildren.size());
    for (CTxMemPool::txiter childiter : setChildren) {
        spent.emplace_back(childiter->GetTx().GetId().ToString());
    }
    info.emplace_back("spentby", std::move(spent));

    return info;
}

UniValue MempoolToJSON(const CTxMemPool &pool, bool verbose) {
    if (verbose) {
        UniValue::Object ret;
        LOCK(pool.cs);
        ret.reserve(pool.mapTx.size());
        for (const CTxMemPoolEntry &e : pool.mapTx) {
            const uint256 &txid = e.GetTx().GetId();
            ret.emplace_back(txid.ToString(), entryToJSON(pool, e));
        }
        return ret;
    }

    std::vector<uint256> vtxids;
    pool.queryHashes(vtxids);
    UniValue::Array ret;
    ret.reserve(vtxids.size());
    for (const uint256 &txid : vtxids) {
        ret.emplace_back(txid.ToString());
    }
    return ret;
}

static UniValue getrawmempool(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"getrawmempool",
                "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"
                "\nHint: use getmempoolentry to fetch a specific transaction from the mempool.\n",
                {
                    {"verbose", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "True for a json object, false for array of transaction ids"},
                }}
                .ToString() +
            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getrawmempool", "true") +
            HelpExampleRpc("getrawmempool", "true"));
    }

    bool fVerbose = false;
    if (!request.params[0].isNull()) {
        fVerbose = request.params[0].get_bool();
    }

    return MempoolToJSON(::g_mempool, fVerbose);
}

static UniValue getmempoolancestors(const Config &config,
                                    const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getmempoolancestors",
                "\nIf txid is in the mempool, returns all in-mempool ancestors.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id (must be in mempool)"},
                    {"verbose", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "True for a json object, false for array of transaction ids"},
                }}
                .ToString() +
            "\nResult (for verbose = false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an "
            "in-mempool ancestor transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempoolancestors", "\"mytxid\"") +
            HelpExampleRpc("getmempoolancestors", "\"mytxid\""));
    }

    bool fVerbose = false;
    if (!request.params[1].isNull()) {
        fVerbose = request.params[1].get_bool();
    }

    TxId txid(ParseHashV(request.params[0], "parameter 1"));

    LOCK(g_mempool.cs);

    CTxMemPool::txiter it = g_mempool.mapTx.find(txid);
    if (it == g_mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Transaction not in mempool");
    }

    CTxMemPool::setEntries setAncestors;
    g_mempool.CalculateMemPoolAncestors(*it, setAncestors, false);

    if (!fVerbose) {
        UniValue::Array ret;
        ret.reserve(setAncestors.size());
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            ret.emplace_back(ancestorIt->GetTx().GetId().ToString());
        }
        return ret;
    }

    UniValue::Object ret;
    ret.reserve(setAncestors.size());
    for (CTxMemPool::txiter ancestorIt : setAncestors) {
        const CTxMemPoolEntry &e = *ancestorIt;
        const TxId &_txid = e.GetTx().GetId();
        ret.emplace_back(_txid.ToString(), entryToJSON(::g_mempool, e));
    }
    return ret;
}

static UniValue getmempooldescendants(const Config &config,
                                      const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getmempooldescendants",
                "\nIf txid is in the mempool, returns all in-mempool descendants.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id (must be in mempool)"},
                    {"verbose", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "True for a json object, false for array of transaction ids"},
                }}
                .ToString() +
            "\nResult (for verbose = false):\n"
            "[                       (json array of strings)\n"
            "  \"transactionid\"           (string) The transaction id of an "
            "in-mempool descendant transaction\n"
            "  ,...\n"
            "]\n"
            "\nResult (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n" +
            EntryDescriptionString() +
            "  }, ...\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempooldescendants", "\"mytxid\"") +
            HelpExampleRpc("getmempooldescendants", "\"mytxid\""));
    }

    bool fVerbose = false;
    if (!request.params[1].isNull()) {
        fVerbose = request.params[1].get_bool();
    }

    TxId txid(ParseHashV(request.params[0], "parameter 1"));

    LOCK(g_mempool.cs);

    CTxMemPool::txiter it = g_mempool.mapTx.find(txid);
    if (it == g_mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Transaction not in mempool");
    }

    CTxMemPool::setEntries setDescendants;
    g_mempool.CalculateDescendants(it, setDescendants);
    // CTxMemPool::CalculateDescendants will include the given tx
    setDescendants.erase(it);

    if (!fVerbose) {
        UniValue::Array ret;
        ret.reserve(setDescendants.size());
        for (CTxMemPool::txiter descendantIt : setDescendants) {
            ret.emplace_back(descendantIt->GetTx().GetId().ToString());
        }
        return ret;
    }

    UniValue::Object ret;
    ret.reserve(setDescendants.size());
    for (CTxMemPool::txiter descendantIt : setDescendants) {
        const CTxMemPoolEntry &e = *descendantIt;
        const TxId &_txid = e.GetTx().GetId();
        ret.emplace_back(_txid.ToString(), entryToJSON(::g_mempool, e));
    }
    return ret;
}

static UniValue getmempoolentry(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getmempoolentry",
                "\nReturns mempool data for given transaction\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id (must be in mempool)"},
                }}
                .ToString() +
            "\nResult:\n"
            "{                           (json object)\n" +
            EntryDescriptionString() +
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempoolentry", "\"mytxid\"") +
            HelpExampleRpc("getmempoolentry", "\"mytxid\""));
    }

    TxId txid(ParseHashV(request.params[0], "parameter 1"));

    LOCK(g_mempool.cs);

    CTxMemPool::txiter it = g_mempool.mapTx.find(txid);
    if (it == g_mempool.mapTx.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Transaction not in mempool");
    }

    const CTxMemPoolEntry &e = *it;
    return entryToJSON(::g_mempool, e);
}

static UniValue getblockhash(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getblockhash",
                "\nReturns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The height index"},
                }}
                .ToString() +
            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") +
            HelpExampleRpc("getblockhash", "1000"));
    }

    LOCK(cs_main);

    int nHeight = request.params[0].get_int();
    if (nHeight < 0 || nHeight > ::ChainActive().Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }

    CBlockIndex *pblockindex = ::ChainActive()[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

static std::string ablaStateHelpCommon(bool trailingComma, size_t extraSpaceLeft=0, size_t extraSpaceMiddle=0) {
    const std::string spL(extraSpaceLeft, ' '), spM(extraSpaceMiddle, ' ');
    return strprintf(
        "%s  \"ablastate\" : {                %s(json object, optional) The block's ABLA state\n"
        "%s    \"epsilon\" : n,               %s(numeric) ABLA state epsilon value\n"
        "%s    \"beta\" : n,                  %s(numeric) ABLA state beta value\n"
        "%s    \"blocksize\" : n,             %s(numeric) The size of this block\n"
        "%s    \"blocksizelimit\" : n,        %s(numeric) The size limit for this block\n"
        "%s    \"nextblocksizelimit\" : n,    %s(numeric) The size limit for the next block\n"
        "%s  }%s\n", spL, spM, spL, spM, spL, spM, spL, spM, spL, spM, spL, spM, spL, trailingComma ? "," : "");
}

/// Requires cs_main; called by getblock() and ParseHashOrHeight(disallow_pruned=true)
static void ThrowIfPrunedBlock(const CBlockIndex *pblockindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    if (IsBlockPruned(pblockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
    }
}

static const CBlockIndex *ParseHashOrHeight(const UniValue &param, bool active_chain_only,
                                            const CBlockIndex **tip_out = nullptr, bool disallow_pruned = false) {
    const CBlockIndex *pindex{};

    LOCK(cs_main);

    if (tip_out) {
        *tip_out = ::ChainActive().Tip();
    }

    if (param.isNum()) {
        const int height = param.get_int();
        const int current_tip = ::ChainActive().Height();
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        pindex = ::ChainActive()[height];
    } else {
        const BlockHash hash(ParseHashV(param, "hash_or_height"));
        pindex = LookupBlockIndex(hash);
        if (active_chain_only && pindex && !::ChainActive().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Block is not in chain %s", Params().NetworkIDString()));
        }
    }
    if (!pindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }
    if (disallow_pruned) {
        ThrowIfPrunedBlock(pindex);
    }

    return pindex;
}

static UniValue getblockheader(const Config &config,
                               const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getblockheader",
                "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"hash_or_height", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The block hash or block height"},
                    {"verbose", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "true for a json object, false for the hex-encoded data"},
                }}
                .ToString() +
            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"hash\" : \"hash\",               (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,           (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"height\" : n,                  (numeric) The block height or index\n"
            "  \"version\" : n,                 (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\",     (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\",         (string) The merkle root\n"
            "  \"time\" : ttt,                  (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,            (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,                   (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\",           (string) The bits\n"
            "  \"difficulty\" : x.xxx,          (numeric) The difficulty\n"
            "  \"chainwork\" : \"0000...1f3\"     (string) Expected number of hashes required to produce the current chain (in hex)\n"
            "  \"nTx\" : n,                     (numeric) The number of transactions in the block.\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\",      (string) The hash of the next block,\n"
            + ablaStateHelpCommon(false) +
            "}\n"
            "\nResult (for verbose=false):\n"
            "\"data\"                           (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "1000") +
            HelpExampleRpc("getblockheader", "1000") +
            HelpExampleCli("getblockheader", "'\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"'") +
            HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));
    }

    const CBlockIndex *tip{};
    const CBlockIndex *pindex = ParseHashOrHeight(request.params[0], false, &tip);

    assert(pindex != nullptr && tip != nullptr);

    bool fVerbose = true;
    if (!request.params[1].isNull()) {
        fVerbose = request.params[1].get_bool();
    }

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pindex->GetBlockHeader();
        return HexStr(ssBlock);
    }

    return blockheaderToJSON(config, tip, pindex);
}

/// Helper for the below Read*Block*() functions
template <typename BlockReadFunc>
void GenericReadBlockHelper(const BlockReadFunc &readFunc) {
    auto doRead = [&] {
        if (!readFunc()) {
            // Block not found on disk. This could be because we have the block
            // header in our index but don't have the block (for example if a
            // non-whitelisted node sends us an unrequested long chain of valid
            // blocks, we add the headers to our index, but don't accept the block).
            throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
        }
    };
    if (fPruneMode) {
        // Note: in pruned mode we must take cs_main here because it's possible for FlushStateToDisk()
        // in validation.cpp to also attempt to remove this file while we have it open.  This is not
        // normally a problem except for on Windows, where FlushStateToDisk() would fail to remove the
        // block file we have open here, in which case on Windows the node would AbortNode().  Hence
        // the need for this locking in the fPrunedMode case only.
        LOCK(cs_main);
        doRead();
    } else {
        // Non-pruned mode, we can benefit from not having to grab cs_main here since blocks never
        // go away -- this increases parallelism in the case of non-pruning nodes.
        doRead();
    }
}

/// Lock-free -- will throw if block not found or was pruned, etc. Guaranteed to return a valid block or fail.
static CBlock ReadBlockChecked(const Config &config, const CBlockIndex *pblockindex) {
    CBlock block;
    GenericReadBlockHelper([&]{
        return ReadBlockFromDisk(block, pblockindex, config.GetChainParams().GetConsensus());
    });
    return block;
}

/// Lock-free -- will throw if block not found or was pruned, etc. Guaranteed to return valid bytes or fail.
/// Like the above function but does no sanity checking on the block. Just returns the bytes it read from disk.
static std::vector<uint8_t> ReadRawBlockUnchecked(const Config &config, const CBlockIndex *pblockindex) {
    std::vector<uint8_t> rawBlock;
    GenericReadBlockHelper([&]{
        return ReadRawBlockFromDisk(rawBlock, pblockindex, config.GetChainParams(), SER_NETWORK,
                                    PROTOCOL_VERSION);
    });
    return rawBlock;
}

static UniValue getblock(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 3) {
        throw std::runtime_error(
            RPCHelpMan{"getblock",
                "\nIf verbosity is 0 or false, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1 or true, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction, including fee.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including fee, and including prevout information for inputs (only for unpruned blocks in the current best chain).\n"
                "If verbosity >= 4, returns the same information as verbosity=3, with additional \"byteCodePattern\" information for all scriptSig and scriptPubKey scripts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The block hash"},
                    {"verbosity", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs"},
                    {"patterns", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "If true then byteCodePattern and redeemScript objects will be added"},
                }}
                .ToString() +
            "\nResult (for verbosity = 0):\n"
            "\"data\"                                  (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nResult (for verbosity = 1):\n"
            "{\n"
            "  \"hash\" : \"hash\",                      (string) The block hash (same as provided)\n"
            "  \"confirmations\" : n,                  (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,                           (numeric) The block size\n"
            "  \"height\" : n,                         (numeric) The block height or index\n"
            "  \"version\" : n,                        (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\",            (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\",                (string) The merkle root\n"
            "  \"tx\" : [                              (array of string) The transaction ids\n"
            "     \"transactionid\"                    (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,                         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,                   (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,                          (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\",                  (string) The bits\n"
            "  \"difficulty\" : x.xxx,                 (numeric) The difficulty\n"
            "  \"chainwork\" : \"xxxx\",                 (string) Expected number of hashes required to produce the chain up to this block (in hex)\n"
            "  \"nTx\" : n,                            (numeric) The number of transactions in the block.\n"
            "  \"previousblockhash\" : \"hash\",         (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"              (string) The hash of the next block,\n"
            + ablaStateHelpCommon(false, 0, 7) +
            "}\n"
            "\nResult (for verbosity = 2):\n"
            "{\n"
            "  ...,                                  Same output as verbosity = 1\n"
            "  \"tx\" : [                              (json array)\n"
            "    {                                   (json object)\n"
            "      ...,                              The transactions in the format of the getrawtransaction RPC; different from verbosity = 1 \"tx\" result\n"
            "      \"fee\" : n                         (numeric) The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available\n"
            "    },\n"
            "    ...\n"
            "  ],\n"
            "  ...                                   Same output as verbosity = 1\n"
            "}\n"
            "\nResult (for verbosity >= 3):\n"
            "{\n"
            "  ...,                                  Same output as verbosity = 2\n"
            "  \"tx\" : [                              (json array)\n"
            "    {                                   (json object)\n"
            "      ...,                              Same output as verbosity = 2\n"
            "      \"vin\" : [                         (json array)\n"
            "        {                               (json object)\n"
            "          ...,                          Same output as verbosity = 2\n"
            "          \"scriptSig\" : {               (json object, optional) Only for non-coinbase tx\n"
            "            ...,                        Same output as verbosity = 2 \n"
            "            \"byteCodePattern\" : {       (json object, optional) Only for patterns == true\n"
            "              \"fingerprint\" : \"str\",    (string) Single SHA-256 hash of script pattern\n"
            "              \"pattern\" : \"str\",        (string) Hex-encoded script pattern\n"
            "              \"patternAsm\" : \"str\",     (string) Script pattern asm\n"
            "              \"data\" : [                (json array) Script data pushes\n"
            "                \"hex\", ...              (string) Hex-encoded data push\n"
            "              ],\n"
            "              \"error\": true             (boolean, optional) Only if there was an error parsing the script\n"
            "            },\n"
            "            \"redeemScript\" : {          (json object, optional) Only for patterns == true and only for p2sh inputs\n"
            "              \"asm\" : \"str\",            (string) The p2sh redeem script asm\n"
            "              \"hex\" : \"str\",            (string) The p2sh redeem script hex\n"
            "              \"byteCodePattern\" : {     (json object) Redeem script byte code pattern information\n"
            "                ...,                    Same schema as for scriptSig.byteCodePattern above\n"
            "                \"p2shType\" : \"str\"      (string) Either \"p2sh20\" or \"p2sh32\"\n"
            "              }\n"
            "            },\n"
            "          },\n"
            "          \"prevout\" : {                 (json object, optional) (Only if undo information is available)\n"
            "            \"generated\" : true|false,   (boolean) Coinbase or not\n"
            "            \"height\" : n,               (numeric) The height of the prevout\n"
            "            \"value\" : n,                (numeric) The value in " + CURRENCY_UNIT + "\n"
            "            \"scriptPubKey\" : {          (json object)\n"
            "              \"asm\" : \"str\",            (string) The asm\n"
            "              \"hex\" : \"str\",            (string) The hex\n"
            "              \"type\" : \"str\",           (string) The type (one of: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata)\n"
            "              \"address\" : \"str\"         (string, optional) The Bitcoin Cash address (only if well-defined address exists)\n"
            "              \"byteCodePattern\" : {...} (json object, optional) Only for patterns == true; byte code pattern information\n"
            "            },\n"
            "            \"tokenData\" : {             (json object, optional) CashToken data (only if the input contained a token)\n"
            "              \"category\" : \"hex\",       (string) Token id\n"
            "              \"amount\" : \"xxx\",         (string) Fungible amount (is a string to support >53-bit amounts)\n"
            "              \"nft\" : {                 (json object, optional) NFT data (only if the token has an NFT)\n"
            "                \"capability\" : \"xxx\",   (string) One of \"none\", \"mutable\", \"minting\"\n"
            "                \"commitment\" : \"hex\"    (string) NFT commitment formatted as hexadecimal\n"
            "              },\n"
            "            }\n"
            "          }\n"
            "        },\n"
            "        ...\n"
            "      ],\n"
            "      \"vout\" : [...]                    Same output as verbosity = 2; patterns == true has additional \"byteCodePattern\" information for all \"scriptPubKey\" scripts\n"
            "    },\n"
            "    ...\n"
            "  ],\n"
            "  ...                                   Same output as verbosity = 2\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
            HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 2") +
            HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 2 true") +
            HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));
    }

    BlockHash hash(ParseHashV(request.params[0], "blockhash"));

    const int verbosity = ParseVerbosity(request.params[1], /* default_verbosity = */ 1, /* allow_bool = */ true);

    bool fPatterns = false;
    if (!request.params[2].isNull()) {
        fPatterns = request.params[2].get_bool();
    }

    const CBlockIndex *pblockindex{};
    const CBlockIndex *tip{};
    {
        LOCK(cs_main);
        pblockindex = LookupBlockIndex(hash);
        tip = ::ChainActive().Tip();
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        ThrowIfPrunedBlock(pblockindex);
    }

    if (verbosity <= 0) {
        const auto rawBlock = ReadRawBlockUnchecked(config, pblockindex);
        return HexStr(rawBlock);
    }

    const CBlock block = ReadBlockChecked(config, pblockindex);

    const BlockTxVerbosity blockTxVerbosity = [&verbosity] {
        using enum BlockTxVerbosity;
        switch (verbosity) {
            case 1: return SHOW_TXID;
            case 2: return SHOW_DETAILS;
            /* verbosity >= 3 */
            default: return SHOW_DETAILS_AND_PREVOUT;
        }
    }();

    return blockToJSON(config, block, tip, pblockindex, TransactionFormatOptions(blockTxVerbosity).WithPatterns(fPatterns));
}

static UniValue pruneblockchain(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"pruneblockchain", "",
                {
                    {"height", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The block height to prune up to. May be set to a discrete height, or a unix timestamp\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                }}
                .ToString() +
            "\nResult:\n"
            "n    (numeric) Height of the last block pruned.\n"
            "\nExamples:\n" +
            HelpExampleCli("pruneblockchain", "1000") +
            HelpExampleRpc("pruneblockchain", "1000"));
    }

    if (!fPruneMode) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Cannot prune blocks because node is not in prune mode.");
    }

    LOCK(cs_main);

    int heightParam = request.params[0].get_int();
    if (heightParam < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
    }

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old
        // timestamps
        CBlockIndex *pindex =
            ::ChainActive().FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW);
        if (!pindex) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int)heightParam;
    unsigned int chainHeight = (unsigned int)::ChainActive().Height();
    if (chainHeight < config.GetChainParams().PruneAfterHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Blockchain is too short for pruning.");
    } else if (height > chainHeight) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Blockchain is shorter than the attempted prune height.");
    } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogPrint(BCLog::RPC, "Attempt to prune blocks close to the tip. "
                             "Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(height);
    return height;
}

static std::optional<CoinStats> GetUTXOStats(CCoinsView *view, const CoinStatsHashType ht,
                                             const std::function<void()>& interruption_point,
                                             const CBlockIndex *pindex = nullptr,
                                             const bool index_requested = true) {
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((ht == CoinStatsHashType::ECMH || ht == CoinStatsHashType::NONE || ht == CoinStatsHashType::MUHASH_TESTING)
        && g_coin_stats_index && index_requested) {
        const BlockHash blockHash = pindex ? pindex->GetBlockHash() : view->GetBestBlock();
        return g_coin_stats_index->GetStatsForHash(blockHash, ht);
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return ComputeUTXOStats(view, ht, interruption_point);
}

static CoinStatsHashType ParseHashType(const std::string_view ht) {
    using namespace std::string_view_literals;
    if (ht == "hash_serialized_3"sv) {
        return CoinStatsHashType::HASH_SERIALIZED_3;
    } else if (ht == "ecmh"sv) {
        return CoinStatsHashType::ECMH;
    } else if (ht == "muhash_testing"sv) {
        return CoinStatsHashType::MUHASH_TESTING;
    } else if (ht == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", ht));
    }
}

static UniValue gettxoutsetinfo(const Config &, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 3) {
        throw std::runtime_error(
            RPCHelpMan{"gettxoutsetinfo",
                "\nReturns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, /* opt */ true, /* default val */ "hash_serialized_3",
                     "Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), "
                     "'ecmh', 'muhash_testing', 'none'."},
                     {"hash_or_height", RPCArg::Type::NUM, /* opt */ true, /* default */ "the current best block",
                      "The block hash or height of the target height (only available with coinstatsindex)."},
                     {"use_index", RPCArg::Type::BOOL, /* opt */ true, /* default */ "true",
                      "Use coinstatsindex (ignored when index is disabled)"},
                }}
                .ToString() +
                R"""(
Result:
{                                     (json object)
  "height" : n,                       (numeric) The block height (index) of the returned statistics
  "bestblock" : "hex",                (string) The hash of the block at which these statistics are calculated
  "txouts" : n,                       (numeric) The number of unspent transaction outputs
  "bogosize" : n,                     (numeric) Database-independent, meaningless metric indicating the UTXO set size
  "hash_serialized_3" : "hex",        (string, optional) The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)
  "ecmh" : "hex",                     (string, optional) The serialized hash (only present if 'ecmh' hash_type is chosen)
  "ecmh_pubkey" : "hex",              (string, optional) The EC MultiSet internal state (only present if 'ecmh' hash_type is chosen)
  "muhash_testing" : "hex",           (string, optional) The serialized hash (only present if 'muhash_testing' hash_type is chosen)
  "transactions" : n,                 (numeric, optional) The number of transactions with unspent outputs (not available when coinstatsindex is used)
  "disk_size" : n,                    (numeric, optional) The estimated size of the chainstate on disk (not available when coinstatsindex is used)
  "total_amount" : n,                 (numeric) The total amount of coins in the UTXO set
  "total_unspendable_amount" : n,     (numeric, optional) The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)
  "block_info" : {                    (json object, optional) Info on amounts in the block at this block height (only available if coinstatsindex is used)
    "prevout_spent" : n,              (numeric) Total amount of all prevouts spent in this block
    "coinbase" : n,                   (numeric) Coinbase subsidy amount of this block
    "new_outputs_ex_coinbase" : n,    (numeric) Total amount of new outputs created by this block
    "unspendable" : n,                (numeric) Total amount of unspendable outputs created in this block
    "unspendables" : {                (json object) Detailed view of the unspendable categories
      "genesis_block" : n,            (numeric) The unspendable amount of the Genesis block subsidy
      "bip30" : n,                    (numeric) Transactions overridden by duplicates (no longer possible with BIP30)
      "scripts" : n,                  (numeric) Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)
      "unclaimed_rewards" : n         (numeric) Fee rewards that miners did not claim in their coinbase transaction
    }
  }
})""" +
            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") +
            HelpExampleCli("gettxoutsetinfo", R"("none")") +
            HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
            HelpExampleCli("gettxoutsetinfo", R"("ecmh" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
            HelpExampleRpc("gettxoutsetinfo", "") +
            HelpExampleRpc("gettxoutsetinfo", R"("none")") +
            HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
            HelpExampleRpc("gettxoutsetinfo", R"("ecmh", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
        );
    }

    const CoinStatsHashType hash_type = request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED_3
                                                                   : ParseHashType(request.params[0].get_str());
    const bool index_requested = request.params[2].isNull() || request.params[2].get_bool();
    const CBlockIndex *pindex = nullptr;

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (hash_type == CoinStatsHashType::HASH_SERIALIZED_3) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_3 hash type cannot be queried for a specific block");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], false);
    } else {
        WITH_LOCK(cs_main, pindex =::ChainActive().Tip());
    }

    assert(pindex);

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

           // If a specific block was requested and the index has already synced past that height, we can return the
           // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    FlushStateToDisk();
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const auto optStats = GetUTXOStats(pcoinsdbview.get(), hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (!optStats) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    const auto &stats = optStats.value();
    UniValue::Object ret;
    ret.reserve(8);
    ret.emplace_back("height", stats.nHeight);
    ret.emplace_back("bestblock", stats.hashBlock.GetHex());
    ret.emplace_back("txouts", stats.nTransactionOutputs);
    ret.emplace_back("bogosize", stats.nBogoSize);
    if (hash_type == CoinStatsHashType::HASH_SERIALIZED_3) {
        ret.emplace_back("hash_serialized_3", stats.hashSerialized.GetHex());
    } else if (hash_type == CoinStatsHashType::MUHASH_TESTING) {
        ret.emplace_back("muhash_testing", stats.hashSerialized.GetHex());
    } else if (hash_type == CoinStatsHashType::ECMH) {
        ret.emplace_back("ecmh", stats.hashSerialized.GetHex());
        if (const auto *ecms = std::get_if<ECMultiSet>(&stats.multiSet)) {
            const auto pkb = ecms->GetPubKeyBytes();
            ret.emplace_back("ecmh_pubkey", HexStr(pkb));
        }
    }
    ret.emplace_back("total_amount", ValueFromAmount(stats.nTotalAmount.value()));
    if (!stats.indexUsed) {
        // no index used
        ret.emplace_back("transactions", stats.nTransactions);
        ret.emplace_back("disk_size", stats.nDiskSize);
    } else {
        // index used
        ret.emplace_back("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

        CoinStats prev_stats;
        if (pindex->nHeight > 0) {
            const auto optprev = GetUTXOStats(pcoinsdbview.get(), hash_type, node.rpc_interruption_point, pindex->pprev,
                                              index_requested);
            if (!optprev) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
            }
            prev_stats = optprev.value();
        }

        UniValue::Object block_info;
        block_info.emplace_back("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount
                                                                 - prev_stats.total_prevout_spent_amount));
        block_info.emplace_back("coinbase", ValueFromAmount(stats.total_coinbase_amount
                                                            - prev_stats.total_coinbase_amount));
        block_info.emplace_back("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount
                                                                           - prev_stats.total_new_outputs_ex_coinbase_amount));
        block_info.emplace_back("unspendable", ValueFromAmount(stats.total_unspendable_amount
                                                               - prev_stats.total_unspendable_amount));

        UniValue::Object unspendables;
        unspendables.emplace_back("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block
                                                                   - prev_stats.total_unspendables_genesis_block));
        unspendables.emplace_back("bip30", ValueFromAmount(stats.total_unspendables_bip30
                                                           - prev_stats.total_unspendables_bip30));
        unspendables.emplace_back("scripts", ValueFromAmount(stats.total_unspendables_scripts
                                                             - prev_stats.total_unspendables_scripts));
        unspendables.emplace_back("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards
                                                                       - prev_stats.total_unspendables_unclaimed_rewards));
        block_info.emplace_back("unspendables", std::move(unspendables));

        ret.emplace_back("block_info", std::move(block_info));
    }
    return ret;
}

UniValue gettxout(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"gettxout",
                "\nReturns details about an unspent transaction output.\n",
                {
                    {"txid", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The transaction id"},
                    {"n", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "vout number"},
                    {"include_mempool", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
                    {"patterns", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "If true then the byteCodePattern object will be added"},
                }}.ToString() +
            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",       (string) the block hash\n"
            "  \"confirmations\" : n,        (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,            (numeric) The transaction value in " + CURRENCY_UNIT + "\n"
            "  \"scriptPubKey\" : {          (json object)\n"
            "     \"asm\" : \"code\",          (string)\n"
            "     \"hex\" : \"hex\",           (string)\n"
            "     \"reqSigs\" : n,           (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\",   (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of Bitcoin Cash addresses\n"
            "        \"address\"             (string) Bitcoin Cash address\n"
            "        ,...\n"
            "     ],\n"
            "     \"byteCodePattern\" : {    (json object, optional) Only for patterns == true\n"
            "       \"fingerprint\" : \"str\", (string) Single SHA-256 hash of script pattern\n"
            "       \"pattern\" : \"str\",     (string) Hex-encoded script pattern\n"
            "       \"patternAsm\" : \"str\",  (string) Script pattern asm\n"
            "       \"data\" : [             (json array) Script data pushes\n"
            "         \"hex\", ...           (string) Hex-encoded data push\n"
            "       ],\n"
            "       \"error\": true          (boolean, optional) Only if there was an error parsing the script (e.g. ending with an incomplete push)\n"
            "     }\n"
            "  },\n"
            "  \"tokenData\" : {             (json object optional)\n"
            "    \"category\" : \"hex\",       (string) token id\n"
            "    \"amount\" : \"xxx\",         (string) fungible amount (is a string to support >53-bit amounts)\n"
            "    \"nft\" : {                 (json object optional)\n"
            "      \"capability\" : \"xxx\",   (string) one of \"none\", \"mutable\", \"minting\"\n"
            "      \"commitment\" : \"hex\"    (string) NFT commitment\n"
            "    }\n"
            "  },\n"
            "  \"coinbase\" : true|false     (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n" +
            HelpExampleCli("listunspent", "") + "\nView the details\n" +
            HelpExampleCli("gettxout", "\"txid\" 1") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("gettxout", "\"txid\", 1"));
    }

    LOCK(cs_main);

    TxId txid(ParseHashV(request.params[0], "txid"));
    int n = request.params[1].get_int();
    COutPoint out(txid, n);
    bool fMempool = true;
    if (!request.params[2].isNull()) {
        fMempool = request.params[2].get_bool();
    }
    const bool fPatterns = !request.params[3].isNull() && request.params[3].get_bool();

    Coin coin;
    if (fMempool) {
        LOCK(g_mempool.cs);
        CCoinsViewMemPool view(pcoinsTip.get(), g_mempool);
        if (!view.GetCoin(out, coin) || g_mempool.isSpent(out)) {
            return UniValue();
        }
    } else {
        if (!pcoinsTip->GetCoin(out, coin)) {
            return UniValue();
        }
    }

    const CBlockIndex *pindex = LookupBlockIndex(pcoinsTip->GetBestBlock());
    const CTxOut &txout = coin.GetTxOut();
    UniValue::Object ret;
    ret.reserve(5u + bool(txout.tokenDataPtr));
    ret.emplace_back("bestblock", pindex->GetBlockHash().GetHex());
    ret.emplace_back("confirmations", coin.GetHeight() == MEMPOOL_HEIGHT ? 0 : pindex->nHeight - coin.GetHeight() + 1);
    ret.emplace_back("value", ValueFromAmount(txout.nValue));
    ret.emplace_back("scriptPubKey", ScriptPubKeyToUniv(config, txout.scriptPubKey, true, false, fPatterns));
    if (txout.tokenDataPtr) {
        ret.emplace_back("tokenData", TokenDataToUniv(*txout.tokenDataPtr));
    }
    ret.emplace_back("coinbase", coin.IsCoinBase());

    return ret;
}

static UniValue verifychain(const Config &config,
                            const JSONRPCRequest &request) {
    int nCheckLevel = gArgs.GetArg("-checklevel", DEFAULT_CHECKLEVEL);
    int nCheckDepth = gArgs.GetArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"verifychain",
                "\nVerifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, /* opt */ true, /* default_val */ strprintf("%d, range=0-4", nCheckLevel), "How thorough the block verification is."},
                    {"nblocks", RPCArg::Type::NUM, /* opt */ true, /* default_val */ strprintf("%d, 0=all", nCheckDepth), "The number of blocks to check."},
                }}
                .ToString() +
            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"
            "\nExamples:\n" +
            HelpExampleCli("verifychain", "") +
            HelpExampleRpc("verifychain", ""));
    }

    LOCK(cs_main);

    if (!request.params[0].isNull()) {
        nCheckLevel = request.params[0].get_int();
    }
    if (!request.params[1].isNull()) {
        nCheckDepth = request.params[1].get_int();
    }

    return CVerifyDB().VerifyDB(config, pcoinsTip.get(), nCheckLevel,
                                nCheckDepth);
}

UniValue getblockchaininfo(const Config &config,
                           const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getblockchaininfo",
                "Returns an object containing various state info regarding blockchain processing.\n", {}}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",              (string) current network name "
            "as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,             (numeric) the current number of "
            "blocks processed in the server\n"
            "  \"headers\": xxxxxx,            (numeric) the current number of "
            "headers we have validated\n"
            "  \"bestblockhash\": \"...\",       (string) the hash of the "
            "currently best block\n"
            "  \"difficulty\": xxxxxx,         (numeric) the current "
            "difficulty\n"
            "  \"mediantime\": xxxxxx,         (numeric) median time for the "
            "current best block\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of "
            "verification progress [0..1]\n"
            "  \"initialblockdownload\": xxxx, (bool) (debug information) "
            "estimate of whether this node is in Initial Block Download mode.\n"
            "  \"chainwork\": \"xxxx\"           (string) total amount of work "
            "in active chain, in hexadecimal\n"
            "  \"size_on_disk\": xxxxxx,       (numeric) the estimated size of "
            "the block and undo files on disk\n"
            "  \"pruned\": xx,                 (boolean) if the blocks are "
            "subject to pruning\n"
            "  \"pruneheight\": xxxxxx,        (numeric) lowest-height "
            "complete block stored (only present if pruning is enabled)\n"
            "  \"automatic_pruning\": xx,      (boolean) whether automatic "
            "pruning is enabled (only present if pruning is enabled)\n"
            "  \"prune_target_size\": xxxxxx,  (numeric) the target size "
            "used by pruning (only present if automatic pruning is enabled)\n"
            "  \"upgrade_status\": {           (json object) details about the next scheduled upgrade\n"
            "      \"name\": \"...\",                            (string) human-readable upgrade name\n"
            "      \"mempool_activated\": true|false,          (boolean) whether the upgrade has activated for the mempool\n"
            "      \"mempool_activation_mtp\": n,              (numeric) mediantime for mempool upgrade activation\n"
            "      \"block_preactivation_height\": n|null,     (numeric or null) block height immediately before activation\n"
            "      \"block_preactivation_hash\": \"...\"|null,   (string or null) hash of the preactivation block\n"
            "      \"block_postactivation_height\": n|null,    (numeric or null) first height enforcing the upgrade\n"
            "      \"block_postactivation_hash\": \"...\"|null,  (string or null) hash of the postactivation block\n"
            "      \"software_expiration_time\": n|null        (numeric or null) UTC time for when this software build expires (null = expiration is disabled)\n"
            "    },\n"
            "  \"warnings\" : \"...\",           (string) any network and "
            "blockchain warnings.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") +
            HelpExampleRpc("getblockchaininfo", ""));
    }

    LOCK(cs_main);

    const CBlockIndex *tip = ::ChainActive().Tip();
    bool automatic_pruning = fPruneMode && gArgs.GetArg("-prune", 0) != 1;
    UniValue::Object obj;
    obj.reserve(fPruneMode ? automatic_pruning ? 16 : 15 : 13);

    obj.emplace_back("chain", config.GetChainParams().NetworkIDString());
    obj.emplace_back("blocks", ::ChainActive().Height());
    obj.emplace_back("headers", pindexBestHeader ? pindexBestHeader->nHeight : -1);
    obj.emplace_back("bestblockhash", tip->GetBlockHash().GetHex());
    obj.emplace_back("difficulty", GetDifficulty(tip));
    obj.emplace_back("mediantime", tip->GetMedianTimePast());
    obj.emplace_back("verificationprogress", GuessVerificationProgress(Params().TxData(), tip));
    obj.emplace_back("initialblockdownload", IsInitialBlockDownload());
    obj.emplace_back("chainwork", tip->nChainWork.GetHex());
    obj.emplace_back("size_on_disk", CalculateCurrentUsage());
    obj.emplace_back("pruned", fPruneMode);

    if (fPruneMode) {
        const CBlockIndex *block = tip;
        assert(block);
        while (block->pprev && block->pprev->nStatus.hasData()) {
            block = block->pprev;
        }

        obj.emplace_back("pruneheight", block->nHeight);

        obj.emplace_back("automatic_pruning", automatic_pruning);
        if (automatic_pruning) {
            obj.emplace_back("prune_target_size", nPruneTarget);
        }
    }

    // "upgrade_status" sub-dictionary
    {
        const auto &consensus = config.GetChainParams().GetConsensus();
        struct UpgradeInfo {
            const std::string name;
            ActivationBlockTracker &tracker;
            const char *cliArg{};
            const int64_t &cliArgDefault;
        } const info = {
            /* Note: Update the below variables whenever we bump the "next" upgrade to be Upgrade2028, etc */
            .name = strprintf("May 2027 Upgrade (%snet)", config.GetChainParams().NetworkIDString()),
            .tracker = g_upgrade2027_block_tracker,
            .cliArg = "-upgrade2027activationtime",
            .cliArgDefault = consensus.upgrade2027ActivationTime
        };
        const auto &isUpgradeActivatedFunc = info.tracker.GetPredicate();
        CHECK_NONFATAL(isUpgradeActivatedFunc != nullptr);

        const int64_t activation_mtp = gArgs.GetArg(info.cliArg, info.cliArgDefault);
        const int64_t expiry_time = software_outdated::nTime;
        const bool expiry_enabled = expiry_time > 0;
        const bool mempool_activated = isUpgradeActivatedFunc(consensus, tip);

        UniValue::Object up;
        up.reserve(8);
        up.emplace_back("name", info.name);
        up.emplace_back("mempool_activated", mempool_activated);
        up.emplace_back("mempool_activation_mtp", activation_mtp);

        if (const CBlockIndex *activation_block{};
                mempool_activated && tip && (activation_block = info.tracker.GetActivationBlock(tip, consensus))) {
            up.emplace_back("block_preactivation_height", static_cast<int64_t>(activation_block->nHeight));
            up.emplace_back("block_preactivation_hash", activation_block->GetBlockHash().GetHex());

            const int post_height = activation_block->nHeight + 1;
            const CBlockIndex *post_block = ::ChainActive()[post_height];
            if (post_block) {
                up.emplace_back("block_postactivation_height", static_cast<int64_t>(post_block->nHeight));
                up.emplace_back("block_postactivation_hash", post_block->GetBlockHash().GetHex());
            } else {
                up.emplace_back("block_postactivation_height", UniValue::VNULL);
                up.emplace_back("block_postactivation_hash", UniValue::VNULL);
            }
        } else {
            up.emplace_back("block_preactivation_height", UniValue::VNULL);
            up.emplace_back("block_preactivation_hash", UniValue::VNULL);
            up.emplace_back("block_postactivation_height", UniValue::VNULL);
            up.emplace_back("block_postactivation_hash", UniValue::VNULL);
        }

        up.emplace_back("software_expiration_time", expiry_enabled ? UniValue(expiry_time) : UniValue{});

        obj.emplace_back("upgrade_status", std::move(up));
    }

    obj.emplace_back("warnings", GetWarnings("statusbar"));

    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex *a, const CBlockIndex *b) const {
        // Make sure that unequal blocks with the same height do not compare
        // equal. Use the pointers themselves to make a distinction.
        if (a->nHeight != b->nHeight) {
            return (a->nHeight > b->nHeight);
        }

        return a < b;
    }
};

static UniValue getchaintips(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {}}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main "
            "chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch "
            "connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain "
            "(active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one "
            "invalid block\n"
            "2.  \"parked\"                This branch contains at least one "
            "parked block\n"
            "3.  \"headers-only\"          Not all blocks for this branch are "
            "available, but the headers are valid\n"
            "4.  \"valid-headers\"         All blocks are available for this "
            "branch, but they were never fully validated\n"
            "5.  \"valid-fork\"            This branch is not part of the "
            "active chain, but is fully validated\n"
            "6.  \"active\"                This is the tip of the active main "
            "chain, which is certainly valid\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") +
            HelpExampleRpc("getchaintips", ""));
    }

    LOCK(cs_main);

    /**
     * Idea:  the set of chain tips is ::ChainActive().tip, plus orphan blocks
     * which do not have another orphan building off of them. Algorithm:
     *  - Make one pass through mapBlockIndex, picking out the orphan blocks,
     * and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by
     * another orphan, it is a chain tip.
     *  - add ::ChainActive().Tip()
     */
    std::set<const CBlockIndex *, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex *> setOrphans;
    std::set<const CBlockIndex *> setPrevs;

    for (const auto & [_, index] : mapBlockIndex) {
        if (!::ChainActive().Contains(&index)) {
            setOrphans.insert(&index);
            setPrevs.insert(index.pprev);
        }
    }

    for (std::set<const CBlockIndex *>::iterator it = setOrphans.begin();
         it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(::ChainActive().Tip());

    /* Construct the output array.  */
    UniValue::Array res;
    res.reserve(setTips.size());
    for (const CBlockIndex *block : setTips) {
        UniValue::Object obj;
        obj.reserve(4);
        obj.emplace_back("height", block->nHeight);
        obj.emplace_back("hash", block->phashBlock->GetHex());
        obj.emplace_back("branchlen", block->nHeight - ::ChainActive().FindFork(block)->nHeight);

        const char *status;
        if (::ChainActive().Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus.isInvalid()) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (block->nStatus.isOnParkedChain()) {
            // This block or one of its ancestors is parked.
            status = "parked";
        } else if (!block->HaveTxsDownloaded()) {
            // This block cannot be connected because full block data for it or
            // one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BlockValidity::SCRIPTS)) {
            // This block is fully validated, but no longer part of the active
            // chain. It was probably the active block once, but was
            // reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BlockValidity::TREE)) {
            // The headers for this block are valid, but it has not been
            // validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.emplace_back("status", status);

        res.emplace_back(std::move(obj));
    }

    return res;
}

UniValue::Object MempoolInfoToJSON(const Config &config, const CTxMemPool &pool) {
    UniValue::Object ret;
    ret.reserve(10);
    ret.emplace_back("loaded", pool.IsLoaded());
    ret.emplace_back("size", pool.size());
    ret.emplace_back("bytes", pool.GetTotalTxSize());
    ret.emplace_back("usage", pool.DynamicMemoryUsage());
    auto maxmempool = config.GetMaxMemPoolSize();
    ret.emplace_back("maxmempool", maxmempool);
    ret.emplace_back("mempoolminfee", ValueFromAmount(std::max(pool.GetMinFee(maxmempool), ::minRelayTxFee).GetFeePerK()));
    ret.emplace_back("minrelaytxfee", ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    ret.emplace_back("permitbaremultisig", ::fIsBareMultisigStd);
    ret.emplace_back("maxdatacarriersize", ::nMaxDatacarrierBytes);
    ret.emplace_back("total_fee", ValueFromAmount(pool.GetTotalFee()));
    return ret;
}

static UniValue getmempoolinfo(const Config &config,
                               const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getmempoolinfo",
                "\nReturns details on the active state of the TX memory pool.\n", {}}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"loaded\": true|false         (boolean) True if the mempool is "
            "fully loaded\n"
            "  \"size\": xxxxx,               (numeric) Current tx count\n"
            "  \"bytes\": xxxxx,              (numeric) Transaction size.\n"
            "  \"usage\": xxxxx,              (numeric) Total memory usage for "
            "the mempool\n"
            "  \"maxmempool\": xxxxx,         (numeric) Maximum memory usage "
            "for the mempool\n"
            "  \"mempoolminfee\": xxxxx       (numeric) Minimum fee rate in " +
            CURRENCY_UNIT +
            "/kB for tx to be accepted. Is the maximum of minrelaytxfee and "
            "minimum mempool fee\n"
            "  \"minrelaytxfee\": xxxxx       (numeric) Current minimum relay "
            "fee for transactions\n"
            "  \"permitbaremultisig\": true|false (boolean) True if the mempool accepts transactions with bare multisig outputs\n"
            "  \"maxdatacarriersize\": xxxxx, (numeric) Maximum total byte size of OP_RETURN scripts for any single mempool tx\n"
            "  \"total_fee\": xxxxx,          (numeric) Total fees for the mempool in " + CURRENCY_UNIT + ", ignoring modified fees through prioritisetransaction\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") +
            HelpExampleRpc("getmempoolinfo", ""));
    }

    return MempoolInfoToJSON(config, ::g_mempool);
}

static UniValue preciousblock(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"preciousblock",
                "\nTreats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "the hash of the block to mark as precious"},
                }}
                .ToString() +
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("preciousblock", "\"blockhash\"") +
            HelpExampleRpc("preciousblock", "\"blockhash\""));
    }

    BlockHash hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex *pblockindex;

    {
        LOCK(cs_main);
        pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    CValidationState state;
    PreciousBlock(config, state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return UniValue();
}

UniValue finalizeblock(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "finalizeblock \"blockhash\"\n"

            "\nTreats a block as final. It cannot be reorged. Any chain\n"
            "that does not contain this block is invalid. Used on a less\n"
            "work chain, it can effectively PUTS YOU OUT OF CONSENSUS.\n"
            "USE WITH CAUTION!\n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("finalizeblock", "\"blockhash\"") +
            HelpExampleRpc("finalizeblock", "\"blockhash\""));
    }

    const BlockHash hash(ParseHashV(request.params[0], "blockhash"));
    CValidationState state;

    {
        LOCK(cs_main);
        CBlockIndex *pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        FinalizeBlockAndInvalidate(config, state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(config, state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, FormatStateMessage(state));
    }

    return UniValue();
}

static UniValue invalidateblock(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"invalidateblock",
                "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "the hash of the block to mark as invalid"},
                }}
                .ToString() +
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") +
            HelpExampleRpc("invalidateblock", "\"blockhash\""));
    }

    const BlockHash hash(ParseHashV(request.params[0], "blockhash"));
    CValidationState state;

    CBlockIndex *pblockindex;
    {
        LOCK(cs_main);
        pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    InvalidateBlock(config, state, pblockindex);

    if (state.IsValid()) {
        ActivateBestChain(config, state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, FormatStateMessage(state));
    }

    return UniValue();
}

UniValue parkblock(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error("parkblock \"blockhash\"\n"
                                 "\nMarks a block as parked.\n"
                                 "\nArguments:\n"
                                 "1. \"blockhash\"   (string, required) the "
                                 "hash of the block to park\n"
                                 "\nResult:\n"
                                 "\nExamples:\n" +
                                 HelpExampleCli("parkblock", "\"blockhash\"") +
                                 HelpExampleRpc("parkblock", "\"blockhash\""));
    }

    const BlockHash hash(ParseHashV(request.params[0], "blockhash"));
    CValidationState state;

    CBlockIndex *pblockindex;
    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        pblockindex = &it->second;
    }
    ParkBlock(config, state, pblockindex);

    if (state.IsValid()) {
        ActivateBestChain(config, state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return UniValue();
}

static UniValue reconsiderblock(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"reconsiderblock",
                "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "the hash of the block to reconsider"},
                }}
                .ToString() +
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") +
            HelpExampleRpc("reconsiderblock", "\"blockhash\""));
    }

    const BlockHash hash(ParseHashV(request.params[0], "blockhash"));

    {
        LOCK(cs_main);
        CBlockIndex *pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        ResetBlockFailureFlags(pblockindex);
    }

    CValidationState state;
    ActivateBestChain(config, state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, FormatStateMessage(state));
    }

    return UniValue();
}

UniValue unparkblock(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "unparkblock \"blockhash\"\n"
            "\nRemoves parked status of a block and its descendants, "
            "reconsider them for activation.\n"
            "This can be used to undo the effects of parkblock.\n"
            "\nArguments:\n"
            "1. \"blockhash\"   (string, required) the hash of the block to "
            "unpark\n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("unparkblock", "\"blockhash\"") +
            HelpExampleRpc("unparkblock", "\"blockhash\""));
    }

    const BlockHash hash(ParseHashV(request.params[0], "blockhash"));

    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        CBlockIndex *pblockindex = &it->second;
        UnparkBlockAndChildren(pblockindex);
    }

    CValidationState state;
    ActivateBestChain(config, state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return UniValue();
}

static UniValue getchaintxstats(const Config &config,
                                const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getchaintxstats",
                "\nCompute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "one month", "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, /* opt */ true, /* default_val */ "", "The hash of the block that ends the window."},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"time\": xxxxx,                         (numeric) The timestamp for the final block in the window in UNIX format.\n"
            "  \"txcount\": xxxxx,                      (numeric) The total number of transactions in the chain up to that point.\n"
            "  \"window_final_block_hash\": \"...\",      (string) The hash of the final block in the window.\n"
            "  \"window_final_block_height\": xxxxx,    (numeric) The height of the final block in the window.\n"
            "  \"window_block_count\": xxxxx,           (numeric) Size of the window in number of blocks.\n"
            "  \"window_tx_count\": xxxxx,              (numeric) The number of transactions in the window. Only returned if \"window_block_count\" is > 0.\n"
            "  \"window_interval\": xxxxx,              (numeric) The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0.\n"
            "  \"txrate\": x.xx,                        (numeric) The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getchaintxstats", "") +
            HelpExampleRpc("getchaintxstats", "2016"));
    }

    const CBlockIndex *pindex;

    // By default: 1 month
    int blockcount = 30 * 24 * 60 * 60 /
                     config.GetChainParams().GetConsensus().nPowTargetSpacing;

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = ::ChainActive().Tip();
    } else {
        BlockHash hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!::ChainActive().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Block is not in main chain");
        }
    }

    assert(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].get_int();

        if (blockcount < 0 ||
            (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: "
                                                      "should be between 0 and "
                                                      "the block's height - 1");
        }
    }

    const CBlockIndex *pindexPast =
        pindex->GetAncestor(pindex->nHeight - blockcount);
    int nTimeDiff =
        pindex->GetMedianTimePast() - pindexPast->GetMedianTimePast();
    const int64_t nTxDiff = static_cast<int64_t>(pindex->GetChainTxCount())
                            - static_cast<int64_t>(pindexPast->GetChainTxCount());

    UniValue::Object ret;
    ret.reserve(blockcount > 0 ? nTimeDiff > 0 ? 8 : 7 : 5);
    ret.emplace_back("time", pindex->GetBlockTime());
    ret.emplace_back("txcount", pindex->GetChainTxCount());
    ret.emplace_back("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.emplace_back("window_final_block_height", pindex->nHeight);
    ret.emplace_back("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.emplace_back("window_tx_count", nTxDiff);
        ret.emplace_back("window_interval", nTimeDiff);
        if (nTimeDiff > 0) {
            ret.emplace_back("txrate", double(nTxDiff) / nTimeDiff);
        }
    }
    return ret;
}

template <typename T>
static T CalculateTruncatedMedian(std::vector<T> &scores) {
    size_t size = scores.size();
    if (size == 0) {
        return T();
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesBySize(Amount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<Amount, int64_t>>& scores, int64_t total_size)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_size / 10.0, total_size / 4.0, total_size / 2.0, (total_size * 3.0) / 4.0, (total_size * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template <typename T> static inline bool SetHasKeys(const std::set<T> &set) {
    return false;
}
template <typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T> &set, const Tk &key,
                              const Args &... args) {
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD =
    sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

/// Lock-free -- will throw if undo rev??.dat file not found or was pruned, etc.
/// Guaranteed to return a valid undo or fail.
static CBlockUndo ReadUndoChecked(const CBlockIndex *pblockindex) {
    CBlockUndo undo;
    auto doRead = [&] {
        // Note: we special-case block 0 to preserve RPC compatibility with previous
        // incarnations of `getblockstats` that did not use the undo mechanism to grab
        // stats. Those earlier versions would return stats for block 0. So, we return
        // empty undo for genesis (genesis has no actual undo file on disk but an empty
        // CBlockUndo is a perfect simulacrum of its undo file if it were to have one)
        if (pblockindex->nHeight != 0 && !UndoReadFromDisk(undo, pblockindex)) {
            // Undo not found on disk. This could be because we have the block
            // header in our index but don't have the block (for example if a
            // non-whitelisted node sends us an unrequested long chain of valid
            // blocks, we add the headers to our index, but don't accept the block).
            // This can also happen if in the extremely rare event that the undo file
            // was pruned from underneath us as we were executing getblockstats().
            throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
        }
    };
    if (fPruneMode) {
        // Note: in pruned mode we must take cs_main here because it's possible for FlushStateToDisk()
        // in validation.cpp to also attempt to remove this file while we have it open.  This is not
        // normally a problem except for on Windows, where FlushStateToDisk() would fail to remove the
        // undo file we have open here, in which case on Windows the node would AbortNode().  Hence
        // the need for this locking in the fPrunedMode case only.
        LOCK(cs_main);
        doRead();
    } else {
        // Non-pruned mode, we can benefit from not having to grab cs_main here since undos never
        // go away -- this increases parallelism in the case of non-pruning nodes.
        doRead();
    }

    return undo;
}

static UniValue getblockstats(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"getblockstats",
                "\nCompute per block statistics for a given window. All amounts are in "
                + CURRENCY_UNIT + ".\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The block hash or height of the target block", "", {"", "string or numeric"}},
                    {"stats", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "Values to plot, by default all values (see result below)",
                        {
                            {"height", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Selected statistic"},
                            {"time", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Selected statistic"},
                        },
                        "stats"},
                }}
                .ToString() +
            "\nResult:\n"
            "{                           (json object)\n"
            "  \"avgfee\": x.xxx,          (numeric) Average fee in the block\n"
            "  \"avgfeerate\": x.xxx,      (numeric) Average feerate (in " +
            CURRENCY_UNIT +
            " per byte)\n"
            "  \"avgtxsize\": xxxxx,       (numeric) Average transaction size\n"
            "  \"blockhash\": xxxxx,       (string) The block hash (to check for potential reorgs)\n"
            "  \"feerate_percentiles\": [  (array of numeric) Feerates at the 10th, 25th, 50th, 75th, and 90th "
            "percentile weight unit (in " + CURRENCY_UNIT + " per byte)\n"
            "      \"10th_percentile_feerate\",      (numeric) The 10th percentile feerate\n"
            "      \"25th_percentile_feerate\",      (numeric) The 25th percentile feerate\n"
            "      \"50th_percentile_feerate\",      (numeric) The 50th percentile feerate\n"
            "      \"75th_percentile_feerate\",      (numeric) The 75th percentile feerate\n"
            "      \"90th_percentile_feerate\",      (numeric) The 90th percentile feerate\n"
            "  ],\n"
            "  \"height\": xxxxx,          (numeric) The height of the block\n"
            "  \"ins\": xxxxx,             (numeric) The number of inputs "
            "(excluding coinbase)\n"
            "  \"maxfee\": xxxxx,          (numeric) Maximum fee in the block\n"
            "  \"maxfeerate\": xxxxx,      (numeric) Maximum feerate (in " +
            CURRENCY_UNIT +
            " per byte)\n"
            "  \"maxtxsize\": xxxxx,       (numeric) Maximum transaction size\n"
            "  \"medianfee\": x.xxx,       (numeric) Truncated median fee in "
            "the block\n"
            "  \"mediantime\": xxxxx,      (numeric) The block median time "
            "past\n"
            "  \"mediantxsize\": xxxxx,    (numeric) Truncated median "
            "transaction size\n"
            "  \"minfee\": x.xxx,          (numeric) Minimum fee in the block\n"
            "  \"minfeerate\": xx.xx,      (numeric) Minimum feerate (in " +
            CURRENCY_UNIT +
            " per byte)\n"
            "  \"mintxsize\": xxxxx,       (numeric) Minimum transaction size\n"
            "  \"outs\": xxxxx,            (numeric) The number of outputs\n"
            "  \"subsidy\": x.xxx,         (numeric) The block subsidy\n"
            "  \"time\": xxxxx,            (numeric) The block time\n"
            "  \"total_out\": x.xxx,       (numeric) Total amount in all "
            "outputs (excluding coinbase and thus reward [ie subsidy + "
            "totalfee])\n"
            "  \"total_size\": xxxxx,      (numeric) Total size of all "
            "non-coinbase transactions\n"
            "  \"totalfee\": x.xxx,        (numeric) The fee total\n"
            "  \"txs\": xxxxx,             (numeric) The number of "
            "transactions (excluding coinbase)\n"
            "  \"utxo_increase\": xxxxx,   (numeric) The increase/decrease in "
            "the number of unspent outputs\n"
            "  \"utxo_size_inc\": xxxxx,   (numeric) The increase/decrease in "
            "size for the utxo index (not discounting op_return and similar)\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getblockstats",
                           "1000 '[\"minfeerate\",\"avgfeerate\"]'") +
            HelpExampleRpc("getblockstats",
                           "1000 '[\"minfeerate\",\"avgfeerate\"]'"));
    }

    const CBlockIndex *pindex = ParseHashOrHeight(request.params[0], true, nullptr, true);

    assert(pindex != nullptr);

    // Note: all of the below code has been verified to not require cs_main

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        for (const UniValue& stat : request.params[1].get_array()) {
            stats.insert(stat.get_str());
        }
    }

    const CBlock block = ReadBlockChecked(config, pindex);

    // Calculate everything if nothing selected (default)
    const bool do_all = stats.size() == 0;
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs =
        do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_size_inc", "totalfee", "avgfee", "avgfeerate",
                   "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size =
        do_mediantxsize || loop_inputs ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize");

    const int64_t thisBlockMaxBlockSize = GetNextBlockSizeLimit(config, pindex->pprev);
    Amount maxfee = Amount::zero();
    Amount maxfeerate = Amount::zero();
    Amount minfee = MAX_MONEY;
    Amount minfeerate = MAX_MONEY;
    Amount total_out = Amount::zero();
    Amount totalfee = Amount::zero();
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = thisBlockMaxBlockSize;
    int64_t outputs = 0;
    int64_t total_size = 0;
    int64_t utxo_size_inc = 0;
    std::vector<Amount> fee_array;
    std::vector<std::pair<Amount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    // read the undo file so we can calculate fees -- but only if loop_inputs is true
    // (since if it's false we won't need this data and we shouldn't spend time deserializing it)
    const CBlockUndo &&blockUndo = loop_inputs ? ReadUndoChecked(pindex) : CBlockUndo{};

    // Reserve for the above vectors only if we use them
    if (do_mediantxsize) txsize_array.reserve(block.vtx.size());
    if (do_medianfee) fee_array.reserve(block.vtx.size());
    if (do_feerate_percentiles) feerate_array.reserve(block.vtx.size());

    for (size_t i_tx = 0; i_tx < block.vtx.size(); ++i_tx) {
        const auto &tx = block.vtx[i_tx];
        outputs += tx->vout.size();
        Amount tx_total_out = Amount::zero();
        if (loop_outputs) {
            for (const CTxOut &out : tx->vout) {
                tx_total_out += out.nValue;
                utxo_size_inc +=
                    GetSerializeSize(out, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        // Don't count coinbase's fake input
        inputs += tx->vin.size();
        // Don't count coinbase reward
        total_out += tx_total_out;

        int64_t tx_size = 0;
        if (do_calculate_size) {
            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        if (loop_inputs) {
            Amount tx_total_in = Amount::zero();
            const auto &txundo = blockUndo.vtxundo.at(i_tx - 1); // checked access here, guard against programming errors
            // We use the block undo info to find the inputs to this tx and use that information to calculate fees
            for (const Coin &coin : txundo.vprevout) {
                const CTxOut &prevoutput = coin.GetTxOut();

                tx_total_in += prevoutput.nValue;
                utxo_size_inc -=
                    GetSerializeSize(prevoutput, PROTOCOL_VERSION) +
                    PER_UTXO_OVERHEAD;
            }

            Amount txfee = tx_total_in - tx_total_out;
            assert(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            Amount feerate = tx_size ? txfee / tx_size : Amount::zero();
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(feerate, tx_size);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    Amount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { Amount::zero() };
    CalculatePercentilesBySize(feerate_percentiles, feerate_array, total_size);

    UniValue::Array feerates_res;
    feerates_res.reserve(NUM_GETBLOCKSTATS_PERCENTILES);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(ValueFromAmount(feerate_percentiles[i]));
    }

    UniValue::Object ret;
    ret.reserve(25); // not critical but be sure to update this reserve size if adding/removing entries below.
    ret.emplace_back("avgfee",
                   ValueFromAmount((block.vtx.size() > 1)
                                       ? totalfee / int((block.vtx.size() - 1))
                                       : Amount::zero()));
    ret.emplace_back("avgfeerate",
                   ValueFromAmount((total_size > 0) ? totalfee / total_size
                                                    : Amount::zero()));
    ret.emplace_back("avgtxsize", (block.vtx.size() > 1)
                                    ? total_size / (block.vtx.size() - 1)
                                    : 0);
    ret.emplace_back("blockhash", pindex->GetBlockHash().GetHex());
    ret.emplace_back("feerate_percentiles", std::move(feerates_res));
    ret.emplace_back("height", pindex->nHeight);
    ret.emplace_back("ins", inputs);
    ret.emplace_back("maxfee", ValueFromAmount(maxfee));
    ret.emplace_back("maxfeerate", ValueFromAmount(maxfeerate));
    ret.emplace_back("maxtxsize", maxtxsize);
    ret.emplace_back("medianfee",
                   ValueFromAmount(CalculateTruncatedMedian(fee_array)));
    ret.emplace_back("mediantime", pindex->GetMedianTimePast());
    ret.emplace_back("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret.emplace_back(
        "minfee",
        ValueFromAmount((minfee == MAX_MONEY) ? Amount::zero() : minfee));
    ret.emplace_back("minfeerate",
                   ValueFromAmount((minfeerate == MAX_MONEY) ? Amount::zero()
                                                             : minfeerate));
    ret.emplace_back("mintxsize", mintxsize == thisBlockMaxBlockSize ? 0 : mintxsize);
    ret.emplace_back("outs", outputs);
    ret.emplace_back("subsidy", ValueFromAmount(GetBlockSubsidy(
                                  pindex->nHeight, Params().GetConsensus())));
    ret.emplace_back("time", pindex->GetBlockTime());
    ret.emplace_back("total_out", ValueFromAmount(total_out));
    ret.emplace_back("total_size", total_size);
    ret.emplace_back("totalfee", ValueFromAmount(totalfee));
    ret.emplace_back("txs", block.vtx.size());
    ret.emplace_back("utxo_increase", outputs - inputs);
    ret.emplace_back("utxo_size_inc", utxo_size_inc);

    if (!do_all) {
        // in this branch, we must return only the keys the client asked for
        UniValue::Object selected;
        selected.reserve(stats.size());
        for (const std::string &stat : stats) {
            UniValue *value = ret.locate(stat);
            if (!value || value->isNull()) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("Invalid selected statistic %s", stat));
            }
            selected.emplace_back(stat, std::move(*value));
        }
        return selected;
    }

    return ret; // compiler will invoke Univalue(Univalue::Object &&) move-constructor.
}

static UniValue savemempool(const Config &config,
                            const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"savemempool",
                "\nDumps the mempool to disk. It will fail until the previous dump is fully loaded.\n", {}}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("savemempool", "")
            + HelpExampleRpc("savemempool", "")
        );
    }

    if (!::g_mempool.IsLoaded()) {
        throw JSONRPCError(RPC_MISC_ERROR, "The mempool was not loaded yet");
    }

    if (!DumpMempool(::g_mempool)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unable to dump mempool to disk");
    }

    return UniValue();
}

//! Search for a given set of pubkey scripts and tokens
static bool FindScriptPubKeysAndTokens(std::atomic<int> &scan_progress,
                                       const std::atomic<bool> &should_abort,
                                       int64_t &count, CCoinsViewCursor *cursor,
                                       const std::set<CScript> &needles,
                                       const std::set<token::Id> &tokenIds,
                                       std::map<COutPoint, Coin> &out_results,
                                       std::function<void()>& interruption_point) {
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) {
            return false;
        }
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            const TxId &txid = key.GetTxId();
            uint32_t high = 0x100 * *txid.begin() + *(txid.begin() + 1);
            scan_progress = int(high * 100.0 / 65536.0 + 0.5);
        }
        const CTxOut &txout = coin.GetTxOut();
        if (needles.count(txout.scriptPubKey)
                || (txout.tokenDataPtr && tokenIds.count(txout.tokenDataPtr->GetId()))) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::mutex g_utxosetscan;
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver {
private:
    bool m_could_reserve;

public:
    explicit CoinsViewScanReserver() : m_could_reserve(false) {}

    bool reserve() {
        assert(!m_could_reserve);
        std::lock_guard<std::mutex> lock(g_utxosetscan);
        if (g_scan_in_progress) {
            return false;
        }
        g_scan_in_progress = true;
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            std::lock_guard<std::mutex> lock(g_utxosetscan);
            g_scan_in_progress = false;
        }
    }
};

static std::optional<token::Id> ParseTokenScanObject(std::string_view sv) {
    std::optional<token::Id> ret;
    // we expect "tok(<64-hex-chars>)"
    if (sv.substr(0, 4) != "tok(" || sv.size() != token::Id::size() * 2u + 5u || sv.back() != ')') {
        // not what we expected
        return ret;
    }
    const std::string_view::size_type begin = 4u,
                                      end = sv.find_last_of(')');
    sv = sv.substr(begin, end - begin);
    ret.emplace(token::Id::Uninitialized);
    if ( ! ParseHashStr(std::string{sv}, *ret)) {
        ret.reset(); // hex parse error
    }
    return ret;
}

static UniValue scantxoutset(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"scantxoutset",
                "\nEXPERIMENTAL warning: this call may be removed or changed in future releases.\n"
                "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
                "Examples of output descriptors are:\n"
                "    addr(<address>)                      Outputs whose scriptPubKey corresponds to the specified address (does not include P2PK)\n"
                "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
                "    combo(<pubkey>)                      P2PK and P2PKH outputs for the given pubkey\n"
                "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
                "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
                "    tok(<category>)                      Outputs containing tokens matching 32-byte hex <category>\n"
                "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
                "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
                "unhardened or hardened child keys.\n"
                "In the latter case, a range needs to be specified by below if different from 1000.\n"
                "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
                {
                    {"action", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The action to execute\n"
            "                                      \"start\" for starting a scan\n"
            "                                      \"abort\" for aborting the current scan (returns true when abort was successful)\n"
            "                                      \"status\" for progress report (in %) of the current scan"},
                    {"scanobjects", RPCArg::Type::ARR, /* opt */ false, /* default_val */ "", "Array of scan objects\n"
            "                                  Every scan object is either a string descriptor or an object:",
                        {
                            {"descriptor", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "An output descriptor"},
                            {"", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "An object with output descriptor and metadata",
                                {
                                    {"desc", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "An output descriptor"},
                                    {"range", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1000", "Up to what child index HD chains should be explored"},
                                },
                            },
                        },
                        "[scanobjects,...]"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"unspents\": [\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction "
            "id\n"
            "    \"vout\": n,                    (numeric) the vout value\n"
            "    \"scriptPubKey\" : \"script\",    (string) the script key\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount "
            "in " +
            CURRENCY_UNIT +
            " of the unspent output\n"
            "    \"height\" : n,                 (numeric) Height of the "
            "unspent transaction output\n"
            "    \"tokenData\" : {               (json object optional)\n"
            "      \"category\" : \"hex\",         (string) token id\n"
            "      \"amount\" : \"xxx\",           (string) fungible amount (is a string to support >53-bit amounts)\n"
            "      \"nft\" : {                   (json object optional)\n"
            "        \"capability\" : \"xxx\",     (string) one of \"none\", \"mutable\", \"minting\"\n"
            "        \"commitment\" : \"hex\"      (string) NFT commitment\n"
            "      }\n"
            "    }\n"
            "  }\n"
            "  ,...],\n"
            "  \"total_amount\" : x.xxx,         (numeric) The total amount of "
            "all found unspent outputs in " + CURRENCY_UNIT + "\n"
            "  \"token_total_amount\" : {...},   (json object optional) The total amount of each fungible token, "
            "by category id\n"
            "]\n");
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR});

    if (request.params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return UniValue();
        }
        UniValue::Object result;
        result.reserve(1);
        result.emplace_back("progress", g_scan_progress.load());
        return result;
    }

    if (request.params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    }

    if (request.params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Scan already in progress, use action \"abort\" or \"status\"");
        }
        std::set<CScript> needles;
        std::set<token::Id> tokenIds;
        Amount total_in = Amount::zero();

        // loop through the scan objects
        for (const UniValue &scanobject : request.params[1].get_array()) {
            std::string desc_str;
            int range = 1000;
            if (scanobject.isStr()) {
                desc_str = scanobject.get_str();
            } else if (scanobject.isObject()) {
                const UniValue & desc_uni = scanobject["desc"];
                if (desc_uni.isNull()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Descriptor needs to be provided in scan object");
                }
                desc_str = desc_uni.get_str();
                const UniValue & range_uni = scanobject["range"];
                if (!range_uni.isNull()) {
                    range = range_uni.get_int();
                    if (range < 0 || range > 1000000) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           "range out of range");
                    }
                }
            } else {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Scan object needs to be either a string or an object");
            }

            FlatSigningProvider provider;
            auto desc = Parse(desc_str, provider);
            if (!desc) {
                // failed to Parse using "Descriptor" subsystem, try our custom "tok(<category>)" syntax as well
                if (auto optTok = ParseTokenScanObject(desc_str)) {
                    // matched a tok(<category>) spec
                    tokenIds.insert(std::move(*optTok));
                    continue;
                } else {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor '%s'", desc_str));
                }
            }
            if (!desc->IsRange()) {
                range = 0;
            }
            for (int i = 0; i <= range; ++i) {
                std::vector<CScript> scripts;
                if (!desc->Expand(i, provider, scripts, provider)) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        strprintf(
                            "Cannot derive script without private keys: '%s'",
                            desc_str));
                }
                needles.insert(scripts.begin(), scripts.end());
            }
        }

        // Scan the unspent transaction output set for inputs
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        g_scan_progress = 0;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        {
            LOCK(cs_main);
            FlushStateToDisk();
            pcursor = std::unique_ptr<CCoinsViewCursor>(pcoinsdbview->Cursor());
            assert(pcursor);
        }
        NodeContext& node = EnsureAnyNodeContext(request.context);
        bool const res = FindScriptPubKeysAndTokens(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles,
                                                    tokenIds, coins, node.rpc_interruption_point);
        UniValue::Array unspents;
        unspents.reserve(coins.size());

        std::map<token::Id, token::SafeAmount> tokenIdTotals;

        for (const auto &it : coins) {
            const COutPoint &outpoint = it.first;
            const Coin &coin = it.second;
            const CTxOut &txo = coin.GetTxOut();
            total_in += txo.nValue;

            UniValue::Object unspent;
            unspent.reserve(5u + bool(txo.tokenDataPtr));
            unspent.emplace_back("txid", outpoint.GetTxId().GetHex());
            unspent.emplace_back("vout", outpoint.GetN());
            unspent.emplace_back("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.emplace_back("amount", ValueFromAmount(txo.nValue));
            unspent.emplace_back("height", coin.GetHeight());
            if (txo.tokenDataPtr) {
                unspent.emplace_back("tokenData", TokenDataToUniv(*txo.tokenDataPtr));
                if (txo.tokenDataPtr->HasAmount()) {
                    auto &amt = tokenIdTotals[txo.tokenDataPtr->GetId()];
                    // guard against overflow in case of weird PATFOs leading to totals exceeding INT64_MAX
                    if (const auto optSum = amt.safeAdd(txo.tokenDataPtr->GetAmount())) {
                        amt = *optSum;
                    }
                }
            }
            unspents.emplace_back(std::move(unspent));
        }

        UniValue::Object result;
        result.reserve(tokenIdTotals.empty() ? 4u : 5u);

        result.emplace_back("success", res);
        result.emplace_back("searched_items", count);
        result.emplace_back("unspents", std::move(unspents));
        result.emplace_back("total_amount", ValueFromAmount(total_in));
        if (!tokenIdTotals.empty()) {
            UniValue::Object tokTotals;
            tokTotals.reserve(tokenIdTotals.size());
            for (const auto & [id, amt] : tokenIdTotals) {
                tokTotals.emplace_back(id.ToString(), SafeAmountToUniv(amt));
            }
            result.emplace_back("token_total_amounts", std::move(tokTotals));
        }
        return result;
    }

    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
}

static UniValue fillmempool(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"fillmempool",
                       "\nFills the mempool with the specified number of megabytes worth of anyone-can-spend txns.\n",
                {
                    {"megabytes", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "",
                     "The number of megabytes worth of txns to fill the mempool with.", "", {"", "numeric"}},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("fillmempool","10")
            + HelpExampleRpc("fillmempool","320")
        );
    }

    // Ensure we are on regtest
    const auto &consensusParams = config.GetChainParams().GetConsensus();
    if ( ! consensusParams.fPowNoRetargeting) {
        throw JSONRPCError(RPC_METHOD_DISABLED,
                           "fillmempool is not supported on this chain. Switch to regtest to use fillmempool.");
    }

    // Check not already running in another thread
    static std::mutex one_at_a_time_mut;
    std::unique_lock one_at_a_time_guard(one_at_a_time_mut, std::try_to_lock);
    if ( ! one_at_a_time_guard.owns_lock()) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "fillmempool is already running in another RPC thread");
    }

    // Temporarily disable the regtest mempool sanity checking since it will slow the below operation down
    const auto orig_check_freq = g_mempool.getSanityCheck();
    Defer restore_sanity_check([&orig_check_freq]{
        // restore the original setting on scope end
        g_mempool.setSanityCheck(orig_check_freq);
    });
    g_mempool.setSanityCheck(0.0);

    Tic t0;
    const size_t target_size = ONE_MEGABYTE * [&request]{
        if (const int arg = request.params[0].get_int(); arg <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "megabytes argument must be greater than 0");
        } else {
            return arg;
        }
    }();
    if (target_size > config.GetMaxMemPoolSize()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Max mempool size is %i which is less than the requested %i",
                                                            config.GetMaxMemPoolSize(), target_size));
    }
    const auto redeem_script = CScript() << OP_DROP << OP_TRUE;
    const CTxDestination destination(ScriptID{redeem_script, /* is32 = */ false});
    const auto destination_spk = GetScriptForDestination(destination);
    using UTXO = std::pair<COutPoint, Amount>;
    using UTXOList = std::list<UTXO>;
    UTXOList utxos;

    // Mine over 100 blocks to get `nCB` valid coinbases we can spend using our "anyone can spend" p2sh
    {
        const auto reward = GetBlockSubsidy(WITH_LOCK(cs_main, return ::ChainActive().Height() + 1), consensusParams);
        assert( reward > Amount::zero());
        const size_t nCB = std::max<size_t>(1, (50 * COIN) / reward); // scale nCB to block reward size
        auto reserve_script = std::make_shared<CReserveScript>();
        reserve_script->reserveScript = destination_spk;
        const auto nBlocks = COINBASE_MATURITY + nCB;
        LogPrint(BCLog::MEMPOOL, "fillmempool: Generating %i blocks, of which %i coinbases will be used ...\n",
                 nBlocks, nCB);
        const auto blockhashes = generateBlocks(config, reserve_script, nBlocks, ~uint64_t{}, false);
        for (size_t i = 0; i < nCB; ++i) {
            const BlockHash bh{ParseHashV(blockhashes.at(i), "blockhash")};
            LOCK(cs_main);
            const CBlockIndex *pindex = LookupBlockIndex(bh);
            CBlock block;
            if (!pindex || !::ChainActive().Contains(pindex) || !ReadBlockFromDisk(block, pindex, consensusParams)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to find mined block #%i", i));
            }
            const auto &ptx = block.vtx.at(0);
            const auto &txid = ptx->GetId();
            const auto &out = ptx->vout.at(0);
            utxos.emplace_back(COutPoint{txid, 0}, out.nValue);
        }
    }

    const size_t op_return_size = std::max<size_t>(3u, ::nMaxDatacarrierBytes) - 3;
    const CTxOut op_return(Amount::zero(), CScript() << OP_RETURN << std::vector<uint8_t>(op_return_size));

    CFeeRate last_fee_rate;
    size_t max_size_seen = 0u, min_size_seen = 0xffffffffu;

    auto SpendToMempool = [&]
        (const size_t tx_num, const UTXO &txoIn, const size_t fanoutSize) -> UTXOList {
        UTXOList ret;
        assert(fanoutSize > 0);
        CMutableTransaction tx;
        const CScript script_sig = CScript() << std::vector<uint8_t>(GetRandInt(MAX_SCRIPT_ELEMENT_SIZE_LEGACY)) // pad txn
                                             << std::vector<uint8_t>(redeem_script.begin(), redeem_script.end());
        tx.vin.emplace_back(txoIn.first, script_sig);
        const auto &amt_in = txoIn.second;
        while (tx.vout.size() < fanoutSize) {
            tx.vout.emplace_back(int64_t((amt_in / SATOSHI) / fanoutSize) * SATOSHI, destination_spk);
        }
        // Now, add a full OP_RETURN to pad the txn
        const size_t n_op_returns = 1;
        tx.vout.push_back(op_return);

        tx.SortBip69();

        auto IsUnspendable = [](const CTxOut &out) {
            return out.nValue == Amount::zero() || out.scriptPubKey.IsUnspendable();
        };

        // Adjust for fees
        const auto tx_size = ::GetSerializeSize(tx, PROTOCOL_VERSION);
        const auto mp_max_size = config.GetMaxMemPoolSize();
        const auto fee_rate = std::max(WITH_LOCK(cs_main, return ::minRelayTxFee), g_mempool.GetMinFee(mp_max_size));
        const auto fee = fee_rate.GetFee(tx_size) / SATOSHI;
        const Amount fee_per_output = int64_t(std::ceil(fee / double(tx.vout.size() - n_op_returns))) * SATOSHI;
        for (auto &out : tx.vout) {
            if (IsUnspendable(out)) {
                // skip op_return
                continue;
            }
            out.nValue -= fee_per_output;
            if (!MoneyRange(out.nValue) || IsDust(out, ::dustRelayFee)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Bad amount for txout: %s", out.nValue.ToString()));
            }
        }

        // Submit the txn
        const CTransactionRef rtx = MakeTransactionRef(tx);
        const Amount tx_fee = amt_in - rtx->GetValueOut();
        if (0 == tx_num % 1000 || last_fee_rate != fee_rate || tx_size > max_size_seen || tx_size < min_size_seen) {
            // log what's happening every 1000th time, or if the fee rate changes, or if we hit a new hi/low tx size
            last_fee_rate = fee_rate;
            max_size_seen = std::max(tx_size, max_size_seen);
            min_size_seen = std::min(tx_size, min_size_seen);
            LogPrint(BCLog::MEMPOOL, "fillmempool: tx_num: %i, size: %i, fee: %i, fee_rate: %s\n",
                     tx_num, tx_size, tx_fee / SATOSHI, fee_rate.ToString());
        }
        const auto &txId = rtx->GetId();
        unsigned outN = 0;
        {
            LOCK(cs_main);
            CValidationState vstate;
            bool missingInputs{};
            const bool ok = AcceptToMemoryPool(config, g_mempool, vstate, rtx, &missingInputs, false, Amount::zero());
            if (!ok || !vstate.IsValid()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   strprintf("Unable to accept txn to mempool: %s",
                                             missingInputs ? "missing inputs" : vstate.GetRejectReason()));
            }
        }

        // Remember utxos
        for (const auto &out : rtx->vout) {
            if ( ! IsUnspendable(out)) {
                ret.emplace_back(COutPoint{txId, outN}, out.nValue);
            }
            ++outN;
        }
        return ret;
    };

    // Generate txns to fill the mempool to the required size.
    // Note that this is a bit fuzzy in that it may be +/- by as
    // much as ~1.5KB dynamic size (or +/- ~500 B serialized size).
    size_t ngen = 0, mp_dynusage = 0;
    while ((mp_dynusage = g_mempool.DynamicMemoryUsage()) + 500 < target_size) {
        assert(!utxos.empty());
        const UTXO utxo = utxos.front();
        utxos.pop_front();
        auto new_utxos = SpendToMempool(ngen + 1, utxo, 2);
        utxos.splice(utxos.end(), std::move(new_utxos));
        ++ngen;
    }

    UniValue::Object ret;
    ret.reserve(7);
    ret.emplace_back("txns_generated", ngen);
    ret.emplace_back("mempool_txns", g_mempool.size());
    ret.emplace_back("mempool_bytes", g_mempool.GetTotalTxSize());
    ret.emplace_back("mempool_dynamic_usage", mp_dynusage);
    ret.emplace_back("elapsed_msec", t0.msec<double>());
    ret.emplace_back("address", EncodeDestination(destination, config));
    ret.emplace_back("redeemscript_hex", HexStr(redeem_script));
    return ret;
}

static UniValue::Object OrphanToJSON(const TxOrphanage::OrphanTxBase &orphan, const size_t extraReserve = 0) {
    const CTransaction &tx = *CHECK_NONFATAL(orphan.tx);
    UniValue::Object o;
    o.reserve(5 + extraReserve);
    o.emplace_back("txid", tx.GetId().ToString());
    o.emplace_back("bytes", tx.GetTotalSize());
    o.emplace_back("entry", orphan.nTimeExpire - ORPHAN_TX_EXPIRE_TIME);
    o.emplace_back("expiration", orphan.nTimeExpire);
    {
        UniValue::Array from;
        from.reserve(1);
        from.push_back(orphan.fromPeer); // only one fromPeer for now
        o.emplace_back("from", std::move(from));
    }
    return o;
}

static UniValue getorphantxs(const Config &, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"getorphantxs", "\nShows transactions in the tx orphanage.\n"
                                       "\nEXPERIMENTAL warning: this call may be changed in future releases.\n",
                       {
                           RPCArg{"verbosity", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0",
                                  "0 for an array of txids (may contain duplicates), 1 for an array of objects with tx"
                                  " details, and 2 for details from (1) and tx hex"},
                       }
            }.ToString() + R"""(
"Result (for verbosity = 0):
[
  "txid",              (string) The transaction id hex
  ...
]

Result (for verbosity >= 1):
[
  {
    "txid": "xxx",     (string) The transaction id hex
    "bytes": n,        (numeric) The serialized transaction size in bytes
    "entry": n,        (numeric) The entry time into the orphanage expressed in UNIX epoch time
    "expiration": n,   (numeric) The orphan expiration time expressed in UNIX epoch time
    "from": [          (array) Peers that announced this orphan tx (array size is always 1 for now)
      "peer_id": n     (numeric) Peer ID
    ],
    "hex": "xxx"       (string, optional) The serialized, hex-encoded transaction data (only present if verbosity >= 2)
  },
  ...
]
)"""
            + "\nExamples:\n"
            + HelpExampleCli("getorphantxs","0")
            + HelpExampleRpc("getorphantxs","1")
        );
    }

    const int verbosity = ParseVerbosity(request.params[0], /* default_verbosity = */ 0, /* allow_bool = */ false);

    const PeerLogicValidation &peerman = EnsureAnyPeerLogicValidation(request.context);
    const std::vector<TxOrphanage::OrphanTxBase> orphanage = peerman.GetOrphanTransactions();

    UniValue::Array ret;
    ret.reserve(orphanage.size());

    if (verbosity == 0) {
        for (auto const &orphan : orphanage) {
            ret.push_back(orphan.tx->GetId().ToString());
        }
    } else if (verbosity == 1) {
        for (auto const &orphan : orphanage) {
            ret.push_back(OrphanToJSON(orphan));
        }
    } else if (verbosity == 2) {
        for (auto const &orphan : orphanage) {
            UniValue::Object o = OrphanToJSON(orphan, 1);
            o.emplace_back("hex", EncodeHexTx(*orphan.tx));
            ret.push_back(std::move(o));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid verbosity value " + std::to_string(verbosity));
    }

    return ret;
}

// clang-format off
static const ContextFreeRPCCommand commands[] = {
    //  category            name                      actor (function)        argNames
    //  ------------------- ------------------------  ----------------------  ----------
    { "blockchain",         "finalizeblock",          finalizeblock,          {"blockhash"} },
    { "blockchain",         "getbestblockhash",       getbestblockhash,       {} },
    { "blockchain",         "getblock",               getblock,               {"blockhash","verbosity|verbose","patterns"} },
    { "blockchain",         "getblockchaininfo",      getblockchaininfo,      {} },
    { "blockchain",         "getblockcount",          getblockcount,          {} },
    { "blockchain",         "getblockhash",           getblockhash,           {"height"} },
    { "blockchain",         "getblockheader",         getblockheader,         {"blockhash|hash_or_height","verbose"} },
    { "blockchain",         "getblockstats",          getblockstats,          {"hash_or_height","stats"} },
    { "blockchain",         "getchaintips",           getchaintips,           {} },
    { "blockchain",         "getchaintxstats",        getchaintxstats,        {"nblocks", "blockhash"} },
    { "blockchain",         "getdifficulty",          getdifficulty,          {} },
    { "blockchain",         "getfinalizedblockhash",  getfinalizedblockhash,  {} },
    { "blockchain",         "getmempoolancestors",    getmempoolancestors,    {"txid","verbose"} },
    { "blockchain",         "getmempooldescendants",  getmempooldescendants,  {"txid","verbose"} },
    { "blockchain",         "getmempoolentry",        getmempoolentry,        {"txid"} },
    { "blockchain",         "getmempoolinfo",         getmempoolinfo,         {} },
    { "blockchain",         "getrawmempool",          getrawmempool,          {"verbose"} },
    { "blockchain",         "gettxout",               gettxout,               {"txid","n","include_mempool", "patterns"} },
    { "blockchain",         "gettxoutsetinfo",        gettxoutsetinfo,        {"hash_type", "hash_or_height", "use_index"} },
    { "blockchain",         "invalidateblock",        invalidateblock,        {"blockhash"} },
    { "blockchain",         "parkblock",              parkblock,              {"blockhash"} },
    { "blockchain",         "preciousblock",          preciousblock,          {"blockhash"} },
    { "blockchain",         "pruneblockchain",        pruneblockchain,        {"height"} },
    { "blockchain",         "reconsiderblock",        reconsiderblock,        {"blockhash"} },
    { "blockchain",         "savemempool",            savemempool,            {} },
    { "blockchain",         "scantxoutset",           scantxoutset,           {"action", "scanobjects"} },
    { "blockchain",         "unparkblock",            unparkblock,            {"blockhash"} },
    { "blockchain",         "verifychain",            verifychain,            {"checklevel","nblocks"} },

    /* Not shown in help */
    { "hidden",             "fillmempool",                      fillmempool,                      {"megabytes"} },
    { "hidden",             "getorphantxs",                     getorphantxs,                     {"verbosity"}},
    { "hidden",             "syncwithvalidationinterfacequeue", syncwithvalidationinterfacequeue, {} },
    { "hidden",             "waitforblock",                     waitforblock,                     {"blockhash","timeout"} },
    { "hidden",             "waitforblockheight",               waitforblockheight,               {"height","timeout"} },
    { "hidden",             "waitfornewblock",                  waitfornewblock,                  {"timeout"} },
};
// clang-format on

void RegisterBlockchainRPCCommands(CRPCTable &t) {
    for (unsigned int vcidx = 0; vcidx < std::size(commands); ++vcidx) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
