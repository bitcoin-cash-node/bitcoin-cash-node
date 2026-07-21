// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <attributes.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <core_io.h>
#include <httpserver.h>
#include <index/txindex.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <undo.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <validation.h>
#include <version.h>

#include <univalue.h>

// Allow a max of 15 outpoints to be queried at once.
static const size_t MAX_GETUTXOS_OUTPOINTS = 15;

enum class RetFormat {
    UNDEF,
    BINARY,
    HEX,
    JSON,
};

static const struct {
    enum RetFormat rf;
    const char *name;
} rf_names[] = {
    {RetFormat::UNDEF, ""},
    {RetFormat::BINARY, "bin"},
    {RetFormat::HEX, "hex"},
    {RetFormat::JSON, "json"},
};

struct CCoin {
    uint32_t nHeight;
    CTxOut out;

    CCoin() : nHeight(0) {}
    explicit CCoin(Coin in)
        : nHeight(in.GetHeight()), out(std::move(in.GetTxOut())) {}

    SERIALIZE_METHODS(CCoin, obj) {
        uint32_t nTxVerDummy = 0;
        READWRITE(nTxVerDummy, obj.nHeight, obj.out);
    }
};

static bool RESTERR(HTTPRequest *req, enum HTTPStatusCode status,
                    std::string message) {
    req->WriteHeader("Content-Type", "text/plain");
    req->WriteReply(status, message + "\r\n");
    return false;
}

static enum RetFormat ParseDataFormat(std::string &param,
                                      const std::string &strReq) {
    const std::string::size_type pos = strReq.rfind('.');
    if (pos == std::string::npos) {
        param = strReq;
        return rf_names[0].rf;
    }

    param = strReq.substr(0, pos);
    const std::string suff(strReq, pos + 1);

    for (size_t i = 0; i < std::size(rf_names); ++i) {
        if (suff == rf_names[i].name) {
            return rf_names[i].rf;
        }
    }

    /* If no suffix is found, return original string.  */
    param = strReq;
    return rf_names[0].rf;
}

static std::string AvailableDataFormatsString() {
    std::string formats;
    for (size_t i = 0; i < std::size(rf_names); ++i) {
        if (strlen(rf_names[i].name) > 0) {
            formats.append(".");
            formats.append(rf_names[i].name);
            formats.append(", ");
        }
    }

    if (formats.length() > 0) {
        return formats.substr(0, formats.length() - 2);
    }

    return formats;
}

static bool CheckWarmup(HTTPRequest *req) {
    std::string statusmessage;
    if (RPCIsInWarmup(&statusmessage)) {
        return RESTERR(req, HTTP_SERVICE_UNAVAILABLE,
                       "Service temporarily unavailable: " + statusmessage);
    }

    return true;
}

static bool rest_headers(const std::any& context, Config &config, HTTPRequest *req,
                         const std::string &strURIPart) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);
    std::vector<std::string> path;
    Split(path, param, "/");

    if (path.size() != 2) {
        return RESTERR(req, HTTP_BAD_REQUEST,
                       "No header count specified. Use "
                       "/rest/headers/<count>/<hash>.<ext>.");
    }

    long count = strtol(path[0].c_str(), nullptr, 10);
    if (count < 1 || count > 2000) {
        return RESTERR(req, HTTP_BAD_REQUEST,
                       "Header count out of range: " + path[0]);
    }

    std::string hashStr = path[1];
    uint256 rawHash;
    if (!ParseHashStr(hashStr, rawHash)) {
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);
    }

    const BlockHash hash(rawHash);

    const CBlockIndex *tip = nullptr;
    std::vector<const CBlockIndex *> headers;
    headers.reserve(count);
    {
        LOCK(cs_main);
        tip = ::ChainActive().Tip();
        const CBlockIndex *pindex = LookupBlockIndex(hash);
        while (pindex != nullptr && ::ChainActive().Contains(pindex)) {
            headers.push_back(pindex);
            if (headers.size() == size_t(count)) {
                break;
            }
            pindex = ::ChainActive().Next(pindex);
        }
    }

    switch (rf) {
        case RetFormat::BINARY: {
            CDataStream ssHeader(SER_NETWORK, PROTOCOL_VERSION);
            for (const CBlockIndex *pindex : headers) {
                ssHeader << pindex->GetBlockHeader();
            }

            req->WriteHeader("Content-Type", "application/octet-stream");
            req->WriteReply(HTTP_OK, MakeUInt8Span(ssHeader));
            return true;
        }

        case RetFormat::HEX: {
            CDataStream ssHeader(SER_NETWORK, PROTOCOL_VERSION);
            for (const CBlockIndex *pindex : headers) {
                ssHeader << pindex->GetBlockHeader();
            }

            std::string strHex = HexStr(ssHeader, false, 1);
            strHex.append("\n");
            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, strHex);
            return true;
        }
        case RetFormat::JSON: {
            UniValue::Array jsonHeaders;
            jsonHeaders.reserve(headers.size());
            for (const CBlockIndex *pindex : headers) {
                jsonHeaders.emplace_back(blockheaderToJSON(config, tip, pindex));
            }
            std::string strJSON = UniValue::stringify(jsonHeaders);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: .bin, .hex)");
        }
    }
}

/**
 * Serialize spent outputs as a vector of per-transaction CTxOut vectors using binary format.
 */
static void SerializeBlockUndo(CDataStream &stream, const CBlockUndo &block_undo) {
    WriteCompactSize(stream, block_undo.vtxundo.size() + 1);
    WriteCompactSize(stream, 0); // dummy entry for coinbase tx; block_undo.vtxundo doesn't contain coinbase tx
    for (const CTxUndo &tx_undo : block_undo.vtxundo) {
        WriteCompactSize(stream, tx_undo.vprevout.size());
        for (const Coin &coin : tx_undo.vprevout) {
            coin.GetTxOut().Serialize(stream);
        }
    }
}

/**
 * Serialize spent outputs as a JSON array of per-transaction CTxOut JSON array of objects.
 */
static UniValue::Array BlockUndoToJSON(const Config &config, const CBlockUndo &block_undo, const bool with_patterns) {
    UniValue::Array result;
    result.reserve(block_undo.vtxundo.size() + 1);
    result.emplace_back(UniValue::VARR); // dummy entry for coinbase tx; block_undo.vtxundo doesn't contain coinbase tx
    for (const CTxUndo &tx_undo : block_undo.vtxundo) {
        UniValue::Array tx_prevouts;
        tx_prevouts.reserve(tx_undo.vprevout.size());
        for (const Coin &coin : tx_undo.vprevout) {
            const CTxOut &txout = coin.GetTxOut();

            UniValue::Object prevout;
            prevout.reserve(2 + bool(txout.tokenDataPtr));

            prevout.emplace_back("value", ValueFromAmount(txout.nValue));;
            prevout.emplace_back("scriptPubKey", ScriptToUniv(config, txout.scriptPubKey, /*include_address=*/true,
                                                              /*include_type=*/true, with_patterns));
            if (txout.tokenDataPtr) {
                prevout.emplace_back("tokenData", TokenDataToUniv(*txout.tokenDataPtr));
            }

            tx_prevouts.push_back(std::move(prevout));
        }
        result.push_back(std::move(tx_prevouts));
    }
    return result;
}

static bool rest_spent_txouts(const Config &config, HTTPRequest *req, const std::string &strURIPart,
                              const bool with_patterns) {
    if (!CheckWarmup(req)) {
        return false;
    }
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    BlockHash hash;
    if (!ParseHashStr(hashStr, hash)) {
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);
    }

    const CBlockIndex * const pblockindex = WITH_LOCK(cs_main, return ::LookupBlockIndex(hash));
    if (!pblockindex) {
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
    }

    CBlockUndo block_undo;
    if (pblockindex->nHeight > 0 && !UndoReadFromDisk(block_undo, pblockindex)) {
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " undo not available");
    }

    switch (rf) {
        case RetFormat::BINARY: {
            CDataStream ssSpentResponse(SER_NETWORK, PROTOCOL_VERSION);
            SerializeBlockUndo(ssSpentResponse, block_undo);
            req->WriteHeader("Content-Type", "application/octet-stream");
            req->WriteReply(HTTP_OK, MakeUInt8Span(ssSpentResponse));
            return true;
        }

        case RetFormat::HEX: {
            CDataStream ssSpentResponse(SER_NETWORK, PROTOCOL_VERSION);
            SerializeBlockUndo(ssSpentResponse, block_undo);
            std::string strHex = HexStr(ssSpentResponse, false, 1);
            strHex.append("\n");
            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, strHex);
            return true;
        }

        case RetFormat::JSON: {
            std::string strJSON = UniValue::stringify(BlockUndoToJSON(config, block_undo, with_patterns));
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }

        default: {
            return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
        }
    }
}

static bool rest_spent_txouts_no_patterns(const std::any &, Config &config, HTTPRequest *req,
                                          const std::string &strURIPart) {
    return rest_spent_txouts(config, req, strURIPart, false);
}

static bool rest_spent_txouts_with_patterns(const std::any &, Config &config, HTTPRequest *req,
                                            const std::string &strURIPart) {
    return rest_spent_txouts(config, req, strURIPart, true);
}

static bool rest_block(const Config &config, HTTPRequest *req,
                       const std::string &strURIPart, const TransactionFormatOptions &txOptions) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 rawHash;
    if (!ParseHashStr(hashStr, rawHash)) {
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);
    }

    const BlockHash hash(rawHash);

    std::vector<uint8_t> rawBlock;
    CBlockIndex *pblockindex = nullptr;
    CBlockIndex *tip = nullptr;
    {
        LOCK(cs_main);
        tip = ::ChainActive().Tip();
        pblockindex = LookupBlockIndex(hash);
        if (!pblockindex) {
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
        }

        if (IsBlockPruned(pblockindex)) {
            return RESTERR(req, HTTP_NOT_FOUND,
                           hashStr + " not available (pruned data)");
        }

        if (!ReadRawBlockFromDisk(rawBlock, pblockindex,
                                  config.GetChainParams(), SER_NETWORK, PROTOCOL_VERSION)) {
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
        }
    }

    switch (rf) {
        case RetFormat::BINARY: {
            req->WriteHeader("Content-Type", "application/octet-stream");
            req->WriteReply(HTTP_OK, rawBlock);
            return true;
        }

        case RetFormat::HEX: {
            std::string strHex = HexStr(rawBlock, false, 1);
            strHex.append("\n");
            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, strHex);
            return true;
        }

        case RetFormat::JSON: {
            CBlock block;
            VectorReader(SER_NETWORK, PROTOCOL_VERSION, rawBlock, 0) >> block;
            UniValue::Object objBlock = blockToJSON(config, block, tip, pblockindex, txOptions);
            std::string strJSON = UniValue::stringify(objBlock);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }

        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: " +
                               AvailableDataFormatsString() + ")");
        }
    }
}

static bool rest_block_extended_with_patterns(const std::any &, Config &config, HTTPRequest *req,
                                              const std::string &strURIPart) {
    return rest_block(config, req, strURIPart, TransactionFormatOptions(BlockTxVerbosity::SHOW_DETAILS_AND_PREVOUT).WithPatterns());
}

static bool rest_block_extended(const std::any& context, Config &config, HTTPRequest *req,
                                const std::string &strURIPart) {
    return rest_block(config, req, strURIPart, BlockTxVerbosity::SHOW_DETAILS_AND_PREVOUT);
}

static bool rest_block_notxdetails(const std::any& context, Config &config, HTTPRequest *req,
                                   const std::string &strURIPart) {
    return rest_block(config, req, strURIPart, BlockTxVerbosity::SHOW_TXID);
}

static bool rest_chaininfo(const std::any& context, Config &config, HTTPRequest *req,
                           const std::string &strURIPart) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
        case RetFormat::JSON: {
            JSONRPCRequest jsonRequest;
            jsonRequest.context = context;
            jsonRequest.params.setArray();
            UniValue chainInfoObject = getblockchaininfo(config, jsonRequest);
            std::string strJSON = UniValue::stringify(chainInfoObject);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: json)");
        }
    }
}

static bool rest_mempool_info(const std::any& context, Config &config, HTTPRequest *req,
                              const std::string &strURIPart) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
        case RetFormat::JSON: {
            UniValue::Object mempoolInfoObject = MempoolInfoToJSON(config, ::g_mempool);

            std::string strJSON = UniValue::stringify(mempoolInfoObject);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: json)");
        }
    }
}

static bool rest_mempool_contents(const std::any& context, Config &config, HTTPRequest *req,
                                  const std::string &strURIPart) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
        case RetFormat::JSON: {
            UniValue mempoolObject = MempoolToJSON(::g_mempool, true);

            std::string strJSON = UniValue::stringify(mempoolObject);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: json)");
        }
    }
}

static bool rest_tx(const std::any& context, Config &config, HTTPRequest *req,
                    const std::string &strURIPart, bool fPatterns = false) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 hash;
    if (!ParseHashStr(hashStr, hash)) {
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);
    }

    const TxId txid(hash);

    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }

    CTransactionRef tx;
    BlockHash hashBlock;
    if (!GetTransaction(txid, tx, config.GetChainParams().GetConsensus(),
                        hashBlock, true)) {
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
    }

    switch (rf) {
        case RetFormat::BINARY: {
            CDataStream ssTx(SER_NETWORK,
                             PROTOCOL_VERSION);
            ssTx << tx;

            req->WriteHeader("Content-Type", "application/octet-stream");
            req->WriteReply(HTTP_OK, MakeUInt8Span(ssTx));
            return true;
        }

        case RetFormat::HEX: {
            CDataStream ssTx(SER_NETWORK,
                             PROTOCOL_VERSION);
            ssTx << tx;

            std::string strHex = HexStr(ssTx, false, 1);
            strHex.append("\n");
            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, strHex);
            return true;
        }

        case RetFormat::JSON: {
            const bool hasHash = !hashBlock.IsNull();
            UniValue::Object objTx = TransactionToUniv(config, *tx, nullptr, TransactionFormatOptions().WithHex().WithPatterns(fPatterns), hasHash);
            if (hasHash) {
                objTx.emplace_back("blockhash", hashBlock.GetHex());
            }
            std::string strJSON = UniValue::stringify(objTx);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }

        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: " +
                               AvailableDataFormatsString() + ")");
        }
    }
}

static bool rest_getutxos(const std::any& context, Config &config, HTTPRequest *req,
                          const std::string &strURIPart) {
    if (!CheckWarmup(req)) {
        return false;
    }

    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    std::vector<std::string> uriParts;
    if (param.length() > 1) {
        std::string strUriParams = param.substr(1);
        Split(uriParts, strUriParams, "/");
    }

    // throw exception in case of an empty request
    std::string strRequestMutable = req->ReadBody();
    if (strRequestMutable.length() == 0 && uriParts.size() == 0) {
        return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
    }

    bool fInputParsed = false;
    bool fCheckMemPool = false;
    std::vector<COutPoint> vOutPoints;

    // parse/deserialize input
    // input-format = output-format, rest/getutxos/bin requires binary input,
    // gives binary output, ...

    if (uriParts.size() > 0) {
        // inputs is sent over URI scheme
        // (/rest/getutxos/checkmempool/txid1-n/txid2-n/...)
        if (uriParts[0] == "checkmempool") {
            fCheckMemPool = true;
        }

        for (size_t i = fCheckMemPool ? 1 : 0; i < uriParts.size(); i++) {
            int32_t nOutput;
            std::string strTxid = uriParts[i].substr(0, uriParts[i].find('-'));
            std::string strOutput =
                uriParts[i].substr(uriParts[i].find('-') + 1);

            if (!ParseInt32(strOutput, &nOutput) || !IsHex(strTxid)) {
                return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");
            }

            TxId txid;
            txid.SetHex(strTxid);
            vOutPoints.push_back(COutPoint(txid, uint32_t(nOutput)));
        }

        if (vOutPoints.size() > 0) {
            fInputParsed = true;
        } else {
            return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
        }
    }

    switch (rf) {
        case RetFormat::HEX: {
            // convert hex to bin, continue then with bin part
            std::vector<uint8_t> strRequestV = ParseHex(strRequestMutable);
            strRequestMutable.assign(strRequestV.begin(), strRequestV.end());
        }
        [[fallthrough]];
        case RetFormat::BINARY: {
            try {
                // deserialize only if user sent a request
                if (strRequestMutable.size() > 0) {
                    // don't allow sending input over URI and HTTP RAW DATA
                    if (fInputParsed) {
                        return RESTERR(req, HTTP_BAD_REQUEST,
                                       "Combination of URI scheme inputs and "
                                       "raw post data is not allowed");
                    }

                    CDataStream oss(SER_NETWORK, PROTOCOL_VERSION);
                    oss << strRequestMutable;
                    oss >> fCheckMemPool;
                    oss >> vOutPoints;
                }
            } catch (const std::ios_base::failure &) {
                // abort in case of unreadable binary data
                return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");
            }
            break;
        }

        case RetFormat::JSON: {
            if (!fInputParsed) {
                return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
            }
            break;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: " +
                               AvailableDataFormatsString() + ")");
        }
    }

    // limit max outpoints
    if (vOutPoints.size() > MAX_GETUTXOS_OUTPOINTS) {
        return RESTERR(
            req, HTTP_BAD_REQUEST,
            strprintf("Error: max outpoints exceeded (max: %d, tried: %d)",
                      MAX_GETUTXOS_OUTPOINTS, vOutPoints.size()));
    }

    // check spentness and form a bitmap (as well as a JSON capable
    // human-readable string representation)
    std::vector<uint8_t> bitmap;
    std::vector<CCoin> outs;
    std::string bitmapStringRepresentation;
    std::vector<bool> hits;
    bitmap.resize((vOutPoints.size() + 7) / 8);
    {
        auto process_utxos = [&vOutPoints, &outs,
                              &hits](const CCoinsView &view,
                                     const CTxMemPool &mempool) {
            for (const COutPoint &vOutPoint : vOutPoints) {
                Coin coin;
                bool hit = !mempool.isSpent(vOutPoint) &&
                           view.GetCoin(vOutPoint, coin);
                hits.push_back(hit);
                if (hit) {
                    outs.emplace_back(std::move(coin));
                }
            }
        };

        if (fCheckMemPool) {
            // use db+mempool as cache backend in case user likes to query
            // mempool
            LOCK2(cs_main, g_mempool.cs);
            CCoinsViewCache &viewChain = *pcoinsTip;
            CCoinsViewMemPool viewMempool(&viewChain, g_mempool);
            process_utxos(viewMempool, g_mempool);
        } else {
            // no need to lock mempool!
            LOCK(cs_main);
            process_utxos(*pcoinsTip, CTxMemPool());
        }

        for (size_t i = 0; i < hits.size(); ++i) {
            const bool hit = hits[i];
            // form a binary string representation (human-readable for json
            // output)
            bitmapStringRepresentation.append(hit ? "1" : "0");
            bitmap[i / 8] |= ((uint8_t)hit) << (i % 8);
        }
    }

    switch (rf) {
        case RetFormat::BINARY: {
            // serialize data
            // use exact same output as mentioned in Bip64
            CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
            {
                LOCK(cs_main);
                ssGetUTXOResponse << ::ChainActive().Height()
                                  << ::ChainActive().Tip()->GetBlockHash() << bitmap
                                  << outs;
            }

            req->WriteHeader("Content-Type", "application/octet-stream");
            req->WriteReply(HTTP_OK, MakeUInt8Span(ssGetUTXOResponse));
            return true;
        }

        case RetFormat::HEX: {
            CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
            {
                LOCK(cs_main);
                ssGetUTXOResponse << ::ChainActive().Height()
                                  << ::ChainActive().Tip()->GetBlockHash() << bitmap
                                  << outs;
            }
            std::string strHex = HexStr(ssGetUTXOResponse, false, 1);
            strHex.append("\n");

            req->WriteHeader("Content-Type", "text/plain");
            req->WriteReply(HTTP_OK, strHex);
            return true;
        }

        case RetFormat::JSON: {
            UniValue::Object objGetUTXOResponse;

            // pack in some essentials
            // use more or less the same output as mentioned in Bip64
            {
                LOCK(cs_main);
                objGetUTXOResponse.emplace_back("chainHeight", ::ChainActive().Height());
                objGetUTXOResponse.emplace_back("chaintipHash", ::ChainActive().Tip()->GetBlockHash().GetHex());
            }
            objGetUTXOResponse.emplace_back("bitmap", bitmapStringRepresentation);

            UniValue::Array utxos;
            utxos.reserve(outs.size());
            for (const CCoin &coin : outs) {
                UniValue::Object utxo;
                utxo.reserve(3);
                utxo.emplace_back("height", coin.nHeight);
                utxo.emplace_back("value", ValueFromAmount(coin.out.nValue));

                // include the script in a json output
                utxo.emplace_back("scriptPubKey", ScriptPubKeyToUniv(config, coin.out.scriptPubKey, true));
                utxos.emplace_back(std::move(utxo));
            }
            objGetUTXOResponse.emplace_back("utxos", std::move(utxos));

            // return json string
            std::string strJSON = UniValue::stringify(objGetUTXOResponse);
            strJSON.append("\n");
            req->WriteHeader("Content-Type", "application/json");
            req->WriteReply(HTTP_OK, strJSON);
            return true;
        }
        default: {
            return RESTERR(req, HTTP_NOT_FOUND,
                           "output format not found (available: " +
                               AvailableDataFormatsString() + ")");
        }
    }
}

static const struct {
    const char *prefix;
    bool (*handler)(const std::any& context, Config &config, HTTPRequest *req,
                    const std::string &strReq);
} uri_prefixes[] = {
    {"/rest/tx/withpatterns/", [](const std::any& context, Config &config, HTTPRequest *req,
                                  const std::string &strReq) { return rest_tx(context, config, req, strReq, true); }},
    {"/rest/tx/",              [](const std::any& context, Config &config, HTTPRequest *req,
                                  const std::string &strReq) { return rest_tx(context, config, req, strReq, false); }},
    {"/rest/block/notxdetails/", rest_block_notxdetails},
    {"/rest/block/withpatterns/", rest_block_extended_with_patterns},
    {"/rest/block/", rest_block_extended},
    {"/rest/chaininfo", rest_chaininfo},
    {"/rest/mempool/info", rest_mempool_info},
    {"/rest/mempool/contents", rest_mempool_contents},
    {"/rest/headers/", rest_headers},
    {"/rest/getutxos", rest_getutxos},
    {"/rest/spenttxouts/withpatterns/", rest_spent_txouts_with_patterns},
    {"/rest/spenttxouts/", rest_spent_txouts_no_patterns},
};

void StartREST(const std::any& context) {
    for (const auto& up : uri_prefixes) {
        auto handler = [context, up](Config& config, HTTPRequest* req, const std::string& prefix) { return up.handler(context, config, req, prefix); };
        RegisterHTTPHandler(up.prefix, false, handler);
    }
}

void InterruptREST() {}

void StopREST() {
    for (size_t i = 0; i < std::size(uri_prefixes); ++i) {
        UnregisterHTTPHandler(uri_prefixes[i].prefix, false);
    }
}
