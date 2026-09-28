// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <consensus/validation.h>
#include <primitives/block.h>

#include <functional>
#include <limits>
#include <type_traits>

class Config;
class CTxMemPool;
namespace Consensus { struct Params; }

// Transaction compression schemes for compact block relay can be introduced by
// writing an actual formatter here.
using TransactionCompression = DefaultFormatter;

class DifferenceFormatter {
    uint64_t m_shift = 0;

public:
    template <typename Stream, typename I> void Ser(Stream &s, I v) {
        static_assert(std::is_unsigned_v<I>);
        if (v < m_shift || v >= std::numeric_limits<uint64_t>::max())
            throw std::ios_base::failure("differential value overflow");
        WriteCompactSize(s, v - m_shift);
        m_shift = uint64_t(v) + 1;
    }
    template <typename Stream, typename I> void Unser(Stream &s, I &v) {
        static_assert(std::is_unsigned_v<I>);
        uint64_t n = ReadCompactSize(s);
        m_shift += n;
        if (m_shift < n || m_shift >= std::numeric_limits<uint64_t>::max() ||
            m_shift < std::numeric_limits<I>::min() ||
            m_shift > std::numeric_limits<I>::max())
            throw std::ios_base::failure("differential value overflow");
        v = I(m_shift++);
    }
};

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    BlockHash blockhash;
    std::vector<uint32_t> indices;

    SERIALIZE_METHODS(BlockTransactionsRequest, obj) {
        READWRITE(obj.blockhash,
                  Using<VectorFormatter<DifferenceFormatter>>(obj.indices));
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    BlockHash blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() {}
    explicit BlockTransactions(const BlockTransactionsRequest &req)
        : blockhash(req.blockhash), txn(req.indices.size()) {}

    SERIALIZE_METHODS(BlockTransactions, obj) {
        READWRITE(obj.blockhash,
                  Using<VectorFormatter<TransactionCompression>>(obj.txn));
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and
// PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint32_t index;
    CTransactionRef tx;

    SERIALIZE_METHODS(PrefilledTransaction, obj) {
        READWRITE(COMPACTSIZE(obj.index),
                  Using<TransactionCompression>(obj.tx));
    }
};

enum ReadStatus {
    READ_STATUS_OK,
    // Invalid object, peer is sending bogus crap.
    // FIXME: differenciate bogus crap from crap that do not fit our policy.
    READ_STATUS_INVALID,
    // Failed to process object.
    READ_STATUS_FAILED,
    // Used only by FillBlock to indicate a failure in CheckBlock.
    READ_STATUS_CHECKBLOCK_FAILED,
};

class CBlockHeaderAndShortTxIDs {
private:
    uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector();

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndShortTxIDs() {}

    CBlockHeaderAndShortTxIDs(const CBlock &block);

    uint64_t GetShortID(const TxHash &txhash) const;

    size_t BlockTxCount() const {
        return shorttxids.size() + prefilledtxn.size();
    }

    SERIALIZE_METHODS(CBlockHeaderAndShortTxIDs, obj) {
        READWRITE(
            obj.header, obj.nonce,
            Using<VectorFormatter<CustomUintFormatter<SHORTTXIDS_LENGTH>>>(
                obj.shorttxids),
            obj.prefilledtxn);

        if (obj.BlockTxCount() > std::numeric_limits<uint32_t>::max()) {
            throw std::ios_base::failure("indexes overflowed 32 bits");
        }

        if constexpr (ser_action.ForRead()) {
            obj.FillShortTxIDSelector();
        }
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txns_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0;
    CTxMemPool *pool;
    const Config *config;

public:
    CBlockHeader header;

    // Can be overriden with a mock block checker for testing (if nullptr, we use real CheckBlock() from validation.h)
    using CheckBlockFn = std::function<bool(const CBlock &block, CValidationState &state,
                                            const Consensus::Params &params, BlockValidationOptions validationOptions,
                                            uint64_t *)>;
    CheckBlockFn m_check_block_mock{nullptr};

    PartiallyDownloadedBlock(const Config &configIn, CTxMemPool *poolIn)
        : pool(poolIn), config(&configIn) {}

    // extra_txn is a list of extra transactions to look at, in <txhash,
    // reference> form.
    ReadStatus
    InitData(const CBlockHeaderAndShortTxIDs &cmpctblock,
             const std::vector<std::pair<TxHash, CTransactionRef>> &extra_txn);
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock &block,
                         const std::vector<CTransactionRef> &vtx_missing);
};
