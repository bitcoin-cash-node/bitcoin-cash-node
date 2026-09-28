// Copyright (c) 2023 The Bitcoin Core developers
// Copyright (c) 2024-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <txmempool.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <vector>

PartiallyDownloadedBlock::CheckBlockFn FuzzedCheckBlock(std::optional<unsigned> result) {
    return [result](const CBlock&, CValidationState& state, const Consensus::Params&, BlockValidationOptions, uint64_t *) {
        if (result) {
            return state.Invalid(false, *result);
        }

        return true;
    };
}

void test_one_input(Span<const uint8_t> buffer) {
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto block{ConsumeDeserializable<CBlock>(fuzzed_data_provider)};
    if (!block || block->vtx.size() == 0 || block->vtx.size() >= std::numeric_limits<uint32_t>::max()) {
        return;
    }

    CBlockHeaderAndShortTxIDs cmpctblock{*block};

    CTxMemPool pool;
    pool.setSanityCheck(1.0);
    DummyConfig config;
    PartiallyDownloadedBlock pdb{config, &pool};

    // Set of available transactions (mempool or extra_txn)
    std::set<uint32_t> available;
    // The coinbase is always available
    available.insert(0);

    std::vector<std::pair<TxHash, CTransactionRef>> extra_txn;
    for (size_t i = 1; i < block->vtx.size(); ++i) {
        auto tx{block->vtx[i]};

        bool add_to_extra_txn{fuzzed_data_provider.ConsumeBool()};
        bool add_to_mempool{fuzzed_data_provider.ConsumeBool()};

        if (add_to_extra_txn) {
            extra_txn.emplace_back(tx->GetHash(), tx);
            available.insert(i);
        }

        if (add_to_mempool && !pool.exists(tx->GetId())) {
            LOCK2(cs_main, pool.cs);
            pool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, *tx));
            available.insert(i);
        }
    }

    auto init_status{pdb.InitData(cmpctblock, extra_txn)};

    std::vector<CTransactionRef> missing;
    // Whether we skipped a transaction that should be included in `missing`.
    // FillBlock should never return READ_STATUS_OK if that is the case.
    bool skipped_missing{false};
    for (size_t i = 0; i < cmpctblock.BlockTxCount(); ++i) {
        // If init_status == READ_STATUS_OK then a available transaction in the
        // compact block (i.e. IsTxAvailable(i) == true) implies that we marked
        // that transaction as available above (i.e. available.count(i) > 0).
        // The reverse is not true, due to possible compact block short id
        // collisions (i.e. available.count(i) > 0 does not imply
        // IsTxAvailable(i) == true).
        if (init_status == READ_STATUS_OK) {
            assert(!pdb.IsTxAvailable(i) || available.count(i) > 0);
        }

        bool skip{fuzzed_data_provider.ConsumeBool()};
        if (!pdb.IsTxAvailable(i) && !skip) {
            missing.push_back(block->vtx[i]);
        }

        skipped_missing |= (!pdb.IsTxAvailable(i) && skip);
    }

    // Mock CheckBlock
    bool fail_check_block{fuzzed_data_provider.ConsumeBool()};
    auto validation_result =
        fuzzed_data_provider.PickValueInArray({REJECT_INVALID,
                                               REJECT_OBSOLETE,
                                               REJECT_CHECKPOINT});
    pdb.m_check_block_mock = FuzzedCheckBlock(
        fail_check_block ?
            std::optional<unsigned>{validation_result} :
            std::nullopt);

    CBlock reconstructed_block;
    auto fill_status{pdb.FillBlock(reconstructed_block, missing)};
    switch (fill_status) {
    case READ_STATUS_OK:
        assert(!skipped_missing);
        assert(!fail_check_block);
        assert(block->GetHash() == reconstructed_block.GetHash());
        break;
    case READ_STATUS_CHECKBLOCK_FAILED: [[fallthrough]];
    case READ_STATUS_FAILED:
        assert(fail_check_block);
        break;
    case READ_STATUS_INVALID:
        break;
    }
}
