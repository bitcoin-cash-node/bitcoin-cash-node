// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/chain.h>

#include <chain.h>
#include <chainparams.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <sync.h>
#include <txmempool.h>
#include <util/system.h>
#include <validation.h>

#include <memory>
#include <utility>

namespace interfaces {
namespace {

    class LockImpl : public Chain::Lock {
        std::optional<int> getHeight() override {
            int height = ::ChainActive().Height();
            if (height >= 0) {
                return height;
            }
            return std::nullopt;
        }
        std::optional<int> getBlockHeight(const BlockHash &hash) override {
            CBlockIndex *block = LookupBlockIndex(hash);
            if (block && ::ChainActive().Contains(block)) {
                return block->nHeight;
            }
            return std::nullopt;
        }
        int getBlockDepth(const BlockHash &hash) override {
            const std::optional<int> tip_height = getHeight();
            const std::optional<int> height = getBlockHeight(hash);
            return tip_height && height ? *tip_height - *height + 1 : 0;
        }
        BlockHash getBlockHash(int height) override {
            CBlockIndex *block = ::ChainActive()[height];
            assert(block != nullptr);
            return block->GetBlockHash();
        }
        int64_t getBlockTime(int height) override {
            CBlockIndex *block = ::ChainActive()[height];
            assert(block != nullptr);
            return block->GetBlockTime();
        }
        int64_t getBlockMedianTimePast(int height) override {
            CBlockIndex *block = ::ChainActive()[height];
            assert(block != nullptr);
            return block->GetMedianTimePast();
        }
        bool haveBlockOnDisk(int height) override {
            CBlockIndex *block = ::ChainActive()[height];
            return block && (block->nStatus.hasData() != 0) && block->nTx > 0;
        }
        std::optional<int> findFirstBlockWithTime(int64_t time, BlockHash *hash) override {
            CBlockIndex *block = ::ChainActive().FindEarliestAtLeast(time);
            if (block) {
                if (hash) {
                    *hash = block->GetBlockHash();
                }
                return block->nHeight;
            }
            return std::nullopt;
        }
        std::optional<int> findFirstBlockWithTimeAndHeight(int64_t time, int height) override {
            // TODO: Could update CChain::FindEarliestAtLeast() to take a height
            // parameter and use it with std::lower_bound() to make this
            // implementation more efficient and allow combining
            // findFirstBlockWithTime and findFirstBlockWithTimeAndHeight into
            // one method.
            for (CBlockIndex *block = ::ChainActive()[height]; block;
                 block = ::ChainActive().Next(block)) {
                if (block->GetBlockTime() >= time) {
                    return block->nHeight;
                }
            }
            return std::nullopt;
        }
        std::optional<int> findPruned(int start_height, std::optional<int> stop_height) override {
            if (::fPruneMode) {
                CBlockIndex *block = stop_height ? ::ChainActive()[*stop_height]
                                                 : ::ChainActive().Tip();
                while (block && block->nHeight >= start_height) {
                    if (block->nStatus.hasData() == 0) {
                        return block->nHeight;
                    }
                    block = block->pprev;
                }
            }
            return std::nullopt;
        }
        std::optional<int> findFork(const BlockHash &hash, std::optional<int> *height) override {
            const CBlockIndex *block = LookupBlockIndex(hash);
            const CBlockIndex *fork =
                block ? ::ChainActive().FindFork(block) : nullptr;
            if (height) {
                if (block) {
                    *height = block->nHeight;
                } else {
                    height->reset();
                }
            }
            if (fork) {
                return fork->nHeight;
            }
            return std::nullopt;
        }
        bool isPotentialTip(const BlockHash &hash) override {
            if (::ChainActive().Tip()->GetBlockHash() == hash) {
                return true;
            }
            CBlockIndex *block = LookupBlockIndex(hash);
            return block && block->GetAncestor(::ChainActive().Height()) ==
                                ::ChainActive().Tip();
        }
        CBlockLocator getLocator() override {
            return ::ChainActive().GetLocator();
        }
        std::optional<int> findLocatorFork(const CBlockLocator &locator) override {
            LockAnnotation lock(::cs_main);
            if (CBlockIndex *fork =
                    FindForkInGlobalIndex(::ChainActive(), locator)) {
                return fork->nHeight;
            }
            return std::nullopt;
        }
        void findCoins(std::map<COutPoint, Coin> &coins) override {
            AssertLockHeld(cs_main);
            LOCK(g_mempool.cs);
            CCoinsViewMemPool mempool_view(pcoinsTip.get(), g_mempool);
            for (auto & [outpoint, coin] : coins) {
                if (!mempool_view.GetCoin(outpoint, coin)) {
                    coin.Clear(); // Either the coin is not in the CCoinsViewCache or is spent
                }
            }
        }
    };

    class LockingStateImpl : public LockImpl,
                             public UniqueLock<RecursiveMutex> {
        using UniqueLock::UniqueLock;
    };

    class ChainImpl : public Chain {
    public:
        std::unique_ptr<Chain::Lock> lock(bool try_lock) override {
            auto result = std::make_unique<LockingStateImpl>(
                ::cs_main, "cs_main", __FILE__, __LINE__, try_lock);
            if (try_lock && result && !*result) {
                return {};
            }
            return result;
        }
        std::unique_ptr<Chain::Lock> assumeLocked() override {
            return std::make_unique<LockImpl>();
        }
        bool findBlock(const BlockHash &hash, CBlock *block, int64_t *time,
                       int64_t *time_max) override {
            CBlockIndex *index;
            {
                LOCK(cs_main);
                index = LookupBlockIndex(hash);
                if (!index) {
                    return false;
                }
                if (time) {
                    *time = index->GetBlockTime();
                }
                if (time_max) {
                    *time_max = index->GetBlockTimeMax();
                }
            }
            if (block &&
                !ReadBlockFromDisk(*block, index, Params().GetConsensus())) {
                block->SetNull();
            }
            return true;
        }
        double guessVerificationProgress(const BlockHash &block_hash) override {
            LOCK(cs_main);
            return GuessVerificationProgress(Params().TxData(),
                                             LookupBlockIndex(block_hash));
        }
    };

} // namespace

std::unique_ptr<Chain> MakeChain() {
    return std::make_unique<ChainImpl>();
}

} // namespace interfaces
