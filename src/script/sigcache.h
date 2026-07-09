// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <script/interpreter.h>

// DoS prevention: limit cache size to 32MB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MB)
static constexpr int64_t DEFAULT_MAX_SIG_CACHE_SIZE = 32;
// Maximum sig cache size allowed
static constexpr int64_t MAX_MAX_SIG_CACHE_SIZE = 16384;

class CPubKey;

/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 *
 * This may exhibit platform endian dependent behavior but because these are
 * nonced hashes (random) and this state is only ever used locally it is safe.
 * All that matters is local consistency.
 */
class SignatureCacheHasher {
public:
    template <uint8_t hash_select>
    uint32_t operator()(const uint256 &key) const noexcept {
        static_assert(hash_select < 8, "SignatureCacheHasher only has 8 hashes available.");
        uint32_t u;
        std::memcpy(&u, key.begin() + 4 * hash_select, 4);
        return u;
    }
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker {
private:
    bool store;

    bool IsCached(const ByteView &vchSig, const CPubKey &vchPubKey, const uint256 &sighash) const;

public:
    CachingTransactionSignatureChecker(const ScriptExecutionContext &contextIn, bool storeIn,
                                       PrecomputedTransactionData &txdataIn)
        : TransactionSignatureChecker(contextIn, txdataIn),
          store(storeIn) {}

    bool VerifySignature(const ByteView &vchSig,
                         const CPubKey &vchPubKey,
                         const uint256 &sighash) const override;

    friend class TestCachingTransactionSignatureChecker;
};

/**
 * Initialize the signature cache. Must be called once in
 * AppInitMain/BasicTestingSetup to initialize the signatureCache. Subsequent
 * calls will reset the cache and clear it. (Re)Initialization of the cache
 * should happen in the main thread before other threads are started since
 * this function takes no locks.
 */
void InitSignatureCache();
