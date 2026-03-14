// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <chainparamsbase.h>
#include <fs.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <scheduler.h>

#include <atomic>
#include <iostream>
#include <optional>
#include <type_traits>

// Enable BOOST_CHECK_EQUAL for enum class types
template <typename T>
std::ostream &operator<<(
    typename std::enable_if<std::is_enum<T>::value, std::ostream>::type &stream,
    const T &e) {
    return stream << static_cast<typename std::underlying_type<T>::type>(e);
}

/**
 * This global and the helpers that use it are not thread-safe.
 *
 * If thread-safety is needed, the global could be made thread_local (given
 * that thread_local is supported on all architectures we support) or a
 * per-thread instance could be used in the multi-threaded test.
 */
extern FastRandomContext g_insecure_rand_ctx;

/**
 * Flag to make GetRand in random.h return the same number
 */
extern bool g_mock_deterministic_tests;

static inline void SeedInsecureRand(bool deterministic = false) {
    g_insecure_rand_ctx = FastRandomContext(deterministic);
}

static inline uint32_t InsecureRand32() {
    return g_insecure_rand_ctx.rand32();
}
static inline uint256 InsecureRand256() {
    return g_insecure_rand_ctx.rand256();
}
static inline uint64_t InsecureRandBits(int bits) {
    return g_insecure_rand_ctx.randbits(bits);
}
static inline uint64_t InsecureRandRange(uint64_t range) {
    return g_insecure_rand_ctx.randrange(range);
}
static inline bool InsecureRandBool() {
    return g_insecure_rand_ctx.randbool();
}

static constexpr Amount CENT(COIN / 100);

/**
 * Basic testing setup.
 * This just configures logging and chain parameters.
 */
struct BasicTestingSetup {
    ECCVerifyHandle globalVerifyHandle;

    explicit BasicTestingSetup(
        const std::string &chainName = CBaseChainParams::MAIN);
    virtual ~BasicTestingSetup();

    fs::path SetDataDir(const std::string &name);

private:
    const fs::path m_path_root;
    //! Returns a unique path in tmp, based on username, the current time, and a random number
    static fs::path MakePathRoot();
    //! Returns the username of this process, as read from the environment
    static std::string GetUserNameFromEnv();
};

/**
 * @brief Helper mixin for struct BasicTestingSetupWithDeadlockExceptions
 */
struct EnableDeadlockExceptionsMixin {
    EnableDeadlockExceptionsMixin() noexcept;
    ~EnableDeadlockExceptionsMixin();
protected:
    static std::atomic_bool saved_g_debug_lockorder_abort;
    static std::atomic_int instance_ctr;
};

/**
 * @brief Testing setup whereby if we are compiled in Debug mode, will also make deadlock
 * detection throw exceptions (rather than abort() the app).
 */
struct BasicTestingSetupWithDeadlockExceptions : BasicTestingSetup, EnableDeadlockExceptionsMixin {
    using BasicTestingSetup::BasicTestingSetup;
};

/**
 * Testing setup that configures a complete environment.
 * Included are data directory, coins database, script check threads setup.
 */
struct TestingSetup : public BasicTestingSetup {
    CScheduler scheduler;

    explicit TestingSetup(
        const std::string &chainName = CBaseChainParams::MAIN);
    ~TestingSetup() override;

protected:
    /// Call this from subclass fixture d'tors to stop the scheduler early before deleting objects that may have work
    /// enqueued on the scheduler. Added for WalletTestingSetup to stop the scheduler before its temp wallet is deleted.
    void StopScheduler();

private:
    bool schedulerIsStopped = false;
};

class CBlock;
class CMutableTransaction;
class CScript;

//
// Testing fixture that pre-creates a
// 100-block REGTEST-mode block chain
//
struct TestChain100Setup : public TestingSetup {
    TestChain100Setup();

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction> &txns,
                                 const CScript &scriptPubKey);

    ~TestChain100Setup() override;

    // For convenience, coinbase transactions.
    std::vector<CTransactionRef> m_coinbase_txns;
    // private/public key needed to spend coinbase transactions.
    CKey coinbaseKey;
};

class CTxMemPoolEntry;

struct TestMemPoolEntryHelper {
    // Default values
    Amount nFee;
    int64_t nTime;
    bool spendsCoinbase;
    unsigned int nSigChecks;
    uint64_t entryId = 0;

    TestMemPoolEntryHelper()
        : nFee(), nTime(0), spendsCoinbase(false), nSigChecks(1) {}

    CTxMemPoolEntry FromTx(const CMutableTransaction &tx);
    CTxMemPoolEntry FromTx(const CTransactionRef &tx);

    // Change the default value
    TestMemPoolEntryHelper &Fee(Amount _fee) {
        nFee = _fee;
        return *this;
    }
    TestMemPoolEntryHelper &Time(int64_t _time) {
        nTime = _time;
        return *this;
    }
    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag) {
        spendsCoinbase = _flag;
        return *this;
    }
    TestMemPoolEntryHelper &SigChecks(unsigned int _nSigChecks) {
        nSigChecks = _nSigChecks;
        return *this;
    }
    TestMemPoolEntryHelper &EntryId(uint64_t _entryId) {
        entryId = _entryId;
        return *this;
    }
};

enum class ScriptError;

// define implicit conversions here so that these types may be used in
// BOOST_*_EQUAL
std::ostream &operator<<(std::ostream &os, const uint256 &num);
std::ostream &operator<<(std::ostream &os, const ScriptError &err);

CBlock getBlock13b8a();

/**
 * BOOST_CHECK_EXCEPTION predicates to check the specific validation error.
 * Use as
 * BOOST_CHECK_EXCEPTION(code that throws, exception type, HasReason("foo"));
 */
class HasReason {
public:
    explicit HasReason(const std::string &reason) : m_reason(reason) {}
    template <typename E>
    bool operator()(const E &e) const {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };

private:
    const std::string m_reason;
};

// Make types usable in BOOST_CHECK_* @{
namespace std {
template <typename T> requires std::is_enum_v<T>
inline std::ostream& operator<<(std::ostream& os, const T& e) {
    return os << static_cast<std::underlying_type_t<T>>(e);
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const std::optional<T>& v) {
    return v ? os << *v
             : os << "std::nullopt";
}
} // namespace std
