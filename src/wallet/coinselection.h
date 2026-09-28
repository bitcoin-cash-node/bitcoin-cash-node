// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2019-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <amount.h>
#include <primitives/transaction.h>
#include <random.h>

//! target minimum change amount
static constexpr Amount MIN_CHANGE{COIN / 100};
//! final minimum change amount after paying for fees
static constexpr Amount MIN_FINAL_CHANGE = MIN_CHANGE / 2;

//! Hint on what attributes to prioritize when performing coin selection.
enum class CoinSelectionHint {
    //! The default case all-around coin selection algorithm.
    Default = 0,

    //! Over all other features, prioritize speed.
    Fast = 1,

    //! Value reserved for future algorithm that prioritizes speed.
    FastReserved = 2,

    //! Largest value in this enum represents invalid.
    Invalid = 3
};

inline bool IsValidCoinSelectionHint(int c) {
    return c >= static_cast<int>(CoinSelectionHint::Default)
        && c < static_cast<int>(CoinSelectionHint::Invalid);
}

class CInputCoin {
    CInputCoin(const COutPoint &op) : outpoint{op} {}
public:
    CInputCoin(const CTransactionRef &tx, unsigned int i, int input_bytes = -1, bool use_max_sig = false)
        : m_input_bytes{input_bytes}, m_use_max_sig{use_max_sig} {
        if (!tx) {
            throw std::invalid_argument("tx should not be null");
        }
        if (i >= tx->vout.size()) {
            throw std::out_of_range("The output index is out of range");
        }

        outpoint = COutPoint(tx->GetId(), i);
        txout = tx->vout[i];
        effective_value = txout.nValue;
    }

    static CInputCoin MakeDummyForSetLookup(const COutPoint &op) { return CInputCoin(op); }

    COutPoint outpoint;
    CTxOut txout;
    Amount effective_value;

    /**
     * Pre-computed estimated size of this output as a fully-signed input in a
     * transaction. Can be -1 if it could not be calculated.
     */
    int m_input_bytes{-1};
    /**
     * Flag used to fee estimation only -- if this is true then the coin is known to be externally signed
     * (watching only) and maximal sizes should be used for the input coin for fee estimation purposes. Comes from
     * the correspondig field COutput::use_max_sig
     */
    bool m_use_max_sig = false;

    bool operator<(const CInputCoin &rhs) const {
        return outpoint < rhs.outpoint;
    }

    bool operator!=(const CInputCoin &rhs) const {
        return outpoint != rhs.outpoint;
    }

    bool operator==(const CInputCoin &rhs) const {
        return outpoint == rhs.outpoint;
    }
};

struct CoinEligibilityFilter {
    /** Minimum number of confirmations for outputs that we sent to ourselves.
     *  We may use unconfirmed UTXOs sent from ourselves, e.g. change outputs. */
    const int conf_mine;
    /** Minimum number of confirmations for outputs received from a different wallet. */
    const int conf_theirs;

    CoinEligibilityFilter(int conf_mine_, int conf_theirs_)
        : conf_mine(conf_mine_), conf_theirs(conf_theirs_) {}
};

struct OutputGroup {
    std::vector<CInputCoin> m_outputs;
    bool m_from_me{true};
    Amount m_value = Amount::zero();
    int m_depth{999};
    Amount effective_value = Amount::zero();
    Amount fee = Amount::zero();
    Amount long_term_fee = Amount::zero();

    OutputGroup() {}
    OutputGroup(std::vector<CInputCoin> &&outputs, bool from_me, Amount value, int depth)
        : m_outputs(std::move(outputs)), m_from_me(from_me), m_value(value), m_depth(depth) {}
    OutputGroup(const CInputCoin &output, int depth, bool from_me)
        : OutputGroup() {
        Insert(output, depth, from_me);
    }
    void Insert(const CInputCoin &output, int depth, bool from_me);
    std::vector<CInputCoin>::iterator Discard(const CInputCoin &output);
    bool EligibleForSpending(const CoinEligibilityFilter &eligibility_filter) const;
};

bool SelectCoinsBnB(std::vector<OutputGroup> &utxo_pool,
                    const Amount &target_value, const Amount &cost_of_change,
                    std::set<CInputCoin> &out_set, Amount &value_ret,
                    const Amount not_input_fees);

// Original coin selection algorithm as a fallback
bool KnapsackSolver(const Amount nTargetValue, std::vector<OutputGroup> &groups,
                    std::set<CInputCoin> &setCoinsRet, Amount &nValueRet);
