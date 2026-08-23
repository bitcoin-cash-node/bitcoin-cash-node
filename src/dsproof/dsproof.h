// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020-2021 Calin Culianu <calin.culianu@gmail.com>
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#pragma once

#include <chain.h> // for cs_main
#include <dsproof/dspid.h>
#include <primitives/transaction.h>
#include <primitives/txid.h>
#include <script/script.h>
#include <script/script_flags.h>
#include <serialize.h>
#include <sync.h> // for thread safety macros

class CTxMemPool;

class DoubleSpendProof
{
public:
    //! Creates an empty DoubleSpendProof
    DoubleSpendProof() = default;

    //! Creates a DoubleSpendProof for tx1 and tx2 for the given prevout.
    //!
    //! Note that this will throw if tx1 or tx2 are invalid, contain invalid
    //! signatures, don't spend prevout, etc.
    //!
    //! Argument `txOut` is the actual previous outpoint's data (used for
    //! signature verification).  Specify nullptr here to disable signature
    //! verification (for unit tests).  If this argument is nullptr, the
    //! generated proof is not guaranteed valid since signatures aren't checked.
    //!
    //! Exceptions:
    //!     std::runtime_error if creation failed
    //!     std::invalid_argument if tx1.GetHash() == tx2.GetHash()
    //! (implemented in dsproof_create.cpp)
    static DoubleSpendProof create(uint32_t scriptFlags, const CTransaction &tx1, const CTransaction &tx2,
                                   const COutPoint &prevout, const CTxOut *txOut = nullptr);

    bool isEmpty() const;

    enum Validity {
        Valid,
        MissingTransaction,
        MissingUTXO,
        Invalid
    };

    const DspId & GetId() const { return m_hash; }

    //! This *must* be called with cs_main and mempool.cs already held!
    //!
    //! Optionally, pass the spending tx for this proof, as an optimization; if
    //! no spendingTx is specified, it will be looked-up in the mempool.
    //!
    //! Exceptions: None
    //! (implemented in dsproof_validate.cpp)
    Validity validate(const CTxMemPool &mempool, CTransactionRef spendingTx = {}) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! This *must* be called with cs_main and mempool.cs already held!
    //!
    //! Checks whether a tx is compatible with dsproofs and/or whether
    //! it can have a double-spend proof generated for it for all of its
    //! inputs.
    //!
    //! For now this basically just checks:
    //!
    //! 1. That all inputs to `tx` have "known" Coins (that is, prevouts
    //!    refering to txs in the mempool or confirmed in the blockchain).
    //! 2. All inputs to `tx` are spends from p2pkh addresses.
    //!
    //! If either of the above are false, this will return false.
    //!
    //! Additionally, if `pProtected` is supplied, then it will be
    //! written-to with true to indicate that all of the transaction's
    //! inputs are SIGHASH_ALL and none are using SIGHASH_ANYONECANPAY.
    //! False will be written to `pProtected` on false return or if
    //! any inputs don't respect the "all are SIGHASH_ALL" and "none are
    //! SIGHASH_ANYONECANPAY" predicate. Note that this function may
    //! return `true` while *pProtected may be false in cases where
    //! a proof is *possible*, but it is not necessarily guaranteed to
    //! protect this transaction.
    static bool checkIsProofPossibleForAllInputsOfTx(const CTxMemPool &mempool, const CTransaction &tx,
                                                     bool *pProtected = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    const TxId & prevTxId() const { return m_outPoint.GetTxId(); }
    uint32_t prevOutIndex() const { return m_outPoint.GetN(); }
    const COutPoint & outPoint() const { return m_outPoint; }

    struct Spender {
        uint32_t txVersion = 0, outSequence = 0, lockTime = 0;
        uint256 hashPrevOutputs, hashSequence, hashOutputs;
        std::vector<std::vector<uint8_t>> pushData;
        bool operator==(const Spender &o) const {
            return txVersion == o.txVersion && outSequence == o.outSequence && lockTime == o.lockTime
                    && hashPrevOutputs == o.hashPrevOutputs && hashSequence == o.hashSequence && hashOutputs == o.hashOutputs
                    && pushData == o.pushData;
        }
        bool operator!=(const Spender &o) const { return !(*this == o); }
    };

    const Spender & spender1() const { return m_spender1; }
    const Spender & spender2() const { return m_spender2; }

    // new fashioned serialization.
    SERIALIZE_METHODS(DoubleSpendProof, obj) {
        READWRITE(obj.m_outPoint);

        READWRITE(obj.m_spender1.txVersion);
        READWRITE(obj.m_spender1.outSequence);
        READWRITE(obj.m_spender1.lockTime);
        READWRITE(obj.m_spender1.hashPrevOutputs);
        READWRITE(obj.m_spender1.hashSequence);
        READWRITE(obj.m_spender1.hashOutputs);
        READWRITE(obj.m_spender1.pushData);

        READWRITE(obj.m_spender2.txVersion);
        READWRITE(obj.m_spender2.outSequence);
        READWRITE(obj.m_spender2.lockTime);
        READWRITE(obj.m_spender2.hashPrevOutputs);
        READWRITE(obj.m_spender2.hashSequence);
        READWRITE(obj.m_spender2.hashOutputs);
        READWRITE(obj.m_spender2.pushData);

        // Calculate and save hash (only necessary to do if we are deserializing)
        SER_READ(obj, obj.setHash());
    }


    // -- Global enable/disable of the double spend proof subsystem.

    //! Returns true if this subsystem is enabled, false otherwise. The double spend proof subsystem can be disabled at
    //! startup by passing -doublespendproof=0 to bitcoind. Default is enabled.
    static bool IsEnabled() { return s_enabled; }

    //! Enable/disable the dsproof subsystem. Called by init.cpp at startup. Default is enabled. Note that this
    //! function is not thread-safe and should only be called once before threads are started to disable.
    static void SetEnabled(bool b) { s_enabled = b; }

    // Equality comparison supported
    bool operator==(const DoubleSpendProof &o) const {
        return m_outPoint == o.m_outPoint && m_spender1 == o.m_spender1 && m_spender2 == o.m_spender2
                && m_hash == o.m_hash;
    }
    bool operator!=(const DoubleSpendProof &o) const { return !(*this == o); }

private:
    COutPoint m_outPoint;           //! Serializable
    Spender m_spender1, m_spender2; //! Serializable

    DspId m_hash;                   //! In-memory only

    //! Recompute m_hash from serializable data members
    void setHash();

    /// Throws std::runtime_error if the proof breaks the sanity of:
    /// - isEmpty()
    /// - does not have exactly 1 pushData per spender vector
    /// - any pushData that is not a valid-looking signature
    /// - any pushData that uses SIGHASH_UTXOs
    /// Called from: `create()` and `validate()` (`validate()` won't throw but will return Invalid)
    void checkSanityOrThrow(uint32_t scriptFlags) const;

    //! Used by IsEnabled() and SetEnabled() static methods; default is: enabled (true)
    static bool s_enabled;

    //! Verifying signature getter. Used for production. May throw std::runtime_error()
    static std::vector<uint8_t> getP2PKHSignature(const CTransaction &tx, unsigned int inputIndex, const CTxOut &txOut);
};
