// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (C) 2021 Fernando Pelliccioni <fpelliccioni@gmail.com>
// Copyright (C) 2022 The Bitcoin developers
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <dsproof/dsproof.h>
#include <logging.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sigencoding.h>
#include <script/standard.h>
#include <txmempool.h>
#include <validation.h> // for pcoinsTip

#include <stdexcept>
#include <vector>

namespace {
class DSPSignatureChecker : public BaseSignatureChecker {
public:
    DSPSignatureChecker(const DoubleSpendProof *proof, const DoubleSpendProof::Spender &spender, const CTxOut &txOut)
        : m_proof(proof),
          m_spender(spender),
          m_txout(txOut)
    {
    }

    bool CheckSig(const ByteView &vchSigIn, const std::vector<uint8_t> &vchPubKey, const ByteView &scriptCode,
                  uint32_t flags, size_t *pbytesHashed) const override {
        if (pbytesHashed) *pbytesHashed = 0;
        CPubKey pubkey(vchPubKey);
        if (!pubkey.IsValid())
            return false;

        ByteView vchSig(vchSigIn);
        if (vchSig.empty())
            return false;
        const SigHashType sigHashType = GetHashType(vchSig);
        vchSig = vchSig.first(vchSig.size() - 1); // drop the hashtype byte tacked on to the end of the signature

        CHashWriter ss(SER_GETHASH, 0);
        ss << m_spender.txVersion << m_spender.hashPrevOutputs << m_spender.hashSequence;
        ss << m_proof->outPoint();
        if (m_txout.tokenDataPtr && (flags & SCRIPT_ENABLE_TOKENS)) {
            // New! For tokens (Upgrade9). If we had tokenData we inject it as a blob of:
            //    token::PREFIX_BYTE + ser_token_data
            // right *before* scriptCode's length byte.  This *intentionally* makes it so that unupgraded software
            // cannot send tokens (and thus cannot unintentionally burn tokens).
            //
            // Note: The serialization operation for token::OutputData may throw if the data it is serializing is not
            // sane.  The data will always be sane when verifying or producing sigs in production. However, the below
            // may throw in tests that intentionally sabotage the tokenData to be inconsistent.
            ss << token::PREFIX_BYTE << *m_txout.tokenDataPtr;
        }
        WriteCompactSize(ss, scriptCode.size());
        ss << scriptCode;
        ss << m_txout.nValue << m_spender.outSequence << m_spender.hashOutputs;
        ss << m_spender.lockTime << sigHashType;
        const uint256 sighash = ss.GetHash();
        if (pbytesHashed) *pbytesHashed = ss.GetNumBytesWritten();

        if (vchSig.size() == 64)
            return pubkey.VerifySchnorr(sighash, vchSig);
        return pubkey.VerifyECDSA(sighash, vchSig);
    }
    bool CheckLockTime(const CScriptNum&) const override {
        return true;
    }
    bool CheckSequence(const CScriptNum&) const override {
        return true;
    }

    const DoubleSpendProof *m_proof;
    const DoubleSpendProof::Spender &m_spender;
    const CTxOut &m_txout;

};
} // namespace

auto DoubleSpendProof::validate(const CTxMemPool &mempool, CTransactionRef spendingTx) const -> Validity
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    const uint32_t scriptFlags = GetMemPoolScriptFlags(::Params().GetConsensus(), ::ChainActive().Tip());

    try {
        // This ensures not empty and that all pushData vectors have exactly 1 item, among other things.
        checkSanityOrThrow(scriptFlags);
    } catch (const std::runtime_error &e) {
        LogPrint(BCLog::DSPROOF, "DoubleSpendProof::%s: %s\n", __func__, e.what());
        return Invalid;
    }

    // Check if ordering is proper
    int32_t diff = m_spender1.hashOutputs.Compare(m_spender2.hashOutputs);
    if (diff == 0)
        diff = m_spender1.hashPrevOutputs.Compare(m_spender2.hashPrevOutputs);
    if (diff > 0)
        return Invalid; // non-canonical order

    // Get the previous output we are spending.
    Coin coin;
    {
        const CCoinsViewMemPool view(pcoinsTip.get(), mempool); // this checks both mempool coins and confirmed coins
        if (!view.GetCoin(outPoint(), coin)) {
            /* if the output we spend is missing then either the tx just got mined
             * or, more likely, our mempool just doesn't have it.
             */
            return MissingUTXO;
        }
    }
    const CTxOut &txOut = coin.GetTxOut();
    const CScript &prevOutScript = coin.GetTxOut().scriptPubKey;

    if (!prevOutScript.IsPayToPubKeyHash()) {
        /*
         * TomZ: At this point (2019-07) we only support P2PKH payments.
         */
        LogPrint(BCLog::DSPROOF, "DoubleSpendProof failed validation: not a P2PKH input\n");
        return Invalid;
    }

    /*
     * Find the matching transaction spending this. Possibly identical to one
     * of the sides of this DSP.
     * We need this because we want the public key that it contains.
     */
    if (!spendingTx) {
        auto it = mempool.mapNextTx.find(m_outPoint);
        if (it == mempool.mapNextTx.end())
            return MissingTransaction;

        spendingTx = mempool.get(it->second->GetId());
    }
    assert(bool(spendingTx));

    std::vector<uint8_t> pubkey;
    for (const auto &vin : spendingTx->vin) {
        if (vin.prevout == m_outPoint) {
            // Found the input script we need!
            const CScript &inScript = vin.scriptSig;
            auto scriptIter = inScript.begin();
            opcodetype type;
            inScript.GetOp(scriptIter, type); // P2PKH: first signature
            inScript.GetOp(scriptIter, type, pubkey); // then pubkey
            break;
        }
    }

    if (pubkey.empty())
        return Invalid;

    CScript inScript;
    inScript << m_spender1.pushData.front();
    inScript << pubkey;
    DSPSignatureChecker checker1(this, m_spender1, txOut);
    ScriptError error;
    ScriptExecutionMetrics metrics; // dummy

    if ( ! VerifyScript(inScript, prevOutScript, scriptFlags, checker1, metrics, &error)) {
        LogPrint(BCLog::DSPROOF, "DoubleSpendProof failed validating first tx due to %s\n", ScriptErrorString(error));
        return Invalid;
    }

    inScript.clear();
    inScript << m_spender2.pushData.front();
    inScript << pubkey;
    DSPSignatureChecker checker2(this, m_spender2, txOut);
    if ( ! VerifyScript(inScript, prevOutScript, scriptFlags, checker2, metrics, &error)) {
        LogPrint(BCLog::DSPROOF, "DoubleSpendProof failed validating second tx due to %s\n", ScriptErrorString(error));
        return Invalid;
    }
    return Valid;
}

/* static */
bool DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(const CTxMemPool &mempool, const CTransaction &tx,
                                                            bool *pProtected)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    if (pProtected) *pProtected = false;
    if (tx.vin.empty() || tx.IsCoinBase()) {
        return false;
    }

    const CCoinsViewMemPool view(pcoinsTip.get(), mempool); // this checks both mempool coins and confirmed coins

    // Check all inputs
    bool foundUnprotected = false;
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        const auto & txin = tx.vin[nIn];
        Coin coin;
        if (!view.GetCoin(txin.prevout, coin)) {
            // if the Coin this tx spends is missing then either this tx just got mined or our mempool + blockchain
            // view just doesn't have the coin.
            return false;
        }
        const CTxOut &txOut = coin.GetTxOut();
        if (!txOut.scriptPubKey.IsPayToPubKeyHash()) {
            // For now, dsproof only supports P2PKH
            return false;
        }
        SigHashType h{uint32_t(0)};
        try {
            h = GetHashType(getP2PKHSignature(tx, nIn, coin.GetTxOut()));
        } catch (const std::runtime_error &) {
            // exceptions ignored, means we couldn't grab signature and this is non-canonical in some way
        }
        if (!h.hasFork()) {
            // this can happen if it's non-canonical in some way or if it's unsupported
            return false;
        }
        foundUnprotected = foundUnprotected || h.hasAnyoneCanPay() || h.getBaseType() != BaseSigHashType::ALL;
    }

    if (pProtected) *pProtected = !foundUnprotected;
    return true;
}
