// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (c) 2021-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dsproof/dsproof.h>
#include <hash.h>
#include <script/script_error.h>
#include <script/sigencoding.h>
#include <tinyformat.h>

#include <limits>
#include <stdexcept>

/* static */
bool DoubleSpendProof::s_enabled = true;

bool DoubleSpendProof::isEmpty() const
{
    // NB: default constructed COutPout has GetN() == 0xffffffff, GetTxId().IsNull().
    return prevOutIndex() > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())
            || prevTxId().IsNull() || GetId().IsNull();
}

void DoubleSpendProof::setHash()
{
    m_hash = SerializeHash(*this);
}

void DoubleSpendProof::checkSanityOrThrow(uint32_t scriptFlags) const
{
    if (isEmpty())
        throw std::runtime_error("DSProof is empty");

    // Check limits for both pushData vectors above
    for (auto *pushData : {&m_spender1.pushData, &m_spender2.pushData}) {
        // Message must contain exactly 1 pushData
        if (pushData->size() != 1)
            throw std::runtime_error("DSProof must contain exactly 1 pushData");
        const auto &vchSig = pushData->front();
        // Push data cannot be empty
        if (vchSig.empty())
            throw std::runtime_error("DSProof signature is empty");
        // Push data must actually just be a valid p2pkh ECDSA or Schnorr signature (valid DER, <= 73 bytes, low-S)
        if (ScriptError serror; !CheckTransactionSignatureEncoding(vchSig, scriptFlags, &serror))
            throw std::runtime_error(strprintf("DSProof contains an invalid signature: %s", ScriptErrorString(serror)));
        // We don't (yet) support SIGHASH_UTXOS for dsproofs
        if (GetHashType(vchSig).hasUtxos())
            throw std::runtime_error("DSProof signature uses SIGHASH_UTXOS, which is unsupported for dsproofs");
    }
    if (m_spender1 == m_spender2)
        throw std::runtime_error("DSProof both spenders are the same");
}
