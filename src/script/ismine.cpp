// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/ismine.h>

#include <key.h>
#include <keystore.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/standard.h>

namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion {
    TOP = 0,  //! scriptPubKey execution
    P2SH = 1, //! P2SH redeemScript
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult {
    NO = 0,         //! Not ours
    WATCH_ONLY = 1, //! Included in watch-only balance
    SPENDABLE = 2,  //! Included in all balances
    INVALID = 3,    //! Not spendable by anyone (P2SH inside P2SH)
};

bool HaveKeys(const std::vector<StackVec> &pubkeys, const CKeyStore &keystore) {
    for (const StackVec &pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) {
            return false;
        }
    }
    return true;
}

IsMineResult IsMineInner(const CKeyStore &keystore, const CScript &scriptPubKey,
                         IsMineSigVersion sigversion) {
    IsMineResult ret = IsMineResult::NO;

    std::vector<StackVec> vSolutions;
    txnouttype whichType = Solver(scriptPubKey, vSolutions, SCRIPT_ENABLE_P2SH_32);

    CKeyID keyID;
    switch (whichType) {
        case TX_NONSTANDARD:
        case TX_NULL_DATA:
        case TX_SCRIPT:
            break;
        case TX_PUBKEY:
            keyID = CPubKey(vSolutions[0]).GetID();
            if (keystore.HaveKey(keyID)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        case TX_PUBKEYHASH:
            keyID = CKeyID(uint160(vSolutions[0]));
            if (keystore.HaveKey(keyID)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        case TX_SCRIPTHASH: {
            if (sigversion != IsMineSigVersion::TOP) {
                // P2SH inside P2SH is invalid.
                return IsMineResult::INVALID;
            }
            ScriptID scriptID;
            if (vSolutions[0].size() == uint160::size()) {
                // p2sh
                scriptID = uint160(vSolutions[0]);
            } else if (vSolutions[0].size() == uint256::size()) {
                // p2sh32
                scriptID = uint256(vSolutions[0]);
            } else {
                // Defensive programming: Should never happen.
                assert(!"Solver returned a script hash that is neither 20 bytes nor 32 bytes.");
            }
            CScript subscript;
            if (keystore.GetCScript(scriptID, subscript)) {
                ret = std::max(ret, IsMineInner(keystore, subscript,
                                                IsMineSigVersion::P2SH));
            }
            break;
        }
        case TX_MULTISIG: {
            // Never treat bare multisig outputs as ours (they can still be made
            // watchonly-though)
            if (sigversion == IsMineSigVersion::TOP) {
                break;
            }

            // Only consider transactions "mine" if we own ALL the keys
            // involved. Multi-signature transactions that are partially owned
            // (somebody else has a key that can spend them) enable
            // spend-out-from-under-you attacks, especially in shared-wallet
            // situations.
            std::vector<StackVec> keys(vSolutions.begin() + 1,
                                       vSolutions.begin() + vSolutions.size() -
                                          1);
            if (HaveKeys(keys, keystore)) {
                ret = std::max(ret, IsMineResult::SPENDABLE);
            }
            break;
        }
    }

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey) {
    switch (IsMineInner(keystore, scriptPubKey, IsMineSigVersion::TOP)) {
        case IsMineResult::INVALID:
        case IsMineResult::NO:
            return ISMINE_NO;
        case IsMineResult::WATCH_ONLY:
            return ISMINE_WATCH_ONLY;
        case IsMineResult::SPENDABLE:
            return ISMINE_SPENDABLE;
    }
    assert(false);
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination &dest) {
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}
