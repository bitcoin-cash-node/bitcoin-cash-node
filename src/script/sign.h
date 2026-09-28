// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/sighashtype.h>
#include <streams.h>

class CKey;
class CKeyID;
class CMutableTransaction;
class CScript;
class ScriptID;
class CTransaction;

struct KeyOriginInfo {
    uint8_t fingerprint[4];
    std::vector<uint32_t> path;
};

/** An interface to be implemented by keystores that support signing. */
class SigningProvider {
public:
    virtual ~SigningProvider() {}
    virtual bool GetCScript(const ScriptID &scriptid, CScript &script) const {
        return false;
    }
    virtual bool HaveCScript(const ScriptID &scriptid) const { return false; }
    virtual bool GetPubKey(const CKeyID &address, CPubKey &pubkey) const {
        return false;
    }
    virtual bool GetKey(const CKeyID &address, CKey &key) const {
        return false;
    }
    virtual bool HaveKey(const CKeyID &address) const { return false; }
    virtual bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const {
        return false;
    }
};

extern const SigningProvider &DUMMY_SIGNING_PROVIDER;

class HidingSigningProvider : public SigningProvider {
private:
    const bool m_hide_secret;
    const bool m_hide_origin;
    const SigningProvider *m_provider;

public:
    HidingSigningProvider(const SigningProvider *provider, bool hide_secret,
                          bool hide_origin)
        : m_hide_secret(hide_secret), m_hide_origin(hide_origin),
          m_provider(provider) {}
    bool GetCScript(const ScriptID &scriptid, CScript &script) const override;
    bool GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const override;
    bool GetKey(const CKeyID &keyid, CKey &key) const override;
    bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const override;
};

struct FlatSigningProvider final : public SigningProvider {
    std::map<ScriptID, CScript> scripts;
    std::map<CKeyID, CPubKey> pubkeys;
    std::map<CKeyID, KeyOriginInfo> origins;
    std::map<CKeyID, CKey> keys;

    bool GetCScript(const ScriptID &scriptid, CScript &script) const override;
    bool GetPubKey(const CKeyID &keyid, CPubKey &pubkey) const override;
    bool GetKeyOrigin(const CKeyID &keyid, KeyOriginInfo &info) const override;
    bool GetKey(const CKeyID &keyid, CKey &key) const override;
};

FlatSigningProvider Merge(const FlatSigningProvider &a,
                          const FlatSigningProvider &b);

/** Interface for signature creators. */
class BaseSignatureCreator {
public:
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker &Checker() const = 0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider &provider,
                           std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                           const CScript &scriptCode, uint32_t scriptFlags) const = 0;

    ///! If true, we are signing with Schnorr
    virtual bool IsSchnorr() const { return false; }
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator {
    const ScriptExecutionContext &context;
    SigHashType sigHashType;
    const bool signSchnorr;
    const TransactionSignatureChecker checker;

public:
    // NB: if `context.isLimited()`, then we won't be able to sign SIGHASH_UTXOS
    explicit TransactionSignatureCreator(const ScriptExecutionContext &context, SigHashType sigHashTypeIn, bool signSchnorr);
    const BaseSignatureChecker &Checker() const override { return checker; }
    bool CreateSig(const SigningProvider &provider,
                   std::vector<uint8_t> &vchSig, const CKeyID &keyid,
                   const CScript &scriptCode, uint32_t scriptFlags) const override;
    bool IsSchnorr() const override { return signSchnorr; }
};

/** A signature creator that just produces 71-byte empty signatures. */
extern const BaseSignatureCreator &DUMMY_SIGNATURE_CREATOR;
/** A signature creator that just produces 72-byte empty signatures. */
extern const BaseSignatureCreator &DUMMY_MAXIMUM_SIGNATURE_CREATOR;
/** A signature creator that just produces 65-byte empty signatures. */
extern const BaseSignatureCreator &DUMMY_SCHNORR_SIGNATURE_CREATOR;

typedef std::pair<CPubKey, std::vector<uint8_t>> SigPair;

// This struct contains information from a transaction input and also contains
// signatures for that input. The information contained here can be used to
// create a signature and is also filled by ProduceSignature in order to
// construct final scriptSigs.
struct SignatureData {
    /// Stores whether the scriptSig are complete.
    bool complete = false;
    /// Filled-in by ProduceSignature to indicate that this was a multisig with mixed ECDSA and Schnorr sigs
    /// Normally if this is true, then `complete` is false
    bool hadBothSchnorrAndEcdsaInMultisig = false;
    /// The scriptSig of an input. Contains complete signatures or the
    /// traditional partial signatures format.
    CScript scriptSig;
    /// The redeemScript (if any) for the input.
    CScript redeem_script;
    /// BIP 174 style partial signatures for the input. May contain all
    /// signatures necessary for producing a final scriptSig.
    std::map<CKeyID, SigPair> signatures;
    std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>> misc_pubkeys;

    SignatureData() {}
    explicit SignatureData(const CScript &script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};

// Takes a stream and multiple arguments and serializes them as if first
// serialized into a vector and then into the stream. The resulting output into
// the stream has the total serialized length of all of the objects followed by
// all objects concatenated with each other.
template <typename Stream, typename... X>
void SerializeToVector(Stream &s, const X &... args) {
    WriteCompactSize(s, GetSerializeSizeMany(s.GetVersion(), args...));
    SerializeMany(s, args...);
}

// Takes a stream and multiple arguments and unserializes them first as a vector
// then each object individually in the order provided in the arguments.
template <typename Stream, typename... X>
void UnserializeFromVector(Stream &s, X &... args) {
    size_t expected_size = ReadCompactSize(s);
    size_t remaining_before = s.size();
    UnserializeMany(s, args...);
    size_t remaining_after = s.size();
    if (remaining_after + expected_size != remaining_before) {
        throw std::ios_base::failure("Size of value was not the stated size");
    }
}

// Deserialize HD keypaths into a map
template <typename Stream>
void DeserializeHDKeypaths(Stream &s, const std::vector<uint8_t> &key,
                           std::map<CPubKey, KeyOriginInfo> &hd_keypaths) {
    // Make sure that the key is the size of pubkey + 1
    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 &&
        key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
        throw std::ios_base::failure(
            "Size of key was not the expected size for the type BIP32 keypath");
    }
    // Read in the pubkey from key
    CPubKey pubkey(key.begin() + 1, key.end());
    if (!pubkey.IsFullyValid()) {
        throw std::ios_base::failure("Invalid pubkey");
    }
    if (hd_keypaths.count(pubkey) > 0) {
        throw std::ios_base::failure(
            "Duplicate Key, pubkey derivation path already provided");
    }

    // Read in key path
    uint64_t value_len = ReadCompactSize(s);
    if (value_len % 4 || value_len == 0) {
        throw std::ios_base::failure("Invalid length for HD key path");
    }

    KeyOriginInfo keypath;
    s >> keypath.fingerprint;
    for (unsigned int i = 4; i < value_len; i += sizeof(uint32_t)) {
        uint32_t index;
        s >> index;
        keypath.path.push_back(index);
    }

    // Add to map
    hd_keypaths.emplace(pubkey, std::move(keypath));
}

// Serialize HD keypaths to a stream from a map
template <typename Stream>
void SerializeHDKeypaths(Stream &s,
                         const std::map<CPubKey, KeyOriginInfo> &hd_keypaths,
                         uint8_t type) {
    for (const auto &keypath_pair : hd_keypaths) {
        if (!keypath_pair.first.IsValid()) {
            throw std::ios_base::failure("Invalid CPubKey being serialized");
        }
        SerializeToVector(s, type, Span{keypath_pair.first});
        WriteCompactSize(s, (keypath_pair.second.path.size() + 1) * sizeof(uint32_t));
        s << keypath_pair.second.fingerprint;
        for (const auto &path : keypath_pair.second.path) {
            s << path;
        }
    }
}

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const SigningProvider &provider,
                      const BaseSignatureCreator &creator,
                      const CScript &scriptPubKey, SignatureData &sigdata,
                      uint32_t scriptFlags);

/** Produce a script signature for a transaction. */
bool SignSignature(const SigningProvider &provider, const CScript &fromPubKey,
                   CMutableTransaction &txTo, unsigned int nIn,
                   const CTxOut &prevTxOut, SigHashType sigHashType,
                   uint32_t scriptFlags, ScriptExecutionContextOpt const& context, bool signSchnorr);

bool SignSignature(const SigningProvider &provider, const CTransaction &txFrom,
                   CMutableTransaction &txTo, unsigned int nIn,
                   SigHashType sigHashType, uint32_t scriptFlags, ScriptExecutionContextOpt const& context,
                   bool signSchnorr);

/** Extract signature data from a transaction input, and insert it. */
SignatureData DataFromTransaction(const ScriptExecutionContext &context, uint32_t scriptFlags);
void UpdateInput(CTxIn &input, const SignatureData &data);

/**
 * Check whether we know how to sign for an output like this, assuming we have
 * all private keys. While this function does not need private keys, the passed
 * keystore is used to look up public keys and redeemscripts by hash.
 * Solvability is unrelated to whether we consider this output to be ours.
 */
bool IsSolvable(const SigningProvider &provider, const CScript &script, uint32_t scriptFlags);

/**
 *  Utility function to generate an error message appropriate for complaining that a signed or partially signed
 *  multisig input mixed Schnorr and ECDSA. Intented to be returned as an RPC error message or used by bitcoin-tx.
 */
std::string MakeHadBothSchnorrAndEcdsaInMultisigErrorMessage(unsigned input, bool nodeIsSchnorr, bool nodeDidAddSigs);
