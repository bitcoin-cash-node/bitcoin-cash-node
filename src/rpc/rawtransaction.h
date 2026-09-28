// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2020-present The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <univalue.h>

class CBasicKeyStore;
class CChainParams;
class CMutableTransaction;

namespace interfaces {
class Chain;
} // namespace interfaces

struct RPCArg;

/** Sign a transaction with the given keystore and previous transactions */
UniValue::Object SignTransaction(interfaces::Chain &chain, CMutableTransaction &mtx, const UniValue &prevTxs,
                                 CBasicKeyStore *keystore, bool tempKeystore, const UniValue &hashType, bool schnorr);

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const CChainParams &params,
                                         const UniValue &inputs_in,
                                         const UniValue &outputs_in,
                                         const UniValue &locktime);

/**
 *  Returns an RPCArg represending the alternate way to specify transaction outputs as:
 *      "address": { "amount": xx, "tokenData" : { ... } }
 *  Used by: ConstructTransaction above as an alternate way to specify outputs with token data in them.
 *  See: createrawtransaction, createpsbt, walletcreatefundedpsbt
 */
RPCArg GetAlternateAddressObjectOutputArgSpec(bool optional = true);
/** Returns an RPCArg spec for: "tokenData" : { "category": "xxx", "amount": nnn ... } */
RPCArg GetTokenDataArgSpec(bool optional = true);
