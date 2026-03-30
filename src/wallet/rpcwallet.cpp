// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <chain.h>
#include <chainparams.h> // for GetConsensus.
#include <config.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <init.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <net.h>
#include <outputtype.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <rpc/mining.h>
#include <rpc/rawtransaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <shutdown.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/psbtwallet.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <univalue.h>

#include <event2/http.h>

#include <functional>
#include <optional>

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";

static std::string urlDecode(const std::string &urlEncoded) {
    std::string res;
    if (!urlEncoded.empty()) {
        char *decoded = evhttp_uridecode(urlEncoded.c_str(), false, nullptr);
        if (decoded) {
            res = std::string(decoded);
            free(decoded);
        }
    }
    return res;
}

bool GetWalletNameFromJSONRPCRequest(const JSONRPCRequest &request,
                                     std::string &wallet_name) {
    if (request.URI.substr(0, WALLET_ENDPOINT_BASE.size()) ==
        WALLET_ENDPOINT_BASE) {
        // wallet endpoint was used
        wallet_name =
            urlDecode(request.URI.substr(WALLET_ENDPOINT_BASE.size()));
        return true;
    }
    return false;
}

std::shared_ptr<CWallet>
GetWalletForJSONRPCRequest(const JSONRPCRequest &request) {
    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        std::shared_ptr<CWallet> pwallet = GetWallet(wallet_name);
        if (!pwallet) {
            throw JSONRPCError(
                RPC_WALLET_NOT_FOUND,
                "Requested wallet does not exist or is not loaded");
        }
        return pwallet;
    }

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    return wallets.size() == 1 || (request.fHelp && wallets.size() > 0)
               ? wallets[0]
               : nullptr;
}

std::string HelpRequiringPassphrase(CWallet *const pwallet) {
    return pwallet && pwallet->IsCrypted()
               ? "\nRequires wallet passphrase to be set with walletpassphrase "
                 "call."
               : "";
}

bool EnsureWalletIsAvailable(CWallet *const pwallet, bool avoidException) {
    if (pwallet) {
        return true;
    }
    if (avoidException) {
        return false;
    }
    if (!HasWallets()) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND,
                           "Method not found (wallet method is disabled "
                           "because no wallet is loaded)");
    }

    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
                       "Wallet file not specified (must request wallet RPC "
                       "through /wallet/<filename> uri-path).");
}

void EnsureWalletIsUnlocked(CWallet &wallet) {
    if (wallet.IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

static void WalletTxToJSON(interfaces::Chain &chain,
                           interfaces::Chain::Lock &locked_chain,
                           const CWalletTx &wtx, UniValue::Object &entry) {
    int confirms = wtx.GetDepthInMainChain(locked_chain);
    entry.emplace_back("confirmations", confirms);
    if (wtx.IsCoinBase()) {
        entry.emplace_back("generated", true);
    }
    if (confirms > 0) {
        entry.emplace_back("blockhash", wtx.hashBlock.GetHex());
        entry.emplace_back("blockindex", wtx.nIndex);
        int64_t block_time;
        bool found_block =
            chain.findBlock(wtx.hashBlock, nullptr /* block */, &block_time);
        assert(found_block);
        entry.emplace_back("blocktime", block_time);
    } else {
        entry.emplace_back("trusted", wtx.IsTrusted(locked_chain));
    }
    uint256 hash = wtx.GetId();
    entry.emplace_back("txid", hash.GetHex());
    UniValue::Array conflicts;
    for (const uint256 &conflict : wtx.GetConflicts()) {
        conflicts.push_back(conflict.GetHex());
    }
    entry.emplace_back("walletconflicts", std::move(conflicts));
    entry.emplace_back("time", wtx.GetTxTime());
    entry.emplace_back("timereceived", (int64_t)wtx.nTimeReceived);

    for (const std::pair<const std::string, std::string> &item : wtx.mapValue) {
        entry.emplace_back(item.first, item.second);
    }
}

static std::string LabelFromValue(const UniValue &value) {
    std::string label = value.get_str();
    if (label == "*") {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "Invalid label name");
    }
    return label;
}

static UniValue getnewaddress(const Config &config,
                              const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getnewaddress",
                "\nReturns a new Bitcoin Cash address for receiving payments.\n"
                "If 'label' is specified, it is added to the address book\n"
                "so payments received with the address will be associated with 'label'.\n",
                {
                    {"label", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "The label name for the address to be linked to. If not provided, the default label \"\" is used. It can also be set to the empty string \"\" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name."},
                }}
                .ToString() +
            "\nResult:\n"
            "\"address\"    (string) The new Bitcoin Cash address\n"
            "\nExamples:\n" +
            HelpExampleRpc("getnewaddress", ""));
    }

    // Belt and suspenders check for disabled private keys
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: Private keys are disabled for this wallet");
    }

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: This wallet has no available keys");
    }

    // Parse the label first so we don't generate a key if there's an error
    std::string label;
    if (!request.params[0].isNull()) {
        label = LabelFromValue(request.params[0]);
    }

    OutputType output_type = pwallet->m_default_address_type;
    if (!request.params[1].isNull()) {
        if (!ParseOutputType(request.params[1].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               strprintf("Unknown address type '%s'",
                                         request.params[1].get_str()));
        }
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(
            RPC_WALLET_KEYPOOL_RAN_OUT,
            "Error: Keypool ran out, please call keypoolrefill first");
    }
    pwallet->LearnRelatedScripts(newKey, output_type);
    CTxDestination dest = GetDestinationForKey(newKey, output_type);

    pwallet->SetAddressBook(dest, label, "receive");

    return EncodeDestination(dest, config);
}

static UniValue getrawchangeaddress(const Config &config,
                                    const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"getrawchangeaddress",
                "\nReturns a new Bitcoin Cash address for receiving change.\n"
                "This is for use with raw transactions, NOT normal use.\n",
                {}}
                .ToString() +
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n" +
            HelpExampleCli("getrawchangeaddress", "") +
            HelpExampleRpc("getrawchangeaddress", ""));
    }

    // Belt and suspenders check for disabled private keys
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: Private keys are disabled for this wallet");
    }

    LOCK(pwallet->cs_wallet);

    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: This wallet has no available keys");
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    OutputType output_type =
        pwallet->m_default_change_type != OutputType::CHANGE_AUTO
            ? pwallet->m_default_change_type
            : pwallet->m_default_address_type;
    if (!request.params[0].isNull()) {
        if (!ParseOutputType(request.params[0].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               strprintf("Unknown address type '%s'",
                                         request.params[0].get_str()));
        }
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true)) {
        throw JSONRPCError(
            RPC_WALLET_KEYPOOL_RAN_OUT,
            "Error: Keypool ran out, please call keypoolrefill first");
    }

    reservekey.KeepKey();

    pwallet->LearnRelatedScripts(vchPubKey, output_type);
    CTxDestination dest = GetDestinationForKey(vchPubKey, output_type);

    return EncodeDestination(dest, config);
}

static UniValue setlabel(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            RPCHelpMan{"setlabel",
                "\nSets the label associated with the given address.\n",
                {
                    {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address to be associated with a label."},
                    {"label", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The label to assign to the address."},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("setlabel", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"tabby\"")
            + HelpExampleRpc("setlabel", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"tabby\"")
        );
    }

    LOCK(pwallet->cs_wallet);

    CTxDestination dest =
        DecodeDestination(request.params[0].get_str(), config.GetChainParams());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid Bitcoin Cash address");
    }

    std::string old_label = pwallet->mapAddressBook[dest].name;
    std::string label = LabelFromValue(request.params[1]);

    if (IsMine(*pwallet, dest)) {
        pwallet->SetAddressBook(dest, label, "receive");
    } else {
        pwallet->SetAddressBook(dest, label, "send");
    }

    return UniValue();
}

static CTransactionRef SendMoney(interfaces::Chain::Lock &locked_chain,
                                 CWallet *const pwallet,
                                 const CTxDestination &address, Amount nValue,
                                 bool fSubtractFeeFromAmount,
                                 const CCoinControl &coinControl,
                                 mapValue_t mapValue, CoinSelectionHint coinsel) {
    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    // Parse Bitcoin Cash address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    Amount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, {}, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    CTransactionRef tx;
    auto rc = pwallet->CreateTransaction(locked_chain, vecSend, tx, reservekey,
                                         nFeeRequired, nChangePosRet, strError,
                                         coinControl, true, coinsel);
    if (rc == CreateTransactionResult::CT_INVALID_PARAMETER) {
        if (nValue <= Amount::zero()) {
            // We override the string in this one for backward compatibility.
            // TODO: Remove this special case when string translation is
            //       removed from CWallet.
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
    } else if (rc == CreateTransactionResult::CT_INSUFFICIENT_FUNDS) {
        // The following check is kind of awkward, but is there for backwards
        // compatibility. We take a performance hit here, calling the expensive
        // GetBalance, to _maybe_ provide an improved error message on
        // insufficient fee.
        if (!fSubtractFeeFromAmount) {
            Amount curBalance = pwallet->GetBalance();
            if (nValue <= curBalance && nValue + nFeeRequired > curBalance) {
                strError = strprintf("Error: This transaction requires a "
                                     "transaction fee of at least %s",
                                     FormatMoney(nFeeRequired));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }
        }
        // We override the error message for backward compatibility.
        // TODO: Don't override after string translation in removed from
        //       CWallet
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
    } else {
        if (rc != CreateTransactionResult::CT_OK) {
            throw JSONRPCError(RPC_WALLET_ERROR, strError);
        }
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */,
                                    reservekey, g_connman.get(), state)) {
        strError =
            strprintf("Error: The transaction was rejected! Reason given: %s",
                      FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    return tx;
}

static UniValue sendtoaddress(const Config &config,
                              const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 2 ||
        request.params.size() > 7) {
        throw std::runtime_error(
            RPCHelpMan{"sendtoaddress",
                "\nSend an amount to a given address." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address to send to."},
                    {"amount", RPCArg::Type::AMOUNT, /* opt */ false, /* default_val */ "", "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
                    {"comment", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "A comment used to store what the transaction is for.\n"
            "                             This is not part of the transaction, just kept in your wallet."},
                    {"comment_to", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "A comment to store the name of the person or organization\n"
            "                             to which you're sending the transaction. This is not part of the\n"
            "                             transaction, just kept in your wallet."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field."},
                    {"coinsel", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0",
                        "Which coin selection algorithm to use. A value of 1 will use a faster algorithm "
                        "suitable for stress tests or use with large wallets. "
                        "This algorithm is likely to produce larger transactions on average."
                        "0 is a slower algorithm using BNB and a knapsack solver, but"
                        "which can produce transactions with slightly better privacy and "
                        "smaller transaction sizes. Values other than 0 or 1 are reserved"
                        "for future algorithms."},
                    {"include_unsafe", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ RPCArg::Default(DEFAULT_INCLUDE_UNSAFE_INPUTS),
                     "Include inputs that are not safe to spend (unconfirmed transactions from outside keys).\n"
                     "Warning: the resulting transaction may become invalid if one of the unsafe inputs "
                     "disappears.\n"
                     "If that happens, you will need to fund the transaction with different inputs and "
                     "republish it."},
                }}
                .ToString() +
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n" +
            HelpExampleCli("sendtoaddress",
                           "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1") +
            HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvay"
                                            "dd\" 0.1 \"donation\" \"seans "
                                            "outpost\"") +
            HelpExampleCli(
                "sendtoaddress",
                "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true") +
            HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvay"
                                            "dd\", 0.1, \"donation\", \"seans "
                                            "outpost\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    CTxDestination dest =
        DecodeDestination(request.params[0].get_str(), config.GetChainParams());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    // Amount
    Amount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= Amount::zero()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    }

    // Wallet comments
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty()) {
        mapValue["comment"] = request.params[2].get_str();
    }
    if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
        mapValue["to"] = request.params[3].get_str();
    }

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coinControl;

    CoinSelectionHint coinsel(CoinSelectionHint::Default);
    if (!request.params[5].isNull()) {
        int c = (request.params[5].get_int());
        if (!IsValidCoinSelectionHint(c)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Unsupported coin selection algorithm");
        }
        coinsel = static_cast<CoinSelectionHint>(c);
    }

    if (!request.params[6].isNull()) {
        coinControl.m_include_unsafe_inputs = request.params[6].get_bool();
    }

    EnsureWalletIsUnlocked(*pwallet);

    CTransactionRef tx =
        SendMoney(*locked_chain, pwallet, dest, nAmount, fSubtractFeeFromAmount,
                  coinControl, std::move(mapValue), coinsel);
    return tx->GetId().GetHex();
}

static UniValue listaddressgroupings(const Config &config,
                                     const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"listaddressgroupings",
                "\nLists groups of addresses which have had their common ownership\n"
                "made public by common use as inputs or as the resulting change\n"
                "in past transactions\n",
                {}}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"address\",            (string) The Bitcoin Cash address\n"
            "      amount,                 (numeric) The amount in " +
            CURRENCY_UNIT +
            "\n"
            "      \"label\"               (string, optional) The label\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("listaddressgroupings", "") +
            HelpExampleRpc("listaddressgroupings", ""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    std::map<CTxDestination, Amount> balances = pwallet->GetAddressBalances(*locked_chain);
    auto groupings = pwallet->GetAddressGroupings();
    UniValue::Array jsonGroupings;
    jsonGroupings.reserve(groupings.size());
    for (const std::set<CTxDestination> &grouping : groupings) {
        UniValue::Array jsonGrouping;
        jsonGrouping.reserve(grouping.size());
        for (const CTxDestination &address : grouping) {
            auto found = pwallet->mapAddressBook.find(address);
            bool label = found != pwallet->mapAddressBook.end();
            UniValue::Array addressInfo;
            addressInfo.reserve(2 + label);
            addressInfo.emplace_back(EncodeDestination(address, config));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            if (label) {
                addressInfo.emplace_back(found->second.name);
            }
            jsonGrouping.emplace_back(std::move(addressInfo));
        }
        jsonGroupings.emplace_back(std::move(jsonGrouping));
    }

    return jsonGroupings;
}

static UniValue signmessage(const Config &config,
                            const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            RPCHelpMan{"signmessage",
                "\nSign a message with the private key of an address" +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address to use for the private key."},
                    {"message", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The message to create a signature of."},
                }}
                .ToString() +
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message "
            "encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n" +
            HelpExampleCli(
                "signmessage",
                "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n" +
            HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4"
                                            "XX\" \"signature\" \"my "
                                            "message\"") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc(
                "signmessage",
                "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\""));
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    const std::string &strAddress = request.params[0].get_str();
    const std::string &strMessage = request.params[1].get_str();

    CTxDestination dest =
        DecodeDestination(strAddress, config.GetChainParams());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = std::get_if<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<uint8_t> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
    }

    return EncodeBase64(vchSig);
}

static UniValue getreceivedbyaddress(const Config &config,
                                     const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getreceivedbyaddress",
                "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n",
                {
                    {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address for transactions."},
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "Only include transactions confirmed at least this many times."},
                }}
                .ToString() +
            "\nResult:\n"
            "amount   (numeric) The total amount in " +
            CURRENCY_UNIT +
            " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n" +
            HelpExampleCli("getreceivedbyaddress",
                           "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") +
            "\nThe amount including unconfirmed transactions, zero "
            "confirmations\n" +
            HelpExampleCli("getreceivedbyaddress",
                           "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 0") +
            "\nThe amount with at least 6 confirmations\n" +
            HelpExampleCli("getreceivedbyaddress",
                           "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 6") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("getreceivedbyaddress",
                           "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", 6"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    // Temporary, for ContextualCheckTransactionForCurrentBlock below. Removed
    // in upcoming commit.
    LockAnnotation lock(::cs_main);
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    // Bitcoin Cash address
    CTxDestination dest =
        DecodeDestination(request.params[0].get_str(), config.GetChainParams());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid Bitcoin Cash address");
    }
    CScript scriptPubKey = GetScriptForDestination(dest);
    if (!IsMine(*pwallet, scriptPubKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull()) {
        nMinDepth = request.params[1].get_int();
    }

    // Tally
    Amount nAmount = Amount::zero();
    for (const std::pair<const TxId, CWalletTx> &pairWtx : pwallet->mapWallet) {
        const CWalletTx &wtx = pairWtx.second;

        CValidationState state;
        if (wtx.IsCoinBase() ||
            !ContextualCheckTransactionForCurrentBlock(
                config.GetChainParams().GetConsensus(), *wtx.tx, state)) {
            continue;
        }

        for (const CTxOut &txout : wtx.tx->vout) {
            if (txout.scriptPubKey == scriptPubKey) {
                if (wtx.GetDepthInMainChain(*locked_chain) >= nMinDepth) {
                    nAmount += txout.nValue;
                }
            }
        }
    }

    return ValueFromAmount(nAmount);
}

static UniValue getreceivedbylabel(const Config &config,
                                   const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"getreceivedbylabel",
                "\nReturns the total amount received by addresses with <label> in transactions with at least [minconf] confirmations.\n",
                {
                    {"label", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The selected label, may be the default label using \"\"."},
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "Only include transactions confirmed at least this many times."},
                }}
                .ToString() +
            "\nResult:\n"
            "amount              (numeric) The total amount in " +
            CURRENCY_UNIT +
            " received for this label.\n"
            "\nExamples:\n"
            "\nAmount received by the default label with at least 1 "
            "confirmation\n" +
            HelpExampleCli("getreceivedbylabel", "\"\"") +
            "\nAmount received at the tabby label including unconfirmed "
            "amounts with zero confirmations\n" +
            HelpExampleCli("getreceivedbylabel", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n" +
            HelpExampleCli("getreceivedbylabel", "\"tabby\" 6") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("getreceivedbylabel", "\"tabby\", 6"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    // Temporary, for ContextualCheckTransactionForCurrentBlock below. Removed
    // in upcoming commit.
    LockAnnotation lock(::cs_main);
    auto locked_chain = pwallet->chain().lock();
    const uint32_t scriptFlags = GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ChainActive().Tip());
    LOCK(pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull()) {
        nMinDepth = request.params[1].get_int();
    }

    // Get the set of pub keys assigned to label
    std::string label = LabelFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetLabelAddresses(label);

    // Tally
    Amount nAmount = Amount::zero();
    for (const std::pair<const TxId, CWalletTx> &pairWtx : pwallet->mapWallet) {
        const CWalletTx &wtx = pairWtx.second;
        CValidationState state;
        if (wtx.IsCoinBase() ||
            !ContextualCheckTransactionForCurrentBlock(
                config.GetChainParams().GetConsensus(), *wtx.tx, state)) {
            continue;
        }

        for (const CTxOut &txout : wtx.tx->vout) {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address, scriptFlags) &&
                IsMine(*pwallet, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain(*locked_chain) >= nMinDepth) {
                    nAmount += txout.nValue;
                }
            }
        }
    }

    return ValueFromAmount(nAmount);
}

static UniValue getbalance(const Config &config,
                           const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || (request.params.size() > 3)) {
        throw std::runtime_error(
            RPCHelpMan{"getbalance",
                "\nReturns the total available balance.\n"
                "The available balance is what the wallet considers currently spendable, and is\n"
                "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
                {
                    {"dummy", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Remains for backward compatibility. Must be excluded or set to \"*\"."},
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0", "Only include transactions confirmed at least this many times."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Also include balance in watch-only addresses (see 'importaddress')"},
                }}
                .ToString() +
            "\nResult:\n"
            "amount              (numeric) The total amount in " +
            CURRENCY_UNIT +
            " received for this wallet.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet with 1 or more confirmations\n" +
            HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 6 blocks confirmed\n" +
            HelpExampleCli("getbalance", "\"*\" 6") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("getbalance", "\"*\", 6"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    const UniValue &dummy_value = request.params[0];
    if (!dummy_value.isNull() && dummy_value.get_str() != "*") {
        throw JSONRPCError(
            RPC_METHOD_DEPRECATED,
            "dummy first argument must be excluded or set to \"*\".");
    }

    int min_depth = 0;
    if (!request.params[1].isNull()) {
        min_depth = request.params[1].get_int();
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    return ValueFromAmount(pwallet->GetBalance(filter, min_depth));
}

static UniValue getunconfirmedbalance(const Config &config,
                                      const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            RPCHelpMan{"getunconfirmedbalance",
                "Returns the server's total unconfirmed balance\n", {}}
                .ToString());
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}

static UniValue sendmany(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 2 ||
        request.params.size() > 7) {
        throw std::runtime_error(
            RPCHelpMan{"sendmany",
                "\nSend multiple times. Amounts are double-precision floating point numbers." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"dummy", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "Must be set to \"\" for backwards compatibility.", "\"\""},
                    {"amounts", RPCArg::Type::OBJ, /* opt */ false, /* default_val */ "", "A json object with addresses and amounts",
                        {
                            {"address", RPCArg::Type::AMOUNT, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value"},
                        },
                    },
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "Only use the balance confirmed at least this many times."},
                    {"comment", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "A comment"},
                    {"subtractfeefrom", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.",
                        {
                            {"address", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Subtract fee from this address"},
                        },
                    },
                    {"coinsel", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0",
                     "Which coin selection algorithm to use. A value of 1 will use a faster algorithm "
                     "suitable for stress tests or use with large wallets. "
                     "This algorithm is likely to produce larger transactions on average."
                     "0 is a slower algorithm using BNB and a knapsack solver, but"
                     "which can produce transactions with slightly better privacy and "
                     "smaller transaction sizes. Values other than 0 or 1 are reserved"
                     "for future algorithms."},
                    {"include_unsafe", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ RPCArg::Default(DEFAULT_INCLUDE_UNSAFE_INPUTS),
                     "Include inputs that are not safe to spend (unconfirmed transactions from outside keys).\n"
                     "Warning: the resulting transaction may become invalid if one of the unsafe inputs "
                     "disappears.\n"
                     "If that happens, you will need to fund the transaction with different inputs and "
                     "republish it."},
                }}
                .ToString() +
             "\nResult:\n"
            "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of\n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n" +
            HelpExampleCli("sendmany",
                           "\"\" "
                           "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,"
                           "\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}"
                           "\"") +
            "\nSend two amounts to two different addresses setting the "
            "confirmation and comment:\n" +
            HelpExampleCli("sendmany",
                           "\"\" "
                           "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,"
                           "\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" "
                           "6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from "
            "amount:\n" +
            HelpExampleCli("sendmany",
                           "\"\" "
                           "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,"
                           "\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" "
                           "1 \"\" "
                           "\"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\","
                           "\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("sendmany",
                           "\"\", "
                           "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,"
                           "\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\","
                           " 6, \"testing\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Dummy value must be set to \"\"");
    }
    const UniValue::Object& sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (!request.params[2].isNull()) {
        nMinDepth = request.params[2].get_int();
    }

    mapValue_t mapValue;
    if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
        mapValue["comment"] = request.params[3].get_str();
    }

    UniValue::Array subtractFeeFromAmount;
    if (!request.params[4].isNull()) {
        subtractFeeFromAmount = request.params[4].get_array();
    }

    std::set<CTxDestination> destinations;
    std::vector<CRecipient> vecSend;

    Amount totalAmount = Amount::zero();
    for (auto &entry : sendTo) {
        CTxDestination dest = DecodeDestination(entry.first, config.GetChainParams());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               std::string("Invalid Bitcoin Cash address: ") +
                                   entry.first);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                std::string("Invalid parameter, duplicated address: ") + entry.first);
        }
        destinations.insert(dest);

        CScript scriptPubKey = GetScriptForDestination(dest);
        Amount nAmount = AmountFromValue(entry.second);
        if (nAmount <= Amount::zero()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        }
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (const UniValue &addr : subtractFeeFromAmount) {
            if (addr.get_str() == entry.first) {
                fSubtractFeeFromAmount = true;
                break;
            }
        }

        CRecipient recipient = {scriptPubKey, nAmount, {}, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked(*pwallet);

    // Check funds
    if (totalAmount > pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           "Wallet has insufficient funds");
    }

    // Shuffle recipient list
    std::shuffle(vecSend.begin(), vecSend.end(), FastRandomContext());

    // Send
    CReserveKey keyChange(pwallet);
    Amount nFeeRequired = Amount::zero();
    int nChangePosRet = -1;
    std::string strFailReason;
    CTransactionRef tx;
    CCoinControl coinControl;
    CoinSelectionHint coinsel(CoinSelectionHint::Default);

    if (!request.params[5].isNull()) {
        const int c = (request.params[5].get_int());
        if (!IsValidCoinSelectionHint(c)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Unsupported coin selection algorithm");
        }
        coinsel = static_cast<CoinSelectionHint>(c);
    }

    if (!request.params[6].isNull()) {
        coinControl.m_include_unsafe_inputs = request.params[6].get_bool();
    }

    bool fCreated =
        pwallet->CreateTransaction(*locked_chain, vecSend, tx, keyChange,
                                   nFeeRequired, nChangePosRet, strFailReason,
                                   coinControl, true /* sign */, coinsel) == CreateTransactionResult::CT_OK;
    if (!fCreated) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */,
                                    keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s",
                                  FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return tx->GetId().GetHex();
}

static UniValue addmultisigaddress(const Config &config,
                                   const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 2 ||
        request.params.size() > 3) {
        const std::string msg =
            RPCHelpMan{"addmultisigaddress",
                "\nAdd a nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
                "Each key is a Bitcoin Cash address or hex-encoded public key.\n"
                "This functionality is only intended for use with non-watchonly addresses.\n"
                "See `importaddress` for watchonly p2sh address support.\n"
                "If 'label' is specified (DEPRECATED), assign address to that label.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The number of required signatures out of the n keys or addresses."},
                    {"keys", RPCArg::Type::ARR, /* opt */ false, /* default_val */ "", "A json array of Bitcoin Cash addresses or hex-encoded public keys",
                        {
                            {"key", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "Bitcoin Cash address or hex-encoded public key"},
                        },
                        },
                    {"label", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "A label to assign the addresses to."},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",    (string) The value of the "
            "new multisig address.\n"
            "  \"redeemScript\":\"script\"         (string) The string value "
            "of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n" +
            HelpExampleCli("addmultisigaddress",
                           "2 "
                           "\"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\","
                           "\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("addmultisigaddress",
                           "2, "
                           "\"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\","
                           "\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"");
        throw std::runtime_error(msg);
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    std::string label;
    if (!request.params[2].isNull()) {
        label = LabelFromValue(request.params[2]);
    }

    int required = request.params[0].get_int();

    // Get the public keys
    std::vector<CPubKey> pubkeys;
    for (const UniValue &key_or_addr : request.params[1].get_array()) {
        const auto& key_or_addr_str = key_or_addr.get_str();
        if (IsHex(key_or_addr_str) &&
            (key_or_addr_str.length() == 2 * CPubKey::COMPRESSED_PUBLIC_KEY_SIZE ||
             key_or_addr_str.length() == 2 * CPubKey::PUBLIC_KEY_SIZE)) {
            pubkeys.push_back(HexToPubKey(key_or_addr_str));
        } else {
            pubkeys.push_back(AddrToPubKey(config.GetChainParams(), pwallet,
                                           key_or_addr_str));
        }
    }

    OutputType output_type = pwallet->m_default_address_type;

    // Construct using pay-to-script-hash:
    CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    CTxDestination dest =
        AddAndGetDestinationForScript(*pwallet, inner, output_type, false /* no p2sh32 */,
                                      false /* no generous vm limits for wallet */);
    pwallet->SetAddressBook(dest, label, "send");

    UniValue::Object result;
    result.reserve(2);
    result.emplace_back("address", EncodeDestination(dest, config));
    result.emplace_back("redeemScript", HexStr(inner));
    return result;
}

struct tallyitem {
    Amount nAmount{Amount::zero()};
    int nConf{std::numeric_limits<int>::max()};
    std::vector<uint256> txids;
    bool fIsWatchonly{false};
    tallyitem() {}
};

static UniValue::Array ListReceived(const Config &config, interfaces::Chain::Lock &locked_chain, CWallet *const pwallet,
                                    const UniValue &params, bool by_label)
    EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
    // Temporary, for ContextualCheckTransactionForCurrentBlock below. Removed
    // in upcoming commit.
    LockAnnotation lock(::cs_main);

    const uint32_t scriptFlags = GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ChainActive().Tip());

    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull()) {
        nMinDepth = params[0].get_int();
    }

    // Whether to include empty labels
    bool fIncludeEmpty = false;
    if (!params[1].isNull()) {
        fIncludeEmpty = params[1].get_bool();
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (!params[2].isNull() && params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    bool has_filtered_address = false;
    CTxDestination filtered_address = CNoDestination();
    if (!by_label && params.size() > 3) {
        if (!IsValidDestinationString(params[3].get_str(),
                                      config.GetChainParams())) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "address_filter parameter was invalid");
        }
        filtered_address =
            DecodeDestination(params[3].get_str(), config.GetChainParams());
        has_filtered_address = true;
    }

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const std::pair<const TxId, CWalletTx> &pairWtx : pwallet->mapWallet) {
        const CWalletTx &wtx = pairWtx.second;

        CValidationState state;
        if (wtx.IsCoinBase() ||
            !ContextualCheckTransactionForCurrentBlock(
                config.GetChainParams().GetConsensus(), *wtx.tx, state)) {
            continue;
        }

        int nDepth = wtx.GetDepthInMainChain(locked_chain);
        if (nDepth < nMinDepth) {
            continue;
        }

        for (const CTxOut &txout : wtx.tx->vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address, scriptFlags)) {
                continue;
            }

            if (has_filtered_address && !(filtered_address == address)) {
                continue;
            }

            isminefilter mine = IsMine(*pwallet, address);
            if (!(mine & filter)) {
                continue;
            }

            tallyitem &item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetId());
            if (mine & ISMINE_WATCH_ONLY) {
                item.fIsWatchonly = true;
            }
        }
    }

    // Reply
    UniValue::Array ret;
    std::map<std::string, tallyitem> label_tally;

    // Create mapAddressBook iterator
    // If we aren't filtering, go from begin() to end()
    auto start = pwallet->mapAddressBook.begin();
    auto end = pwallet->mapAddressBook.end();
    // If we are filtering, find() the applicable entry
    if (has_filtered_address) {
        start = pwallet->mapAddressBook.find(filtered_address);
        if (start != end) {
            end = std::next(start);
        }
    }

    for (auto item_it = start; item_it != end; ++item_it) {
        const CTxDestination &address = item_it->first;
        const std::string &label = item_it->second.name;
        std::map<CTxDestination, tallyitem>::iterator it =
            mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty) {
            continue;
        }

        Amount nAmount = Amount::zero();
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (by_label) {
            tallyitem &_item = label_tally[label];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        } else {
            UniValue::Object obj;
            obj.reserve(5 + fIsWatchonly);
            if (fIsWatchonly) {
                obj.emplace_back("involvesWatchonly", true);
            }
            obj.emplace_back("address", EncodeDestination(address, config));
            obj.emplace_back("amount", ValueFromAmount(nAmount));
            obj.emplace_back("confirmations", nConf == std::numeric_limits<int>::max() ? 0 : nConf);
            obj.emplace_back("label", label);
            UniValue::Array transactions;
            if (it != mapTally.end()) {
                transactions.reserve(it->second.txids.size());
                for (const uint256 &_item : it->second.txids) {
                    transactions.emplace_back(_item.GetHex());
                }
            }
            obj.emplace_back("txids", std::move(transactions));
            ret.emplace_back(std::move(obj));
        }
    }

    if (by_label) {
        ret.reserve(label_tally.size());
        for (const auto &entry : label_tally) {
            Amount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue::Object obj;
            obj.reserve(3 + entry.second.fIsWatchonly);
            if (entry.second.fIsWatchonly) {
                obj.emplace_back("involvesWatchonly", true);
            }
            obj.emplace_back("amount", ValueFromAmount(nAmount));
            obj.emplace_back("confirmations", nConf == std::numeric_limits<int>::max() ? 0 : nConf);
            obj.emplace_back("label", entry.first);
            ret.emplace_back(std::move(obj));
        }
    }

    return ret;
}

static UniValue listreceivedbyaddress(const Config &config,
                                      const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"listreceivedbyaddress",
                "\nList balances by receiving address.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to include addresses that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to include watch-only addresses (see 'importaddress')."},
                    {"address_filter", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "If present, only return information on this address."},
                }}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if "
            "imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving "
            "address\n"
            "    \"amount\" : x.xxx,                  (numeric) The total "
            "amount in " +
            CURRENCY_UNIT +
            " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of "
            "confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\",               (string) The label of "
            "the receiving address. The default label is \"\".\n"
            "    \"txids\": [\n"
            "       \"txid\",                         (string) The ids of "
            "transactions received with the address\n"
            "       ...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbyaddress", "") +
            HelpExampleCli("listreceivedbyaddress", "6 true") +
            HelpExampleRpc("listreceivedbyaddress", "6, true, true") +
            HelpExampleRpc(
                "listreceivedbyaddress",
                "6, true, true, \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    return ListReceived(config, *locked_chain, pwallet, request.params, false);
}

static UniValue listreceivedbylabel(const Config &config,
                                    const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 3) {
        throw std::runtime_error(
            RPCHelpMan{"listreceivedbylabel",
                "\nList received transactions by label.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to include labels that haven't received any payments."},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to include watch-only addresses (see 'importaddress')."},
                }}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if "
            "imported addresses were involved in transaction\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount "
            "received by addresses with this label\n"
            "    \"confirmations\" : n,          (numeric) The number of "
            "confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) The label of the "
            "receiving address. The default label is \"\".\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n" +
            HelpExampleCli("listreceivedbylabel", "") +
            HelpExampleCli("listreceivedbylabel", "6 true") +
            HelpExampleRpc("listreceivedbylabel", "6, true, true"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    return ListReceived(config, *locked_chain, pwallet, request.params, true);
}

static void MaybePushAddress(UniValue::Object &entry, const CTxDestination &dest) {
    if (IsValidDestination(dest)) {
        entry.emplace_back("address", EncodeDestination(dest, GetConfig()));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  pwallet        The wallet.
 * @param  wtx            The wallet transaction.
 * @param  nMinDepth      The minimum confirmation depth.
 * @param  fLong          Whether to include the JSON version of the
 * transaction.
 * @param  ret            The UniValue::Array into which the result is stored.
 * @param  filter_ismine  The "is mine" filter flags.
 * @param  filter_label   Optional label string to filter incoming transactions.
 */
static void ListTransactions(interfaces::Chain::Lock &locked_chain,
                             CWallet *const pwallet, const CWalletTx &wtx,
                             int nMinDepth, bool fLong, UniValue::Array &ret,
                             const isminefilter &filter_ismine,
                             const std::string *filter_label) {
    Amount nFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, filter_ismine);

    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if (!filter_label) {
        for (const COutputEntry &s : listSent) {
            UniValue::Object entry;
            if (involvesWatchonly ||
                (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY)) {
                entry.emplace_back("involvesWatchonly", true);
            }
            MaybePushAddress(entry, s.destination);
            entry.emplace_back("category", "send");
            entry.emplace_back("amount", ValueFromAmount(-s.amount));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.emplace_back("label", pwallet->mapAddressBook[s.destination].name);
            }
            entry.emplace_back("vout", s.vout);
            entry.emplace_back("fee", ValueFromAmount(-1 * nFee));
            if (fLong) {
                WalletTxToJSON(pwallet->chain(), locked_chain, wtx, entry);
            }
            entry.emplace_back("abandoned", wtx.isAbandoned());
            ret.emplace_back(std::move(entry));
        }
    }

    // Received
    if (listReceived.size() > 0 &&
        wtx.GetDepthInMainChain(locked_chain) >= nMinDepth) {
        for (const COutputEntry &r : listReceived) {
            std::string label;
            if (pwallet->mapAddressBook.count(r.destination)) {
                label = pwallet->mapAddressBook[r.destination].name;
            }
            if (filter_label && label != *filter_label) {
                continue;
            }
            UniValue::Object entry;
            if (involvesWatchonly ||
                (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY)) {
                entry.emplace_back("involvesWatchonly", true);
            }
            MaybePushAddress(entry, r.destination);
            if (wtx.IsCoinBase()) {
                if (wtx.GetDepthInMainChain(locked_chain) < 1) {
                    entry.emplace_back("category", "orphan");
                } else if (wtx.IsImmatureCoinBase(locked_chain)) {
                    entry.emplace_back("category", "immature");
                } else {
                    entry.emplace_back("category", "generate");
                }
            } else {
                entry.emplace_back("category", "receive");
            }
            entry.emplace_back("amount", ValueFromAmount(r.amount));
            if (pwallet->mapAddressBook.count(r.destination)) {
                entry.emplace_back("label", label);
            }
            entry.emplace_back("vout", r.vout);
            if (fLong) {
                WalletTxToJSON(pwallet->chain(), locked_chain, wtx, entry);
            }
            ret.emplace_back(std::move(entry));
        }
    }
}

UniValue listtransactions(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"listtransactions",
                "\nIf a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions.\n",
                {
                    {"label", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "If set, should be a valid label name to return only incoming transactions\n"
            "              with the specified label, or \"*\" to disable filtering and return all transactions."},
                    {"count", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "10", "The number of transactions to return"},
                    {"skip", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0", "The number of transactions to skip"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Include transactions to watch-only addresses (see 'importaddress')"},
                }}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"address\":\"address\",    (string) The Bitcoin Cash address of "
            "the transaction.\n"
            "    \"category\":\"send|receive\", (string) The transaction "
            "category.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " +
            CURRENCY_UNIT +
            ". This is negative for the 'send' category, and is positive\n"
            "                                        for the 'receive' "
            "category,\n"
            "    \"label\": \"label\",       (string) A comment for the "
            "address/transaction, if any\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee "
            "in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the\n"
            "                                         'send' category of "
            "transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of "
            "confirmations for the transaction. Negative confirmations "
            "indicate the\n"
            "                                         transaction conflicts "
            "with the block chain\n"
            "    \"trusted\": xxx,           (bool) Whether we consider the "
            "outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash "
            "containing the transaction.\n"
            "    \"blockindex\": n,          (numeric) The index of the "
            "transaction in the block that includes it.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in "
            "seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id.\n"
            "    \"time\": xxx,              (numeric) The transaction time in "
            "seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in "
            "seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"comment\": \"...\",       (string) If a comment is "
            "associated with the transaction.\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction "
            "has been abandoned (inputs are respendable). Only available for "
            "the\n"
            "                                         'send' category of "
            "transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n" +
            HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n" +
            HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("listtransactions", "\"*\", 20, 100"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const std::string *filter_label = nullptr;
    if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
        filter_label = &request.params[0].get_str();
        if (filter_label->empty()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Label argument must be a valid label name or \"*\".");
        }
    }
    int nCount = 10;
    if (!request.params[1].isNull()) {
        nCount = request.params[1].get_int();
    }

    int nFrom = 0;
    if (!request.params[2].isNull()) {
        nFrom = request.params[2].get_int();
    }

    isminefilter filter = ISMINE_SPENDABLE;
    if (!request.params[3].isNull() && request.params[3].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    if (nCount < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    }
    if (nFrom < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");
    }
    UniValue::Array ret;

    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);

        const CWallet::TxItems &txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin();
             it != txOrdered.rend(); ++it) {
            CWalletTx *const pwtx = (*it).second;
            ListTransactions(*locked_chain, pwallet, *pwtx, 0, true, ret,
                             filter, filter_label);
            if (int(ret.size()) >= (nCount + nFrom)) {
                break;
            }
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size()) {
        nFrom = ret.size();
    }
    if ((nFrom + nCount) > (int)ret.size()) {
        nCount = ret.size() - nFrom;
    }

    auto first = ret.begin() + nFrom;
    auto last = first + nCount;

    ret.erase(last, ret.end());
    ret.erase(ret.begin(), first);

    // Return oldest to newest
    std::reverse(ret.begin(), ret.end());

    return ret;
}

static UniValue listsinceblock(const Config &config,
                               const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"listsinceblock",
                "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n",
                {
                    {"blockhash", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "The block hash to list transactions since"},
                    {"target_confirmations", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Include transactions to watch-only addresses (see 'importaddress')"},
                    {"include_removed", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "Show transactions that were removed due to a reorg in the \"removed\" array\n"
            "                                                           (not guaranteed to work on pruned nodes)"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"address\":\"address\",    (string) The Bitcoin Cash address of "
            "the transaction. Not present for move transactions (category = "
            "move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction "
            "category. 'send' has negative amounts, 'receive' has positive "
            "amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " +
            CURRENCY_UNIT +
            ". This is negative for the 'send' category, and for the 'move' "
            "category for moves\n"
            "                                          outbound. It is "
            "positive for the 'receive' category, and for the 'move' category "
            "for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee "
            "in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the 'send' category of "
            "transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of "
            "confirmations for the transaction. Available for 'send' and "
            "'receive' category of transactions.\n"
            "                                          When it's < 0, it means "
            "the transaction conflicted that many blocks ago.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash "
            "containing the transaction. Available for 'send' and 'receive' "
            "category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the "
            "transaction in the block that includes it. Available for 'send' "
            "and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in "
            "seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. "
            "Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in "
            "seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in "
            "seconds since epoch (Jan 1 1970 GMT). Available for 'send' and "
            "'receive' category of transactions.\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction "
            "has been abandoned (inputs are respendable). Only available for "
            "the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is "
            "associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the "
            "address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is "
            "associated with the transaction.\n"
            "  ],\n"
            "  \"removed\": [\n"
            "    <structure is the same as \"transactions\" above, only "
            "present if include_removed=true>\n"
            "    Note: transactions that were re-added in the active chain "
            "will appear as-is in this array, and may thus have a positive "
            "confirmation count.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the "
            "block (target_confirmations-1) from the best block on the main "
            "chain. This is typically used to feed back into listsinceblock "
            "the next time you call it. So you would generally use a "
            "target_confirmations of say 6, so you will be continually "
            "re-notified of transactions until they've reached 6 confirmations "
            "plus any new ones\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("listsinceblock", "") +
            HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc4"
                                             "5ef753ee9a7d38571037cdb1a57f663ad"
                                             "\" 6") +
            HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc4"
                                             "5ef753ee9a7d38571037cdb1a57f663ad"
                                             "\", 6"));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    // The way the 'height' is initialized is just a workaround for the gcc bug #47679 since version 4.6.0.
    std::optional<int> height; // Height of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    std::optional<int> altheight; // Height of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    BlockHash blockId;
    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        blockId = BlockHash(ParseHashV(request.params[0], "blockhash"));
        height = locked_chain->findFork(blockId, &altheight);
        if (!height) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    bool include_removed =
        (request.params[3].isNull() || request.params[3].get_bool());

    const std::optional<int> tip_height = locked_chain->getHeight();
    int depth = tip_height && height ? (1 + *tip_height - *height) : -1;

    UniValue::Array transactions;

    for (const std::pair<const TxId, CWalletTx> &pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain(*locked_chain) < depth) {
            ListTransactions(*locked_chain, pwallet, tx, 0, true, transactions,
                             filter, nullptr /* filter_label */);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue::Array removed;
    while (include_removed && altheight && *altheight > *height) {
        CBlock block;
        if (!pwallet->chain().findBlock(blockId, &block) || block.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "Can't read block from disk");
        }
        for (const CTransactionRef &tx : block.vtx) {
            auto it = pwallet->mapWallet.find(tx->GetId());
            if (it != pwallet->mapWallet.end()) {
                // We want all transactions regardless of confirmation count to
                // appear here, even negative confirmation ones, hence the big
                // negative.
                ListTransactions(*locked_chain, pwallet, it->second, -100000000,
                                 true, removed, filter,
                                 nullptr /* filter_label */);
            }
        }
        blockId = block.hashPrevBlock;
        --*altheight;
    }

    int last_height = tip_height ? *tip_height + 1 - target_confirms : -1;
    BlockHash lastblock = last_height >= 0
                              ? locked_chain->getBlockHash(last_height)
                              : BlockHash();

    UniValue::Object ret;
    ret.reserve(2 + include_removed);
    ret.emplace_back("transactions", std::move(transactions));
    if (include_removed) {
        ret.emplace_back("removed", std::move(removed));
    }
    ret.emplace_back("lastblock", lastblock.GetHex());

    return ret;
}

static UniValue gettransaction(const Config &config,
                               const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"gettransaction",
                "\nGet detailed information about in-wallet transaction <txid>\n",
                {
                    {"txid", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The transaction id"},
                    {"include_watchonly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to include watch-only addresses in balance calculation and details[]"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount "
            "in " +
            CURRENCY_UNIT +
            "\n"
            "  \"fee\": x.xxx,            (numeric) The amount of the fee in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the\n"
            "                              'send' category of transactions.\n"
            "  \"confirmations\" : n,     (numeric) The number of "
            "confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the "
            "transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since "
            "epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in "
            "seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in "
            "seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether "
            "this transaction could be replaced due to BIP125 "
            "(replace-by-fee) (DEPRECATED);\n"
            "                                                   may be unknown "
            "for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"address\" : \"address\",          (string) The Bitcoin Cash "
            "address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, "
            "either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount "
            "in " +
            CURRENCY_UNIT +
            "\n"
            "      \"label\" : \"label\",              "
            "(string) A comment for the address/transaction, "
            "if any\n"
            "      \"vout\" : n,                       "
            "(numeric) the vout value\n"
            "      \"fee\": x.xxx,                     "
            "(numeric) The amount of the fee in " +
            CURRENCY_UNIT +
            ". This is negative and only available for the\n"
            "                                           'send' category of "
            "transactions.\n"
            "      \"abandoned\": xxx                  (bool) 'true' if the "
            "transaction has been abandoned (inputs are respendable). Only "
            "available for the\n"
            "                                           'send' category of "
            "transactions.\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e211"
                                             "5b9345e16c5cf302fc80e9d5fbf5d48d"
                                             "\"") +
            HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e211"
                                             "5b9345e16c5cf302fc80e9d5fbf5d48d"
                                             "\" true") +
            HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e211"
                                             "5b9345e16c5cf302fc80e9d5fbf5d48d"
                                             "\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    TxId txid(ParseHashV(request.params[0], "txid"));

    isminefilter filter = ISMINE_SPENDABLE;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    UniValue::Object entry;
    auto it = pwallet->mapWallet.find(txid);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid or non-wallet transaction id");
    }
    const CWalletTx &wtx = it->second;

    Amount nCredit = wtx.GetCredit(*locked_chain, filter);
    Amount nDebit = wtx.GetDebit(filter);
    Amount nNet = nCredit - nDebit;
    Amount nFee = (wtx.IsFromMe(filter) ? wtx.tx->GetValueOut() - nDebit
                                        : Amount::zero());

    entry.emplace_back("amount", ValueFromAmount(nNet - nFee));
    if (wtx.IsFromMe(filter)) {
        entry.emplace_back("fee", ValueFromAmount(nFee));
    }

    WalletTxToJSON(pwallet->chain(), *locked_chain, wtx, entry);

    UniValue::Array details;
    ListTransactions(*locked_chain, pwallet, wtx, 0, false, details, filter,
                     nullptr /* filter_label */);
    entry.emplace_back("details", std::move(details));

    entry.emplace_back("hex", EncodeHexTx(*wtx.tx));

    return entry;
}

static UniValue abandontransaction(const Config &config,
                                   const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"abandontransaction",
                "\nMark in-wallet transaction <txid> as abandoned\n"
                "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
                "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
                "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
                "It has no effect on transactions which are already abandoned.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id"},
                }}
                .ToString() +
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084"
                                                 "e2115b9345e16c5cf302fc80e9d5f"
                                                 "bf5d48d\"") +
            HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084"
                                                 "e2115b9345e16c5cf302fc80e9d5f"
                                                 "bf5d48d\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    TxId txid(ParseHashV(request.params[0], "txid"));

    if (!pwallet->mapWallet.count(txid)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid or non-wallet transaction id");
    }

    if (!pwallet->AbandonTransaction(*locked_chain, txid)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Transaction not eligible for abandonment");
    }

    return UniValue();
}

static UniValue backupwallet(const Config &config,
                             const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"backupwallet",
                "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n",
                {
                    {"destination", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The destination directory or file"},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return UniValue();
}

static UniValue keypoolrefill(const Config &config,
                              const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"keypoolrefill",
                "\nFills the keypool."+
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"newsize", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "100", "The new keypool size"},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );
    }

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: Private keys are disabled for this wallet");
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by
    // -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].get_int() < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, expected valid size.");
        }
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return UniValue();
}

static UniValue walletpassphrase(const Config &config,
                                 const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            RPCHelpMan{"walletpassphrase",
                "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
                "This is needed prior to performing transactions related to private keys such as sending bitcoins\n",
                {
                    {"passphrase", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The wallet passphrase"},
                    {"timeout", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The time to keep the decryption key in seconds; capped at 100000000 (~3 years)."},
                }}
                .ToString() +
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already "
            "unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 60 seconds\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n" +
            HelpExampleCli("walletlock", "") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60"));
    }

    int64_t nSleepTime;
    int64_t relock_time;
    // Prevent concurrent calls to walletpassphrase with the same wallet.
    LOCK(pwallet->m_unlock_mutex);
    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);

        if (!pwallet->IsCrypted()) {
            throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE,
                               "Error: running with an unencrypted wallet, but "
                               "walletpassphrase was called.");
        }

        // Note that the walletpassphrase is stored in request.params[0] which is
        // not mlock()ed
        SecureString strWalletPass;
        strWalletPass.reserve(100);
        // TODO: get rid of this .c_str() by implementing
        // SecureString::operator=(std::string)
        // Alternately, find a way to make request.params[0] mlock()'d to begin
        // with.
        strWalletPass = request.params[0].get_str().c_str();

        // Get the timeout
        nSleepTime = request.params[1].get_int64();
        // Timeout cannot be negative, otherwise it will relock immediately
        if (nSleepTime < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Timeout cannot be negative.");
        }
        // Clamp timeout
        // larger values trigger a macos/libevent bug?
        constexpr int64_t MAX_SLEEP_TIME = 100000000;
        if (nSleepTime > MAX_SLEEP_TIME) {
            nSleepTime = MAX_SLEEP_TIME;
        }

        if (strWalletPass.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
        }

        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }

        pwallet->TopUpKeyPool();

        pwallet->nRelockTime = GetTime() + nSleepTime;
        relock_time = pwallet->nRelockTime;
    }

    // rpcRunLater must be called without cs_wallet held otherwise a deadlock
    // can occur. The deadlock would happen when RPCRunLater removes the
    // previous timer (and waits for the callback to finish if already running)
    // and the callback locks cs_wallet.
    AssertLockNotHeld(wallet->cs_wallet);
    // Keep a weak pointer to the wallet so that it is possible to unload the
    // wallet before the following callback is called. If a valid shared pointer
    // is acquired in the callback then the wallet is still loaded.
    std::weak_ptr<CWallet> weak_wallet = wallet;
    RPCRunLater(
        strprintf("lockwallet(%s)", pwallet->GetName()),
        [weak_wallet, relock_time] {
            if (auto shared_wallet = weak_wallet.lock()) {
                LOCK(shared_wallet->cs_wallet);
                // Skip if this is not the most recent rpcRunLater callback.
                if (shared_wallet->nRelockTime != relock_time) {
                    return;
                }
                shared_wallet->Lock();
                shared_wallet->nRelockTime = 0;
            }
        },
        nSleepTime);

    return UniValue();
}

static UniValue walletpassphrasechange(const Config &config,
                                       const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            RPCHelpMan{"walletpassphrasechange",
                "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n",
                {
                    {"oldpassphrase", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The current passphrase"},
                    {"newpassphrase", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The new passphrase"},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE,
                           "Error: running with an unencrypted wallet, but "
                           "walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing
    // SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin
    // with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.empty() || strNewWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
    }

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(
            RPC_WALLET_PASSPHRASE_INCORRECT,
            "Error: The wallet passphrase entered was incorrect.");
    }

    return UniValue();
}

static UniValue walletlock(const Config &config,
                           const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"walletlock",
                "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
                "After calling this method, you will need to call walletpassphrase again\n"
                "before being able to call any methods which require the wallet to be unlocked.\n",
                {}}
                .ToString() +
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n" +
            HelpExampleCli("sendtoaddress",
                           "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is "
            "up\n" +
            HelpExampleCli("walletlock", "") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("walletlock", ""));
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE,
                           "Error: running with an unencrypted wallet, but "
                           "walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return UniValue();
}

static UniValue encryptwallet(const Config &config,
                              const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"encryptwallet",
                "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
                "After this, any calls that interact with private keys such as sending or signing\n"
                "will require the passphrase to be set prior the making these calls.\n"
                "Use the walletpassphrase call for this, and then walletlock call.\n"
                "If the wallet is already encrypted, use the walletpassphrasechange call.\n",
                {
                    {"passphrase", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long."},
                }}
                .ToString() +
            "\nExamples:\n"
            "\nEncrypt your wallet\n" +
            HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing "
            "or sending bitcoin\n" +
            HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n" +
            HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n" +
            HelpExampleCli("walletlock", "") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("encryptwallet", "\"my pass phrase\""));
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE,
                           "Error: running with an encrypted wallet, but "
                           "encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing
    // SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin
    // with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "passphrase can not be empty");
    }

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED,
                           "Error: Failed to encrypt the wallet.");
    }

    return "wallet encrypted; The keypool has been flushed and a new HD seed "
           "was generated (if you are using HD). You need to make a new "
           "backup.";
}

static UniValue lockunspent(const Config &config,
                            const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"lockunspent",
                "\nUpdates list of temporarily unspendable outputs.\n"
                "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
                "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
                "A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.\n"
                "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
                "is always cleared (by virtue of process exit) when a node stops or fails.\n"
                "Also see the listunspent call\n",
                {
                    {"unlock", RPCArg::Type::BOOL, /* opt */ false, /* default_val */ "", "Whether to unlock (true) or lock (false) the specified transactions"},
                    {"transactions", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array of objects. Each object the txid (string) vout (numeric)",
                        {
                            {"", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The output number"},
                                },
                            },
                        },
                    },
                }}
                .ToString() +
            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or "
            "not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" +
            HelpExampleCli("lockunspent", "false "
                                          "\"[{\\\"txid\\\":"
                                          "\\\"a08e6907dbbd3d809776dbfc5d82e371"
                                          "b764ed838b5655e72f463568df1aadf0\\\""
                                          ",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" +
            HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" +
            HelpExampleCli("lockunspent", "true "
                                          "\"[{\\\"txid\\\":"
                                          "\\\"a08e6907dbbd3d809776dbfc5d82e371"
                                          "b764ed838b5655e72f463568df1aadf0\\\""
                                          ",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("lockunspent", "false, "
                                          "\"[{\\\"txid\\\":"
                                          "\\\"a08e6907dbbd3d809776dbfc5d82e371"
                                          "b764ed838b5655e72f463568df1aadf0\\\""
                                          ",\\\"vout\\\":1}]\""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    RPCTypeCheckArgument(request.params[0], UniValue::MBOOL);

    bool fUnlock = request.params[0].get_bool();

    if (request.params[1].isNull()) {
        if (fUnlock) {
            pwallet->UnlockAllCoins();
        }
        return true;
    }

    RPCTypeCheckArgument(request.params[1], UniValue::VARR);

    const UniValue &output_params = request.params[1];

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (size_t idx = 0; idx < output_params.size(); idx++) {
        const UniValue::Object &o = output_params[idx].get_obj();

        RPCTypeCheckObj(o, {
                               {"txid", UniValue::VSTR},
                               {"vout", UniValue::VNUM},
                           });

        const int nOutput = o["vout"].get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, vout must be positive");
        }

        const TxId txid(ParseHashO(o, "txid"));
        const auto it = pwallet->mapWallet.find(txid);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, unknown transaction");
        }

        const COutPoint output(txid, nOutput);
        const CWalletTx &trans = it->second;
        if (output.GetN() >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(*locked_chain, output)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(output);
        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Invalid parameter, output already locked");
        }

        outputs.push_back(output);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint &output : outputs) {
        if (fUnlock) {
            pwallet->UnlockCoin(output);
        } else {
            pwallet->LockCoin(output);
        }
    }

    return true;
}

static UniValue listlockunspent(const Config &config,
                                const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            RPCHelpMan{"listlockunspent",
                "\nReturns list of temporarily unspendable outputs.\n"
                "See the lockunspent call to lock and unlock transactions for spending.\n",
                {}}
                .ToString() +
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id "
            "locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n" +
            HelpExampleCli("lockunspent", "false "
                                          "\"[{\\\"txid\\\":"
                                          "\\\"a08e6907dbbd3d809776dbfc5d82e371"
                                          "b764ed838b5655e72f463568df1aadf0\\\""
                                          ",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n" +
            HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n" +
            HelpExampleCli("lockunspent", "true "
                                          "\"[{\\\"txid\\\":"
                                          "\\\"a08e6907dbbd3d809776dbfc5d82e371"
                                          "b764ed838b5655e72f463568df1aadf0\\\""
                                          ",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n" + HelpExampleRpc("listlockunspent", ""));
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue::Array ret;
    ret.reserve(vOutpts.size());
    for (const COutPoint &output : vOutpts) {
        UniValue::Object o;
        o.reserve(2);
        o.emplace_back("txid", output.GetTxId().GetHex());
        o.emplace_back("vout", output.GetN());
        ret.emplace_back(std::move(o));
    }
    return ret;
}

static UniValue settxfee(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"settxfee",
                "\nSet the transaction fee per kB for this wallet. Overrides the global -paytxfee command line parameter.\n",
                {
                    {"amount", RPCArg::Type::AMOUNT, /* opt */ false, /* default_val */ "", "The transaction fee in " + CURRENCY_UNIT + "/kB"},
                }}
                .ToString() +
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n" +
            HelpExampleCli("settxfee", "0.00001") +
            HelpExampleRpc("settxfee", "0.00001"));
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    Amount nAmount = AmountFromValue(request.params[0]);
    CFeeRate tx_fee_rate(nAmount, 1000);
    if (tx_fee_rate == CFeeRate()) {
        // automatic selection
    } else if (tx_fee_rate < ::minRelayTxFee) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("txfee cannot be less than min relay tx fee (%s)",
                      ::minRelayTxFee.ToString()));
    } else if (tx_fee_rate < pwallet->m_min_fee) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("txfee cannot be less than wallet min fee (%s)",
                      pwallet->m_min_fee.ToString()));
    }

    pwallet->m_pay_tx_fee = tx_fee_rate;
    return true;
}

static UniValue getwalletinfo(const Config &config,
                              const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"getwalletinfo",
                "Returns an object containing various wallet state info.\n", {}}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"walletname\": xxxxx,             (string) the wallet name\n"
            "  \"walletversion\": xxxxx,          (numeric) the wallet "
            "version\n"
            "  \"balance\": xxxxxxx,              (numeric) the total "
            "confirmed balance of the wallet in " +
            CURRENCY_UNIT +
            "\n"
            "  \"unconfirmed_balance\": xxx,      (numeric) "
            "the total unconfirmed balance of the wallet in " +
            CURRENCY_UNIT +
            "\n"
            "  \"immature_balance\": xxxxxx,      (numeric) "
            "the total immature balance of the wallet in " +
            CURRENCY_UNIT +
            "\n"
            "  \"txcount\": xxxxxxx,              (numeric) the total number "
            "of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,         (numeric) the timestamp "
            "(seconds since Unix epoch) of the oldest pre-generated key in the "
            "key pool\n"
            "  \"keypoolsize\": xxxx,             (numeric) how many new keys "
            "are pre-generated (only counts external keys)\n"
            "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys "
            "are pre-generated for internal use (used for change outputs, only "
            "appears if the wallet is using this feature, otherwise external "
            "keys are used)\n"
            "  \"unlocked_until\": ttt,           (numeric) the timestamp in "
            "seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is "
            "unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,              (numeric) the transaction "
            "fee configuration, set in " +
            CURRENCY_UNIT +
            "/kB\n"
            "  \"hdseedid\": \"<hash160>\"          (string, optional) the "
            "Hash160 of the HD seed (only present when HD is enabled)\n"
            "  \"hdmasterkeyid\": \"<hash160>\"     (string, optional) alias "
            "for hdseedid retained for backwards-compatibility. Will be "
            "removed in V0.21.\n"
            "  \"private_keys_enabled\": true|false (boolean) false if "
            "privatekeys are disabled for this wallet (enforced watch-only "
            "wallet)\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getwalletinfo", "") +
            HelpExampleRpc("getwalletinfo", ""));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    UniValue::Object obj;
    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.emplace_back("walletname", pwallet->GetName());
    obj.emplace_back("walletversion", pwallet->GetVersion());
    obj.emplace_back("balance", ValueFromAmount(pwallet->GetBalance()));
    obj.emplace_back("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance()));
    obj.emplace_back("immature_balance", ValueFromAmount(pwallet->GetImmatureBalance()));
    obj.emplace_back("txcount", pwallet->mapWallet.size());
    obj.emplace_back("keypoololdest", pwallet->GetOldestKeyPoolTime());
    obj.emplace_back("keypoolsize", kpExternalSize);
    CKeyID seed_id = pwallet->GetHDChain().seed_id;
    if (!seed_id.IsNull() && pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.emplace_back("keypoolsize_hd_internal", pwallet->GetKeyPoolSize() - kpExternalSize);
    }
    if (pwallet->IsCrypted()) {
        obj.emplace_back("unlocked_until", pwallet->nRelockTime);
    }
    obj.emplace_back("paytxfee", ValueFromAmount(pwallet->m_pay_tx_fee.GetFeePerK()));
    if (!seed_id.IsNull()) {
        obj.emplace_back("hdseedid", seed_id.GetHex());
        obj.emplace_back("hdmasterkeyid", seed_id.GetHex());
    }
    obj.emplace_back("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    return obj;
}

static UniValue listwalletdir(const Config &config,
                              const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n", {}}
                .ToString() +
            "{\n"
            "  \"wallets\" : [                (json array of objects)\n"
            "    {\n"
            "      \"name\" : \"name\"          (string) The wallet name\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("listwalletdir", "") +
            HelpExampleRpc("listwalletdir", ""));
    }

    auto paths = ListWalletDir();
    UniValue::Array wallets;
    wallets.reserve(paths.size());
    for (const auto &path : paths) {
        UniValue::Object wallet;
        wallet.reserve(1);
        wallet.emplace_back("name", path.string());
        wallets.emplace_back(std::move(wallet));
    }

    UniValue::Object result;
    result.reserve(1);
    result.emplace_back("wallets", std::move(wallets));
    return result;
}

static UniValue listwallets(const Config &config,
                            const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {}}
                .ToString() +
            "\nResult:\n"
            "[                         (json array of strings)\n"
            "  \"walletname\"            (string) the wallet name\n"
            "   ...\n"
            "]\n"
            "\nExamples:\n" +
            HelpExampleCli("listwallets", "") +
            HelpExampleRpc("listwallets", ""));
    }

    auto wallets = GetWallets();
    UniValue::Array obj;
    obj.reserve(wallets.size());
    for (const std::shared_ptr<CWallet> &wallet : wallets) {
        if (!EnsureWalletIsAvailable(wallet.get(), request.fHelp)) {
            return UniValue();
        }

        LOCK(wallet->cs_wallet);

        obj.emplace_back(wallet->GetName());
    }

    return obj;
}

static UniValue loadwallet(const Config &config,
                           const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"loadwallet",
                "\nLoads a wallet from a wallet file or directory."
                "\nNote that all wallet command-line options used when starting bitcoind will be"
                "\napplied to the new wallet (eg -zapwallettxes, upgradewallet, rescan, etc).\n",
                {
                    {"filename", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The wallet directory or .dat file."},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"name\" :    <wallet_name>,        (string) The wallet name if "
            "loaded successfully.\n"
            "  \"warning\" : <warning>,            (string) Warning message if "
            "wallet was not loaded cleanly.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("loadwallet", "\"test.dat\"") +
            HelpExampleRpc("loadwallet", "\"test.dat\""));
    }

    const CChainParams &chainParams = config.GetChainParams();

    WalletLocation location(request.params[0].get_str());
    std::string error;

    if (!location.Exists()) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                           "Wallet " + location.GetName() + " not found.");
    } else if (fs::is_directory(location.GetPath())) {
        // The given filename is a directory. Check that there's a wallet.dat
        // file.
        fs::path wallet_dat_file = location.GetPath() / "wallet.dat";
        if (fs::symlink_status(wallet_dat_file).type() == fs::file_not_found) {
            throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                               "Directory " + location.GetName() +
                                   " does not contain a wallet.dat file.");
        }
    }

    std::string warning;
    if (!CWallet::Verify(chainParams, *g_rpc_node->chain, location, false,
                         error, warning)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Wallet file verification failed: " + std::move(error));
    }

    std::shared_ptr<CWallet> const wallet = CWallet::CreateWalletFromFile(
        chainParams, *g_rpc_node->chain, location);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet loading failed.");
    }
    AddWallet(wallet);

    wallet->postInitProcess();

    UniValue::Object obj;
    obj.reserve(2);
    obj.emplace_back("name", wallet->GetName());
    obj.emplace_back("warning", std::move(warning));
    return obj;
}

static UniValue createwallet(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"createwallet",
                "\nCreates and loads a new wallet.\n",
                {
                    {"wallet_name", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
                    {"disable_private_keys", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
                    {"blank", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Create a blank wallet. A blank wallet has no keys or HD seed. One can be set using sethdseed."},
                    {"passphrase", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Encrypt the wallet with this passphrase."},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"name\" :    <wallet_name>,        (string) The wallet name if "
            "created successfully. If the wallet was created using a full "
            "path, the wallet_name will be the full path.\n"
            "  \"warning\" : <warning>,            (string) Warning message if "
            "wallet was not loaded cleanly.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("createwallet", "\"testwallet\"") +
            HelpExampleRpc("createwallet", "\"testwallet\""));
    }

    const CChainParams &chainParams = config.GetChainParams();

    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::string warning;
    if (!request.params[3].isNull()) {
        passphrase = request.params[3].get_str().c_str();
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warning = "Empty string given as passphrase, wallet will not be encrypted.";
        }
    }

    std::string error;
    std::string create_warning;
    WalletCreationStatus status;
    std::shared_ptr<CWallet> wallet = CreateWallet(chainParams, *g_rpc_node->chain, request.params[0].get_str(), error,
                                                   create_warning, status, passphrase, flags);
    if (status == WalletCreationStatus::CREATION_FAILED) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    } else if (status == WalletCreationStatus::ENCRYPTION_FAILED) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, error);
    } else if (status != WalletCreationStatus::SUCCESS) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet creation failed");
    }

    if (!warning.empty() && !create_warning.empty()) {
        warning += "; ";
    }
    warning += create_warning;

    UniValue::Object obj;
    obj.reserve(2);
    obj.emplace_back("name", wallet->GetName());
    obj.emplace_back("warning", std::move(warning));
    return obj;
}

static UniValue unloadwallet(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint otherwise unloads the wallet specified in the argument.\n"
                "Specifying the wallet name on a wallet endpoint is invalid.",
                {
                    {"wallet_name", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "The name of the wallet to unload."},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
        );
    }

    std::string wallet_name;
    if (GetWalletNameFromJSONRPCRequest(request, wallet_name)) {
        if (!request.params[0].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Cannot unload the requested wallet");
        }
    } else {
        wallet_name = request.params[0].get_str();
    }

    std::shared_ptr<CWallet> wallet = GetWallet(wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                           "Requested wallet does not exist or is not loaded");
    }

    // Release the "main" shared pointer and prevent further notifications.
    // Note that any attempt to load the same wallet would fail until the wallet
    // is destroyed (see CheckUniqueFileid).
    if (!RemoveWallet(wallet)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
    }

    UnloadWallet(std::move(wallet));

    return UniValue();
}

static UniValue resendwallettransactions(const Config &config,
                                         const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            RPCHelpMan{"resendwallettransactions",
                "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
                "Intended only for testing; the wallet code periodically re-broadcasts\n",
                {}}
                .ToString() +
            "automatically.\n"
            "Returns an RPC error if -walletbroadcast is set to false.\n"
            "Returns array of transaction ids that were re-broadcast.\n");
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    if (!pwallet->GetBroadcastTransactions()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet transaction "
                                             "broadcasting is disabled with "
                                             "-walletbroadcast");
    }

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(
        *locked_chain, GetTime(), g_connman.get());
    UniValue::Array result;
    result.reserve(txids.size());
    for (const uint256 &txid : txids) {
        result.emplace_back(txid.ToString());
    }

    return result;
}

static UniValue listunspent(const Config &config,
                            const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 5) {
        throw std::runtime_error(
            RPCHelpMan{"listunspent",
                "\nReturns array of unspent transaction outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n",
                {
                    {"minconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1", "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "9999999", "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array of Bitcoin Cash addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Bitcoin Cash address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "Include outputs that are not safe to spend\n"
            "                  See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "JSON with query options",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "0", "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "unlimited", "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "unlimited", "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "unlimited", "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                            {"includeTokens", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to show UTXOs with CashTokens on them"},
                            {"tokensOnly", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Whether to only show UTXOs with CashTokens on them (implies includeTokens=true)"},
                        },
                        "query_options"},
                }}
                .ToString() +
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",          (string) the transaction id\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",    (string) the Bitcoin Cash address\n"
            "    \"label\" : \"label\",        (string) The associated label, "
            "or \"\" for the default label\n"
            "    \"scriptPubKey\" : \"key\",   (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction output "
            "amount in " +
            CURRENCY_UNIT +
            "\n"
            "    \"tokenData\" : { ... },    (object optional) token data\n"
            "    \"confirmations\" : n,      (numeric) The number of "
            "confirmations\n"
            "    \"redeemScript\" : n        (string) The redeemScript if "
            "scriptPubKey is P2SH\n"
            "    \"spendable\" : xxx,        (bool) Whether we have the "
            "private keys to spend this output\n"
            "    \"solvable\" : xxx,         (bool) Whether we know how to "
            "spend this output, ignoring the lack of keys\n"
            "    \"safe\" : xxx              (bool) Whether this output is "
            "considered safe to spend. Unconfirmed transactions\n"
            "                              from outside keys are considered "
            "unsafe and are not eligible for spending by\n"
            "                              fundrawtransaction and "
            "sendtoaddress.\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n" +
            HelpExampleCli("listunspent", "") +
            HelpExampleCli("listunspent",
                           "6 9999999 "
                           "\"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\","
                           "\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"") +
            HelpExampleRpc("listunspent",
                           "6, 9999999 "
                           "\"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\","
                           "\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"") +
            HelpExampleCli(
                "listunspent",
                "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'") +
            HelpExampleRpc(
                "listunspent",
                "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } "));
    }

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        for (const UniValue& input : request.params[2].get_array()) {
            const auto& inputStr = input.get_str();
            CTxDestination dest = DecodeDestination(inputStr, config.GetChainParams());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   std::string("Invalid Bitcoin Cash address: ") +
                                       inputStr);
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    std::string("Invalid parameter, duplicated address: ") +
                        inputStr);
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::MBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    Amount nMinimumAmount = Amount::zero();
    Amount nMaximumAmount = MAX_MONEY;
    Amount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;
    std::unique_ptr<CCoinControl> coinControl;

    if (!request.params[4].isNull()) {
        const UniValue::Object &options = request.params[4].get_obj();

        if (auto minimumAmountUV = options.locate("minimumAmount")) {
            nMinimumAmount = AmountFromValue(*minimumAmountUV);
        }

        if (auto maximumAmountUV = options.locate("maximumAmount")) {
            nMaximumAmount = AmountFromValue(*maximumAmountUV);
        }

        if (auto minimumSumAmountUV = options.locate("minimumSumAmount")) {
            nMinimumSumAmount = AmountFromValue(*minimumSumAmountUV);
        }

        if (auto maximumCountUV = options.locate("maximumCount")) {
            nMaximumCount = maximumCountUV->get_int64();
        }
        if (auto includeTokensUV = options.locate("includeTokens")) {
            if (includeTokensUV->get_bool()) {
                if (!coinControl) coinControl = std::make_unique<CCoinControl>();
                coinControl->m_allow_tokens = true;
            }
        }
        if (auto tokensOnlyUV = options.locate("tokensOnly")) {
            if (tokensOnlyUV->get_bool()) {
                if (!coinControl) coinControl = std::make_unique<CCoinControl>();
                coinControl->m_tokens_only = coinControl->m_allow_tokens = true;
            }
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const auto scriptFlags = []{
        LOCK(cs_main);
        return GetMemPoolScriptFlags(Params().GetConsensus(), ::ChainActive().Tip());
    }();

    UniValue::Array results;
    std::vector<COutput> vecOutputs;
    {
        auto locked_chain = pwallet->chain().lock();
        LOCK(pwallet->cs_wallet);
        pwallet->AvailableCoins(*locked_chain, vecOutputs, !include_unsafe,
                                coinControl.get(), nMinimumAmount, nMaximumAmount,
                                nMinimumSumAmount, nMaximumCount, nMinDepth,
                                nMaxDepth);
    }

    LOCK(pwallet->cs_wallet);

    for (const COutput &out : vecOutputs) {
        CTxDestination address;
        const CScript &scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        const token::OutputDataPtr &tokenDataPtr = out.tx->tx->vout[out.i].tokenDataPtr;
        bool fValidAddress = ExtractDestination(scriptPubKey, address, scriptFlags);

        if (destinations.size() &&
            (!fValidAddress || !destinations.count(address))) {
            continue;
        }

        UniValue::Object entry;
        entry.emplace_back("txid", out.tx->GetId().GetHex());
        entry.emplace_back("vout", out.i);

        if (fValidAddress) {
            entry.emplace_back("address", EncodeDestination(address, config));

            auto i = pwallet->mapAddressBook.find(address);
            if (i != pwallet->mapAddressBook.end()) {
                entry.emplace_back("label", i->second.name);
            }

            if (scriptPubKey.IsPayToScriptHash(scriptFlags)) {
                const ScriptID &hash = std::get<ScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.emplace_back("redeemScript", HexStr(redeemScript));
                }
            }
        }

        entry.emplace_back("scriptPubKey", HexStr(scriptPubKey));
        entry.emplace_back("amount", ValueFromAmount(out.tx->tx->vout[out.i].nValue));
        if (tokenDataPtr) {
            entry.emplace_back("tokenData", TokenDataToUniv(*tokenDataPtr));
        }
        entry.emplace_back("confirmations", out.nDepth);
        entry.emplace_back("spendable", out.fSpendable);
        entry.emplace_back("solvable", out.fSolvable);
        entry.emplace_back("safe", out.fSafe);
        results.emplace_back(std::move(entry));
    }

    return results;
}

void FundTransaction(CWallet *const pwallet, CMutableTransaction &tx,
                     Amount &fee_out, int &change_position, const UniValue& options) {
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    CCoinControl coinControl;
    change_position = -1;
    bool lockUnspents = false;
    UniValue::Array subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    if (!options.isNull()) {
        if (options.isBool()) {
            // backward compatibility bool only fallback
            coinControl.fAllowWatchOnly = options.get_bool();
        } else {
            RPCTypeCheckArgument(options, UniValue::VOBJ);
            const UniValue::Object& options_obj = options.get_obj();
            RPCTypeCheckObjStrict(
                options_obj,
                {
                    {"include_unsafe", UniValue::MBOOL|UniValue::VNULL},
                    {"changeAddress", UniValue::VSTR|UniValue::VNULL},
                    {"changePosition", UniValue::VNUM|UniValue::VNULL},
                    {"includeWatching", UniValue::MBOOL|UniValue::VNULL},
                    {"lockUnspents", UniValue::MBOOL|UniValue::VNULL},
                    {"feeRate", UniValue::VNUM|UniValue::VSTR|UniValue::VNULL},
                    {"subtractFeeFromOutputs", UniValue::VARR|UniValue::VNULL},
                });

            if (auto changeAddressUV = options_obj.locate("changeAddress")) {
                CTxDestination dest = DecodeDestination(
                    changeAddressUV->get_str(), pwallet->chainParams);

                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "changeAddress must be a valid Bitcoin Cash address");
                }

                coinControl.destChange = dest;
            }

            if (auto changePositionUV = options_obj.locate("changePosition")) {
                change_position = changePositionUV->get_int();
            }

            if (auto includeWatchingUV = options_obj.locate("includeWatching")) {
                coinControl.fAllowWatchOnly = includeWatchingUV->get_bool();
            }

            if (auto lockUnspentsUV = options_obj.locate("lockUnspents")) {
                lockUnspents = lockUnspentsUV->get_bool();
            }

            if (auto includeUnsafeUV = options_obj.locate("include_unsafe")) {
                coinControl.m_include_unsafe_inputs = includeUnsafeUV->get_bool();
            }

            if (auto feeRateUV = options_obj.locate("feeRate")) {
                coinControl.m_feerate = CFeeRate(AmountFromValue(*feeRateUV));
                coinControl.fOverrideFeeRate = true;
            }

            if (auto subtractFeeFromOutputsUV = options_obj.locate("subtractFeeFromOutputs")) {
                subtractFeeFromOutputs = subtractFeeFromOutputsUV->get_array();
            }
        }
    }

    if (tx.vout.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "TX must have at least one output");
    }

    if (change_position != -1 &&
        (change_position < 0 ||
         (unsigned int)change_position > tx.vout.size())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "changePosition out of bounds");
    }

    for (size_t idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter, duplicated position: %d", pos));
        }
        if (pos < 0) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter, negative position: %d", pos));
        }
        if (pos >= int(tx.vout.size())) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter, position too large: %d", pos));
        }
        setSubtractFeeFromOutputs.insert(pos);
    }

    std::string strFailReason;

    if (!pwallet->FundTransaction(tx, fee_out, change_position, strFailReason,
                                  lockUnspents, setSubtractFeeFromOutputs,
                                  coinControl)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }
}

static UniValue fundrawtransaction(const Config &config,
                                   const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"fundrawtransaction",
                "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                "This will not modify existing inputs, and will add at most one change output to the outputs.\n"
                "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                "The inputs added will not be signed, use signrawtransactionwithkey or signrawtransactionwithwallet for that.\n"
                "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The hex string of the raw transaction"},
                    {"options", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}",
                        {
                            {"include_unsafe", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ RPCArg::Default(DEFAULT_INCLUDE_UNSAFE_INPUTS),
                             "Include inputs that are not safe to spend (unconfirmed transactions from outside keys).\n"
                             "Warning: the resulting transaction may become invalid if one of the unsafe inputs "
                             "disappears.\n"
                             "If that happens, you will need to fund the transaction with different inputs and "
                             "republish it."},
                            {"changeAddress", RPCArg::Type::STR, /* opt */ true, /* default_val */ "pool address", "The Bitcoin Cash address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "random", "The index of the change output"},
                            {"includeWatching", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Also select inputs which are watch only"},
                            {"lockUnspents", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Lock selected unspent outputs"},
                            {"feeRate", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "not set: makes wallet determine the fee", "Set a specific fee rate in " + CURRENCY_UNIT + "/kB"},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", "The zero-based output index, before a change output is added."},
                                },
                            },
                        },
                        "options"},
                }}
                .ToString() +
                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransactionwithwallet", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ|UniValue::MBOOL|UniValue::VNULL});

    // parse hex string from parameter
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    Amount fee;
    int change_position;
    FundTransaction(pwallet, tx, fee, change_position, request.params[1]);

    UniValue::Object result;
    result.reserve(3);
    result.emplace_back("hex", EncodeHexTx(CTransaction(tx)));
    result.emplace_back("fee", ValueFromAmount(fee));
    result.emplace_back("changepos", change_position);
    return result;
}

UniValue signrawtransactionwithwallet(const Config &config,
                                      const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 3) {
        throw std::runtime_error(
            RPCHelpMan{"signrawtransactionwithwallet",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction hex string"},
                    {"prevtxs", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array of previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, /* opt */ false, /* default_val */ "", "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "script key"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, /* opt */ true, /* default_val */ "", "(required for P2SH)"},
                                    {"amount", RPCArg::Type::AMOUNT, /* opt */ false, /* default_val */ "", "The amount spent"},
                                    GetTokenDataArgSpec(),
                                },
                            },
                        },
                    },
                    {"sighashtype", RPCArg::Type::STR, /* opt */ true, /* default_val */ "ALL|FORKID", "The signature hash type. Must be one of\n"
            "       \"ALL|FORKID\"\n"
            "       \"NONE|FORKID\"\n"
            "       \"SINGLE|FORKID\"\n"
            "       \"ALL|FORKID|ANYONECANPAY\"\n"
            "       \"NONE|FORKID|ANYONECANPAY\"\n"
            "       \"SINGLE|FORKID|ANYONECANPAY\"\n"
            "       \"ALL|FORKID|UTXOS\"    (after May 2023 upgrade)\n"
            "       \"NONE|FORKID|UTXOS\"   (after May 2023 upgrade)\n"
            "       \"SINGLE|FORKID|UTXOS\" (after May 2023 upgrade)\n"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",                  (string) The hex-encoded "
            "raw transaction with signature(s)\n"
            "  \"complete\" : true|false,          (boolean) If the "
            "transaction has a complete set of signatures\n"
            "  \"errors\" : [                      (json array of objects) "
            "Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",              (string) The hash of the "
            "referenced, previous transaction\n"
            "      \"vout\" : n,                   (numeric) The index of the "
            "output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",          (string) The hex-encoded "
            "signature script\n"
            "      \"sequence\" : n,               (numeric) Script sequence "
            "number\n"
            "      \"error\" : \"text\"              (string) Verification or "
            "signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"") +
            HelpExampleRpc("signrawtransactionwithwallet", "\"myhex\""));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR|UniValue::VNULL, UniValue::VSTR|UniValue::VNULL});

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Sign the transaction
    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    return SignTransaction(pwallet->chain(), mtx, request.params[1], pwallet,
                           false, request.params[2]);
}

UniValue generate(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"generate",
                "\nMine up to nblocks blocks immediately (before the RPC call returns) to an address in the wallet.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "How many blocks are generated immediately."},
                    {"maxtries", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", "How many iterations to try (default = 1000000)."},
                }}
                .ToString() +
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n" +
            HelpExampleCli("generate", "11"));
    }

    int num_generate = request.params[0].get_int();
    uint64_t max_tries = 1000000;
    if (!request.params[1].isNull()) {
        max_tries = request.params[1].get_int();
    }

    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbase_script) {
        throw JSONRPCError(
            RPC_WALLET_KEYPOOL_RAN_OUT,
            "Error: Keypool ran out, please call keypoolrefill first");
    }

    // throw an error if no script was provided
    if (coinbase_script->reserveScript.empty()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available");
    }

    return generateBlocks(config, coinbase_script, num_generate, max_tries,
                          true);
}

UniValue rescanblockchain(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"rescanblockchain",
                "\nRescan the local blockchain for wallet related transactions.\n",
                {
                    {"start_height", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", "block height where the rescan should start"},
                    {"stop_height", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", "the last block height that should be scanned"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"start_height\"     (numeric) The block height where the "
            "rescan has started. If omitted, rescan started from the genesis "
            "block.\n"
            "  \"stop_height\"      (numeric) The height of the last rescanned "
            "block. If omitted, rescan stopped at the chain tip.\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("rescanblockchain", "100000 120000") +
            HelpExampleRpc("rescanblockchain", "100000 120000"));
    }

    WalletRescanReserver reserver(pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int start_height = 0;
    BlockHash start_block, stop_block;
    {
        auto locked_chain = pwallet->chain().lock();
        std::optional<int> tip_height = locked_chain->getHeight();

        if (!request.params[0].isNull()) {
            start_height = request.params[0].get_int();
            if (start_height < 0 || !tip_height || start_height > *tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Invalid start_height");
            }
        }

        std::optional<int> stop_height;
        if (!request.params[1].isNull()) {
            stop_height = request.params[1].get_int();
            if (*stop_height < 0 || !tip_height || *stop_height > *tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Invalid stop_height");
            } else if (*stop_height < start_height) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "stop_height must be greater than start_height");
            }
        }

        // We can't rescan beyond non-pruned blocks, stop and throw an error
        if (locked_chain->findPruned(start_height, stop_height)) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "Can't rescan beyond pruned data. Use RPC call "
                "getblockchaininfo to determine your pruned height.");
        }

        if (tip_height) {
            start_block = locked_chain->getBlockHash(start_height);

            if (stop_height) {
                stop_block = locked_chain->getBlockHash(*stop_height);
            }
        }
    }

    CWallet::ScanResult result = pwallet->ScanForWalletTransactions(
        start_block, stop_block, reserver, true /* fUpdate */);
    switch (result.status) {
        case CWallet::ScanResult::SUCCESS:
            break;
        case CWallet::ScanResult::FAILURE:
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "Rescan failed. Potentially corrupted data files.");
        case CWallet::ScanResult::USER_ABORT:
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
            // no default case, so the compiler can warn about missing cases
    }
    UniValue::Object response;
    response.reserve(2);
    response.emplace_back("start_height", start_height);
    if (result.stop_height) {
        response.emplace_back("stop_height", *result.stop_height);
    } else {
        response.emplace_back(std::piecewise_construct, std::forward_as_tuple("stop_height"), std::forward_as_tuple());
    }
    return response;
}

/**
 * Appends key-value pairs to entries describing the address dest.
 * Includes additional information if the address is in wallet pwallet (can be nullptr).
 * obj is the UniValue object to append to.
 */
static void DescribeWalletAddress(CWallet *pwallet, const CTxDestination &dest, UniValue::Object& obj,
                                  const uint32_t scriptFlags);

class DescribeWalletAddressVisitor {
    CWallet *const pwallet;
    UniValue::Object& obj;
    uint32_t scriptFlags{};

    void ProcessSubScript(const CScript &subscript,
                          bool include_addresses = false) const {
        // Always present: script type and redeemscript
        std::vector<std::vector<uint8_t>> solutions_data;
        txnouttype which_type = Solver(subscript, solutions_data, scriptFlags);
        obj.emplace_back("script", GetTxnOutputType(which_type));
        obj.emplace_back("hex", HexStr(subscript));

        CTxDestination embedded;
        UniValue::Array a;
        if (ExtractDestination(subscript, embedded, scriptFlags)) {
            // Only when the script corresponds to an address.
            UniValue::Object subobj;
            DescribeWalletAddress(pwallet, embedded, subobj, scriptFlags);
            subobj.emplace_back("address", EncodeDestination(embedded, GetConfig()));
            subobj.emplace_back("scriptPubKey", HexStr(subscript));
            // Always report the pubkey at the top level, so that
            // `getnewaddress()['pubkey']` always works.
            if (auto pubkeyUV = subobj.locate("pubkey")) {
                obj.emplace_back("pubkey", *pubkeyUV);
            }
            obj.emplace_back("embedded", std::move(subobj));
            if (include_addresses) {
                a.emplace_back(EncodeDestination(embedded, GetConfig()));
            }
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not
            // have a corresponding address).
            // TODO: abstract out the common functionality between this logic
            // and ExtractDestinations.
            obj.emplace_back("sigsrequired", solutions_data[0][0]);
            UniValue::Array pubkeys;
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) {
                    a.emplace_back(EncodeDestination(key.GetID(), GetConfig()));
                }
                pubkeys.emplace_back(HexStr(key));
            }
            obj.emplace_back("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys
        // using their P2PKH address. For that reason, only add the 'addresses'
        // field when needed for backward compatibility. New applications can
        // use the 'pubkeys' field for inspecting multisig participants.
        if (include_addresses) {
            obj.emplace_back("addresses", std::move(a));
        }
    }

public:

    explicit DescribeWalletAddressVisitor(CWallet *_pwallet, UniValue::Object& _obj, uint32_t scriptFlags_)
        : pwallet(_pwallet), obj(_obj), scriptFlags(scriptFlags_) {}

    void operator()(const CNoDestination &) const {}

    void operator()(const CKeyID &keyID) const {
        CPubKey vchPubKey;
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.emplace_back("pubkey", HexStr(vchPubKey));
            obj.emplace_back("iscompressed", vchPubKey.IsCompressed());
        }
    }

    void operator()(const ScriptID &scriptID) const {
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, true);
        }
    }
};

// Upstream version of this function has only two arguments and returns an intermediate UniValue object.
// Instead, our version directly appends the new key-value pairs to the target UniValue object.
static void DescribeWalletAddress(CWallet *pwallet, const CTxDestination &dest, UniValue::Object& obj,
                                  const uint32_t scriptFlags) {
    DescribeAddress(dest, obj);
    std::visit(DescribeWalletAddressVisitor(pwallet, obj, scriptFlags), dest);
}

/** Convert CAddressBookData to JSON record.  */
static UniValue::Object AddressBookDataToJSON(const CAddressBookData &data, const bool verbose) {
    UniValue::Object ret;
    ret.reserve(1 + verbose);
    if (verbose) {
        ret.emplace_back("name", data.name);
    }
    ret.emplace_back("purpose", data.purpose);
    return ret;
}

UniValue getaddressinfo(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getaddressinfo",
                "\nReturn information about the given Bitcoin Cash address. Some information requires the address\n"
                "to be in the wallet.\n",
                {
                    {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The Bitcoin Cash address to get the information of."},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"address\" : \"address\",        (string) The Bitcoin Cash address "
            "validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex-encoded "
            "scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is "
            "yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is "
            "watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a "
            "script\n"
            "  \"ischange\" : true|false,      (boolean) If the address was "
            "used for change output\n"
            "  \"script\" : \"type\"             (string, optional) The output "
            "script type. Only if \"isscript\" is true and the redeemscript is "
            "known. Possible types: nonstandard, pubkey, pubkeyhash, "
            "scripthash, multisig, nulldata\n"
            "  \"hex\" : \"hex\",                (string, optional) The "
            "redeemscript for the p2sh address\n"
            "  \"pubkeys\"                     (string, optional) Array of "
            "pubkeys associated with the known redeemscript (only if "
            "\"script\" is \"multisig\")\n"
            "    [\n"
            "      \"pubkey\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"sigsrequired\" : xxxxx        (numeric, optional) Number of "
            "signatures required to spend multisig output (only if \"script\" "
            "is \"multisig\")\n"
            "  \"pubkey\" : \"publickeyhex\",    (string, optional) The hex "
            "value of the raw public key, for single-key addresses (possibly "
            "embedded in P2SH or P2WSH)\n"
            "  \"embedded\" : {...},           (object, optional) Information "
            "about the address embedded in P2SH or P2WSH, if relevant and "
            "known. It includes all getaddressinfo output fields for the "
            "embedded address, excluding metadata (\"timestamp\", "
            "\"hdkeypath\", \"hdseedid\") and relation to the wallet "
            "(\"ismine\", \"iswatchonly\").\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is "
            "compressed\n"
            "  \"label\" :  \"label\"         (string) The label associated "
            "with the address, \"\" is the default label\n"
            "  \"timestamp\" : timestamp,      (number, optional) The creation "
            "time of the key if available in seconds since epoch (Jan 1 1970 "
            "GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD "
            "keypath if the key is HD and available\n"
            "  \"hdseedid\" : \"<hash160>\"      (string, optional) The "
            "Hash160 of the HD seed\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) alias for "
            "hdseedid maintained for backwards compatibility. Will be removed "
            "in V0.21.\n"
            "  \"labels\"                      (object) Array of labels "
            "associated with the address.\n"
            "    [\n"
            "      { (json object of label data)\n"
            "        \"name\": \"labelname\" (string) The label\n"
            "        \"purpose\": \"string\" (string) Purpose of address "
            "(\"send\" for sending address, \"receive\" for receiving "
            "address)\n"
            "      },...\n"
            "    ]\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getaddressinfo",
                           "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"") +
            HelpExampleRpc("getaddressinfo",
                           "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\""));
    }

    const uint32_t scriptFlags = [&config] {
        LOCK(cs_main);
        return GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ChainActive().Tip());
    }();

    LOCK(pwallet->cs_wallet);

    UniValue::Object ret;
    CTxDestination dest =
        DecodeDestination(request.params[0].get_str(), config.GetChainParams());

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    ret.emplace_back("address", EncodeDestination(dest, config));

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.emplace_back("scriptPubKey", HexStr(scriptPubKey));

    isminetype mine = IsMine(*pwallet, dest);
    ret.emplace_back("ismine", bool(mine & ISMINE_SPENDABLE));
    ret.emplace_back("iswatchonly", bool(mine & ISMINE_WATCH_ONLY));
    DescribeWalletAddress(pwallet, dest, ret, scriptFlags);
    if (pwallet->mapAddressBook.count(dest)) {
        ret.emplace_back("label", pwallet->mapAddressBook[dest].name);
    }
    ret.emplace_back("ischange", pwallet->IsChange(scriptPubKey));
    const CKeyMetadata *meta = nullptr;
    CKeyID key_id = GetKeyForDestination(*pwallet, dest);
    if (!key_id.IsNull()) {
        auto it = pwallet->mapKeyMetadata.find(key_id);
        if (it != pwallet->mapKeyMetadata.end()) {
            meta = &it->second;
        }
    }
    if (!meta) {
        auto it = pwallet->m_script_metadata.find(ScriptID(scriptPubKey, false /* isP2SH32 */));
        if (it == pwallet->m_script_metadata.end()) {
            // try again with P2SH32
            it = pwallet->m_script_metadata.find(ScriptID(scriptPubKey, true));
        }
        if (it != pwallet->m_script_metadata.end()) {
            meta = &it->second;
        }
    }
    if (meta) {
        ret.emplace_back("timestamp", meta->nCreateTime);
        if (!meta->hdKeypath.empty()) {
            ret.emplace_back("hdkeypath", meta->hdKeypath);
            ret.emplace_back("hdseedid", meta->hd_seed_id.GetHex());
            ret.emplace_back("hdmasterkeyid", meta->hd_seed_id.GetHex());
        }
    }

    // Currently only one label can be associated with an address, return an
    // array so the API remains stable if we allow multiple labels to be
    // associated with an address.
    UniValue::Array labels;
    std::map<CTxDestination, CAddressBookData>::iterator mi =
        pwallet->mapAddressBook.find(dest);
    if (mi != pwallet->mapAddressBook.end()) {
        labels.reserve(1);
        labels.emplace_back(AddressBookDataToJSON(mi->second, true));
    }
    ret.emplace_back("labels", std::move(labels));

    return ret;
}

UniValue getaddressesbylabel(const Config &config,
                             const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            RPCHelpMan{"getaddressesbylabel",
                "\nReturns the list of addresses assigned the specified label.\n",
                {
                    {"label", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The label."},
                }}
                .ToString() +
            "\nResult:\n"
            "{ (json object with addresses as keys)\n"
            "  \"address\": { (json object with information about address)\n"
            "    \"purpose\": \"string\" (string)  Purpose of address "
            "(\"send\" for sending address, \"receive\" for receiving "
            "address)\n"
            "  },...\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getaddressesbylabel", "\"tabby\"") +
            HelpExampleRpc("getaddressesbylabel", "\"tabby\""));
    }

    LOCK(pwallet->cs_wallet);

    const std::string &label = LabelFromValue(request.params[0]);

    // Find all addresses that have the given label
    UniValue::Object ret;
    for (const std::pair<const CTxDestination, CAddressBookData> &item :
         pwallet->mapAddressBook) {
        if (item.second.name == label) {
            ret.emplace_back(EncodeDestination(item.first, config), AddressBookDataToJSON(item.second, false));
        }
    }

    if (ret.empty()) {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, "No addresses with label " + label);
    }

    return ret;
}

UniValue listlabels(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            RPCHelpMan{"listlabels",
                "\nReturns the list of all labels, or labels that are assigned to addresses with a specific purpose.\n",
                {
                    {"purpose", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "Address purpose to list labels for ('send','receive'). An empty string is the same as not providing this argument."},
                }}
                .ToString() +
            "\nResult:\n"
            "[               (json array of string)\n"
            "  \"label\",      (string) Label name\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            "\nList all labels\n" +
            HelpExampleCli("listlabels", "") +
            "\nList labels that have receiving addresses\n" +
            HelpExampleCli("listlabels", "receive") +
            "\nList labels that have sending addresses\n" +
            HelpExampleCli("listlabels", "send") + "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("listlabels", "receive"));
    }

    LOCK(pwallet->cs_wallet);

    std::string purpose;
    if (!request.params[0].isNull()) {
        purpose = request.params[0].get_str();
    }

    // Add to a set to sort by label name, then insert into Univalue array
    std::set<std::string> label_set;
    for (const std::pair<const CTxDestination, CAddressBookData> &entry :
         pwallet->mapAddressBook) {
        if (purpose.empty() || entry.second.purpose == purpose) {
            label_set.insert(entry.second.name);
        }
    }

    UniValue::Array ret;
    ret.reserve(label_set.size());
    for (const std::string &name : label_set) {
        ret.emplace_back(name);
    }
    return ret;
}

static UniValue sethdseed(const Config &config, const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            RPCHelpMan{"sethdseed",
                "\nSet or generate a new HD wallet seed. Non-HD wallets will not be upgraded to being a HD wallet. Wallets that are already\n"
                "HD will have a new HD seed set so that new keys added to the keypool will be derived from this new seed.\n"
                "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the HD wallet seed." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"newkeypool", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "Whether to flush old unused addresses, including change addresses, from the keypool and regenerate it.\n"
            "                             If true, the next address from getnewaddress and change address from getrawchangeaddress will be from this new seed.\n"
            "                             If false, addresses (including change addresses if the wallet already had HD Chain Split enabled) from the existing\n"
            "                             keypool will be used until it has been depleted."},
                    {"seed", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "The WIF private key to use as the new HD seed; if not provided a random seed will be used.\n"
            "                             The seed value can be retrieved using the dumpwallet command. It is the private key marked hdseed=1"},
                }}
                .ToString() +
            "\nExamples:\n"
            + HelpExampleCli("sethdseed", "")
            + HelpExampleCli("sethdseed", "false")
            + HelpExampleCli("sethdseed", "true \"wifkey\"")
            + HelpExampleRpc("sethdseed", "true, \"wifkey\"")
            );
    }

    if (IsInitialBlockDownload()) {
        throw JSONRPCError(
            RPC_CLIENT_IN_INITIAL_DOWNLOAD,
            "Cannot set a new HD seed while still in Initial Block Download");
    }

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Cannot set a HD seed to a wallet with private keys disabled");
    }

    auto locked_chain = pwallet->chain().lock();
    LOCK(pwallet->cs_wallet);

    // Do not do anything to non-HD wallets
    if (!pwallet->CanSupportFeature(FEATURE_HD)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Cannot set a HD seed on a non-HD wallet. Start with "
            "-upgradewallet in order to upgrade a non-HD wallet to HD");
    }

    EnsureWalletIsUnlocked(*pwallet);

    bool flush_key_pool = true;
    if (!request.params[0].isNull()) {
        flush_key_pool = request.params[0].get_bool();
    }

    CPubKey master_pub_key;
    if (request.params[1].isNull()) {
        master_pub_key = pwallet->GenerateNewSeed();
    } else {
        CKey key = DecodeSecret(request.params[1].get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Invalid private key");
        }

        if (HaveKey(*pwallet, key)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Already have this key (either as an HD seed or "
                               "as a loose private key)");
        }

        master_pub_key = pwallet->DeriveNewSeed(key);
    }

    pwallet->SetHDSeed(master_pub_key);
    if (flush_key_pool) {
        pwallet->NewKeyPool();
    }

    return UniValue();
}

static UniValue walletprocesspsbt(const Config &config,
                                  const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 1 ||
        request.params.size() > 4) {
        throw std::runtime_error(
            RPCHelpMan{"walletprocesspsbt",
                "\nUpdate a PSBT with input information from our wallet and then sign inputs\n"
                "that we can sign for." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"psbt", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The transaction base64 string"},
                    {"sign", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true", "Also sign the transaction when updating"},
                    {"sighashtype", RPCArg::Type::STR, /* opt */ true, /* default_val */ "ALL|FORKID", "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"ALL|FORKID\"\n"
            "       \"NONE|FORKID\"\n"
            "       \"SINGLE|FORKID\"\n"
            "       \"ALL|FORKID|ANYONECANPAY\"\n"
            "       \"NONE|FORKID|ANYONECANPAY\"\n"
            "       \"SINGLE|FORKID|ANYONECANPAY\"\n"
            "       \"ALL|FORKID|UTXOS\"    (after May 2023 upgrade)\n"
            "       \"NONE|FORKID|UTXOS\"   (after May 2023 upgrade)\n"
            "       \"SINGLE|FORKID|UTXOS\" (after May 2023 upgrade)\n"},
                    {"bip32derivs", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "If true, includes the BIP 32 derivation paths for public keys if we know them"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"psbt\" : \"value\",          (string) The base64-encoded "
            "partially signed transaction\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a "
            "complete set of signatures\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("walletprocesspsbt", "\"psbt\""));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::MBOOL, UniValue::VSTR, UniValue::MBOOL|UniValue::VNULL});

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodePSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           strprintf("TX decode failed %s", error));
    }

    // Get the sighash type
    SigHashType nHashType = ParseSighashString(request.params[2]);
    if (!nHashType.hasFork()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Signature must use SIGHASH_FORKID");
    }

    const uint32_t scriptFlags = [&config] {
        LOCK(cs_main);
        return GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ::ChainActive().Tip());
    }();

    // Fill transaction with our data and also sign
    bool sign =
        request.params[1].isNull() ? true : request.params[1].get_bool();
    bool bip32derivs =
        request.params[3].isNull() ? false : request.params[3].get_bool();
    bool complete = FillPSBT(pwallet, psbtx, scriptFlags, nHashType, sign, bip32derivs);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    UniValue::Object result;
    result.reserve(2);
    result.emplace_back("psbt", EncodeBase64(MakeUInt8Span(ssTx)));
    result.emplace_back("complete", complete);
    return result;
}

static UniValue walletcreatefundedpsbt(const Config &config,
                                       const JSONRPCRequest &request) {
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet *const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return UniValue();
    }

    if (request.fHelp || request.params.size() < 2 ||
        request.params.size() > 5) {
        throw std::runtime_error(
            RPCHelpMan{"walletcreatefundedpsbt",
                "\nCreates and funds a transaction in the Partially Signed Transaction format. Inputs will be added if supplied inputs are not enough\n"
                "Implements the Creator and Updater roles.\n",
                {
                    {"inputs", RPCArg::Type::ARR, /* opt */ false, /* default_val */ "", "A json array of json objects",
                        {
                            {"", RPCArg::Type::OBJ, /* opt */ false, /* default_val */ "", "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, /* opt */ false, /* default_val */ "", "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The output number"},
                                    {"sequence", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The sequence number"},
                                },
                            },
                        },
                        },
                    {"outputs", RPCArg::Type::ARR, /* opt */ false, /* default_val */ "", "a json array with outputs (key-value pairs)."
                            "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                            "                             accepted as second parameter.",
                        {
                            {"", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "",
                                {
                                    {"address", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "", "A key-value pair. The key (string) is the Bitcoin Cash address, the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
                                },
                                },
                            GetAlternateAddressObjectOutputArgSpec(),
                            {"", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "",
                                {
                                    {"data", RPCArg::Type::STR_HEX, /* opt */ true, /* default_val */ "", "A key-value pair. The key must be \"data\", the value is a hex-encoded data string or an array of hex-encoded data strings (each item yields a separate data push)"},
                                },
                            },
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "0", "Raw locktime. Non-0 value also locktime-activates inputs\n"
                            "                             Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible."},
                    {"options", RPCArg::Type::OBJ, /* opt */ true, /* default_val */ "", "",
                        {
                            {"include_unsafe", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ RPCArg::Default(DEFAULT_INCLUDE_UNSAFE_INPUTS),
                             "Include inputs that are not safe to spend (unconfirmed transactions from outside keys).\n"
                             "Warning: the resulting transaction may become invalid if one of the unsafe inputs "
                             "disappears.\n"
                             "If that happens, you will need to fund the transaction with different inputs and "
                             "republish it."},
                            {"changeAddress", RPCArg::Type::STR_HEX, /* opt */ true, /* default_val */ "pool address", "The Bitcoin Cash address to receive the change"},
                            {"changePosition", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "random", "The index of the change output"},
                            {"includeWatching", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Also select inputs which are watch only"},
                            {"lockUnspents", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "Lock selected unspent outputs"},
                            {"feeRate", RPCArg::Type::AMOUNT, /* opt */ true, /* default_val */ "not set: makes wallet determine the fee", "Set a specific fee rate in " + CURRENCY_UNIT + "/kB"},
                            {"subtractFeeFromOutputs", RPCArg::Type::ARR, /* opt */ true, /* default_val */ "", "A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", ""},
                                },
                            },
                        },
                        "options"},
                    {"bip32derivs", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "false", "If true, includes the BIP 32 derivation paths for public keys if we know them"},
                }}
                .ToString() +
                            "\nResult:\n"
                            "{\n"
                            "  \"psbt\": \"value\",        (string)  The resulting raw transaction (base64-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("walletcreatefundedpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                            );
    }

    RPCTypeCheck(request.params,
                 {UniValue::VARR,
                  UniValue::VARR|UniValue::VOBJ,
                  UniValue::VNUM|UniValue::VNULL,
                  UniValue::VOBJ|UniValue::VNULL,
                  UniValue::MBOOL|UniValue::VNULL});

    const uint32_t scriptFlags = [&config] {
        LOCK(cs_main);
        return GetMemPoolScriptFlags(config.GetChainParams().GetConsensus(), ::ChainActive().Tip());
    }();

    Amount fee;
    int change_position;
    CMutableTransaction rawTx =
        ConstructTransaction(config.GetChainParams(), request.params[0],
                             request.params[1], request.params[2]);
    FundTransaction(pwallet, rawTx, fee, change_position, request.params[3]);

    // Make a blank psbt
    const CTransaction tx(rawTx);
    PartiallySignedTransaction psbtx(tx);

    // Fill transaction with out data but don't sign
    bool bip32derivs =
        request.params[4].isNull() ? false : request.params[4].get_bool();
    FillPSBT(pwallet, psbtx, scriptFlags, SigHashType().withFork(), false, bip32derivs);

    // Serialize the PSBT
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    UniValue::Object result;
    result.reserve(3);
    result.emplace_back("psbt", EncodeBase64(MakeUInt8Span(ssTx)));
    result.emplace_back("fee", ValueFromAmount(fee));
    result.emplace_back("changepos", change_position);
    return result;
}

// clang-format off
static const ContextFreeRPCCommand commands[] = {
    //  category            name                            actor (function)              argNames
    //  ------------------- ------------------------        ----------------------        ----------
    { "generating",         "generate",                     generate,                     {"nblocks","maxtries"} },
    { "hidden",             "resendwallettransactions",     resendwallettransactions,     {} },
    { "rawtransactions",    "fundrawtransaction",           fundrawtransaction,           {"hexstring","options"} },
    { "wallet",             "abandontransaction",           abandontransaction,           {"txid"} },
    { "wallet",             "addmultisigaddress",           addmultisigaddress,           {"nrequired","keys","label"} },
    { "wallet",             "backupwallet",                 backupwallet,                 {"destination"} },
    { "wallet",             "createwallet",                 createwallet,                 {"wallet_name", "disable_private_keys", "blank", "passphrase"} },
    { "wallet",             "encryptwallet",                encryptwallet,                {"passphrase"} },
    { "wallet",             "getaddressesbylabel",          getaddressesbylabel,          {"label"} },
    { "wallet",             "getaddressinfo",               getaddressinfo,               {"address"} },
    { "wallet",             "getbalance",                   getbalance,                   {"dummy","minconf","include_watchonly"} },
    { "wallet",             "getnewaddress",                getnewaddress,                {"label", "address_type"} },
    { "wallet",             "getrawchangeaddress",          getrawchangeaddress,          {"address_type"} },
    { "wallet",             "getreceivedbyaddress",         getreceivedbyaddress,         {"address","minconf"} },
    { "wallet",             "getreceivedbylabel",           getreceivedbylabel,           {"label","minconf"} },
    { "wallet",             "gettransaction",               gettransaction,               {"txid","include_watchonly"} },
    { "wallet",             "getunconfirmedbalance",        getunconfirmedbalance,        {} },
    { "wallet",             "getwalletinfo",                getwalletinfo,                {} },
    { "wallet",             "keypoolrefill",                keypoolrefill,                {"newsize"} },
    { "wallet",             "listaddressgroupings",         listaddressgroupings,         {} },
    { "wallet",             "listlabels",                   listlabels,                   {"purpose"} },
    { "wallet",             "listlockunspent",              listlockunspent,              {} },
    { "wallet",             "listreceivedbyaddress",        listreceivedbyaddress,        {"minconf","include_empty","include_watchonly","address_filter"} },
    { "wallet",             "listreceivedbylabel",          listreceivedbylabel,          {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",               listsinceblock,               {"blockhash","target_confirmations","include_watchonly","include_removed"} },
    { "wallet",             "listtransactions",             listtransactions,             {"label","count","skip","include_watchonly"} },
    { "wallet",             "listunspent",                  listunspent,                  {"minconf","maxconf","addresses","include_unsafe","query_options"} },
    { "wallet",             "listwalletdir",                listwalletdir,                {} },
    { "wallet",             "listwallets",                  listwallets,                  {} },
    { "wallet",             "loadwallet",                   loadwallet,                   {"filename"} },
    { "wallet",             "lockunspent",                  lockunspent,                  {"unlock","transactions"} },
    { "wallet",             "rescanblockchain",             rescanblockchain,             {"start_height", "stop_height"} },
    { "wallet",             "sendmany",                     sendmany,                     {"dummy","amounts","minconf","comment","subtractfeefrom", "coinsel", "include_unsafe"} },
    { "wallet",             "sendtoaddress",                sendtoaddress,                {"address","amount","comment","comment_to","subtractfeefromamount","coinsel", "include_unsafe"} },
    { "wallet",             "sethdseed",                    sethdseed,                    {"newkeypool","seed"} },
    { "wallet",             "setlabel",                     setlabel,                     {"address","label"} },
    { "wallet",             "settxfee",                     settxfee,                     {"amount"} },
    { "wallet",             "signmessage",                  signmessage,                  {"address","message"} },
    { "wallet",             "signrawtransactionwithwallet", signrawtransactionwithwallet, {"hexstring","prevtxs","sighashtype"} },
    { "wallet",             "unloadwallet",                 unloadwallet,                 {"wallet_name"} },
    { "wallet",             "walletcreatefundedpsbt",       walletcreatefundedpsbt,       {"inputs","outputs","locktime","options","bip32derivs"} },
    { "wallet",             "walletlock",                   walletlock,                   {} },
    { "wallet",             "walletpassphrase",             walletpassphrase,             {"passphrase","timeout"} },
    { "wallet",             "walletpassphrasechange",       walletpassphrasechange,       {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletprocesspsbt",            walletprocesspsbt,            {"psbt","sign","sighashtype","bip32derivs"} },
};
// clang-format on

void RegisterWalletRPCCommands(CRPCTable &t) {
    for (unsigned int vcidx = 0; vcidx < std::size(commands); ++vcidx) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
