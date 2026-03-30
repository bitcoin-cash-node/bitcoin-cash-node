// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>

#include <config.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sigencoding.h>
#include <script/standard.h>
#include <serialize.h>
#include <streams.h>
#include <undo.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <algorithm>
#include <limits>
#include <utility>

TransactionFormatOptions::TransactionFormatOptions(const BlockTxVerbosity verbosity) noexcept {
    using enum BlockTxVerbosity;
    switch (verbosity) {
        case SHOW_TXID:
            block_level.txids_only = true;
            break;
        case SHOW_DETAILS_AND_PREVOUT:
            prevout_options.emplace();
            prevout_options->nest_prevouts = prevout_options->include_height = prevout_options->include_generated = true;
            [[fallthrough]];
        case SHOW_DETAILS:
            include_hex = include_fee = true;
            break;
    }
}

UniValue ValueFromAmount(const Amount &amount) {
    const bool sign = amount < Amount::zero();
    const int64_t i_amt = amount / SATOSHI;
    const uint64_t u_abs = i_amt == std::numeric_limits<int64_t>::min() // handle fact that -(INT64_MIN) is UB
                               ? static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1u // abs(INT64_MIN)
                               : static_cast<uint64_t>(sign ? -i_amt : i_amt);
    const uint64_t coin_sats = COIN / SATOSHI;
    const uint64_t quotient = u_abs / coin_sats;
    const uint64_t remainder = u_abs % coin_sats;
    return UniValue(UniValue::VNUM, strprintf("%s%u.%08u", sign ? "-" : "", quotient, remainder));
}

std::string FormatScript(const CScript &script) {
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<uint8_t> vch;
        if (script.GetOp(it, op, vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            }

            if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            }

            if (op >= OP_NOP && op < FIRST_UNDEFINED_OP_VALUE) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }

            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            } else {
                ret += strprintf("0x%x ", HexStr(it2, it));
            }

            continue;
        }

        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }

    return ret.substr(0, ret.size() - 1);
}

const std::map<uint8_t, std::string> mapSigHashTypes = {
    {SIGHASH_ALL, "ALL"},
    {SIGHASH_ALL | SIGHASH_ANYONECANPAY, "ALL|ANYONECANPAY"},
    {SIGHASH_ALL | SIGHASH_UTXOS, "ALL|UTXOS"},

    {SIGHASH_ALL | SIGHASH_FORKID, "ALL|FORKID"},
    {SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY, "ALL|FORKID|ANYONECANPAY"},
    {SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS, "ALL|FORKID|UTXOS"},

    {SIGHASH_NONE, "NONE"},
    {SIGHASH_NONE | SIGHASH_ANYONECANPAY, "NONE|ANYONECANPAY"},
    {SIGHASH_NONE | SIGHASH_UTXOS, "NONE|UTXOS"},

    {SIGHASH_NONE | SIGHASH_FORKID, "NONE|FORKID"},
    {SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,  "NONE|FORKID|ANYONECANPAY"},
    {SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_UTXOS,  "NONE|FORKID|UTXOS"},

    {SIGHASH_SINGLE, "SINGLE"},
    {SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, "SINGLE|ANYONECANPAY"},
    {SIGHASH_SINGLE | SIGHASH_UTXOS, "SINGLE|UTXOS"},

    {SIGHASH_SINGLE | SIGHASH_FORKID, "SINGLE|FORKID"},
    {SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY, "SINGLE|FORKID|ANYONECANPAY"},
    {SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_UTXOS, "SINGLE|FORKID|UTXOS"},
};

std::string SighashToStr(uint8_t sighash_type) {
    const auto &it = mapSigHashTypes.find(sighash_type);
    if (it == mapSigHashTypes.end()) {
        return "";
    }
    return it->second;
}

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string
 * representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash
 * types on data within the script that matches the format of a signature. Only
 * pass true for scripts you believe could contain signatures. For example, pass
 * false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript &script, bool fAttemptSighashDecode) {
    std::string str;
    opcodetype opcode;
    std::vector<uint8_t> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }

        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }

        size_t const maxScriptNumSize = CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT;

        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= maxScriptNumSize) {
                str += strprintf("%d", CScriptNum(vch, false, maxScriptNumSize).getint64());
            } else {
                // the IsUnspendable check makes sure not to try to decode
                // OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from
                    // data that looks like a signature within a scriptSig. This
                    // won't decode correctly formatted public keys in Pubkey or
                    // Multisig scripts due to the restrictions on the pubkey
                    // formats (see IsCompressedOrUncompressedPubKey) being
                    // incongruous with the checks in
                    // CheckTransactionSignatureEncoding.
                    uint32_t flags = SCRIPT_VERIFY_STRICTENC;
                    if (vch.back() & SIGHASH_FORKID) {
                        // If the transaction is using SIGHASH_FORKID, we need
                        // to set the appropriate flag.
                        // TODO: Remove after the Hard Fork.
                        flags |= SCRIPT_ENABLE_SIGHASH_FORKID;
                        if (vch.back() & SIGHASH_UTXOS) {
                            // After activation of upgrade9, to ensure we parse SIGHASH_UTXOS correctly.
                            flags |= SCRIPT_ENABLE_TOKENS;
                        }
                    }
                    if (CheckTransactionSignatureEncoding(vch, flags,
                                                          nullptr)) {
                        const uint8_t chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode =
                                "[" +
                                mapSigHashTypes.find(chSigHashType)->second +
                                "]";
                            // remove the sighash type byte. it will be replaced
                            // by the decode.
                            vch.pop_back();
                        }
                    }

                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }

    return str;
}

std::string EncodeHexTx(const CTransaction &tx) {
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx);
}

UniValue::Object ScriptToUniv(const Config &config, const CScript &script, bool include_address,
                              bool include_type, bool include_pattern) {
    CTxDestination address;
    // Enable all flags that may influence the correct parsing of a scriptPubKey now or in the future, even if such
    // flags are not currently activated.
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS
                           | SCRIPT_ENABLE_MAY2026;
    bool extracted = include_address && ExtractDestination(script, address, flags);

    UniValue::Object out;
    out.reserve(2 + include_type + extracted + include_pattern);
    out.emplace_back("asm", ScriptToAsmStr(script, false));
    out.emplace_back("hex", HexStr(script));

    if (include_type) {
        std::vector<std::vector<uint8_t>> solns;
        out.emplace_back("type", GetTxnOutputType(Solver(script, solns, flags)));
    }

    if (extracted) {
        out.emplace_back("address", EncodeDestination(address, config));
    }
    if (include_pattern) {
        out.emplace_back("byteCodePattern", ScriptToByteCodePatternUniv(script));
    }

    return out;
}

UniValue::Object ScriptPubKeyToUniv(const Config &config, const CScript &scriptPubKey, bool fIncludeHex,
                                    bool fIncludeP2SH, bool include_pattern) {
    UniValue::Object out;
    out.reserve(4 + fIncludeHex + 2*fIncludeP2SH + include_pattern);
    out.emplace_back("asm", ScriptToAsmStr(scriptPubKey, false));
    if (fIncludeHex) {
        out.emplace_back("hex", HexStr(scriptPubKey));
    }

    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;
    const uint32_t flags = STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_ENABLE_P2SH_32 | SCRIPT_ENABLE_TOKENS
                           | SCRIPT_ENABLE_MAY2026;
    bool extracted = ExtractDestinations(scriptPubKey, type, addresses, nRequired, flags);

    if (extracted) {
        out.emplace_back("reqSigs", nRequired);
    }

    out.emplace_back("type", GetTxnOutputType(type));

    if (extracted) {
        UniValue::Array a;
        a.reserve(addresses.size());
        for (const CTxDestination &addr : addresses) {
            a.emplace_back(EncodeDestination(addr, config));
        }
        out.emplace_back("addresses", std::move(a));
    }

    if (fIncludeP2SH && type != TX_SCRIPTHASH) {
        // P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
        // don't return the address for a P2SH of the P2SH.
        out.emplace_back("p2sh", EncodeDestination(ScriptID(scriptPubKey, false), config));
        out.emplace_back("p2sh_32", EncodeDestination(ScriptID(scriptPubKey, true), config));
    }

    if (include_pattern) {
        out.emplace_back("byteCodePattern", ScriptToByteCodePatternUniv(scriptPubKey));
    }

    return out;
}

UniValue::Object TransactionToUniv(const Config &config, const CTransaction &tx, const CTxUndo *txundo,
                                   const TransactionFormatOptions &options, size_t extraFieldsToReserve) {
    const bool tx_is_coinbase = tx.IsCoinBase();
    const bool have_prevouts = !tx_is_coinbase && txundo && txundo->vprevout.size() == tx.vin.size();
    const bool include_hex = options.include_hex;
    const bool include_patterns = options.include_patterns;
    // Fields that require prevouts will be silently omitted if prevouts are missing
    const bool include_fee = have_prevouts && options.include_fee;
    const bool include_prevouts = have_prevouts && options.prevout_options.has_value();
    const bool include_prevout_height = include_prevouts && options.prevout_options->include_height;
    const bool include_prevout_generated = include_prevouts && options.prevout_options->include_generated;
    const bool nest_prevouts = include_prevouts && options.prevout_options->nest_prevouts;
    Amount amt_total_in = Amount::zero();
    Amount amt_total_out = Amount::zero();

    UniValue::Object entry;
    entry.reserve(7u + include_hex + include_fee + extraFieldsToReserve);
    entry.emplace_back("txid", tx.GetId().GetHex());
    entry.emplace_back("hash", tx.GetHash().GetHex());
    entry.emplace_back("version", tx.nVersion);
    entry.emplace_back("size", ::GetSerializeSize(tx, PROTOCOL_VERSION));
    entry.emplace_back("locktime", tx.nLockTime);

    UniValue::Array vin;
    vin.reserve(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const CTxIn &txin = tx.vin[i];
        UniValue::Object in;
        const size_t prevout_size = include_prevouts ? (2u // value and scriptPubKey
                                                        + 1u // maybe has_token_data
                                                        + include_prevout_generated
                                                        + include_prevout_height
                                                        + include_patterns)
                                                     : 0u;
        const size_t in_rsv_sz = (tx_is_coinbase ? 2u : 4u) + // txid and index + scriptSig and sequence for non-coinbase
                                 (include_prevouts ? (nest_prevouts ? 1u : prevout_size) : 0u); // prevout object or flattened fields
        in.reserve(in_rsv_sz);
        std::optional<std::vector<uint8_t>> optMaybeRedeemScript;
        if (tx_is_coinbase) {
            in.emplace_back("coinbase", HexStr(txin.scriptSig));
        } else {
            in.emplace_back("txid", txin.prevout.GetTxId().GetHex());
            in.emplace_back("vout", txin.prevout.GetN());
            UniValue::Object o;
            o.reserve(2 + include_patterns /* byteCodePattern */ + (include_prevouts && include_patterns) /* maybe redeemScript */);
            o.emplace_back("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.emplace_back("hex", HexStr(txin.scriptSig));
            if (include_patterns) {
                o.emplace_back("byteCodePattern", ScriptToByteCodePatternUniv(txin.scriptSig, &optMaybeRedeemScript));
            }
            in.emplace_back("scriptSig", std::move(o));
        }

        if (have_prevouts) {
            assert(txundo != nullptr);
            const Coin& prev_coin = txundo->vprevout.at(i);
            const CTxOut& prev_txout = prev_coin.GetTxOut();

            if (include_fee) {
                amt_total_in += prev_txout.nValue;
            }

            if (include_prevouts) {
                UniValue::Object o_script_pub_key = ScriptToUniv(config, prev_txout.scriptPubKey,
                                                                 /*include_address=*/true, /*include type=*/true,
                                                                 /*include_pattern=*/include_patterns);
                UniValue::Object p;
                const bool has_token_data = prev_txout.tokenDataPtr;
                if (prevout_size) {
                    p.reserve(prevout_size - !has_token_data);
                }
                if (include_prevout_generated) {
                    p.emplace_back("generated", prev_coin.IsCoinBase());
                }
                if (include_prevout_height) {
                    p.emplace_back("height", prev_coin.GetHeight());
                }
                p.emplace_back("value", ValueFromAmount(prev_txout.nValue));
                if (include_patterns && optMaybeRedeemScript.has_value()) {
                    // Maybe add the redeemScript & pattern to the input's `scriptSig` JSON object as well, if the
                    // spk was p2sh-ish; contents of `o_script_pub_key["byteCodePattern"]["pattern"]` determines this.
                    std::string p2sh;
                    if (const UniValue *pat; (pat = o_script_pub_key.locate("byteCodePattern"))
                                              && (pat = pat->locate("pattern"))) {
                        if (pat->getValStr() == "a95187") {
                            p2sh = "p2sh20";
                        } else if (pat && pat->getValStr() == "aa5187") {
                            p2sh = "p2sh32";
                        }
                    }

                    if (!p2sh.empty()) {
                        const CScript redeem_script{optMaybeRedeemScript->begin(), optMaybeRedeemScript->end()};
                        UniValue::Object redeemScript = ScriptToUniv(config, redeem_script,
                                                                     /*include_address=*/false, /*include_type=*/false,
                                                                     /*include_pattern=*/include_patterns);
                        // place the p2sh type into byteCodePattern subobject of redeemScript
                        if (auto *rs_pat = redeemScript.locate("byteCodePattern"); rs_pat && rs_pat->isObject()) {
                            rs_pat->get_obj().emplace_back("p2shType", std::move(p2sh));
                        }
                        // place the redeemScript object and its pattern data into input's "scriptSig" object.
                        if (auto *scriptSig = in.locate("scriptSig"); scriptSig && scriptSig->isObject()) {
                            scriptSig->get_obj().emplace_back("redeemScript", std::move(redeemScript));
                        }
                    }
                }
                p.emplace_back("scriptPubKey", std::move(o_script_pub_key));
                if (has_token_data) {
                    p.emplace_back("tokenData", TokenDataToUniv(*prev_txout.tokenDataPtr));
                }
                if (nest_prevouts) {
                    in.emplace_back("prevout", std::move(p));
                } else {
                    for (auto &kvpair : p) {
                        in.push_back(std::move(kvpair));
                    }
                }
            }
        }
        in.emplace_back("sequence", txin.nSequence);
        vin.emplace_back(std::move(in));
    }
    entry.emplace_back("vin", std::move(vin));

    UniValue::Array vout;
    vout.reserve(tx.vout.size());
    for (const CTxOut &txout : tx.vout) {
        UniValue::Object out;
        const bool has_token_data = txout.tokenDataPtr;
        out.reserve(3u + has_token_data);
        out.emplace_back("value", ValueFromAmount(txout.nValue));
        out.emplace_back("n", vout.size());
        out.emplace_back("scriptPubKey", ScriptPubKeyToUniv(config, txout.scriptPubKey, /*fIncludeHex=*/true,
                                                            /*fIncludeP2SH=*/false, include_patterns));
        if (has_token_data) {
            out.emplace_back("tokenData", TokenDataToUniv(*txout.tokenDataPtr));
        }
        if (include_fee) {
            amt_total_out += txout.nValue;
        }
        vout.emplace_back(std::move(out));
    }
    entry.emplace_back("vout", std::move(vout));

    if (include_fee) {
        auto CheckAmount = [&tx](const Amount &amt, const char *desc) {
            if (!MoneyRange(amt)) [[unlikely]] {
                // This should never happen (indicates db corruption)
                throw std::runtime_error(strprintf("TransactionToUniv: Bad amount \"%s\" encountered for %s for tx %s",
                                                   amt.ToString(), desc, tx.GetId().ToString()));
            }
        };
        CheckAmount(amt_total_in, "amt_total_in");
        CheckAmount(amt_total_out, "amt_total_out");
        const Amount fee = amt_total_in - amt_total_out;
        CheckAmount(fee, "fee");
        entry.emplace_back("fee", ValueFromAmount(fee));
    }

    if (include_hex) {
        // The hex-encoded transaction. Used the name "hex" to be consistent
        // with the verbose output of "getrawtransaction".
        entry.emplace_back("hex", EncodeHexTx(tx));
    }

    return entry;
}

UniValue::Object TokenDataToUniv(const token::OutputData &tok) {
    UniValue::Object obj;
    obj.reserve(tok.HasNFT() ? 3u : 2u);
    obj.emplace_back("category", tok.GetId().ToString());
    obj.emplace_back("amount", SafeAmountToUniv(tok.GetAmount()));
    if (tok.HasNFT()) {
        UniValue::Object nft_obj;
        nft_obj.reserve(2u);

        nft_obj.emplace_back("capability", [&tok] {
            if (tok.IsMutableNFT()) return "mutable";
            else if (tok.IsMintingNFT()) return "minting";
            else return "none";
        }());
        nft_obj.emplace_back("commitment", HexStr(tok.GetCommitment()));

        obj.emplace_back("nft", std::move(nft_obj));
    }
    return obj;
}

UniValue SafeAmountToUniv(const token::SafeAmount val) {
    UniValue uv = val.getint64();
    // This value may exceed the maximal safe JSON integer (~53 bits). Insist it be a string always instead.
    // We will use UniValue's string serializer for ints since it is fast and locale-independent.
    std::string numStr = uv.getValStr(); // note: to avoid UB, we must copy to temp obj first to assign it back to `uv`
    uv = std::move(numStr);
    return uv;
}

UniValue::Object ScriptToByteCodePatternUniv(const CScript &scriptIn, std::optional<std::vector<uint8_t>> *pOptLastPush) {
    struct ByteCodePattern {
        uint256 fingerprint; ///< single-sha256 hash of `pattern`
        CScript pattern;
        std::vector<std::vector<uint8_t>> data;
        bool error = false;
    };

    auto ParseScriptToPattern = [](const CScript &script) -> ByteCodePattern  {
        ByteCodePattern ret;
        opcodetype opcode;
        std::vector<uint8_t> vch;
        CScript::const_iterator pc = script.begin();
        size_t ccPushes = 0;

        auto FlushPushes = [&ccPushes, &ret]() {
            if (ccPushes > 0) {
                ret.pattern << ScriptInt::fromIntUnchecked(ccPushes);
                ccPushes = 0;
            }
        };

        while (pc < script.end()) {
            if (!script.GetOp(pc, opcode, vch)) {
                ret.error = true;
                break;
            }

            if (opcode >= OP_0 && opcode <= OP_PUSHDATA4) { // OP_0 = 0x00, OP_PUSHDATA4 = 0x4e
                // note: OP_0 will push empty element: ""
                ret.data.push_back(std::move(vch));
                ++ccPushes;
            } else if (opcode >= OP_1NEGATE && opcode <= OP_16 && opcode != OP_RESERVED) { // OP_1NEGATE = 0x4f, OP_16 = 0x60, OP_RESERVED = 0x50
                // vch will be empty so we have to calculate resulting stack element
                if (opcode == OP_1NEGATE) {
                    ret.data.emplace_back(size_t{1}, uint8_t{0x81u}); // 0x81 is scriptnum encoding of -1
                } else {
                    ret.data.emplace_back(size_t{1}, uint8_t(opcode - 0x50u));
                }
                ++ccPushes;
            } else {
                FlushPushes();
                ret.pattern << opcode;
            }
        }
        FlushPushes();

        if (ret.error) {
            // push remainder of the script to the last data position, starting from the errored-out opcode itself.
            CScript::const_iterator copyfrom = pc;
            if (copyfrom > script.begin()) {
                // go back 1, if we can, so that we may start copying from the errored-out opcode
                --copyfrom;
            }
            copyfrom = std::clamp(copyfrom, script.begin(), script.end()); // ensure in range
            ret.data.emplace_back(copyfrom, script.end());
        }

        CSHA256{}.Write(ret.pattern).Finalize(ret.fingerprint);

        return ret;
    };

    ByteCodePattern bcp = ParseScriptToPattern(scriptIn);
    UniValue::Object ret;
    UniValue::Array a;

    a.reserve(bcp.data.size());
    for (const auto &datum : bcp.data) {
        a.emplace_back(HexStr(datum));
    }

    ret.reserve(4 + bcp.error);
    ret.emplace_back("fingerprint", HexStr(bcp.fingerprint));
    ret.emplace_back("pattern", HexStr(bcp.pattern));
    ret.emplace_back("patternAsm", ScriptToAsmStr(bcp.pattern));
    ret.emplace_back("data", std::move(a));
    if (bcp.error) {
        ret.emplace_back("error", bcp.error);
    }

    // caller wants info on the last push
    if (pOptLastPush) {
        if (!bcp.error && !bcp.data.empty()) {
            pOptLastPush->emplace(std::move(bcp.data.back())); // fast move
        } else {
            // had error or no last push, indicate this by making this be a std::nullopt
            pOptLastPush->reset();
        }
    }

    return ret;
}
