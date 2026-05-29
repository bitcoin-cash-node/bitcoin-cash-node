// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <test/scriptflags.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <version.h>

#include <test/fuzz/fuzz.h>

#include <cstdio>

/** Flags that are not forbidden by an assert */
static bool IsValidFlagCombination(uint32_t flags);

/** VerifyScript() return values are passed to this function. Mismatches are allowed in certain cases. */
static bool IsExpected(bool ret, bool ret_fuzzed, uint32_t verify_flags, ScriptError serror,
                       uint32_t verify_flags_fuzzed, ScriptError serror_fuzzed);

void test_one_input(Span<const uint8_t> buffer) {
    GenericVectorReader ds(SER_NETWORK, INIT_PROTO_VERSION, buffer, 0);
    try {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure &) {
        return;
    }

    try {
        const CTransaction tx(deserialize, ds);
        PrecomputedTransactionData txdata;

        uint32_t verify_flags;
        ds >> verify_flags;

        if (!IsValidFlagCombination(verify_flags)) {
            return;
        }

        uint32_t fuzzed_flags;
        ds >> fuzzed_flags;

        for (unsigned int i = 0; i < tx.vin.size(); ++i) {
            CTxOut prevout;
            ds >> prevout;

            const ScriptExecutionContext limited_context(i, prevout, tx);
            if (!txdata.populated) txdata.PopulateFromContext(limited_context);

            const TransactionSignatureChecker checker{limited_context, txdata};

            ScriptError serror;
            const auto pre_fuzz_verify_flags = verify_flags;
            const bool ret = VerifyScript(tx.vin.at(i).scriptSig, prevout.scriptPubKey, verify_flags, checker, &serror);
            assert(ret == (serror == ScriptError::OK));

            // Verify that removing flags from a passing test or adding flags to
            // a failing test does not change the result
            if (ret) {
                verify_flags &= ~fuzzed_flags;
            } else {
                verify_flags |= fuzzed_flags;
            }
            if (!IsValidFlagCombination(verify_flags)) {
                return;
            }

            ScriptError serror_fuzzed;
            const bool ret_fuzzed =
                VerifyScript(tx.vin.at(i).scriptSig, prevout.scriptPubKey, verify_flags, checker, &serror_fuzzed);
            assert(ret_fuzzed == (serror_fuzzed == ScriptError::OK));

            if ( ! IsExpected(ret, ret_fuzzed, pre_fuzz_verify_flags, serror, verify_flags, serror_fuzzed)) {
                std::fprintf(stderr, "---> Unexpected result for script re-evaluation: %s\n",
                             strprintf("ret: %i, ret_fuzzed: %i, serror: %s, serror_fuzzed: %s\n"
                                       "flags       : %x -> %s\n"
                                       "flags_fuzzed: %x -> %s\n"
                                       "scriptSig (hex): %s\n"
                                       "scriptPubKey (hex): %s\n",
                                       int(ret), int(ret_fuzzed),
                                       ScriptErrorString(serror), ScriptErrorString(serror_fuzzed),
                                       pre_fuzz_verify_flags, FormatScriptFlags(pre_fuzz_verify_flags),
                                       verify_flags, FormatScriptFlags(verify_flags),
                                       HexStr(tx.vin.at(i).scriptSig),
                                       HexStr(prevout.scriptPubKey)).c_str());
                assert(!"Unexpected result during re-evaluation of script with different flags. Please check the log.");
            }
        }
    } catch (const std::ios_base::failure &) {
        return;
    }
}

static bool IsValidFlagCombination(uint32_t flags) {
    // If the CLEANSTACK flag is set, then P2SH should also be set
    return ((~flags & SCRIPT_VERIFY_CLEANSTACK) || (flags & SCRIPT_VERIFY_P2SH))
            // Additionally, if P2SH_32 is set, P2SH should also be set
            && ((~flags & SCRIPT_ENABLE_P2SH_32) || (flags & SCRIPT_VERIFY_P2SH));
}

static bool IsExpected(bool ret, bool ret_fuzzed, uint32_t verify_flags, ScriptError serror,
                       uint32_t verify_flags_fuzzed, ScriptError serror_fuzzed) {
    // We expect the two runs of VerifyScript() to match in return value.
    if (ret == ret_fuzzed) {
        return true;
    }

    auto is_bad_opcode = [](ScriptError script_error) {
        return script_error == ScriptError::BAD_OPCODE || script_error == ScriptError::DISABLED_OPCODE;
    };

    // If reason they mismatch is BAD_OPCODE or DISABLED_OPCODE error in only one of them, then allow pass for flags
    // differing for the script flags that we know added opcodes to the interpreter.
    if (is_bad_opcode(serror) || is_bad_opcode(serror_fuzzed)) {
        const uint32_t flags_that_added_opcodes[] = {
            SCRIPT_ENABLE_TOKENS, SCRIPT_ENABLE_MAY2026
        };
        for (const uint32_t flag : flags_that_added_opcodes) {
            if ((verify_flags_fuzzed & flag) != (verify_flags & flag)) {
                return true;
            }
        }
    }
    // If the reason they mismatch is due to may2025 flag flip, tolerate errors related to that flag being flipped.
    else if (serror == ScriptError::INVALID_NUMBER_RANGE_BIG_INT || serror_fuzzed == ScriptError::INVALID_NUMBER_RANGE_BIG_INT
             || serror == ScriptError::INVALID_NUMBER_RANGE_64_BIT || serror_fuzzed == ScriptError::INVALID_NUMBER_RANGE_64_BIT
             || serror == ScriptError::OP_COST || serror_fuzzed == ScriptError::OP_COST
             || serror == ScriptError::TOO_MANY_HASH_ITERS || serror_fuzzed == ScriptError::TOO_MANY_HASH_ITERS
             || serror == ScriptError::CONDITIONAL_STACK_DEPTH || serror_fuzzed == ScriptError::CONDITIONAL_STACK_DEPTH) {
        if ((verify_flags_fuzzed & SCRIPT_ENABLE_MAY2025) != (verify_flags & SCRIPT_ENABLE_MAY2025)) {
            return true;
        }
    }

    return false;
}
