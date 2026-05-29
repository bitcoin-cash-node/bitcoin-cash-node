// Copyright (c) 2017-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <test/scriptflags.h>
#include <util/string.h>

#ifndef NO_BOOST
#include <boost/test/unit_test.hpp>
#else
#include <cassert>
#endif

#include <map>
#include <vector>

static std::map<std::string, uint32_t> mapFlagNames = {
    {"NONE", SCRIPT_VERIFY_NONE},
    {"P2SH", SCRIPT_VERIFY_P2SH},
    {"STRICTENC", SCRIPT_VERIFY_STRICTENC},
    {"DERSIG", SCRIPT_VERIFY_DERSIG},
    {"LOW_S", SCRIPT_VERIFY_LOW_S},
    {"SIGPUSHONLY", SCRIPT_VERIFY_SIGPUSHONLY},
    {"MINIMALDATA", SCRIPT_VERIFY_MINIMALDATA},
    {"DISCOURAGE_UPGRADABLE_NOPS", SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {"CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK},
    {"MINIMALIF", SCRIPT_VERIFY_MINIMALIF},
    {"NULLFAIL", SCRIPT_VERIFY_NULLFAIL},
    {"CHECKLOCKTIMEVERIFY", SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {"CHECKSEQUENCEVERIFY", SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {"SIGHASH_FORKID", SCRIPT_ENABLE_SIGHASH_FORKID},
    {"DISALLOW_SEGWIT_RECOVERY", SCRIPT_DISALLOW_SEGWIT_RECOVERY},
    {"SCHNORR_MULTISIG", SCRIPT_ENABLE_SCHNORR_MULTISIG},
    {"INPUT_SIGCHECKS", SCRIPT_VERIFY_INPUT_SIGCHECKS},
    {"ENABLE_TOKENS", SCRIPT_ENABLE_TOKENS},
    {"P2SH_32", SCRIPT_ENABLE_P2SH_32},
    {"ENABLE_MAY2025", SCRIPT_ENABLE_MAY2025},
    {"VM_LIMITS_STANDARD", SCRIPT_VM_LIMITS_STANDARD},
    {"ENABLE_MAY2026", SCRIPT_ENABLE_MAY2026},
};

uint32_t ParseScriptFlags(const std::string &strFlags) {
    if (strFlags.empty()) {
        return 0;
    }

    uint32_t flags = 0;
    std::vector<std::string> words;
    Split(words, strFlags, ",");

    for (const std::string &word : words) {
        const auto it = mapFlagNames.find(word);
        if (it == mapFlagNames.end()) {
#ifndef NO_BOOST
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
#else
            assert(!"Bad test: unknown verification flag");
#endif
        }
        flags |= it->second;
    }

    return flags;
}

std::string FormatScriptFlags(uint32_t flags) {
    if (flags == 0) {
        return "";
    }

    std::string ret;
    std::map<std::string, uint32_t>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }

    return ret.substr(0, ret.size() - 1);
}
