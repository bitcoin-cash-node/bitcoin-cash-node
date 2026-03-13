// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <keystore.h>
#include <pubkey.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <util/overloaded.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <univalue.h>

#include <utility>
#include <variant>

NodeContext *g_rpc_node = nullptr;

// Converts a hex string to a public key if possible
CPubKey HexToPubKey(const std::string &hex_in) {
    if (!IsHex(hex_in)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid public key: " + hex_in);
    }
    CPubKey vchPubKey(ParseHex(hex_in));
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid public key: " + hex_in);
    }
    return vchPubKey;
}

// Retrieves a public key for an address from the given CKeyStore
CPubKey AddrToPubKey(const CChainParams &chainparams, CKeyStore *const keystore,
                     const std::string &addr_in) {
    CTxDestination dest = DecodeDestination(addr_in, chainparams);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid address: " + addr_in);
    }
    CKeyID key = GetKeyForDestination(*keystore, dest);
    if (key.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           strprintf("%s does not refer to a key", addr_in));
    }
    CPubKey vchPubKey;
    if (!keystore->GetPubKey(key, vchPubKey)) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            strprintf("no full public key for address %s", addr_in));
    }
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Wallet contains an invalid public key");
    }
    return vchPubKey;
}

// Creates a multisig redeemscript from a given list of public keys and number
// required.
CScript CreateMultisigRedeemscript(const int required,
                                   const std::vector<CPubKey> &pubkeys) {
    // Gather public keys
    if (required < 1) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "a multisignature address must require at least one key to redeem");
    }
    if ((int)pubkeys.size() < required) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("not enough keys supplied (got %u keys, "
                                     "but need at least %d to redeem)",
                                     pubkeys.size(), required));
    }
    if (pubkeys.size() > 16) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Number of keys involved in the multisignature "
                           "address creation > 16\nReduce the number");
    }

    CScript result = GetScriptForMultisig(required, pubkeys);

    // Note: We use the legacy limit of 520 bytes for the redeemScript here, since that should be enough for all
    // consensus-valid multisig scripts.
    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE_LEGACY) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            (strprintf("redeemScript exceeds size limit: %d > %d",
                       result.size(), MAX_SCRIPT_ELEMENT_SIZE_LEGACY)));
    }

    return result;
}

// Upstream version of this function has only one argument and returns an intermediate UniValue object.
// Instead, our version directly appends the new key-value pairs to the target UniValue object.
void DescribeAddress(const CTxDestination &dest, UniValue::Object& obj) {
    std::visit(
        util::Overloaded {
            [](const CNoDestination &) {},
            [&obj](const CKeyID &) { obj.emplace_back("isscript", false); },
            [&obj](const ScriptID &) { obj.emplace_back("isscript", true); },
        }, dest);
}

int ParseVerbosity(const UniValue &arg, int default_verbosity) {
    if (!arg.isNull()) {
        if (arg.isBool()) {
            return arg.get_bool(); // true = 1, false = 0
        } else {
            return arg.get_int();
        }
    }
    return default_verbosity;
}

struct Section {
    Section(const std::string& left, const std::string& right)
        : m_left{left}, m_right{right} {}
    const std::string m_left;
    const std::string m_right;
};

struct Sections {
    std::vector<Section> m_sections;
    size_t m_max_pad{0};

    void PushSection(const Section& s)
    {
        m_max_pad = std::max(m_max_pad, s.m_left.size());
        m_sections.push_back(s);
    }

    /**
     * Recursive helper to translate an RPCArg into sections
     */
    void Push(const RPCArg& arg, const size_t current_indent = 5, const OuterType outer_type = OuterType::NONE)
    {
        const auto indent = std::string(current_indent, ' ');
        const auto indent_next = std::string(current_indent + 2, ' ');
        switch (arg.m_type) {
        case RPCArg::Type::STR_HEX:
        case RPCArg::Type::STR:
        case RPCArg::Type::NUM:
        case RPCArg::Type::AMOUNT:
        case RPCArg::Type::BOOL: {
            if (outer_type == OuterType::NONE) return; // Nothing more to do for non-recursive types on first recursion
            auto left = indent;
            if (arg.m_type_str.size() != 0 && outer_type == OuterType::OBJ) {
                left += "\"" + arg.m_name + "\": " + arg.m_type_str.at(0);
            } else {
                left += outer_type == OuterType::OBJ ? arg.ToStringObj(/* oneline */ false) : arg.ToString(/* oneline */ false);
            }
            left += ",";
            PushSection({left, arg.ToDescriptionString(/* implicitly_required */ outer_type == OuterType::ARR)});
            break;
        }
        case RPCArg::Type::OBJ:
        case RPCArg::Type::OBJ_USER_KEYS: {
            const auto right = outer_type == OuterType::NONE ? "" : arg.ToDescriptionString(/* implicitly_required */ outer_type == OuterType::ARR);
            const auto keyPart = outer_type == OuterType::OBJ && !arg.m_name.empty() ? "\"" + arg.m_name + "\": " : "";
            PushSection({indent + keyPart + "{", right});
            for (const auto& arg_inner : arg.m_inner) {
                Push(arg_inner, current_indent + 2, OuterType::OBJ);
            }
            if (arg.m_type != RPCArg::Type::OBJ) {
                PushSection({indent_next + "...", ""});
            }
            PushSection({indent + "}" + (outer_type != OuterType::NONE ? "," : ""), ""});
            break;
        }
        case RPCArg::Type::ARR: {
            auto left = indent;
            left += outer_type == OuterType::OBJ ? "\"" + arg.m_name + "\": " : "";
            left += "[";
            const auto right = outer_type == OuterType::NONE ? "" : arg.ToDescriptionString(/* implicitly_required */ outer_type == OuterType::ARR);
            PushSection({left, right});
            for (const auto& arg_inner : arg.m_inner) {
                Push(arg_inner, current_indent + 2, OuterType::ARR);
            }
            PushSection({indent_next + "...", ""});
            PushSection({indent + "]" + (outer_type != OuterType::NONE ? "," : ""), ""});
            break;
        }

            // no default case, so the compiler can warn about missing cases
        }
    }

    std::string ToString() const
    {
        std::string ret;
        const size_t pad = m_max_pad + 4;
        for (const auto& s : m_sections) {
            if (s.m_right.empty()) {
                ret += s.m_left;
                ret += "\n";
                continue;
            }

            std::string left = s.m_left;
            left.resize(pad, ' ');
            ret += left;

            // Properly pad after newlines
            std::string right;
            size_t begin = 0;
            size_t new_line_pos = s.m_right.find_first_of('\n');
            while (true) {
                right += s.m_right.substr(begin, new_line_pos - begin);
                if (new_line_pos == std::string::npos) {
                    break; //No new line
                }
                right += "\n" + std::string(pad, ' ');
                begin = s.m_right.find_first_not_of(' ', new_line_pos + 1);
                if (begin == std::string::npos) {
                    break; // Empty line
                }
                new_line_pos = s.m_right.find_first_of('\n', begin + 1);
            }
            ret += right;
            ret += "\n";
        }
        return ret;
    }
};

std::string RPCResults::ToDescriptionString() const {
    std::string result;
    for (const auto &r : m_results) {
        if (r.m_cond.empty()) {
            result += "\nResult:\n";
        } else {
            result += "\nResult (" + r.m_cond + "):\n";
        }
        result += r.m_result;
    }
    return result;
}

std::string RPCExamples::ToDescriptionString() const {
    return m_examples.empty() ? m_examples : "\nExamples:\n" + m_examples;
}

// Remove once PR14987 backport is completed
std::string RPCHelpMan::ToString() const {
    std::string ret;

    // Oneline summary
    ret += m_name;
    bool is_optional{false};
    for (const auto &arg : m_args) {
        ret += " ";
        if (arg.m_optional) {
            if (!is_optional) {
                ret += "( ";
            }
            is_optional = true;
        } else {
            // Currently we still support unnamed arguments, so any argument
            // following an optional argument must also be optional If support
            // for positional arguments is deprecated in the future, remove this
            // line
            assert(!is_optional);
        }
        ret += arg.ToString(/* oneline */ true);
    }
    if (is_optional) {
        ret += " )";
    }
    ret += "\n";

    // Description
    ret += m_description;

    // Arguments
    Sections sections;
    for (size_t i{0}; i < m_args.size(); ++i) {
        const auto& arg = m_args.at(i);

        if (i == 0) ret += "\nArguments:\n";

        // Push named argument name and description
        const auto str_wrapper = (arg.m_type == RPCArg::Type::STR || arg.m_type == RPCArg::Type::STR_HEX) ? "\"" : "";
        sections.m_sections.emplace_back(std::to_string(i + 1) + ". " + str_wrapper + arg.m_name + str_wrapper, arg.ToDescriptionString());
        sections.m_max_pad = std::max(sections.m_max_pad, sections.m_sections.back().m_left.size());

        // Recursively push nested args
        sections.Push(arg);
    }
    ret += sections.ToString();

    return ret;
}

// Rename to ToString() once PR14987 backport is completed
std::string RPCHelpMan::ToStringWithResultsAndExamples() const {
    std::string ret;

    // Oneline summary
    ret += m_name;
    bool was_optional{false};
    for (const auto &arg : m_args) {
        ret += " ";
        if (arg.m_optional) {
            if (!was_optional) {
                ret += "( ";
            }
            was_optional = true;
        } else {
            if (was_optional) {
                ret += ") ";
            }
            was_optional = false;
        }
        ret += arg.ToString(/* oneline */ true);
    }
    if (was_optional) {
        ret += " )";
    }
    ret += "\n";

    // Description
    ret += m_description;

    // Arguments
    Sections sections;
    for (size_t i{0}; i < m_args.size(); ++i) {
        const auto &arg = m_args.at(i);

        if (i == 0) {
            ret += "\nArguments:\n";
        }

        // Push named argument name and description
        sections.m_sections.emplace_back(std::to_string(i + 1) + ". " +
                                             arg.m_name,
                                         arg.ToDescriptionString());
        sections.m_max_pad = std::max(sections.m_max_pad,
                                      sections.m_sections.back().m_left.size());

        // Recursively push nested args
        sections.Push(arg);
    }
    ret += sections.ToString();

    // Result
    ret += m_results.ToDescriptionString();

    // Examples
    ret += m_examples.ToDescriptionString();

    return ret;
}

std::string RPCArg::ToDescriptionString(const bool implicitly_required) const {
    std::string ret;
    ret += "(";
    if (m_type_str.size() != 0) {
        ret += m_type_str.at(1);
    } else {
        switch (m_type) {
        case Type::STR_HEX:
        case Type::STR: {
            ret += "string";
            break;
        }
        case Type::NUM: {
            ret += "numeric";
            break;
        }
        case Type::AMOUNT: {
            ret += "numeric or string";
            break;
        }
        case Type::BOOL: {
            ret += "boolean";
            break;
        }
        case Type::OBJ:
        case Type::OBJ_USER_KEYS: {
            ret += "json object";
            break;
        }
        case Type::ARR: {
            ret += "json array";
            break;
        }

            // no default case, so the compiler can warn about missing cases
        }
    }
    if (!implicitly_required) {
        ret += ", ";
        if (m_optional) {
            ret += "optional";
            if (!m_default_value.empty()) {
                ret += ", default=" + m_default_value;
            } else {
                // TODO enable this assert, when all optional parameters have their default value documented
                //assert(false);
            }
        } else {
            ret += "required";
            assert(m_default_value.empty()); // Default value is ignored, and must not be present
        }
    }
    ret += ")";
    ret += m_description.empty() ? "" : " " + m_description;
    return ret;
}

std::string RPCArg::ToStringObj(const bool oneline) const
{
    std::string res;
    res += "\"";
    res += m_name;
    if (oneline) {
        res += "\":";
    } else {
        res += "\": ";
    }
    switch (m_type) {
    case Type::STR:
        return res + "\"str\"";
    case Type::STR_HEX:
        return res + "\"hex\"";
    case Type::NUM:
        return res + "n";
    case Type::AMOUNT:
        return res + "amount";
    case Type::BOOL:
        return res + "bool";
    case Type::ARR:
        res += "[";
        for (const auto& i : m_inner) {
            res += i.ToString(oneline) + ",";
        }
        return res + "...]";
    case Type::OBJ:
        return res;
    case Type::OBJ_USER_KEYS:
        // Currently unused, so avoid writing dead code
        assert(false);
    // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

std::string RPCArg::ToString(const bool oneline) const
{
    if (oneline && !m_oneline_description.empty()) return m_oneline_description;

    switch (m_type) {
        case Type::STR_HEX:
        case Type::STR: {
            return "\"" + m_name + "\"";
        }
        case Type::NUM:
        case Type::AMOUNT:
        case Type::BOOL: {
            return m_name;
        }
        case Type::OBJ:
        case Type::OBJ_USER_KEYS: {
            const std::string res = Join(m_inner, ",", [&](const RPCArg &i) { return i.ToStringObj(oneline); });
            if (m_type == Type::OBJ) {
                return "{" + res + "}";
            } else {
                return "{" + res + ",...}";
            }
        }
        case Type::ARR: {
            std::string res;
            for (const auto &i : m_inner) {
                res += i.ToString(oneline) + ",";
            }
            return "[" + res + "...]";
        }

            // no default case, so the compiler can warn about missing cases
    }
    assert(false);
}

UniValue::Array GetServicesNames(const ServiceFlags services) {
    UniValue::Array ret;

    constexpr std::pair<ServiceFlags, const char *> flag2String[] = {
        {NODE_NETWORK, "NETWORK"},
        {NODE_GETUTXO, "GETUTXO"},
        {NODE_BLOOM, "BLOOM"},
        {NODE_XTHIN, "XTHIN"},
        {NODE_BITCOIN_CASH, "BITCOIN_CASH"},
        {NODE_GRAPHENE, "GRAPHENE"},
        {NODE_CF, "CF"},
        {NODE_NETWORK_LIMITED, "NETWORK_LIMITED"},
        {NODE_EXTVERSION, "EXTVERSION"},
    };

    for (const auto & [flag, name] : flag2String) {
        if (services & flag) {
            ret.push_back(name);
        }
    }

    return ret;
}
