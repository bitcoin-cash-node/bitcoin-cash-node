// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <protocol.h>
#include <script/standard.h> // For CTxDestination
#include <univalue.h> // For UniValue::Object, UniValue::stringify
#include <util/check.h>

#include <string>
#include <vector>

class CChainParams;
class CKeyStore;
class CPubKey;
class CScript;
struct NodeContext;

//! Pointers to interfaces that need to be accessible from RPC methods. Due to
//! limitations of the RPC framework, there's currently no direct way to pass in
//! state to RPC method implementations.
extern NodeContext *g_rpc_node;

CPubKey HexToPubKey(const std::string &hex_in);
CPubKey AddrToPubKey(const CChainParams &chainparams, CKeyStore *const keystore,
                     const std::string &addr_in);
CScript CreateMultisigRedeemscript(const int required,
                                   const std::vector<CPubKey> &pubkeys);

/**
 * Appends key-value pairs to entries describing the address dest.
 * obj is the UniValue object to append to.
 */
void DescribeAddress(const CTxDestination &dest, UniValue::Object& obj);

/** Returns, given services flags, a univalue array of human-readable (known) network services */
UniValue::Array GetServicesNames(ServiceFlags services);

/**
 * Serializing JSON objects depends on the outer type. Only arrays and
 * dictionaries can be nested in json. The top-level outer type is "NONE".
 */
enum class OuterType {
    ARR,
    OBJ,
    NONE, // Only set on first recursion
};

struct RPCArg {
    enum class Type {
        OBJ,
        ARR,
        STR,
        NUM,
        BOOL,
        //! Special type where the user must set the keys e.g. to define
        //! multiple addresses; as opposed to e.g. an options object where the
        //! keys are predefined
        OBJ_USER_KEYS,
        //! Special type representing a floating point amount (can be either NUM
        //! or STR)
        AMOUNT,
        //! Special type that is a STR with only hex chars
        STR_HEX,
    };
    //! The name of the arg (can be empty for inner args)
    const std::string m_name;
    const Type m_type;
    //! Only used for arrays or dicts
    const std::vector<RPCArg> m_inner;
    const bool m_optional;
    const std::string m_default_value; //!< Only used for optional args
    const std::string m_description;
    const std::string m_oneline_description; //!< Should be empty unless it is supposed to override the auto-generated summary line
    const std::vector<std::string> m_type_str; //!< Should be empty unless it is supposed to override the auto-generated type strings. Vector length is either 0 or 2, m_type_str.at(0) will override the type of the value in a key-value pair, m_type_str.at(1) will override the type in the argument description.

    RPCArg(
        std::string&& name,
        Type type,
        bool opt,
        std::string&& default_val,
        std::string&& description,
        std::string&& oneline_description = "",
        std::vector<std::string>&& type_str = {})
        : m_name{std::move(name)},
          m_type{type},
          m_optional{opt},
          m_default_value{std::move(default_val)},
          m_description{std::move(description)},
          m_oneline_description{std::move(oneline_description)},
          m_type_str{std::move(type_str)}
    {
        CHECK_NONFATAL(type != Type::ARR && type != Type::OBJ);
    }

    RPCArg(
        std::string&& name,
        Type type,
        bool opt,
        std::string&& default_val,
        std::string&& description,
        std::vector<RPCArg>&& inner,
        std::string&& oneline_description = "",
        std::vector<std::string>&& type_str = {})
        : m_name{std::move(name)},
          m_type{type},
          m_inner{std::move(inner)},
          m_optional{opt},
          m_default_value{std::move(default_val)},
          m_description{std::move(description)},
          m_oneline_description{std::move(oneline_description)},
          m_type_str{std::move(type_str)}
    {
        CHECK_NONFATAL(type == Type::ARR || type == Type::OBJ);
    }

    /**
     * Return the type string of the argument.
     * Set oneline to allow it to be overrided by a custom oneline type string (m_oneline_description).
     */
    std::string ToString(bool oneline) const;
    /**
     * Return the type string of the argument when it is in an object (dict).
     * Set oneline to get the oneline representation (less whitespace)
     */
    std::string ToStringObj(bool oneline) const;
    /**
     * Return the description string, including the argument type and whether
     * the argument is required.
     * implicitly_required is set for arguments in an array, which are neither optional nor required.
     */
    std::string ToDescriptionString(bool implicitly_required = false) const;

    //! Helper for constructing the default_val member: Convert any C++ basic type that is
    //! UniValue-compatible to a string.
    static std::string Default(const UniValue &uv) { return UniValue::stringify(uv); }
};

struct RPCResult {
    const std::string m_cond;
    const std::string m_result;

    explicit RPCResult(std::string&& result)
        : m_cond{}, m_result{std::move(result)} {
    }

    RPCResult(std::string&& cond, std::string&& result)
        : m_cond{std::move(cond)}, m_result{std::move(result)} {
    }
};

struct RPCResults {
    const std::vector<RPCResult> m_results;

    RPCResults() : m_results{} {}

    RPCResults(RPCResult&& result) : m_results{std::move(result)} {}

    RPCResults(std::initializer_list<RPCResult> results) : m_results(results) {}

    /**
     * Return the description string.
     */
    std::string ToDescriptionString() const;
};

struct RPCExamples {
    const std::string m_examples;
    RPCExamples(std::string&& examples) : m_examples(std::move(examples)) {}
    RPCExamples() = default;
    std::string ToDescriptionString() const;
};

class RPCHelpMan {
public:

    // Remove once PR14987 backport is completed
    RPCHelpMan(std::string&& name, std::string&& description, std::vector<RPCArg>&& args) :
        m_name(std::move(name)),
        m_description(std::move(description)),
        m_args(std::move(args)),
        m_results(RPCResults()),
        m_examples(RPCExamples()) {}

    RPCHelpMan(std::string&& name, std::string&& description, std::vector<RPCArg>&& args,
               RPCResults&& results, RPCExamples&& examples) :
        m_name(std::move(name)),
        m_description{std::move(description)},
        m_args(std::move(args)),
        m_results(std::move(results)),
        m_examples(std::move(examples)) {}

    std::string ToString() const;

    // Remove once PR14987 backport is completed
    std::string ToStringWithResultsAndExamples() const;

private:
    const std::string m_name;
    const std::string m_description;
    const std::vector<RPCArg> m_args;
    const RPCResults m_results;
    const RPCExamples m_examples;
};
