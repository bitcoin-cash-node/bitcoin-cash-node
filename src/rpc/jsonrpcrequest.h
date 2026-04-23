// Copyright (c) 2018-2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <any>
#include <string>

#include <univalue.h>

class JSONRPCRequest {
public:
    UniValue id;
    std::string strMethod;
    UniValue params;
    bool fHelp = false;
    std::string URI;
    std::string authUser;
    std::string peerAddr;
    std::any context;

    void parse(UniValue&& valRequest);

    // Internal helper (used in multiple places); Returns the "method" key's string, or throws JSONRPCError if not found
    // and/or the value under "method" is not a JSON string.
    static std::string &parseMethod(UniValue::Object &request);
};
