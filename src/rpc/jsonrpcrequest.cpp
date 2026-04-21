// Copyright (c) 2018-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <rpc/jsonrpcrequest.h>
#include <rpc/protocol.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <univalue.h>

void JSONRPCRequest::parse(UniValue&& valRequest) {
    // Parse request
    if (!valRequest.isObject()) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    }
    UniValue::Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    if (auto idFound = request.locate("id")) {
        id = std::move(*idFound);
    } else {
        id.setNull();
    }

    // Parse method
    auto methodFound = request.locate("method");
    if (!methodFound) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    }
    if (!methodFound->isStr()) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    }
    strMethod = std::move(methodFound->get_str());
    if (fLogIPs) {
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s user=%s peeraddr=%s\n", SanitizeString(strMethod),
                 this->authUser, this->peerAddr);
    } else {
        LogPrint(BCLog::RPC, "ThreadRPCServer method=%s\n", SanitizeString(strMethod));
    }

    // Parse params
    if (auto paramsFound = request.locate("params")) {
        if (paramsFound->isArray() || paramsFound->isObject()) {
            params = std::move(*paramsFound);
        } else if (paramsFound->isNull()) {
            params.setArray();
        } else {
            throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
        }
    } else {
        params.setArray();
    }
}
