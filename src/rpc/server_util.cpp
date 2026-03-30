// Copyright (c) 2021 The Bitcoin Core developers
// Copyright (c) 2022-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server_util.h>

#include <node/context.h>
#include <rpc/protocol.h>
#include <util/system.h>

#include <any>

NodeContext& EnsureAnyNodeContext(const std::any& context) {
    auto node_context = util::AnyPtr<NodeContext>(context);
    if (!node_context) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not found");
    }
    return *node_context;
}

PeerLogicValidation& EnsurePeerLogicValidation(const NodeContext& node) {
    if (!node.peerLogic) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }
    return *node.peerLogic;
}

PeerLogicValidation& EnsureAnyPeerLogicValidation(const std::any& context) {
    return EnsurePeerLogicValidation(EnsureAnyNodeContext(context));
}
