// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>

#include <banman.h>
#include <chainparams.h>
#include <clientversion.h>
#include <config.h>
#include <core_io.h>
#include <net.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <netbase.h>
#include <policy/policy.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <sync.h>
#include <timedata.h>
#include <ui_interface.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>
#include <warnings.h>

#include <univalue.h>

static UniValue getconnectioncount(const Config &config,
                                   const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(RPCHelpMan{
            "getconnectioncount",
            "\nReturns the number of connections to other nodes.\n",
            {},
            RPCResult{"n          (numeric) The connection count\n"},
            RPCExamples{HelpExampleCli("getconnectioncount", "") +
                        HelpExampleRpc("getconnectioncount", "")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    return g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
}

static UniValue ping(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(RPCHelpMan{
            "ping",
            "\nRequests that a ping be sent to all other nodes, to measure ping time.\n"
            "Results provided in getpeerinfo, pingtime and pingwait fields are decimal seconds.\n"
            "Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n",
            {},
            RPCResults{},
            RPCExamples{HelpExampleCli("ping", "") +
                        HelpExampleRpc("ping", "")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    // Request that each node send a ping during next message processing pass
    g_connman->ForEachNode([](const NodeRef &pnode) { pnode->fPingQueued = true; });
    return UniValue();
}

static UniValue getpeerinfo(const Config &, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(RPCHelpMan{
            "getpeerinfo",
            "\nReturns data about each connected network node as a json array "
            "of objects.\n",
            {},
            RPCResult{
                "[\n"
                "  {\n"
                "    \"id\": n,                        (numeric) Peer index\n"
                "    \"addr\":\"host:port\",             (string) The IP address and port of the peer\n"
                "    \"addrbind\":\"ip:port\",           (string) Bind address of the connection to the peer\n"
                "    \"addrlocal\":\"ip:port\",          (string) Local address as reported by the peer\n"
                "    \"mapped_as\":\"mapped_as\",        (string) "
                "The AS in the BGP route to the peer used for diversifying peer selection (only available if the asmap config flag is set)\n"
                "    \"services\":\"xxxxxxxxxxxxxxxx\",  (string) The services offered\n"
                "    \"servicesnames\":[               (array) The services offered, in human-readable form\n"
                "       \"SERVICE_NAME\",              (string) The service name if it is recognized\n"
                "       ...\n"
                "    ],\n"
                "    \"relaytxes\":true|false,         (boolean) Whether peer has asked us to relay transactions to it\n"
                "    \"lastsend\": ttt,                (numeric) "
                "The time in seconds since epoch (Jan 1 1970 GMT) of the last send\n"
                "    \"lastrecv\": ttt,                (numeric) "
                "The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
                "    \"bytessent\": n,                 (numeric) The total bytes sent\n"
                "    \"bytesrecv\": n,                 (numeric) The total bytes received\n"
                "    \"conntime\": ttt,                (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)\n"
                "    \"timeoffset\": ttt,              (numeric) The time offset in seconds\n"
                "    \"pingtime\": n,                  (numeric) ping time (if available)\n"
                "    \"minping\": n,                   (numeric) minimum observed ping time (if any at all)\n"
                "    \"pingwait\": n,                  (numeric) ping wait (if non-zero)\n"
                "    \"version\": v,                   (numeric) The peer version, such as 70001\n"
                "    \"subver\": \"/Satoshi:0.8.5/\",    (string) The string version\n"
                "    \"inbound\": true|false,          (boolean) Inbound (true) or Outbound (false)\n"
                "    \"bip152_hb_to\": true|false,     (boolean) Whether we selected peer as (compact blocks) high-bandwidth peer\n"
                "    \"bip152_hb_from\": true|false,   (boolean) Whether peer selected us as (compact blocks) high-bandwidth peer\n"
                "    \"addnode\": true|false,          (boolean) "
                "Whether connection was due to addnode/-connect or if it was an automatic/inbound connection\n"
                "    \"startingheight\": n,            (numeric) The starting height (block) of the peer\n"
                "    \"banscore\": n,                  (numeric) The ban score\n"
                "    \"synced_headers\": n,            (numeric) The last header we have in common with this peer\n"
                "    \"synced_blocks\": n,             (numeric) The last block we have in common with this peer\n"
                "    \"inflight\": [\n"
                "       n,                           (numeric) The heights of blocks we're currently asking from this peer\n"
                "       ...\n"
                "    ],\n"
                "    \"addr_processed\": n,            (numeric) The total number of addresses processed, excluding those dropped due to rate limiting\n"
                "    \"addr_rate_limited\": n,         (numeric) The total number of addresses dropped due to rate limiting\n"
                "    \"whitelisted\": true|false,      (boolean) Whether the peer is whitelisted\n"
                "    \"minfeefilter\": n,              (numeric) The minimum fee rate for transactions this peer accepts\n"
                "    \"bytessent_per_msg\": {\n"
                "       \"addr\": n,                   (numeric) The total bytes sent aggregated by message type\n"
                "       ...\n"
                "    },\n"
                "    \"bytesrecv_per_msg\": {\n"
                "       \"addr\": n,                   (numeric) The total bytes received aggregated by message type\n"
                "       ...\n"
                "    }\n"
                "  }\n"
                "  ,...\n"
                "]\n"},
            RPCExamples{HelpExampleCli("getpeerinfo", "") +
                        HelpExampleRpc("getpeerinfo", "")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    std::vector<CNodeStats> vstats;
    g_connman->GetNodeStats(vstats);

    UniValue::Array ret;
    ret.reserve(vstats.size());

    for (CNodeStats &stats : vstats) {
        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        bool addrlocal = !stats.addrLocal.empty();
        bool addrbind = stats.addrBind.IsValid();
        bool pingtime = stats.dPingTime > 0.0;
        bool minping = stats.dMinPing < double(std::numeric_limits<int64_t>::max()) / 1e6;
        bool pingwait = stats.dPingWait > 0.0;
        UniValue::Object obj;
        obj.reserve(25 + addrlocal + addrbind + pingtime + minping + pingwait + fStateStats * 4);
        obj.emplace_back("id", stats.nodeid);
        obj.emplace_back("addr", std::move(stats.addrName));
        if (addrlocal) {
            obj.emplace_back("addrlocal", std::move(stats.addrLocal));
        }
        if (addrbind) {
            obj.emplace_back("addrbind", stats.addrBind.ToString());
        }
        if (stats.m_mapped_as != 0) {
            obj.emplace_back("mapped_as", uint64_t(stats.m_mapped_as));
        }
        obj.emplace_back("services", strprintf("%016x", stats.nServices));
        obj.emplace_back("servicesnames", GetServicesNames(stats.nServices));
        obj.emplace_back("relaytxes", stats.fRelayTxes);
        obj.emplace_back("lastsend", stats.nLastSend);
        obj.emplace_back("lastrecv", stats.nLastRecv);
        obj.emplace_back("bytessent", stats.nSendBytes);
        obj.emplace_back("bytesrecv", stats.nRecvBytes);
        obj.emplace_back("conntime", stats.nTimeConnected);
        obj.emplace_back("timeoffset", stats.nTimeOffset);
        if (pingtime) {
            obj.emplace_back("pingtime", stats.dPingTime);
        }
        if (minping) {
            obj.emplace_back("minping", stats.dMinPing);
        }
        if (pingwait) {
            obj.emplace_back("pingwait", stats.dPingWait);
        }
        obj.emplace_back("version", stats.nVersion);
        // Use the sanitized form of subver here, to avoid tricksy remote peers
        // from corrupting or modifying the JSON output by putting special
        // characters in their ver message.
        obj.emplace_back("subver", std::move(stats.cleanSubVer));
        obj.emplace_back("inbound", stats.fInbound);
        obj.emplace_back("bip152_hb_to", stats.m_bip152_highbandwidth_to);
        obj.emplace_back("bip152_hb_from", stats.m_bip152_highbandwidth_from);
        obj.emplace_back("addnode", stats.m_manual_connection);
        obj.emplace_back("startingheight", stats.nStartingHeight);
        if (fStateStats) {
            obj.emplace_back("banscore", statestats.nMisbehavior);
            obj.emplace_back("synced_headers", statestats.nSyncHeight);
            obj.emplace_back("synced_blocks", statestats.nCommonHeight);
            UniValue::Array heights;
            heights.reserve(statestats.vHeightInFlight.size());
            for (const int height : statestats.vHeightInFlight) {
                heights.emplace_back(height);
            }
            obj.emplace_back("inflight", std::move(heights));
        }
        obj.emplace_back("addr_processed", stats.m_addr_processed);
        obj.emplace_back("addr_rate_limited", stats.m_addr_rate_limited);
        obj.emplace_back("whitelisted", stats.m_legacyWhitelisted);
        auto permissionStrings = NetPermissions::ToStrings(stats.m_permissionFlags);
        UniValue::Array permissions;
        permissions.reserve(permissionStrings.size());
        for (auto &permission : permissionStrings) {
            permissions.emplace_back(std::move(permission));
        }
        obj.emplace_back("permissions", std::move(permissions));
        obj.emplace_back("minfeefilter", ValueFromAmount(stats.minFeeFilter));

        UniValue::Object sendPerMsgType;
        for (const mapMsgTypeSize::value_type &i : stats.mapSendBytesPerMsgType) {
            if (i.second > 0) {
                sendPerMsgType.emplace_back(i);
            }
        }
        obj.emplace_back("bytessent_per_msg", std::move(sendPerMsgType));

        UniValue::Object recvPerMsgType;
        for (const mapMsgTypeSize::value_type &i : stats.mapRecvBytesPerMsgType) {
            if (i.second > 0) {
                recvPerMsgType.emplace_back(i);
            }
        }
        obj.emplace_back("bytesrecv_per_msg", std::move(recvPerMsgType));

        ret.emplace_back(obj);
    }

    return ret;
}

static UniValue addnode(const Config &config, const JSONRPCRequest &request) {
    std::string strCommand;
    if (!request.params[1].isNull()) {
        strCommand = request.params[1].get_str();
    }

    if (request.fHelp || request.params.size() != 2 || (strCommand != "onetry" && strCommand != "add" && strCommand != "remove")) {
        throw std::runtime_error(RPCHelpMan{
            "addnode",
            "\nAttempts to add or remove a node from the addnode list.\n"
            "Or try a connection to a node once.\n"
            "Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be\n"
            "full nodes as other outbound peers are (though such peers will not be synced from).\n",
            {
                {"node", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The node (see getpeerinfo for nodes)"},
                {"command", RPCArg::Type::STR, /* opt */ false, /* default_val */ "",
                 "'add' to add a node to the list, "
                 "'remove' to remove a node from the list, "
                 "'onetry' to try a connection to the node once"},
            },
            RPCResults{},
            RPCExamples{
                HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\"") +
                HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\"")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    const std::string &strNode = request.params[0].get_str();

    if (strCommand == "onetry") {
        CAddress addr;
        g_connman->OpenNetworkConnection(addr, false, nullptr, strNode.c_str(),
                                         false, false, true);
        return UniValue();
    }

    if (strCommand == "add" && !g_connman->AddNode(strNode)) {
        throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED,
                           "Error: Node already added");
    } else if (strCommand == "remove" && !g_connman->RemoveAddedNode(strNode)) {
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED,
                           "Error: Node has not been added.");
    }

    return UniValue();
}

static UniValue disconnectnode(const Config &config,
                               const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() == 0 || request.params.size() >= 3) {
        throw std::runtime_error(RPCHelpMan{
            "disconnectnode",
            "\nImmediately disconnects from the specified peer node.\n"
            "\nStrictly one out of 'address' and 'nodeid' can be provided to identify the node.\n"
            "\nTo disconnect by nodeid, either set 'address' to the empty string,"
            " or call using the named 'nodeid' argument only.\n",
            {
                {"address", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "The IP address/port of the node"},
                {"nodeid", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "", "The node ID (see getpeerinfo for node IDs)"},
            },
            RPCResults{},
            RPCExamples{
                HelpExampleCli("disconnectnode", "\"192.168.0.6:8333\"") +
                HelpExampleCli("disconnectnode", "\"\" 1") +
                HelpExampleRpc("disconnectnode", "\"192.168.0.6:8333\"") +
                HelpExampleRpc("disconnectnode", "\"\", 1")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    bool success;
    const UniValue &address_arg = request.params[0];
    const UniValue &id_arg = request.params[1];

    if (!address_arg.isNull() && id_arg.isNull()) {
        /* handle disconnect-by-address */
        success = g_connman->DisconnectNode(address_arg.get_str());
    } else if (!id_arg.isNull() &&
               (address_arg.isNull() ||
                (address_arg.isStr() && address_arg.get_str().empty()))) {
        /* handle disconnect-by-id */
        NodeId nodeid = (NodeId)id_arg.get_int64();
        success = g_connman->DisconnectNode(nodeid);
    } else {
        throw JSONRPCError(
            RPC_INVALID_PARAMS,
            "Only one of address and nodeid should be provided.");
    }

    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_NOT_CONNECTED,
                           "Node not found in connected nodes");
    }

    return UniValue();
}

static UniValue getaddednodeinfo(const Config &config,
                                 const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(RPCHelpMan{
            "getaddednodeinfo",
            "\nReturns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n",
            {
                {"node", RPCArg::Type::STR, /* opt */ true, /* default_val */ "",
                 "If provided, return information about this specific node, otherwise all nodes are returned."},
            },
            RPCResult{
                "[\n"
                "  {\n"
                "    \"addednode\" : \"192.168.0.201\",   (string) The node IP address or name (as provided to addnode)\n"
                "    \"connected\" : true|false,        (boolean) If connected\n"
                "    \"addresses\" : [                  (list of objects) Only when connected = true\n"
                "       {\n"
                "         \"address\" : \"192.168.0.201:8333\",  (string) The bitcoin server IP and port we're connected to\n"
                "         \"connected\" : \"outbound\"           (string) connection, inbound or outbound\n"
                "       }\n"
                "     ]\n"
                "  }\n"
                "  ,...\n"
                "]\n"},
            RPCExamples{
                HelpExampleCli("getaddednodeinfo", "\"192.168.0.201\"") +
                HelpExampleRpc("getaddednodeinfo", "\"192.168.0.201\"")},
        }
                                     .ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    std::vector<AddedNodeInfo> vInfo = g_connman->GetAddedNodeInfo();

    if (!request.params[0].isNull()) {
        bool found = false;
        for (AddedNodeInfo &info : vInfo) {
            if (info.strAddedNode == request.params[0].get_str()) {
                AddedNodeInfo selected = std::move(info);
                vInfo.resize(1);
                vInfo.front() = std::move(selected);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED,
                               "Error: Node has not been added.");
        }
    }

    UniValue::Array ret;
    ret.reserve(vInfo.size());

    for (AddedNodeInfo &info : vInfo) {
        UniValue::Object obj;
        obj.emplace_back("addednode", std::move(info.strAddedNode));
        obj.emplace_back("connected", info.fConnected);
        UniValue::Array addresses;
        if (info.fConnected) {
            UniValue::Object address;
            address.emplace_back("address", info.resolvedAddress.ToString());
            address.emplace_back("connected", info.fInbound ? "inbound" : "outbound");
            addresses.emplace_back(std::move(address));
        }
        obj.emplace_back("addresses", std::move(addresses));
        ret.emplace_back(std::move(obj));
    }

    return ret;
}

static UniValue getnettotals(const Config &config,
                             const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(RPCHelpMan{
            "getnettotals",
            "\nReturns information about network traffic, including bytes in, bytes out,\n"
            "and current time.\n",
            {},
            RPCResult{
                "{\n"
                "  \"totalbytesrecv\": n,   (numeric) Total bytes received\n"
                "  \"totalbytessent\": n,   (numeric) Total bytes sent\n"
                "  \"timemillis\": t,       (numeric) Current UNIX time in milliseconds\n"
                "  \"uploadtarget\":\n"
                "  {\n"
                "    \"timeframe\": n,                         (numeric) Length of the measuring timeframe in seconds\n"
                "    \"target\": n,                            (numeric) Target in bytes\n"
                "    \"target_reached\": true|false,           (boolean) True if target is reached\n"
                "    \"serve_historical_blocks\": true|false,  (boolean) True if serving historical blocks\n"
                "    \"bytes_left_in_cycle\": t,               (numeric) Bytes left in current time cycle\n"
                "    \"time_left_in_cycle\": t                 (numeric) Seconds left in current time cycle\n"
                "  }\n"
                "}\n"},
            RPCExamples{HelpExampleCli("getnettotals", "") +
                        HelpExampleRpc("getnettotals", "")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    UniValue::Object obj;
    obj.reserve(4);

    obj.emplace_back("totalbytesrecv", g_connman->GetTotalBytesRecv());
    obj.emplace_back("totalbytessent", g_connman->GetTotalBytesSent());
    obj.emplace_back("timemillis", GetTimeMillis());

    UniValue::Object outboundLimit;
    outboundLimit.reserve(6);
    outboundLimit.emplace_back("timeframe", g_connman->GetMaxOutboundTimeframe());
    outboundLimit.emplace_back("target", g_connman->GetMaxOutboundTarget());
    outboundLimit.emplace_back("target_reached", g_connman->OutboundTargetReached(false));
    outboundLimit.emplace_back("serve_historical_blocks", !g_connman->OutboundTargetReached(true));
    outboundLimit.emplace_back("bytes_left_in_cycle", g_connman->GetOutboundTargetBytesLeft());
    outboundLimit.emplace_back("time_left_in_cycle", g_connman->GetMaxOutboundTimeLeftInCycle());
    obj.emplace_back("uploadtarget", std::move(outboundLimit));

    return obj;
}

static UniValue::Array GetNetworksInfo() {
    UniValue::Array networks;
    for (int n = 0; n < NET_MAX; ++n) {
        enum Network network = static_cast<enum Network>(n);
        if (network == NET_UNROUTABLE || network == NET_INTERNAL) {
            continue;
        }
        proxyType proxy;
        GetProxy(network, proxy);
        UniValue::Object obj;
        obj.reserve(5);
        obj.emplace_back("name", GetNetworkName(network));
        obj.emplace_back("limited", !IsReachable(network));
        obj.emplace_back("reachable", IsReachable(network));
        obj.emplace_back("proxy", proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string());
        obj.emplace_back("proxy_randomize_credentials", proxy.randomize_credentials);
        networks.emplace_back(std::move(obj));
    }
    return networks;
}

static UniValue getnetworkinfo(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(RPCHelpMan{
            "getnetworkinfo",
            "Returns an object containing various state info regarding P2P networking.\n",
            {},
            RPCResult{
                "{\n"
                "  \"version\": xxxxx,                             (numeric) the server version\n"
                "  \"subversion\": \"/Bitcoin Cash Node:x.x.x/\",    (string) the server subversion string\n"
                "  \"protocolversion\": xxxxx,                     (numeric) the protocol version\n"
                "  \"localservices\": \"xxxxxxxxxxxxxxxx\",          (string) the services we offer to the network\n"
                "  \"localservicesnames\": [                       (array) the services we offer to the network, in human-readable form\n"
                "    \"SERVICE_NAME\"                              (string) the service name\n"
                "    ,...\n"
                "  ],\n"
                "  \"localrelay\": true|false,                     (bool) true if transaction relay is requested from peers\n"
                "  \"timeoffset\": xxxxx,                          (numeric) the time offset\n"
                "  \"connections\": xxxxx,                         (numeric) the total number of connections\n"
                "  \"connections_in\": xxxxx,                      (numeric) the number of inbound connections\n"
                "  \"connections_out\": xxxxx,                     (numeric) the number of outbound connections\n"
                "  \"networkactive\": true|false,                  (bool) whether p2p networking is enabled\n"
                "  \"networks\": [                                 (array) information per network\n"
                "  {\n"
                "    \"name\": \"xxx\",                              (string) network (ipv4, ipv6 or onion)\n"
                "    \"limited\": true|false,                      (boolean) is the network limited using -onlynet?\n"
                "    \"reachable\": true|false,                    (boolean) is the network reachable?\n"
                "    \"proxy\": \"host:port\"                        (string) "
                "the proxy that is used for this network, or empty if none\n"
                "    \"proxy_randomize_credentials\": true|false,  (bool) whether randomized credentials are used\n"
                "  }\n"
                "  ,...\n"
                "  ],\n"
                "  \"relayfee\": x.xxxxxxxx,                       (numeric) "
                "minimum relay fee for transactions in " + CURRENCY_UNIT + "/kB\n"
                "  \"excessutxocharge\": x.xxxxxxxx,               (numeric) "
                "minimum charge for excess utxos in " + CURRENCY_UNIT + "\n"
                "  \"localaddresses\": [                           (array) list of local addresses\n"
                "  {\n"
                "    \"address\": \"xxxx\",                          (string) network address\n"
                "    \"port\": xxx,                                (numeric) network port\n"
                "    \"score\": xxx                                (numeric) relative score\n"
                "  }\n"
                "  ,...\n"
                "  ],\n"
                "  \"warnings\": \"...\"                             (string) any network and blockchain warnings\n"
                "}\n"},
            RPCExamples{HelpExampleCli("getnetworkinfo", "") +
                        HelpExampleRpc("getnetworkinfo", "")},
        }.ToStringWithResultsAndExamples());
    }

    LOCK(cs_main);
    UniValue::Object obj;
    obj.reserve(g_connman ? 14 : 10);
    obj.emplace_back("version", CLIENT_VERSION);
    obj.emplace_back("subversion", userAgent(config));
    obj.emplace_back("protocolversion", PROTOCOL_VERSION);
    if (g_connman) {
        const ServiceFlags services = g_connman->GetLocalServices();
        obj.emplace_back("localservices", strprintf("%016x", services));
        obj.emplace_back("localservicesnames", GetServicesNames(services));
    }
    obj.emplace_back("localrelay", g_relay_txes);
    obj.emplace_back("timeoffset", GetTimeOffset());
    if (g_connman) {
        obj.emplace_back("networkactive", g_connman->GetNetworkActive());
        obj.emplace_back("connections", g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
        obj.emplace_back("connections_in", g_connman->GetNodeCount(CConnman::CONNECTIONS_IN));
        obj.emplace_back("connections_out", g_connman->GetNodeCount(CConnman::CONNECTIONS_OUT));
    }
    obj.emplace_back("networks", GetNetworksInfo());
    obj.emplace_back("relayfee", ValueFromAmount(::minRelayTxFee.GetFeePerK()));
    obj.emplace_back("excessutxocharge", ValueFromAmount(config.GetExcessUTXOCharge()));
    UniValue::Array localAddresses;
    {
        LOCK(cs_mapLocalHost);
        localAddresses.reserve(mapLocalHost.size());
        for (const std::pair<const CNetAddr, LocalServiceInfo> &item : mapLocalHost) {
            UniValue::Object rec;
            rec.reserve(3);
            rec.emplace_back("address", item.first.ToString());
            rec.emplace_back("port", item.second.nPort);
            rec.emplace_back("score", item.second.nScore);
            localAddresses.emplace_back(std::move(rec));
        }
    }
    obj.emplace_back("localaddresses", std::move(localAddresses));
    obj.emplace_back("warnings", GetWarnings("statusbar"));
    return obj;
}

static UniValue setban(const Config &config, const JSONRPCRequest &request) {
    std::string strCommand;
    if (!request.params[1].isNull()) {
        strCommand = request.params[1].get_str();
    }

    if (request.fHelp || request.params.size() < 2 ||
        (strCommand != "add" && strCommand != "remove")) {
        throw std::runtime_error(RPCHelpMan{
            "setban",
            "\nAttempts to add or remove an IP/Subnet from the "
            "banned list.\n",
            {
                {"subnet", RPCArg::Type::STR, /* opt */ false, /* default_val */ "",
                 "The IP/Subnet (see getpeerinfo for nodes IP) with an optional netmask (default is /32 = single IP)"},
                {"command", RPCArg::Type::STR, /* opt */ false, /* default_val */ "",
                 "'add' to add an IP/Subnet to the list, 'remove' to remove an IP/Subnet from the list"},
                {"bantime", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "",
                 "time in seconds how long (or until when if [absolute] is set) the IP is banned "
                 "(0 or empty means using the default time of 24h "
                 "which can also be overwritten by the -bantime startup argument)"},
                {"absolute", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "",
                 "If set, the bantime must be an absolute timestamp in seconds since epoch (Jan 1 1970 GMT)"},
            },
            RPCResults{},
            RPCExamples{
                HelpExampleCli("setban", "\"192.168.0.6\" \"add\" 86400") +
                HelpExampleCli("setban", "\"192.168.0.0/24\" \"add\"") +
                HelpExampleRpc("setban", "\"192.168.0.6\", \"add\", 86400")},
        }.ToStringWithResultsAndExamples());
    }
    if (!g_banman) {
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "Error: Ban database not loaded");
    }

    CSubNet subNet;
    CNetAddr netAddr;
    bool isSubnet = false;

    if (request.params[0].get_str().find('/') != std::string::npos) {
        isSubnet = true;
    }

    if (!isSubnet) {
        CNetAddr resolved;
        LookupHost(request.params[0].get_str(), resolved, false);
        netAddr = resolved;
    } else {
        LookupSubNet(request.params[0].get_str(), subNet);
    }

    if (!(isSubnet ? subNet.IsValid() : netAddr.IsValid())) {
        throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET,
                           "Error: Invalid IP/Subnet");
    }

    if (strCommand == "add") {
        if (isSubnet ? g_banman->IsBanned(subNet)
                     : g_banman->IsBanned(netAddr)) {
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED,
                               "Error: IP/Subnet already banned");
        }

        // Use standard bantime if not specified.
        int64_t banTime = 0;
        if (!request.params[2].isNull()) {
            banTime = request.params[2].get_int64();
        }

        bool absolute = false;
        if (request.params[3].isTrue()) {
            absolute = true;
        }

        if (isSubnet) {
            g_banman->Ban(subNet, banTime, absolute);
            if (g_connman) {
                g_connman->DisconnectNode(subNet);
            }
        } else {
            g_banman->Ban(netAddr, banTime, absolute);
            if (g_connman) {
                g_connman->DisconnectNode(netAddr);
            }
        }
    } else if (strCommand == "remove") {
        if (!(isSubnet ? g_banman->Unban(subNet) : g_banman->Unban(netAddr))) {
            throw JSONRPCError(RPC_CLIENT_INVALID_IP_OR_SUBNET,
                               "Error: Unban failed. Requested address/subnet "
                               "was not previously manually banned.");
        }
    }
    return UniValue();
}

static UniValue listbanned(const Config&,
                           const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(RPCHelpMan{
            "listbanned",
            "\nList all manually banned IPs/Subnets.\n",
            {},
            RPCResults{},
            RPCExamples{HelpExampleCli("listbanned", "") +
                        HelpExampleRpc("listbanned", "")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_banman) {
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "Error: Ban database not loaded");
    }

    BanTables banMap;
    g_banman->GetBanned(banMap);

    UniValue::Array bannedAddresses;
    const auto allBans = banMap.toAggregatedMap();
    bannedAddresses.reserve(allBans.size());
    for (const auto &entry : allBans) {
        const CBanEntry &banEntry = entry.second;
        UniValue::Object rec;
        rec.reserve(4);
        rec.emplace_back("address", entry.first.ToString());
        rec.emplace_back("banned_until", banEntry.nBanUntil);
        rec.emplace_back("ban_created", banEntry.nCreateTime);
        rec.emplace_back("ban_reason", "manually added"); //! For backward compatibility

        bannedAddresses.emplace_back(std::move(rec));
    }

    return bannedAddresses;
}

static UniValue clearbanned(const Config &config,
                            const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(RPCHelpMan{
            "clearbanned",
            "\nClear all banned and/or discouraged IPs.\n",
            {
                {"manual", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true",
                 "true to clear all manual bans, false to not clear them"},
                {"automatic", RPCArg::Type::BOOL, /* opt */ true, /* default_val */ "true",
                 "true to clear all automatic discouragements, false to not clear them"}
            },
            RPCResults{},
            RPCExamples{HelpExampleCli("clearbanned", "") +
                        HelpExampleCli("clearbanned", "true") +
                        HelpExampleCli("clearbanned", "true false") +
                        HelpExampleRpc("clearbanned", "") +
                        HelpExampleRpc("clearbanned", "false, true")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_banman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    bool manual = true, automatic = true;

    if (request.params.size() > 0)
        manual = request.params[0].get_bool();
    if (request.params.size() > 1)
        automatic = request.params[1].get_bool();

    if (manual)
        g_banman->ClearBanned();
    if (automatic)
        g_banman->ClearDiscouraged();

    return UniValue();
}

static UniValue setnetworkactive(const Config &config,
                                 const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(RPCHelpMan{
            "setnetworkactive",
            "\nDisable/enable all p2p network activity.\n",
            {
                {"state", RPCArg::Type::BOOL, /* opt */ false, /* default_val */ "",
                 "true to enable networking, false to disable"},
            },
            RPCResults{},
            RPCExamples{""},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    g_connman->SetNetworkActive(request.params[0].get_bool());

    return g_connman->GetNetworkActive();
}

static UniValue getnodeaddresses(const Config &, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(RPCHelpMan{
            "getnodeaddresses",
            "\nReturn known addresses, which can potentially be used to find new nodes on the network.\n",
            {
                {"count", RPCArg::Type::NUM, /* opt */ true, /* default_val */ "1",
                 "The maximum number of addresses to return. Specify 0 to return all known addresses."},
            },
            RPCResult{
                "[\n"
                "  {\n"
                "    \"time\": ttt,                (numeric) "
                "Timestamp in seconds since epoch (Jan 1 1970 GMT) keeping track of when the node was last seen\n"
                "    \"services\": n,              (numeric) The services offered by the node\n"
                "    \"servicesnames\":[           (array) The services offered, in human-readable form\n"
                "       \"SERVICE_NAME\"           (string) The service name if it is recognized\n"
                "       ,...\n"
                "    ],\n"
                "    \"address\": \"host\",          (string) The address of the node\n"
                "    \"port\": n,                  (numeric) The port number of the node\n"
                "    \"network\": \"name\"           (string) The network (ipv4, ipv6, onion) the node connected through\n"
                "  }\n"
                "  ,....\n"
                "]\n"},
            RPCExamples{HelpExampleCli("getnodeaddresses", "8") +
                        HelpExampleRpc("getnodeaddresses", "8")},
        }.ToStringWithResultsAndExamples());
    }
    if (!g_connman) {
        throw JSONRPCError(
            RPC_CLIENT_P2P_DISABLED,
            "Error: Peer-to-peer functionality missing or disabled");
    }

    int count = 1;
    if (!request.params[0].isNull()) {
        count = request.params[0].get_int();
        if (count < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Address count out of range");
        }
    }

    // returns a shuffled list of CAddress
    const std::vector<CAddress> vAddr = g_connman->GetAddresses(count, /* max_pct */ 0);
    const size_t address_return_count = std::min<size_t>(count, vAddr.size());
    UniValue::Array ret;
    ret.reserve(address_return_count);
    for (const CAddress& addr : vAddr) {
        UniValue::Object obj;
        obj.reserve(6);
        obj.emplace_back("time", addr.nTime);
        obj.emplace_back("services", addr.nServices);
        obj.emplace_back("servicesnames", GetServicesNames(addr.nServices));
        obj.emplace_back("address", addr.ToStringIP());
        obj.emplace_back("port", addr.GetPort());
        obj.emplace_back("network", GetNetworkName(addr.GetNetClass()));
        ret.emplace_back(std::move(obj));
    }
    return ret;
}

static UniValue addconnection(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(RPCHelpMan{
            "addconnection",
            "\nOpen an outbound connection to a specified node. This RPC is for testing only.\n" ,
            {
                {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "",
                 "The IP address and port to attempt connecting to."},
                {"dummy", RPCArg::Type::STR, /* opt */ true, /* default_val */ "",
                 "This parameter is ignored and is provided for compatibility with other software."},
            },
            RPCResult{
                "{\n"
                "  \"address\": \"addr:port\",      (string) The address and port of the newly added connection.\n"
                "}\n"},
            RPCExamples{HelpExampleCli("addconnection", "\"1.2.3.4:8333\"") +
                        HelpExampleRpc("addconnection", "\"1.2.3.4:8333\"")},
        }.ToStringWithResultsAndExamples());
    }
    // Ensure we are on regtest
    if (const auto &cparams = config.GetChainParams().GetConsensus(); ! cparams.fPowNoRetargeting) {
        throw JSONRPCError(RPC_METHOD_DISABLED, "addconnection is for regression testing (-regtest mode) only.");
    }
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});
    const std::string address = request.params[0].get_str();
    if (!g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled.");
    }
    const bool success = g_connman->AddConnection(address);
    if (!success) {
        throw JSONRPCError(RPC_CLIENT_NODE_CAPACITY_REACHED, "Error: Already at capacity for specified connection type.");
    }
    UniValue::Object info;
    info.emplace_back("address", address);
    return info;
}

static UniValue addpeeraddress(const Config &config, const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(RPCHelpMan{
            "addpeeraddress",
            "\nAdd the address of a potential peer to the address manager. This RPC is for testing only.\n",
            {
                {"address", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The IP address of the peer"},
                {"port", RPCArg::Type::NUM, /* opt */ false, /* default_val */ "", "The port of the peer"},
            },
            RPCResult{
                "{\n"
                "  \"success\": true|false,      (numeric) whether the peer address was successfully added to the address manager\n"
                "}\n"},
            RPCExamples{HelpExampleCli("addpeeraddress", "\"1.2.3.4\" 8333") +
                        HelpExampleRpc("addpeeraddress", "\"1.2.3.4\", 8333")},
        }.ToStringWithResultsAndExamples());
    }

    if (!g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    UniValue::Object obj;
    obj.reserve(1);

    std::string addr_string = request.params[0].get_str();
    uint16_t port = request.params[1].get_int();

    CNetAddr net_addr;
    if (!LookupHost(addr_string, net_addr, false)) {
        obj.emplace_back("success", false);
        return obj;
    }
    CAddress address = CAddress({net_addr, port}, ServiceFlags(NODE_NETWORK));
    address.nTime = GetAdjustedTime();
    // The source address is set equal to the address. This is equivalent to the peer
    // announcing itself.
    if (!g_connman->AddNewAddresses({address}, address)) {
        obj.emplace_back("success", false);
        return obj;
    }

    obj.emplace_back("success", true);
    return obj;
}

// clang-format off
static const ContextFreeRPCCommand commands[] = {
    //  category            name                      actor (function)        argNames
    //  ------------------- ------------------------  ----------------------  ----------
    { "network",            "getconnectioncount",     getconnectioncount,     {} },
    { "network",            "ping",                   ping,                   {} },
    { "network",            "getpeerinfo",            getpeerinfo,            {} },
    { "network",            "addnode",                addnode,                {"node","command"} },
    { "network",            "disconnectnode",         disconnectnode,         {"address", "nodeid"} },
    { "network",            "getaddednodeinfo",       getaddednodeinfo,       {"node"} },
    { "network",            "getnettotals",           getnettotals,           {} },
    { "network",            "getnetworkinfo",         getnetworkinfo,         {} },
    { "network",            "setban",                 setban,                 {"subnet", "command", "bantime", "absolute"} },
    { "network",            "listbanned",             listbanned,             {} },
    { "network",            "clearbanned",            clearbanned,            {"manual", "automatic"} },
    { "network",            "setnetworkactive",       setnetworkactive,       {"state"} },
    { "network",            "getnodeaddresses",       getnodeaddresses,       {"count"} },


    { "hidden",             "addconnection",          addconnection,          {"address", "dummy"} },
    { "hidden",             "addpeeraddress",         addpeeraddress,         {"address", "port"} },
};
// clang-format on

void RegisterNetRPCCommands(CRPCTable &t) {
    for (unsigned int vcidx = 0; vcidx < std::size(commands); ++vcidx) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
