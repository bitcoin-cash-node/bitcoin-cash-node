// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <addrdb.h>
#include <addrman.h>
#include <amount.h>
#include <bloom.h>
#include <chainparams.h>
#include <compat.h>
#include <crypto/siphash.h>
#include <dsproof/dspid.h>
#include <extversion.h>
#include <hash.h>
#include <net_nodeid.h>
#include <net_permissions.h>
#include <netaddress.h>
#include <peerratelimiter.h>
#include <protocol.h>
#include <random.h>
#include <streams.h>
#include <sync.h>
#include <threadinterrupt.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <thread>

#ifndef WIN32
#include <arpa/inet.h>
#endif

class BanMan;
class Config;
class CNode;
class CScheduler;

/** Default for -whitelistrelay. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for -whitelistforcerelay. */
static const bool DEFAULT_WHITELISTFORCERELAY = false;

/**
 * Time between pings automatically sent out for latency probing and keepalive
 * (in seconds).
 */
static const int PING_INTERVAL = 2 * 60;
/**
 * Time after which to disconnect, after waiting for a ping response (or
 * inactivity).
 */
static const int TIMEOUT_INTERVAL = 20 * 60;
/** Run the feeler connection loop once every 2 minutes or 120,000 ms. **/
static const int FEELER_INTERVAL = 120000;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
static_assert(MAX_PROTOCOL_MESSAGE_LENGTH > MAX_INV_SZ * sizeof(CInv),
              "Max protocol message length must be greater than largest "
              "possible INV message");
/** The maximum number of entries in a locator */
static const unsigned int MAX_LOCATOR_SZ = 101;
/** The maximum number of addresses from our addrman to return in response to a getaddr message. */
static constexpr size_t MAX_ADDR_TO_SEND = 1000;
/**
 *  The maximum rate of address records we're willing to process on average. Can be bypassed using
 *  the NetPermissionFlags::PF_ADDR permission.
*/
static constexpr double MAX_ADDR_RATE_PER_SECOND = 0.1;
/**
 *  The soft limit of the address processing token bucket (the regular MAX_ADDR_RATE_PER_SECOND
 *  based increments won't go above this, but the MAX_ADDR_TO_SEND increment following GETADDR
 *  is exempt from this limit).
*/
static constexpr size_t MAX_ADDR_PROCESSING_TOKEN_BUCKET = MAX_ADDR_TO_SEND;
/** Maximum length of the user agent string in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;
/** Maximum number of automatic outgoing nodes */
static const int MAX_OUTBOUND_CONNECTIONS = 8;
/** Maximum number of addnode outgoing nodes */
static const int MAX_ADDNODE_CONNECTIONS = 8;
/** -listen default */
static const bool DEFAULT_LISTEN = true;
/** The maximum number of peer connections to maintain. */
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 125;
/** The default for -maxuploadtarget. 0 = Unlimited */
static const uint64_t DEFAULT_MAX_UPLOAD_TARGET = 0;
/** The default timeframe for -maxuploadtarget. 1 day. */
static const uint64_t MAX_UPLOAD_TIMEFRAME = 60 * 60 * 24;
/** Default for blocks only*/
static const bool DEFAULT_BLOCKSONLY = false;
/** -peertimeout default */
static const int64_t DEFAULT_PEER_CONNECT_TIMEOUT = 60;

static const bool DEFAULT_FORCEDNSSEED = false;
static const size_t DEFAULT_MAXRECEIVEBUFFER = 5 * 1000;
static const size_t DEFAULT_MAXSENDBUFFER = 1 * 1000;

struct AddedNodeInfo {
    std::string strAddedNode;
    CService resolvedAddress;
    bool fConnected;
    bool fInbound;
};

struct CNodeStats;
class CClientUIInterface;

struct CSerializedNetMsg {
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg &&) = default;
    CSerializedNetMsg &operator=(CSerializedNetMsg &&) = default;
    // No copying, only moves.
    CSerializedNetMsg(const CSerializedNetMsg &msg) = delete;
    CSerializedNetMsg &operator=(const CSerializedNetMsg &) = delete;

    std::vector<uint8_t> data;
    std::string m_type;
};

using NodeRef = std::shared_ptr<CNode>;
using NodeCRef = std::shared_ptr<const CNode>; //! unused; maybe should be used in some places for const-correctness

class NetEventsInterface;
class CConnman {
public:
    enum NumConnections {
        CONNECTIONS_NONE = 0,
        CONNECTIONS_IN = (1U << 0),
        CONNECTIONS_OUT = (1U << 1),
        CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
    };

    struct Options {
        ServiceFlags nLocalServices = NODE_NONE;
        int nMaxConnections = 0;
        int nMaxOutbound = 0;
        int nMaxAddnode = 0;
        int nMaxFeeler = 0;
        int nBestHeight = 0;
        CClientUIInterface *uiInterface = nullptr;
        NetEventsInterface *m_msgproc = nullptr;
        BanMan *m_banman = nullptr;
        unsigned int nSendBufferMaxSize = 0;
        unsigned int nReceiveFloodSize = 0;
        uint64_t nMaxOutboundTimeframe = 0;
        uint64_t nMaxOutboundLimit = 0;
        int64_t m_peer_connect_timeout = DEFAULT_PEER_CONNECT_TIMEOUT;
        std::vector<std::string> vSeedNodes;
        std::vector<NetWhitelistPermissions> vWhitelistedRange;
        std::vector<NetWhitebindPermissions> vWhiteBinds;
        std::vector<CService> vBinds;
        std::vector<CService> onion_binds;
        bool m_use_addrman_outgoing = true;
        std::vector<std::string> m_specified_outgoing;
        std::vector<std::string> m_added_nodes;
        std::vector<bool> m_asmap;
    };

    void Init(const Options &connOptions) {
        nLocalServices = connOptions.nLocalServices;
        nMaxConnections = connOptions.nMaxConnections;
        nMaxOutbound =
            std::min(connOptions.nMaxOutbound, connOptions.nMaxConnections);
        m_use_addrman_outgoing = connOptions.m_use_addrman_outgoing;
        nMaxAddnode = connOptions.nMaxAddnode;
        nMaxFeeler = connOptions.nMaxFeeler;
        nBestHeight = connOptions.nBestHeight;
        clientInterface = connOptions.uiInterface;
        m_banman = connOptions.m_banman;
        m_msgproc = connOptions.m_msgproc;
        nSendBufferMaxSize = connOptions.nSendBufferMaxSize;
        nReceiveFloodSize = connOptions.nReceiveFloodSize;
        m_peer_connect_timeout = connOptions.m_peer_connect_timeout;
        {
            LOCK(cs_totalBytesSent);
            nMaxOutboundTimeframe = connOptions.nMaxOutboundTimeframe;
            nMaxOutboundLimit = connOptions.nMaxOutboundLimit;
        }
        vWhitelistedRange = connOptions.vWhitelistedRange;
        {
            LOCK(cs_vAddedNodes);
            vAddedNodes = connOptions.m_added_nodes;
        }
    }

    CConnman(const Config &configIn, uint64_t seed0, uint64_t seed1);
    ~CConnman();

    bool Start(CScheduler &scheduler, const Options &options);

    // TODO: Remove NO_THREAD_SAFETY_ANALYSIS. Lock cs_vNodes before reading the
    // variable vNodes.
    //
    // When removing NO_THREAD_SAFETY_ANALYSIS be aware of the following lock
    // order requirements:
    // * CheckForStaleTipAndEvictPeers locks cs_main before indirectly calling
    //   GetExtraOutboundCount which locks cs_vNodes.
    // * ProcessMessage locks cs_main and g_cs_orphans before indirectly calling
    //   ForEachNode which locks cs_vNodes.
    //
    // Thus the implicit locking order requirement is: (1) cs_main, (2)
    // g_cs_orphans, (3) cs_vNodes.
    void Stop() NO_THREAD_SAFETY_ANALYSIS;

    void Interrupt();
    bool GetNetworkActive() const { return fNetworkActive; };
    bool GetUseAddrmanOutgoing() const { return m_use_addrman_outgoing; };
    void SetNetworkActive(bool active);
    void OpenNetworkConnection(const CAddress &addrConnect, bool fCountFailure,
                               CSemaphoreGrant *grantOutbound = nullptr,
                               const char *strDest = nullptr,
                               bool fOneShot = false, bool fFeeler = false,
                               bool manual_connection = false);
    bool CheckIncomingNonce(uint64_t nonce) const;

    bool ForNode(NodeId id, std::function<bool(NodeRef pnode)> func, bool fullyConnectedOnly = true) const;

    void PushMessage(const NodeRef &pnode, CSerializedNetMsg &&msg);

    template <typename Callable> void ForEachNode(Callable &&func) const {
        LOCK(cs_mNodes);
        for (const auto & [_, node] : mNodes) {
            if (NodeFullyConnected(node)) {
                func(node);
            }
        }
    };

    template <typename Callable, typename CallableAfter>
    void ForEachNodeThen(Callable &&pre, CallableAfter &&post) const {
        LOCK(cs_mNodes);
        for (const auto & [_, node] : mNodes) {
            if (NodeFullyConnected(node)) {
                pre(node);
            }
        }
        post();
    };

    // Addrman functions
    void SetServices(const CService &addr, ServiceFlags nServices);
    void MarkAddressGood(const CAddress &addr);
    bool AddNewAddresses(const std::vector<CAddress> &vAddr, const CAddress &addrFrom, int64_t nTimePenalty = 0);
    std::vector<CAddress> GetAddresses(size_t max_addresses, size_t max_pct);
    /**
     * In this version, a cache is used to minimize topology leaks, so it
     * should be used for all non-trusted calls, for example, p2p.
     * A non-malicious call (from RPC or a peer with addr permission) should
     * call the regular GetAddresses() function to avoid using the cache.
     */
    std::vector<CAddress> GetAddressesUntrusted(CNode &requestor, size_t max_addresses, size_t max_pct);

    // This allows temporarily exceeding nMaxOutbound, with the goal of finding
    // a peer that is better than all our current peers.
    void SetTryNewOutboundPeer(bool flag);
    bool GetTryNewOutboundPeer();

    // Return the number of outbound peers we have in excess of our target (eg,
    // if we previously called SetTryNewOutboundPeer(true), and have since set
    // to false, we may have extra peers that we wish to disconnect). This may
    // return a value less than (num_outbound_connections - num_outbound_slots)
    // in cases where some outbound connections are not yet fully connected, or
    // not yet fully disconnected.
    int GetExtraOutboundCount();

    bool AddNode(const std::string &node);
    bool RemoveAddedNode(const std::string &node);
    std::vector<AddedNodeInfo> GetAddedNodeInfo();

    /**
     * Attempts to open a connection. Currently only used from tests.
     *
     * @param[in]   address     Address of node to try connecting to
     * @return      bool        Returns false if there are no available
     *                          outbound slots for this connection.
     */
    bool AddConnection(const std::string& address);

    size_t GetNodeCount(NumConnections num) const;
    void GetNodeStats(std::vector<CNodeStats> &vstats) const;
    bool DisconnectNode(const std::string &node);
    bool DisconnectNode(const CSubNet &subnet);
    bool DisconnectNode(const CNetAddr &addr);
    bool DisconnectNode(NodeId id);

    ServiceFlags GetLocalServices() const;

    //! set the max outbound target in bytes.
    void SetMaxOutboundTarget(uint64_t limit);
    uint64_t GetMaxOutboundTarget();

    //! set the timeframe for the max outbound target.
    void SetMaxOutboundTimeframe(uint64_t timeframe);
    uint64_t GetMaxOutboundTimeframe();

    //! check if the outbound target is reached. If param
    //! historicalBlockServingLimit is set true, the function will response true
    //! if the limit for serving historical blocks has been reached.
    bool OutboundTargetReached(bool historicalBlockServingLimit);

    //! response the bytes left in the current max outbound cycle in case of no
    //! limit, it will always response 0
    uint64_t GetOutboundTargetBytesLeft();

    //! response the time in second left in the current max outbound cycle in
    //! case of no limit, it will always response 0
    uint64_t GetMaxOutboundTimeLeftInCycle();

    uint64_t GetTotalBytesRecv();
    uint64_t GetTotalBytesSent();

    void SetBestHeight(int height);
    int GetBestHeight() const;

    /** Get a unique deterministic randomizer. */
    CSipHasher GetDeterministicRandomizer(uint64_t id) const;

    unsigned int GetReceiveFloodSize() const;

    void WakeMessageHandler();

    /**
     * Attempts to obfuscate tx time through exponentially distributed emitting.
     * Works assuming that a single interval is used.
     * Variable intervals will result in privacy decrease.
     */
    int64_t PoissonNextSendInbound(int64_t now, int average_interval_ms);

    void SetAsmap(std::vector<bool> asmap) { addrman.m_asmap = std::move(asmap); }

private:
    struct ListenSocket {
    public:
        SOCKET socket;
        inline void AddSocketPermissionFlags(NetPermissionFlags &flags) const {
            NetPermissions::AddFlag(flags, m_permissions);
        }
        ListenSocket(SOCKET socket_, NetPermissionFlags permissions_)
            : socket(socket_), m_permissions(permissions_) {}

    private:
        NetPermissionFlags m_permissions;
    };

    bool BindListenPort(const CService &bindAddr, std::string &strError,
                        NetPermissionFlags permissions);
    bool Bind(const CService &addr, unsigned int flags,
              NetPermissionFlags permissions);
    bool InitBinds(const std::vector<CService> &binds, const std::vector<NetWhitebindPermissions> &whiteBinds,
                   const std::vector<CService> &onion_binds);
    void ThreadOpenAddedConnections();
    void AddOneShot(const std::string &strDest);
    void ProcessOneShot();
    void ThreadOpenConnections(std::vector<std::string> connect);
    void ThreadMessageHandler();
    void AcceptConnection(const ListenSocket &hListenSocket);
    // Disconnect and either discourage or ban the specified node. Whether or not to ban, and the ban time depends on
    // the given PeerRateLimitRule's configured ban time.
    void PeerRateLimitViolated(const NodeRef &pnode, const PeerRateLimitRule &rule);
    void DisconnectNodes();
    void NotifyNumConnectionsChanged();
    void InactivityCheck(const NodeRef &pnode) const;
    bool GenerateSelectSet(std::set<SOCKET> &recv_set, std::set<SOCKET> &send_set, std::set<SOCKET> &error_set);
    void SocketEvents(std::set<SOCKET> &recv_set, std::set<SOCKET> &send_set, std::set<SOCKET> &error_set);
    void SocketHandler();
    void ThreadSocketHandler();
    void ThreadDNSAddressSeed();

    uint64_t CalculateKeyedNetGroup(const CAddress &ad) const;

    NodeRef FindNode(const CNetAddr &ip) const;
    NodeRef FindNode(const CSubNet &subNet) const;
    NodeRef FindNode(const std::string &addrName) const;
    NodeRef FindNode(const CService &addr) const;

    bool AttemptToEvictConnection();
    NodeRef ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure, bool manual_connection);
    void AddWhitelistPermissionFlags(NetPermissionFlags &flags,
                                     const CNetAddr &addr) const;

    void NodeDeleter_(CNode *pnode); ///< deleter function for NodeRef std::shared_ptr. Don't call this directly.

    // Returns a lambda suitable for passing to CNode::Make's first arg. Used internally.
    inline auto MakeNodeDeleter() { return [this](CNode *p) { NodeDeleter_(p); }; }

    NodeId GetNewNodeId();

    size_t SocketSendData(const NodeRef &pnode) const;
    void DumpAddresses();

    // Network stats
    // Returns the violated rule if a peer rate limit rule was violated
    std::optional<PeerRateLimitRule> RecordBytesRecv(uint64_t bytes, const NodeRef &pnode);
    std::optional<PeerRateLimitRule> RecordBytesSent(uint64_t bytes, const NodeRef &pnode);

    // Whether the node should be passed out in ForEach* callbacks
    static bool NodeFullyConnected(const NodeRef &pnode);

    const Config *config;

    // Network usage totals
    RecursiveMutex cs_totalBytesRecv;
    RecursiveMutex cs_totalBytesSent;
    uint64_t nTotalBytesRecv GUARDED_BY(cs_totalBytesRecv);
    uint64_t nTotalBytesSent GUARDED_BY(cs_totalBytesSent);

    // outbound limit & stats
    uint64_t nMaxOutboundTotalBytesSentInCycle GUARDED_BY(cs_totalBytesSent);
    uint64_t nMaxOutboundCycleStartTime GUARDED_BY(cs_totalBytesSent);
    uint64_t nMaxOutboundLimit GUARDED_BY(cs_totalBytesSent);
    uint64_t nMaxOutboundTimeframe GUARDED_BY(cs_totalBytesSent);

    // P2P timeout in seconds
    int64_t m_peer_connect_timeout;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    std::vector<NetWhitelistPermissions> vWhitelistedRange;

    unsigned int nSendBufferMaxSize{0};
    unsigned int nReceiveFloodSize{0};

    std::vector<ListenSocket> vhListenSocket;
    std::atomic<bool> fNetworkActive{true};
    bool fAddressesInitialized{false};
    CAddrMan addrman;
    std::deque<std::string> vOneShots GUARDED_BY(cs_vOneShots);
    RecursiveMutex cs_vOneShots;
    std::vector<std::string> vAddedNodes GUARDED_BY(cs_vAddedNodes);
    RecursiveMutex cs_vAddedNodes;
    using NodeMap = std::map<NodeId, NodeRef>;
    NodeMap mNodes GUARDED_BY(cs_mNodes);
    std::list<NodeRef> vNodesDisconnected;
    mutable RecursiveMutex cs_mNodes;
    std::atomic<NodeId> nLastNodeId{0};
    unsigned int nPrevNodeCount{0};

    /**
     * Cache responses to addr requests to minimize privacy leak.
     * Attack example: scraping addrs in real-time may allow an attacker
     * to infer new connections of the victim by detecting new records
     * with fresh timestamps (per self-announcement).
     */
    struct CachedAddrResponse {
        std::vector<CAddress> m_addrs_response_cache;
        std::chrono::microseconds m_cache_entry_expiration{0};
    };

    RecursiveMutex cs_addr_response_caches;
    /**
     * Addr responses stored in different caches
     * per (network, local socket) prevent cross-network node identification.
     * If a node for example is multi-homed under Tor and IPv6,
     * a single cache (or no cache at all) would let an attacker
     * to easily detect that it is the same node by comparing responses.
     * Indexing by local socket prevents leakage when a node has multiple
     * listening addresses on the same network.
     *
     * The used memory equals to 1000 CAddress records (or around 40 bytes) per
     * distinct Network (up to 5) we have/had an inbound peer from,
     * resulting in at most ~196 KB. Every separate local socket may
     * add up to ~196 KB extra.
     */
    std::map<uint64_t, CachedAddrResponse> m_addr_response_caches GUARDED_BY(cs_addr_response_caches);

    /** Services this instance offers */
    ServiceFlags nLocalServices;

    std::unique_ptr<CSemaphore> semOutbound;
    std::unique_ptr<CSemaphore> semAddnode;
    int nMaxConnections;
    int nMaxOutbound;
    int nMaxAddnode;
    int nMaxFeeler;
    bool m_use_addrman_outgoing;
    std::atomic<int> nBestHeight;
    CClientUIInterface *clientInterface;
    NetEventsInterface *m_msgproc;
    BanMan *m_banman;

    /** SipHasher seeds for deterministic randomness */
    const uint64_t nSeed0, nSeed1;

    /** flag for waking the message processor. */
    bool fMsgProcWake;

    std::condition_variable condMsgProc;
    Mutex mutexMsgProc;
    std::atomic<bool> flagInterruptMsgProc{false};

    CThreadInterrupt interruptNet;

    std::thread threadDNSAddressSeed;
    std::thread threadSocketHandler;
    std::thread threadOpenAddedConnections;
    std::thread threadOpenConnections;
    std::thread threadMessageHandler;

    /**
     * Flag for deciding to connect to an extra outbound peer, in excess of
     * nMaxOutbound.
     * This takes the place of a feeler connection.
     */
    std::atomic_bool m_try_another_outbound_peer;

    std::atomic<int64_t> m_next_send_inv_to_incoming{0};

    std::shared_ptr<std::atomic_bool> deleted; ///< Used to suppress further scheduler tasks if this instance is gone.

    friend struct CConnmanTest;
};

extern std::unique_ptr<CConnman> g_connman;
extern std::unique_ptr<BanMan> g_banman;
void Discover();
unsigned short GetListenPort();

/**
 * Interface for message handling
 */
class NetEventsInterface {
public:
    virtual bool ProcessMessages(const Config &config, NodeRef pnode, std::atomic<bool> &interrupt) = 0;
    virtual bool SendMessages(const Config &config, NodeRef pnode, std::atomic<bool> &interrupt) = 0;
    virtual void InitializeNode(const Config &config, NodeRef pnode) = 0;
    virtual void FinalizeNode(const Config &config, NodeId id, bool &update_connection_time) = 0;
    virtual bool IsPerPeerRateLimitingTemporarilySuppressed() const = 0;

protected:
    /**
     * Protected destructor so that instances can only be deleted by derived
     * classes. If that restriction is no longer desired, this should be made
     * public and virtual.
     */
    ~NetEventsInterface() = default;
};

enum {
    // unknown
    LOCAL_NONE,
    // address a local interface listens on
    LOCAL_IF,
    // address explicit bound to
    LOCAL_BIND,
    // address reported by UPnP or NAT-PMP
    LOCAL_MAPPED,
    // address explicitly specified (-externalip=)
    LOCAL_MANUAL,

    LOCAL_MAX
};

bool IsPeerAddrLocalGood(const NodeRef &pnode);
void AdvertiseLocal(const NodeRef &pnode);

/**
 * Mark a network as reachable or unreachable (no automatic connects to it)
 * @note Networks are reachable by default
 */
void SetReachable(enum Network net, bool reachable);
/** @returns true if the network is reachable, false otherwise */
bool IsReachable(enum Network net);
/** @returns true if the address is in a reachable network, false otherwise */
bool IsReachable(const CNetAddr &addr);

bool AddLocal(const CService &addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr &addr, int nScore = LOCAL_NONE);
void RemoveLocal(const CService &addr);
bool SeenLocal(const CService &addr);
bool IsLocal(const CService &addr);
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = nullptr);
CAddress GetLocalAddress(const CNetAddr *paddrPeer,
                         ServiceFlags nLocalServices);

extern bool fDiscover;
extern bool fListen;
extern bool g_relay_txes;

struct LocalServiceInfo {
    int nScore;
    int nPort;
};

extern RecursiveMutex cs_mapLocalHost;
extern std::map<CNetAddr, LocalServiceInfo>
    mapLocalHost GUARDED_BY(cs_mapLocalHost);

// Message type, total bytes
typedef std::map<std::string, uint64_t> mapMsgTypeSize;

/**
 * POD that contains various stats about a node.
 * Usually constructed from CConman::GetNodeStats. Stats are filled from the
 * node using CNode::copyStats.
 */
struct CNodeStats {
    NodeId nodeid;
    ServiceFlags nServices;
    bool fRelayTxes;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    // We requested high bandwidth connection to peer
    bool m_bip152_highbandwidth_to{};
    // Peer requested high bandwidth connection
    bool m_bip152_highbandwidth_from{};
    bool m_manual_connection;
    int nStartingHeight;
    uint64_t nSendBytes;
    mapMsgTypeSize mapSendBytesPerMsgType;
    uint64_t nRecvBytes;
    mapMsgTypeSize mapRecvBytesPerMsgType;
    NetPermissionFlags m_permissionFlags;
    bool m_legacyWhitelisted;
    double dPingTime;
    double dPingWait;
    double dMinPing;
    Amount minFeeFilter;
    // Our address, as reported by the peer
    std::string addrLocal;
    // Address of this peer
    CAddress addr;
    // Bind address of our side of the connection
    CAddress addrBind;
    uint32_t m_mapped_as;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
};

class CNetMessage {
private:
    mutable CHash256 hasher;
    mutable uint256 data_hash;

public:
    // Parsing header (false) or data (true)
    bool in_data;

    // Partially received header.
    CDataStream hdrbuf;
    // Complete header.
    CMessageHeader hdr;
    uint32_t nHdrPos;

    // Received message data.
    CDataStream vRecv;
    uint32_t nDataPos;

    // Time (in microseconds) of message receipt.
    int64_t nTime;

    CNetMessage(const CMessageHeader::MessageMagic &pchMessageStartIn,
                int nTypeIn, int nVersionIn)
        : hdrbuf(nTypeIn, nVersionIn), hdr(pchMessageStartIn),
          vRecv(nTypeIn, nVersionIn) {
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const {
        if (!in_data) {
            return false;
        }

        return (hdr.nMessageSize == nDataPos);
    }

    const uint256 &GetMessageHash() const;

    void SetVersion(int nVersionIn) {
        hdrbuf.SetVersion(nVersionIn);
        vRecv.SetVersion(nVersionIn);
    }

    int readHeader(const Config &config, const char *pch, uint32_t nBytes);
    int readData(const char *pch, uint32_t nBytes);
};

/** Information about a peer */
class CNode : public std::enable_shared_from_this<CNode> {
    friend class CConnman;

public:
    // socket
    std::atomic<ServiceFlags> nServices{NODE_NONE};
    SOCKET hSocket GUARDED_BY(cs_hSocket);
    // Total size of all vSendMsg entries.
    size_t nSendSize{0};
    // Offset inside the first vSendMsg already sent.
    size_t nSendOffset{0};
    uint64_t nSendBytes GUARDED_BY(cs_vSend){0};
    std::deque<std::vector<uint8_t>> vSendMsg GUARDED_BY(cs_vSend);
    mutable RecursiveMutex cs_vSend;
    RecursiveMutex cs_hSocket;
    RecursiveMutex cs_vRecv;

    RecursiveMutex cs_vProcessMsg;
    std::list<CNetMessage> vProcessMsg GUARDED_BY(cs_vProcessMsg);
    size_t nProcessQueueSize{0};

    RecursiveMutex cs_sendProcessing;

    std::deque<CInv> vRecvGetData;
    uint64_t nRecvBytes GUARDED_BY(cs_vRecv){0};
    std::atomic<int> nRecvVersion{INIT_PROTO_VERSION};

    std::atomic<int64_t> nLastSend{0};
    std::atomic<int64_t> nLastRecv{0};
    const int64_t nTimeConnected;
    std::atomic<int64_t> nTimeOffset{0};
    // Address of this peer
    const CAddress addr;
    // Bind address of our side of the connection
    const CAddress addrBind;
    std::atomic<int> nVersion{0};
    RecursiveMutex cs_SubVer;
    /**
     * cleanSubVer is a sanitized string of the user agent byte array we read
     * from the wire. This cleaned string can safely be logged or displayed.
     */
    std::string cleanSubVer GUARDED_BY(cs_SubVer){};
    // This peer is preferred for eviction.
    bool m_prefer_evict{false};
    bool HasPermission(NetPermissionFlags permission) const {
        return NetPermissions::HasFlag(m_permissionFlags, permission);
    }
    // This boolean is unusued in actual processing, only present for backward
    // compatibility at RPC/QT level
    bool m_legacyWhitelisted{false};
    // If true this node is being used as a short lived feeler.
    bool fFeeler{false};
    bool fOneShot{false};
    bool m_manual_connection{false};
    // set by version message
    bool fClient{false};
    // after BIP159, set by version message
    bool m_limited_node{false};
    /**
     * Whether the peer has signaled support for receiving ADDRv2 (BIP155)
     * messages, implying a preference to receive ADDRv2 instead of ADDR ones.
     */
    std::atomic_bool m_wants_addrv2{false};

    /**
     *  Number of addresses that can be processed from this peer. Start at 1 to
     *  permit self-announcement. Owned-by: msghand thread, hence no locks.
     */
    double m_addr_token_bucket{1.0};
    /** When m_addr_token_bucket was last updated. Owned-by: msghand thread. */
    std::chrono::microseconds m_addr_token_timestamp{GetTime<std::chrono::microseconds>()};
    /** Total number of addresses that were dropped due to rate limiting. */
    std::atomic<uint64_t> m_addr_rate_limited{0};
    /** Total number of addresses that were processed (excludes rate-limited ones). */
    std::atomic<uint64_t> m_addr_processed{0};

    const bool fInbound;
    std::atomic_bool fSuccessfullyConnected{false};
    std::atomic_bool fDisconnect{false};
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version
    // message.
    // b) the peer may tell us in its version message that we should not relay
    // tx invs unless it loads a bloom filter.
    bool fRelayTxes GUARDED_BY(cs_filter){false};
    bool fSentAddr{false};
    CSemaphoreGrant grantOutbound;
    mutable RecursiveMutex cs_filter;
    std::unique_ptr<CBloomFilter> pfilter PT_GUARDED_BY(cs_filter);

    const uint64_t nKeyedNetGroup;
    std::atomic_bool fPauseRecv{false};
    std::atomic_bool fPauseSend{false};

    // We selected peer as (compact blocks) high-bandwidth peer (BIP152)
    std::atomic_bool m_bip152_highbandwidth_to{false};
    // Peer selected us as (compact blocks) high-bandwidth peer (BIP152)
    std::atomic_bool m_bip152_highbandwidth_from{false};

    /* ExtVersion support */
    Mutex cs_extversion;
    //! Stores the peer's extversion message. This member is only valid if extversionEnabled is true.
    extversion::Message extversion GUARDED_BY(cs_extversion);
    //! Set to true if peer supports extversion and has a valid extversion::Message
    std::atomic_bool extversionEnabled{false};
    //! Set to true if extversion is the next message expected
    std::atomic_bool extversionExpected{false};
    //! Optional per-peer rate limits. May be nullptr
    std::unique_ptr<ClientUsageTracker> m_rateTracker;

protected:
    mapMsgTypeSize mapSendBytesPerMsgType;
    mapMsgTypeSize mapRecvBytesPerMsgType GUARDED_BY(cs_vRecv);

public:
    BlockHash hashContinue;
    std::atomic<int> nStartingHeight{-1};

    // flood relay
    std::vector<CAddress> vAddrToSend;
    CRollingBloomFilter addrKnown;
    bool fGetAddr{false};
    std::chrono::microseconds m_next_addr_send GUARDED_BY(cs_sendProcessing){0};
    std::chrono::microseconds m_next_local_addr_send GUARDED_BY(cs_sendProcessing){0};

    // Inventory based relay.
    CRollingBloomFilter filterInventoryKnown GUARDED_BY(cs_inventory);
    // Set of transaction ids we still have to announce. They are sorted by the
    // mempool acceptance order (topological ordering).
    std::set<std::pair<uint64_t /* EntryId */, TxId>> setInventoryTxToSendTopoSorted GUARDED_BY(cs_inventory);
    // List of block ids we still have announce. There is no final sorting
    // before sending, as they are always sent immediately and in the order
    // requested.
    std::vector<BlockHash> vInventoryBlockToSend GUARDED_BY(cs_inventory);
    std::deque<CInv> vInventoryToSend GUARDED_BY(cs_inventory);
    RecursiveMutex cs_inventory;
    std::chrono::microseconds nNextInvSend{0};
    // Used for headers announcements - unfiltered blocks to relay.
    std::vector<BlockHash> vBlockHashesToAnnounce GUARDED_BY(cs_inventory);
    // Used for BIP35 mempool sending.
    bool fSendMempool GUARDED_BY(cs_inventory){false};

    // Last time a "MEMPOOL" request was serviced.
    std::atomic<int64_t> timeLastMempoolReq{0};

    // Block and TXN accept times
    std::atomic<int64_t> nLastBlockTime{0};
    std::atomic<int64_t> nLastTXTime{0};

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    std::atomic<uint64_t> nPingNonceSent{0};
    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    std::atomic<int64_t> nPingUsecStart{0};
    // Last measured round-trip time.
    std::atomic<int64_t> nPingUsecTime{0};
    // Best measured round-trip time.
    std::atomic<int64_t> nMinPingUsecTime{std::numeric_limits<int64_t>::max()};
    // Whether a ping is requested.
    std::atomic<bool> fPingQueued{false};
    // Minimum fee rate with which to filter inv's to this node
    Amount minFeeFilter GUARDED_BY(cs_feeFilter){Amount::zero()};
    RecursiveMutex cs_feeFilter;
    Amount lastSentFeeFilter{Amount::zero()};
    int64_t nextSendTimeFeeFilter{0};

private:
    // Never use this c'tor. Always use `Make()`
    CNode(NodeId id, ServiceFlags nLocalServicesIn, int nMyStartingHeightIn,
          SOCKET hSocketIn, const CAddress &addrIn, uint64_t nKeyedNetGroupIn,
          uint64_t nLocalHostNonceIn, const CAddress &addrBindIn,
          const std::string &addrNameIn = "", bool fInboundIn = false);

public:
    [[nodiscard]]
    static NodeRef Make(std::function<void(CNode *)> deleter /* may be null to use default delete */,
                        NodeId id, ServiceFlags nLocalServicesIn, int nMyStartingHeightIn,
                        SOCKET hSocketIn, const CAddress &addrIn, uint64_t nKeyedNetGroupIn,
                        uint64_t nLocalHostNonceIn, const CAddress &addrBindIn,
                        const std::string &addrNameIn = "", bool fInboundIn = false);

    ~CNode();
    CNode(const CNode &) = delete;
    CNode &operator=(const CNode &) = delete;

private:
    const NodeId id;
    const uint64_t nLocalHostNonce;
    // Services offered to this peer
    const ServiceFlags nLocalServices;
    const int nMyStartingHeight;
    int nSendVersion{0};
    NetPermissionFlags m_permissionFlags{PF_NONE};
    // Used only by SocketHandler thread
    std::list<CNetMessage> vRecvMsg;

    mutable RecursiveMutex cs_addrName;
    std::string addrName GUARDED_BY(cs_addrName);

    // Our address, as reported by the peer
    CService addrLocal GUARDED_BY(cs_addrLocal);
    mutable RecursiveMutex cs_addrLocal;

public:
    NodeId GetId() const { return id; }

    uint64_t GetLocalNonce() const { return nLocalHostNonce; }

    int GetMyStartingHeight() const { return nMyStartingHeight; }

    bool ReceiveMsgBytes(const Config &config, const char *pch, uint32_t nBytes,
                         bool &complete);

    void SetRecvVersion(int nVersionIn) { nRecvVersion = nVersionIn; }
    int GetRecvVersion() const { return nRecvVersion; }
    void SetSendVersion(int nVersionIn);
    int GetSendVersion() const;

    CService GetAddrLocal() const;
    //! May not be called more than once
    void SetAddrLocal(const CService &addrLocalIn);

    void AddAddressKnown(const CAddress &_addr) {
        addrKnown.insert(_addr.GetKey());
    }

    void PushAddress(const CAddress &_addr, FastRandomContext &insecure_rand) {
        // Whether the peer supports the address in `_addr`. For example,
        // nodes that do not implement BIP155 cannot receive Tor v3 addresses
        // because they require ADDRv2 (BIP155) encoding.
        const bool addr_format_supported = m_wants_addrv2 || _addr.IsAddrV1Compatible();

        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        if (_addr.IsValid() && !addrKnown.contains(_addr.GetKey()) && addr_format_supported) {
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND) {
                vAddrToSend[insecure_rand.randrange(vAddrToSend.size())] =
                    _addr;
            } else {
                vAddrToSend.push_back(_addr);
            }
        }
    }

    void AddInventoryKnown(const CInv &inv) {
        LOCK(cs_inventory);
        filterInventoryKnown.insert(inv.hash);
    }

    void PushInventory(const CInv &inv, uint64_t entryId = 0 /* topo sort, MSG_TX only */) {
        LOCK(cs_inventory);
        if (inv.type == MSG_TX) {
            // inv.hash is a TxId
            if (!filterInventoryKnown.contains(inv.hash)) {
                setInventoryTxToSendTopoSorted.emplace(entryId, inv.hash);
            }
        } else if (inv.type == MSG_BLOCK) {
            // inv.hash is a BlockHash
            vInventoryBlockToSend.emplace_back(inv.hash);
        } else if (inv.type == MSG_DOUBLESPENDPROOF) {
            // inv.hash is a DspId
            if (!filterInventoryKnown.contains(inv.hash)) {
                vInventoryToSend.push_back(inv);
            }
        } else if (inv.type) {
            vInventoryToSend.push_back(inv);
        }
    }

    void PushBlockHash(const BlockHash &hash) {
        LOCK(cs_inventory);
        vBlockHashesToAnnounce.push_back(hash);
    }

    void CloseSocketDisconnect();

    void copyStats(CNodeStats &stats, const std::vector<bool> &m_asmap);

    ServiceFlags GetLocalServices() const { return nLocalServices; }

    std::string GetAddrName() const;
    //! Sets the addrName only if it was not previously set
    void MaybeSetAddrName(const std::string &addrNameIn);

    void ReadConfigFromExtversion() EXCLUSIVE_LOCKS_REQUIRED(cs_extversion);

    //! Returns the number of bytes enqeueud (and eventually sent) for a particular command
    uint64_t GetBytesSentForMsgType(const std::string &msg_type) const;
};

/**
 * Return a timestamp in the future (in microseconds) for exponentially
 * distributed events.
 */
int64_t PoissonNextSend(int64_t now, int average_interval_ms);

/** Wrapper to return mockable type */
inline std::chrono::microseconds PoissonNextSend(std::chrono::microseconds now, std::chrono::milliseconds average_interval_ms) {
    return std::chrono::microseconds{PoissonNextSend(now.count(), average_interval_ms.count())};
}

std::string getSubVersionEB(uint64_t MaxBlockSize);
std::string userAgent(const Config &config);
