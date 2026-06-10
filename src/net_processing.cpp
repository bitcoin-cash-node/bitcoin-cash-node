// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (c) 2020-2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing.h>
#include <net_processing_internal.h>

#include <addrman.h>
#include <arith_uint256.h>
#include <banman.h>
#include <blockencodings.h>
#include <blockvalidity.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <dsproof/dsproof.h>
#include <dsproof/storage.h>
#include <extversion.h>
#include <hash.h>
#include <merkleblock.h>
#include <net.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <scheduler.h>
#include <streams.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>
#include <validationinterface.h>

#include <chrono>
#include <cmath>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>

#if defined(NDEBUG)
#error "Bitcoin cannot be compiled without assertions."
#endif

/**
 * Headers download timeout expressed in microseconds.
 * Timeout = base + per_header * (expected number of headers)
 */
// 15 minutes
static constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE = 15 * 60 * 1000000;
// 1ms/header
static constexpr int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER = 1000;
/**
 * Protect at least this many outbound peers from disconnection due to
 * slow/behind headers chain.
 */
static constexpr int32_t MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4;
/**
 * Timeout for (unprotected) outbound peers to sync to our chainwork, in
 * seconds.
 */
// 20 minutes
static constexpr int64_t CHAIN_SYNC_TIMEOUT = 20 * 60;
/** How frequently to check for stale tips, in seconds */
// 10 minutes
static constexpr int64_t STALE_CHECK_INTERVAL = 10 * 60;
/**
 * How frequently to check for extra outbound peers and disconnect, in seconds.
 */
static constexpr int64_t EXTRA_PEER_CHECK_INTERVAL = 45;
/**
 * Minimum time an outbound-peer-eviction candidate must be connected for, in
 * order to evict, in seconds.
 */
static constexpr int64_t MINIMUM_CONNECT_TIME = 30;
/** SHA256("main address relay")[0:8] */
static constexpr uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL;
/// Age after which a stale block will no longer be served if requested as
/// protection against fingerprinting. Set to one month, denominated in seconds.
static constexpr int STALE_RELAY_AGE_LIMIT = 30 * 24 * 60 * 60;
/// Age after which a block is considered historical for purposes of rate
/// limiting block relay. Set to one week, denominated in seconds.
static constexpr int HISTORICAL_BLOCK_AGE = 7 * 24 * 60 * 60;
/** Maximum number of in-flight transaction requests from a peer. It is not a hard limit, but the threshold at which
 *  point the OVERLOADED_PEER_TX_DELAY kicks in. */
static constexpr int32_t MAX_PEER_TX_REQUEST_IN_FLIGHT = 100;
/** Maximum number of announced transactions from a peer */
static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS = 2 * MAX_INV_SZ;
/** How long to delay requesting transactions from non-preferred peers */
static constexpr auto NONPREF_PEER_TX_DELAY = std::chrono::seconds{2};
/** How long to delay requesting transactions from overloaded peers (see MAX_PEER_TX_REQUEST_IN_FLIGHT). */
static constexpr auto OVERLOADED_PEER_TX_DELAY = std::chrono::seconds{2};
/** How long to wait before downloading a transaction from an additional peer. */
static constexpr auto GETDATA_TX_INTERVAL = std::chrono::seconds{60}; // 1 minute
/**
 * Limit to avoid sending big packets. Not used in processing incoming GETDATA
 * for compatibility.
 */
static const unsigned int MAX_GETDATA_SZ = 1000;

/// How many non standard orphan do we consider from a node before ignoring it.
static constexpr uint32_t MAX_NON_STANDARD_ORPHAN_PER_NODE = 5;

/**
 * Average delay between local address broadcasts
 */
inline constexpr std::chrono::hours AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL{24};
/**
 * Average delay between peer address broadcasts
 */
inline constexpr std::chrono::seconds AVG_ADDRESS_BROADCAST_INTERVAL{30};
/**
 * Average delay between feefilter broadcasts in milliseconds.
 */
static constexpr unsigned int AVG_FEEFILTER_BROADCAST_INTERVAL = 10 * 60 * 1000;
/**
 * Maximum feefilter broadcast delay after significant change.
 */
static constexpr unsigned int MAX_FEEFILTER_CHANGE_DELAY = 5 * 60;

/**
 * The maximum percentage of addresses from our addrman to return in response to a getaddr message.
 */
static constexpr size_t MAX_PCT_ADDR_TO_SEND = 23;

// Internal stuff
namespace {
/** Number of nodes with fSyncStarted. */
int nSyncStarted GUARDED_BY(cs_main) = 0;

/**
 * Sources of received blocks, saved to be able to send them reject messages or
 * discourage them when processing happens afterwards.
 * Set mapBlockSource[hash].second to false if the node should not be punished
 * if the block is invalid.
 */
std::map<uint256, std::pair<NodeId, bool>> mapBlockSource GUARDED_BY(cs_main);

/**
 * Blocks that are in flight, and that are in the queue to be downloaded.
 */
struct QueuedBlock {
    uint256 hash;
    //! Optional.
    const CBlockIndex *pindex;
    //! Whether this block has validated headers at the time of request.
    bool fValidatedHeaders;
    //! Optional, used for CMPCTBLOCK downloads
    std::unique_ptr<PartiallyDownloadedBlock> partialBlock;
};

using BlockDownloadMap = std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>>;
BlockDownloadMap mapBlocksInFlight GUARDED_BY(cs_main);

/** Stack of nodes which we have set to announce using compact blocks */
std::list<NodeId> lNodesAnnouncingHeaderAndIDs GUARDED_BY(cs_main);

/** Number of preferable block download peers. */
int nPreferredDownload GUARDED_BY(cs_main) = 0;

/** Number of peers from which we're downloading blocks. */
int nPeersWithValidatedDownloads GUARDED_BY(cs_main) = 0;

/** Number of outbound peers with m_chain_sync.m_protect. */
int g_outbound_peers_with_protect_from_disconnect GUARDED_BY(cs_main) = 0;

/** When our tip was last updated. */
std::atomic<int64_t> g_last_tip_update(0);

/** Relay map. */
typedef std::map<uint256, CTransactionRef> MapRelay;
MapRelay mapRelay GUARDED_BY(cs_main);
/**
 * Expiration-time ordered list of (expire time, relay map entry) pairs,
 * protected by cs_main).
 */
std::deque<std::pair<int64_t, MapRelay::iterator>>
    vRelayExpiration GUARDED_BY(cs_main);

// Used only to inform the wallet of when we last received a block
std::atomic<int64_t> nTimeBestReceived(0);

bool IsBlockRequested(const uint256& hash, BlockDownloadMap::iterator *pit = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    auto it = mapBlocksInFlight.lower_bound(hash);
    if (pit) *pit = it;
    return it != mapBlocksInFlight.end() && it->first == hash;
}

[[nodiscard]]
bool IsBlockRequestedFromOutbound(CConnman *connman, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; ++range.first) {
        const auto & [nodeid, block_it] = range.first->second;
        NodeRef peer;
        connman->ForNode(nodeid, [&peer](const NodeRef &n){ peer = n; return true; });
        if (peer && !peer->fInbound) {
            return true;
        }
    }

    return false;
}

// Data returned from GetNodeBlockRequestStatus()
struct NodeBlockRequestStatus {
    //! Number of requests in flight from all nodes for this block hash
    size_t already_in_flight{};
    //! If true, this is the first request for this block
    bool first_in_flight{};
    //! Will be non-nullptr only if the block in question was requested from this peer.
    //! NB: Even if this is not null, member `requested_block_from_this_peer->partialBlock` may still be null, however.
    QueuedBlock *requested_block_from_this_peer = nullptr;
};

[[nodiscard]]
NodeBlockRequestStatus GetNodeBlockRequestStatus(NodeId id, const BlockHash &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    NodeBlockRequestStatus ret;
    auto range_flight = mapBlocksInFlight.equal_range(hash);
    ret.already_in_flight = std::distance(range_flight.first, range_flight.second);

    // Multimap ensures ordering of outstanding requests. It's either empty or first in line.
    ret.first_in_flight = ret.already_in_flight == 0 || (range_flight.first->second.first == id);

    while (range_flight.first != range_flight.second) {
        if (range_flight.first->second.first == id) {
            ret.requested_block_from_this_peer = &*range_flight.first->second.second;
            break;
        }
        ++range_flight.first;
    }

    return ret;
}

struct CBlockReject {
    uint8_t chRejectCode;
    std::string strRejectReason;
    uint256 hashBlock;
};

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
    //! The peer's address
    const CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and marked as discouraged (unless whitelisted with noban).
    bool fShouldDiscourage;
    //! String name of this peer (debugging/logging purposes).
    const std::string name;
    //! List of asynchronously-determined block rejections to notify this peer
    //! about.
    std::vector<CBlockReject> rejects;
    //! The best known block we know this peer has announced.
    const CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    BlockHash hashLastUnknownBlock;
    //! The last full block we both have.
    const CBlockIndex *pindexLastCommonBlock;
    //! The best header we have sent our peer.
    const CBlockIndex *pindexBestHeaderSent;
    //! Length of current-streak of unconnecting headers announcements
    int nUnconnectingHeaders;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! When to potentially disconnect peer for stalling headers download
    int64_t nHeadersSyncTimeout;
    //! Since when we're stalling block download progress (in microseconds), or
    //! 0.
    int64_t nStallingSince;
    std::list<QueuedBlock> vBlocksInFlight;
    //! When the first entry in vBlocksInFlight started downloading. Don't care
    //! when vBlocksInFlight is empty.
    int64_t nDownloadingSince;
    int nBlocksInFlightValidHeaders;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for block
    //! announcements.
    bool fPreferHeaders;
    //! Whether this peer wants invs or cmpctblocks (when possible) for block
    //! announcements.
    bool fPreferHeaderAndIDs;
    /**
     * Whether this peer will send us cmpctblocks if we request them.
     * This is not used to gate request logic, as we really only care about
     * fSupportsDesiredCmpctVersion, but is used as a flag to "lock in" the
     * version of compact blocks we send.
     */
    bool fProvidesHeaderAndIDs;
    /**
     * If we've announced NODE_WITNESS to this peer: whether the peer sends
     * witnesses in cmpctblocks/blocktxns, otherwise: whether this peer sends
     * non-witnesses in cmpctblocks/blocktxns.
     */
    bool fSupportsDesiredCmpctVersion;

    /**
     * State used to enforce CHAIN_SYNC_TIMEOUT
     * Only in effect for outbound, non-manual connections,
     * with m_protect == false
     * Algorithm: if a peer's best known block has less work than our tip, set a
     * timeout CHAIN_SYNC_TIMEOUT seconds in the future:
     *   - If at timeout their best known block now has more work than our tip
     * when the timeout was set, then either reset the timeout or clear it
     * (after comparing against our current tip's work)
     *   - If at timeout their best known block still has less work than our tip
     * did when the timeout was set, then send a getheaders message, and set a
     * shorter timeout, HEADERS_RESPONSE_TIME seconds in future. If their best
     * known block is still behind when that new timeout is reached, disconnect.
     */
    struct ChainSyncTimeoutState {
        //! A timeout used for checking whether our peer has sufficiently
        //! synced.
        int64_t m_timeout;
        //! A header with the work we require on our peer's chain.
        const CBlockIndex *m_work_header;
        //! After timeout is reached, set to true after sending getheaders.
        bool m_sent_getheaders;
        //! Whether this peer is protected from disconnection due to a bad/slow
        //! chain.
        bool m_protect;
    };

    ChainSyncTimeoutState m_chain_sync;

    //! Time of last new block announcement
    int64_t m_last_block_announcement;

    CNodeState(const CAddress &addrIn, const std::string &addrNameIn)
        : address(addrIn), name(addrNameIn) {
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldDiscourage = false;
        pindexBestKnownBlock = nullptr;
        hashLastUnknownBlock = BlockHash();
        pindexLastCommonBlock = nullptr;
        pindexBestHeaderSent = nullptr;
        nUnconnectingHeaders = 0;
        fSyncStarted = false;
        nHeadersSyncTimeout = 0;
        nStallingSince = 0;
        nDownloadingSince = 0;
        nBlocksInFlightValidHeaders = 0;
        fPreferredDownload = false;
        fPreferHeaders = false;
        fPreferHeaderAndIDs = false;
        fProvidesHeaderAndIDs = false;
        fSupportsDesiredCmpctVersion = false;
        m_chain_sync = {0, nullptr, false, false};
        m_last_block_announcement = 0;
    }
};

/** Map maintaining per-node state. */
static std::map<NodeId, CNodeState> mapNodeState GUARDED_BY(cs_main);

static CNodeState *State(NodeId pnode) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    std::map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end()) {
        return nullptr;
    }

    return &it->second;
}

static void UpdatePreferredDownload(const NodeRef &node, CNodeState *state)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload =
        (!node->fInbound || node->HasPermission(PF_NOBAN)) && !node->fOneShot &&
        !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

// Returns a bool indicating whether we requested this block.
// Also used if a block was /not/ received and timed out or started with another
// peer.
static bool MarkBlockAsReceived(const uint256 &hash, std::optional<NodeId> from_peer)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    auto range = mapBlocksInFlight.equal_range(hash);
    if (range.first == range.second) {
        // Block was not requested from any peer
        return false;
    }

    // We should not have requested too many of this block
    //Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    bool ret = false;
    while (range.first != range.second) {
        const auto &itInFlight = range.first;
        const auto & [node_id, list_it] = itInFlight->second;

        if (from_peer && *from_peer != node_id) {
            ++range.first;
            continue;
        }
        ret = true;

        CNodeState *state = State(node_id);
        assert(state != nullptr);

        state->nBlocksInFlightValidHeaders -= list_it->fValidatedHeaders;

        if (state->nBlocksInFlightValidHeaders == 0 && list_it->fValidatedHeaders) {
            // Last validated block on the queue for this peer was received.
            --nPeersWithValidatedDownloads;
        }

        if (state->vBlocksInFlight.begin() == list_it) {
            // First block on the queue was received, update the start download time for the next one
            state->nDownloadingSince = std::max(state->nDownloadingSince, GetTimeMicros());
        }
        state->vBlocksInFlight.erase(list_it);

        state->nStallingSince = 0;

        range.first = mapBlocksInFlight.erase(range.first);
    }

    return ret;
}

// returns false, still setting pit, if the block was already in flight from the
// same peer
// pit will only be valid as long as the same cs_main lock is being held.
static bool
MarkBlockAsInFlight(const Config &config, NodeId nodeid, const uint256 &hash,
                    const Consensus::Params &consensusParams [[maybe_unused]],
                    const CBlockIndex *pindex = nullptr,
                    std::list<QueuedBlock>::iterator **pit = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    // Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    // Short-circuit most stuff in case it is from the same node.
    auto hint = mapBlocksInFlight.end();
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; ++range.first) {
        if (range.first->second.first == nodeid) {
            if (pit) {
                *pit = &range.first->second.second;
            }
            return false;
        }
        hint = range.first;
    }

    // Make sure it's not being fetched already from same peer.
    MarkBlockAsReceived(hash, nodeid);

    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(
        state->vBlocksInFlight.end(),
        {hash, pindex, pindex != nullptr,
         std::unique_ptr<PartiallyDownloadedBlock>(
             pit ? new PartiallyDownloadedBlock(config, &g_mempool)
                 : nullptr)});
    state->nBlocksInFlightValidHeaders += it->fValidatedHeaders;
    if (state->vBlocksInFlight.size() == 1) {
        // We're starting a block download (batch) from this peer.
        state->nDownloadingSince = GetTimeMicros();
    }

    if (state->nBlocksInFlightValidHeaders == 1 && pindex != nullptr) {
        ++nPeersWithValidatedDownloads;
    }

    auto itInFlight = mapBlocksInFlight.emplace_hint(hint, hash, std::make_pair(nodeid, it));

    if (pit) {
        *pit = &itInFlight->second.second;
    }

    return true;
}

/** Check whether the last unknown block a peer advertised is not yet known. */
static void ProcessBlockAvailability(NodeId nodeid)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    if (!state->hashLastUnknownBlock.IsNull()) {
        const CBlockIndex *pindex =
            LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->nChainWork > 0) {
            if (state->pindexBestKnownBlock == nullptr ||
                pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
static void UpdateBlockAvailability(NodeId nodeid, const BlockHash &hash)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    ProcessBlockAvailability(nodeid);

    const CBlockIndex *pindex = LookupBlockIndex(hash);
    if (pindex && pindex->nChainWork > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == nullptr ||
            pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork) {
            state->pindexBestKnownBlock = pindex;
        }
    } else {
        // An unknown block was announced; just assume that the latest one is
        // the best one.
        state->hashLastUnknownBlock = hash;
    }
}

/**
 * When a peer sends us a valid block, instruct it to announce blocks to us
 * using CMPCTBLOCK if possible by adding its nodeid to the end of
 * lNodesAnnouncingHeaderAndIDs, and keeping that list under a certain size by
 * removing the first element if necessary.
 */
static void MaybeSetPeerAsAnnouncingHeaderAndIDs(NodeId nodeid,
                                                 CConnman *connman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    CNodeState *nodestate = State(nodeid);
    if (!nodestate) {
        LogPrint(BCLog::NET, "node state unavailable: peer=%d\n", nodeid);
        return;
    }
    if (!nodestate->fProvidesHeaderAndIDs) {
        return;
    }
    for (std::list<NodeId>::iterator it = lNodesAnnouncingHeaderAndIDs.begin();
         it != lNodesAnnouncingHeaderAndIDs.end(); it++) {
        if (*it == nodeid) {
            lNodesAnnouncingHeaderAndIDs.erase(it);
            lNodesAnnouncingHeaderAndIDs.push_back(nodeid);
            return;
        }
    }
    connman->ForNode(nodeid, [&connman](NodeRef pfrom) {
        AssertLockHeld(cs_main);
        static constexpr uint64_t nCMPCTBLOCKVersion = 1;
        if (lNodesAnnouncingHeaderAndIDs.size() >= 3) {
            // As per BIP152, we only get 3 of our peers to announce
            // blocks using compact encodings.
            connman->ForNode(
                lNodesAnnouncingHeaderAndIDs.front(),
                [&connman](NodeRef pnodeStop) {
                    AssertLockHeld(cs_main);
                    connman->PushMessage(
                        pnodeStop, CNetMsgMaker(pnodeStop->GetSendVersion())
                                       .Make(NetMsgType::SENDCMPCT,
                                             /*fAnnounceUsingCMPCTBLOCK=*/false,
                                             nCMPCTBLOCKVersion));
                    // save BIP152 bandwidth state: we select peer to be low-bandwidth
                    pnodeStop->m_bip152_highbandwidth_to = false;
                    return true;
                });
            lNodesAnnouncingHeaderAndIDs.pop_front();
        }
        connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion())
                                        .Make(NetMsgType::SENDCMPCT,
                                              /*fAnnounceUsingCMPCTBLOCK=*/true,
                                              nCMPCTBLOCKVersion));
        // save BIP152 bandwidth state: we select peer to be high-bandwidth
        pfrom->m_bip152_highbandwidth_to = true;
        lNodesAnnouncingHeaderAndIDs.push_back(pfrom->GetId());
        return true;
    });
}

static bool TipMayBeStale(const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    if (g_last_tip_update == 0) {
        g_last_tip_update = GetTime();
    }
    return g_last_tip_update <
               GetTime() - consensusParams.nPowTargetSpacing * 3 &&
           mapBlocksInFlight.empty();
}

static bool CanDirectFetch(const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    return ::ChainActive().Tip()->GetBlockTime() >
           GetAdjustedTime() - consensusParams.nPowTargetSpacing * 20;
}

static bool PeerHasHeader(CNodeState *state, const CBlockIndex *pindex)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    if (state->pindexBestKnownBlock &&
        pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight)) {
        return true;
    }
    if (state->pindexBestHeaderSent &&
        pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight)) {
        return true;
    }
    return false;
}

/**
 * Update pindexLastCommonBlock and add not-in-flight missing successors to
 * vBlocks, until it has at most count entries.
 */
static void FindNextBlocksToDownload(NodeId nodeid, unsigned int count,
                                     std::vector<const CBlockIndex *> &vBlocks,
                                     NodeId &nodeStaller,
                                     const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    if (count == 0) {
        return;
    }

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    if (state->pindexBestKnownBlock == nullptr ||
        state->pindexBestKnownBlock->nChainWork <
            ::ChainActive().Tip()->nChainWork ||
        state->pindexBestKnownBlock->nChainWork < nMinimumChainWork) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == nullptr) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking
        // point. Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = ::ChainActive()[std::min(
            state->pindexBestKnownBlock->nHeight, ::ChainActive().Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an
    // ancestor of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(
        state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock) {
        return;
    }

    std::vector<const CBlockIndex *> vToFetch;
    const CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more
    // than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last linked block we have in
    // common with this peer. The +1 is so we can detect stalling, namely if we
    // would be able to download that next block if the window were 1 larger.
    int nWindowEnd =
        state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight =
        std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 128 (or more, if more blocks than that are needed)
        // successors of pindexWalk (towards pindexBestKnownBlock) into
        // vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as
        // expensive as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight,
                                std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(
            pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding
        // the ones that are not yet downloaded and not in flight to vBlocks. In
        // the meantime, update pindexLastCommonBlock as long as all ancestors
        // are already downloaded, or if it's already part of our chain (and
        // therefore don't need it even if pruned).
        for (const CBlockIndex *pindex : vToFetch) {
            if (!pindex->IsValid(BlockValidity::TREE)) {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (pindex->nStatus.hasData() || ::ChainActive().Contains(pindex)) {
                if (pindex->HaveTxsDownloaded()) {
                    state->pindexLastCommonBlock = pindex;
                }
            } else if (BlockDownloadMap::iterator itInFlight; !IsBlockRequested(pindex->GetBlockHash(), &itInFlight)) {
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != nodeid) {
                        // We aren't able to fetch anything, but we would be if
                        // the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight block.
                assert(itInFlight != mapBlocksInFlight.end());
                waitingfor = itInFlight->second.first;
            }
        }
    }
}

} // namespace

// This function is used for testing the stale tip eviction logic, see
// denialofservice_tests.cpp
void internal::UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) {
    LOCK(cs_main);
    CNodeState *state = State(node);
    if (state) {
        state->m_last_block_announcement = time_in_seconds;
    }
}

// Returns true for outbound peers, excluding manual connections, feelers, and
// one-shots.
static bool IsOutboundDisconnectionCandidate(const NodeRef &node) {
    return !(node->fInbound || node->m_manual_connection || node->fFeeler ||
             node->fOneShot);
}

void PeerLogicValidation::PushNodeVersion(const Config &config, const NodeRef &pnode, const int64_t nTime) const {
    const ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
    const uint64_t nonce = pnode->GetLocalNonce();
    const int nNodeStartingHeight = pnode->GetMyStartingHeight();
    const NodeId nodeid = pnode->GetId();
    const CAddress addr = pnode->addr;

    const CAddress addrYou = addr.IsRoutable() && !IsProxy(addr)
                                 ? addr
                                 : CAddress(CService(), addr.nServices);
    const CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    connman->PushMessage(pnode,
                         CNetMsgMaker(INIT_PROTO_VERSION)
                             .Make(NetMsgType::VERSION, PROTOCOL_VERSION, uint64_t(nLocalNodeServices), nTime, addrYou,
                                   addrMe, nonce, userAgent(config), nNodeStartingHeight, ::g_relay_txes));

    if (fLogIPs) {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n",
                 PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), addrYou.ToString(), nodeid);
    } else {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, peer=%d\n",
                 PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), nodeid);
    }
}

void PeerLogicValidation::InitializeNode(const Config &config, NodeRef pnode) {
    CAddress addr = pnode->addr;
    std::string addrName = pnode->GetAddrName();
    NodeId nodeid = pnode->GetId();
    {
        LOCK(cs_main);
        mapNodeState.emplace_hint(
            mapNodeState.end(), std::piecewise_construct,
            std::forward_as_tuple(nodeid),
            std::forward_as_tuple(addr, std::move(addrName)));
        assert(m_txrequest.Count(nodeid) == 0);
    }
    if (!pnode->fInbound) {
        PushNodeVersion(config, pnode, GetTime());
    }
    // We only track data usage to enforce peer rate limit rules for the specified node if:
    // (1) rules exist, and (2) we are regtest *or* the node is not whiltelisted and not maunally added and not local
    if (!m_peerRateLimitRules.empty() &&
        (m_is_regtest || (!pnode->HasPermission(PF_NOBAN) && !pnode->m_manual_connection && !pnode->addr.IsLocal()))) {
        pnode->m_rateTracker = std::make_unique<ClientUsageTracker>(m_peerRateLimitRules);
    }
}

void PeerLogicValidation::FinalizeNode(const Config &config, NodeId nodeid,
                                       bool &fUpdateConnectionTime) {
    fUpdateConnectionTime = false;
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    if (state->fSyncStarted) {
        nSyncStarted--;
    }

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        fUpdateConnectionTime = true;
    }

    for (const QueuedBlock &entry : state->vBlocksInFlight) {
        auto range = mapBlocksInFlight.equal_range(entry.pindex->GetBlockHash());
        while (range.first != range.second) {
            const auto & [node_id, list_it] = range.first->second;
            if (node_id != nodeid) {
                ++range.first;
            } else {
                range.first = mapBlocksInFlight.erase(range.first);
            }
        }
    }
    m_orphanage.EraseForPeer(nodeid);
    m_txrequest.DisconnectedPeer(nodeid);
    nPreferredDownload -= state->fPreferredDownload;
    nPeersWithValidatedDownloads -= (state->nBlocksInFlightValidHeaders != 0);
    assert(nPeersWithValidatedDownloads >= 0);
    g_outbound_peers_with_protect_from_disconnect -= state->m_chain_sync.m_protect;
    assert(g_outbound_peers_with_protect_from_disconnect >= 0);

    mapNodeState.erase(nodeid);

    if (mapNodeState.empty()) {
        // Do a consistency check after the last peer is removed.
        assert(mapBlocksInFlight.empty());
        assert(nPreferredDownload == 0);
        assert(nPeersWithValidatedDownloads == 0);
        assert(g_outbound_peers_with_protect_from_disconnect == 0);
        assert(m_txrequest.Size() == 0);
    }
    LogPrint(BCLog::NET, "Cleared nodestate for peer=%d\n", nodeid);
}

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == nullptr) {
        return false;
    }
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight =
        state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock
                              ? state->pindexLastCommonBlock->nHeight
                              : -1;
    for (const QueuedBlock &queue : state->vBlocksInFlight) {
        if (queue.pindex) {
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
        }
    }
    return true;
}

void PeerLogicValidation::AddToCompactExtraTransactions(const CTransactionRef &tx) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    const int64_t max_extra_txn = gArgs.GetArg("-blockreconstructionextratxn", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN);
    if (max_extra_txn <= 0 || uint64_t(max_extra_txn) > uint64_t(std::numeric_limits<size_t>::max())) {
        return;
    }

    if (!m_vExtraTxnForCompact.size()) {
        m_vExtraTxnForCompact.resize(max_extra_txn);
    }

    m_vExtraTxnForCompact[m_vExtraTxnForCompactIt] = std::make_pair(tx->GetHash(), tx);
    m_vExtraTxnForCompactIt = (m_vExtraTxnForCompactIt + 1u) % m_vExtraTxnForCompact.size();
}

/**
 * Mark a misbehaving peer to be discouraged depending upon the value of `-banscore`.
 */
void Misbehaving(NodeId pnode, int howmuch, const std::string &reason)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    if (howmuch == 0) {
        return;
    }

    CNodeState *state = State(pnode);
    if (state == nullptr) {
        return;
    }

    state->nMisbehavior += howmuch;
    int banscore = gArgs.GetArg("-banscore", DEFAULT_BANSCORE_THRESHOLD);
    if (state->nMisbehavior >= banscore &&
        state->nMisbehavior - howmuch < banscore) {
        LogPrintf(
            "%s: %s peer=%d (%d -> %d) reason: %s DISCOURAGE THRESHOLD EXCEEDED\n",
            __func__, state->name, pnode, state->nMisbehavior - howmuch,
            state->nMisbehavior, reason.c_str());
        state->fShouldDiscourage = true;
    } else {
        LogPrintf("%s: %s peer=%d (%d -> %d) reason: %s\n", __func__,
                  state->name, pnode, state->nMisbehavior - howmuch,
                  state->nMisbehavior, reason.c_str());
    }
}

// overloaded variant of above to operate on CNode*s
static void Misbehaving(const NodeRef &node, int howmuch, const std::string &reason)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    Misbehaving(node->GetId(), howmuch, reason);
}

//////////////////////////////////////////////////////////////////////////////
//
// blockchain -> download logic notification
//

// To prevent fingerprinting attacks, only send blocks/headers outside of the
// active chain if they are no more than a month older (both in time, and in
// best equivalent proof of work) than the best header chain we know about and
// we fully-validated them at some point.
static bool BlockRequestAllowed(const CBlockIndex *pindex,
                                const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    if (::ChainActive().Contains(pindex)) {
        return true;
    }
    return pindex->IsValid(BlockValidity::SCRIPTS) &&
           (pindexBestHeader != nullptr) &&
           (pindexBestHeader->GetBlockTime() - pindex->GetBlockTime() <
            STALE_RELAY_AGE_LIMIT) &&
           (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex,
                                        *pindexBestHeader, consensusParams) <
            STALE_RELAY_AGE_LIMIT);
}

PeerLogicValidation::PeerLogicValidation(CConnman *connmanIn, BanMan *banman,
                                         CScheduler &scheduler,
                                         bool enable_bip61, bool enable_feefilter)
    : connman(connmanIn), m_banman(banman), deleted(std::make_shared<std::atomic_bool>(false)),
      m_stale_tip_check_time(0), m_enable_bip61(enable_bip61), m_enable_feefilter(enable_feefilter),
      m_is_regtest{gArgs.GetChainName() == CBaseChainParams::REGTEST} {
    m_recentRejects = std::make_unique<CRollingBloomFilter>(120000, 0.000001);

    const Consensus::Params &consensusParams = Params().GetConsensus();
    // Stale tip checking and peer eviction are on two different timers, but we
    // don't want them to get out of sync due to drift in the scheduler, so we
    // combine them in one function and schedule at the quicker (peer-eviction)
    // timer.
    static_assert(
        EXTRA_PEER_CHECK_INTERVAL < STALE_CHECK_INTERVAL,
        "peer eviction timer should be less than stale tip check timer");
    scheduler.scheduleEvery(
        [this, consensusParams, this_deleted = this->deleted]() {
            if (*this_deleted) return false; // guard against case where this instance may be deleted before scheduler
            this->CheckForStaleTipAndEvictPeers(consensusParams);
            return true;
        },
        EXTRA_PEER_CHECK_INTERVAL * 1000);
}

PeerLogicValidation::~PeerLogicValidation() {
    *deleted = true; // guard againse use-after-free in case our periodic lambda is triggered again
}

/**
 * Evict orphan txn pool entries (m_orphanage) based on a newly connected block,
 * and also delete tracked announcements for recently confirmed transactions.
 * Also save the time of the last tip update.
 */
void PeerLogicValidation::BlockConnected(const std::shared_ptr<const CBlock> &pblock,
                                         const CBlockIndex *, const std::vector<CTransactionRef> &) {
    LOCK(cs_main);
    m_orphanage.EraseForBlock(*pblock);
    for (const auto &ptx : pblock->vtx) {
        m_txrequest.ForgetTxId(ptx->GetId());
    }

    g_last_tip_update = GetTime();
}

// All of the following cache a recent block, and are protected by
// cs_most_recent_block
static RecursiveMutex cs_most_recent_block;
static std::shared_ptr<const CBlock>
    most_recent_block GUARDED_BY(cs_most_recent_block);
static std::shared_ptr<const CBlockHeaderAndShortTxIDs>
    most_recent_compact_block GUARDED_BY(cs_most_recent_block);
static uint256 most_recent_block_hash GUARDED_BY(cs_most_recent_block);

/**
 * Maintain state about the best-seen block and fast-announce a compact block
 * to compatible peers.
 */
void PeerLogicValidation::NewPoWValidBlock(
    const CBlockIndex *pindex, const std::shared_ptr<const CBlock> &pblock) {
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> pcmpctblock =
        std::make_shared<const CBlockHeaderAndShortTxIDs>(*pblock);
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);

    LOCK(cs_main);

    static int nHighestFastAnnounce = 0;
    if (pindex->nHeight <= nHighestFastAnnounce) {
        return;
    }
    nHighestFastAnnounce = pindex->nHeight;

    uint256 hashBlock(pblock->GetHash());

    {
        LOCK(cs_most_recent_block);
        most_recent_block_hash = hashBlock;
        most_recent_block = pblock;
        most_recent_compact_block = pcmpctblock;
    }

    connman->ForEachNode([this, &pcmpctblock, pindex, &msgMaker,
                          &hashBlock](const NodeRef &pnode) {
        AssertLockHeld(cs_main);

        // TODO: Avoid the repeated-serialization here
        if (pnode->nVersion < INVALID_CB_NO_BAN_VERSION || pnode->fDisconnect) {
            return;
        }
        ProcessBlockAvailability(pnode->GetId());
        CNodeState &state = *State(pnode->GetId());
        // If the peer has, or we announced to them the previous block already,
        // but we don't think they have this one, go ahead and announce it.
        if (state.fPreferHeaderAndIDs && !PeerHasHeader(&state, pindex) &&
            PeerHasHeader(&state, pindex->pprev)) {
            LogPrint(BCLog::NET, "%s sending header-and-ids %s to peer=%d\n",
                     "PeerLogicValidation::NewPoWValidBlock",
                     hashBlock.ToString(), pnode->GetId());
            connman->PushMessage(
                pnode, msgMaker.Make(NetMsgType::CMPCTBLOCK, *pcmpctblock));
            state.pindexBestHeaderSent = pindex;
        }
    });
}

/**
 * Update our best height and announce any block hashes which weren't previously
 * in ::ChainActive() to our peers.
 */
void PeerLogicValidation::UpdatedBlockTip(const CBlockIndex *pindexNew,
                                          const CBlockIndex *pindexFork,
                                          bool fInitialDownload) {
    const int nNewHeight = pindexNew->nHeight;
    connman->SetBestHeight(nNewHeight);

    m_cachedLastIBDFlagSeen.store(fInitialDownload, std::memory_order_relaxed);
    SetServiceFlagsIBDCache(!fInitialDownload);
    if (!fInitialDownload) {
        // Find the hashes of all blocks that weren't previously in the best
        // chain.
        std::vector<BlockHash> vHashes;
        const CBlockIndex *pindexToAnnounce = pindexNew;
        while (pindexToAnnounce != pindexFork) {
            vHashes.push_back(pindexToAnnounce->GetBlockHash());
            pindexToAnnounce = pindexToAnnounce->pprev;
            if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) {
                // Limit announcements in case of a huge reorganization. Rely on
                // the peer's synchronization mechanism in that case.
                break;
            }
        }
        // Relay inventory, but don't relay old inventory during initial block
        // download.
        connman->ForEachNode([nNewHeight, &vHashes](const NodeRef &pnode) {
            if (nNewHeight > (pnode->nStartingHeight != -1
                                  ? pnode->nStartingHeight - 2000
                                  : 0)) {
                for (const BlockHash &hash : reverse_iterate(vHashes)) {
                    pnode->PushBlockHash(hash);
                }
            }
        });
        connman->WakeMessageHandler();
    }

    nTimeBestReceived = GetTime();
}

/**
 * Handle invalid block rejection and consequent peer discouragement, maintain which
 * peers announce compact blocks.
 */
void PeerLogicValidation::BlockChecked(const CBlock &block,
                                       const CValidationState &state) {
    LOCK(cs_main);

    const uint256 hash(block.GetHash());
    std::map<uint256, std::pair<NodeId, bool>>::iterator it =
        mapBlockSource.find(hash);

    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        // Don't send reject message with code 0 or an internal reject code.
        if (it != mapBlockSource.end() && State(it->second.first) &&
            state.GetRejectCode() > 0 &&
            state.GetRejectCode() < REJECT_INTERNAL) {
            CBlockReject reject = {
                uint8_t(state.GetRejectCode()),
                state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH),
                hash};
            State(it->second.first)->rejects.push_back(reject);
            if (nDoS > 0 && it->second.second) {
                Misbehaving(it->second.first, nDoS, state.GetRejectReason());
            }
        }
    }
    // Check that:
    // 1. The block is valid
    // 2. We're not in initial block download
    // 3. This is currently the best block we're aware of. We haven't updated
    //    the tip yet so we have no way to check this directly here. Instead we
    //    just check that there are currently no other blocks in flight.
    else if (state.IsValid() && !IsInitialBlockDownload() &&
             mapBlocksInFlight.count(hash) == mapBlocksInFlight.size()) {
        if (it != mapBlockSource.end()) {
            MaybeSetPeerAsAnnouncingHeaderAndIDs(it->second.first, connman);
        }
    }

    if (it != mapBlockSource.end()) {
        mapBlockSource.erase(it);
    }
}

void PeerLogicValidation::SetPeerRateLimitRules(const std::vector<PeerRateLimitRule> &rules) {
    m_peerRateLimitRules = rules;
}

bool PeerLogicValidation::IsPerPeerRateLimitingTemporarilySuppressed() const /* override */ {
    const int flag = m_cachedLastIBDFlagSeen.load(std::memory_order_relaxed);
    return flag >= 0 ? flag : IsInitialBlockDownload(); // if flag not set, fall-back to the potentially-slower call
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool PeerLogicValidation::AlreadyHave(const CInv &inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    switch (inv.type) {
        case MSG_TX: {
            assert(m_recentRejects);
            if (const auto tipHash = ::ChainActive().Tip()->GetBlockHash(); tipHash != m_hashRecentRejectsChainTip) {
                // If the chain tip has changed previously rejected transactions
                // might be now valid, e.g. due to a nLockTime'd tx becoming
                // valid, or a double-spend. Reset the rejects filter and give
                // those txs a second chance.
                m_hashRecentRejectsChainTip = tipHash;
                m_recentRejects->reset();
            }

            const TxId txid(inv.hash);
            if (m_orphanage.HaveTx(txid)) {
                return true;
            }

            // Use pcoinsTip->HaveCoinInCache as a quick approximation to
            // exclude requesting or processing some txs which have already been
            // included in a block. As this is best effort, we only check for
            // output 0 and 1. This works well enough in practice and we get
            // diminishing returns with 2 onward.
            return m_recentRejects->contains(txid) ||
                   g_mempool.exists(txid) ||
                   pcoinsTip->HaveCoinInCache(COutPoint(txid, 0)) ||
                   pcoinsTip->HaveCoinInCache(COutPoint(txid, 1));
        }
        case MSG_BLOCK:
            return LookupBlockIndex(BlockHash(inv.hash)) != nullptr;
        case MSG_DOUBLESPENDPROOF:
            return g_mempool.doubleSpendProofStorage()->exists(inv.hash)
                    || g_mempool.doubleSpendProofStorage()->isRecentlyRejectedProof(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}

void PeerLogicValidation::RelayTransaction(const CTransaction &tx, uint64_t entryId) const {
    CInv inv(MSG_TX, tx.GetId());
    if (!entryId) {
        LOCK(g_mempool.cs);
        if (auto optIter = g_mempool.GetIter(tx.GetId())) {
            entryId = (*optIter)->GetEntryId();
        }
    }
    connman->ForEachNode([&inv, entryId](const NodeRef &pnode) { pnode->PushInventory(inv, entryId); });
}

void PeerLogicValidation::RelayAddress(const CAddress &addr, bool fReachable) const {
    // Limited relaying of addresses outside our network(s)
    unsigned int nRelayNodes = fReachable ? 2 : 1;

    // Relay to a limited number of other nodes.
    // Use deterministic randomness to send to the same nodes for 24 hours at a
    // time so the addrKnowns of the chosen nodes prevent repeats.
    uint64_t hashAddr = addr.GetHash();
    const CSipHasher hasher = connman->GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY)
                                  .Write(hashAddr << 32)
                                  .Write((GetTime() + hashAddr) / (24 * 60 * 60));
    FastRandomContext insecure_rand;

    std::array<std::pair<uint64_t, NodeRef>, 2> best{{{0, nullptr}, {0, nullptr}}};
    assert(nRelayNodes <= best.size());

    auto sortfunc = [&best, &hasher, nRelayNodes](const NodeRef &pnode) {
        uint64_t hashKey = CSipHasher(hasher).Write(pnode->GetId()).Finalize();
        for (unsigned int i = 0; i < nRelayNodes; ++i) {
            if (hashKey > best[i].first) {
                std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
                best[i] = std::make_pair(hashKey, pnode);
                break;
            }
        }
    };

    auto pushfunc = [&addr, &best, nRelayNodes, &insecure_rand] {
        for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; ++i) {
            if (best[i].second) best[i].second->PushAddress(addr, insecure_rand);
        }
    };

    connman->ForEachNodeThen(std::move(sortfunc), std::move(pushfunc));
}

void PeerLogicValidation::ProcessGetBlockData(const Config &config, const NodeRef &pfrom, const CInv &inv,
                                              const std::atomic<bool> &interruptMsgProc [[maybe_unused]]) const {
    const Consensus::Params &consensusParams = config.GetChainParams().GetConsensus();

    const BlockHash hash(inv.hash);

    bool send = false;
    std::shared_ptr<const CBlock> a_recent_block;
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> a_recent_compact_block;
    {
        LOCK(cs_most_recent_block);
        a_recent_block = most_recent_block;
        a_recent_compact_block = most_recent_compact_block;
    }

    bool need_activate_chain = false;
    {
        LOCK(cs_main);
        const CBlockIndex *pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->HaveTxsDownloaded() &&
                !pindex->IsValid(BlockValidity::SCRIPTS) &&
                pindex->IsValid(BlockValidity::TREE)) {
                // If we have the block and all of its parents, but have not yet
                // validated it, we might be in the middle of connecting it (ie
                // in the unlock of cs_main before ActivateBestChain but after
                // AcceptBlock). In this case, we need to run ActivateBestChain
                // prior to checking the relay conditions below.
                need_activate_chain = true;
            }
        }
    } // release cs_main before calling ActivateBestChain
    if (need_activate_chain) {
        CValidationState state;
        if (!ActivateBestChain(config, state, a_recent_block)) {
            LogPrint(BCLog::NET, "failed to activate chain (%s)\n",
                     FormatStateMessage(state));
        }
    }

    LOCK(cs_main);
    const CBlockIndex *pindex = LookupBlockIndex(hash);
    if (pindex) {
        send = BlockRequestAllowed(pindex, consensusParams);
        if (!send) {
            LogPrint(BCLog::NET,
                     "%s: ignoring request from peer=%i for old "
                     "block that isn't in the main chain\n",
                     __func__, pfrom->GetId());
        }
    }
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    // Disconnect node in case we have reached the outbound limit for serving
    // historical blocks.
    // Never disconnect whitelisted nodes.
    if (send && connman->OutboundTargetReached(true) &&
        (((pindexBestHeader != nullptr) &&
          (pindexBestHeader->GetBlockTime() - pindex->GetBlockTime() >
           HISTORICAL_BLOCK_AGE)) ||
         inv.type == MSG_FILTERED_BLOCK) &&
        !pfrom->HasPermission(PF_NOBAN)) {
        LogPrint(BCLog::NET,
                 "historical block serving limit reached, disconnect peer=%d\n",
                 pfrom->GetId());

        // disconnect node
        pfrom->fDisconnect = true;
        send = false;
    }
    // Avoid leaking prune-height by never sending blocks below the
    // NODE_NETWORK_LIMITED threshold.
    // Add two blocks buffer extension for possible races
    if (send && !pfrom->HasPermission(PF_NOBAN) &&
        ((((pfrom->GetLocalServices() & NODE_NETWORK_LIMITED) ==
           NODE_NETWORK_LIMITED) &&
          ((pfrom->GetLocalServices() & NODE_NETWORK) != NODE_NETWORK) &&
          (::ChainActive().Tip()->nHeight - pindex->nHeight >
           (int)NODE_NETWORK_LIMITED_MIN_BLOCKS + 2)))) {
        LogPrint(BCLog::NET,
                 "Ignore block request below NODE_NETWORK_LIMITED "
                 "threshold from peer=%d\n",
                 pfrom->GetId());

        // disconnect node and prevent it from stalling (would otherwise wait
        // for the missing block)
        pfrom->fDisconnect = true;
        send = false;
    }
    // Pruned nodes may have deleted the block, so check whether it's available
    // before trying to send.
    if (send && pindex->nStatus.hasData()) {
        std::shared_ptr<const CBlock> pblock;
        if (a_recent_block &&
            a_recent_block->GetHash() == pindex->GetBlockHash()) {
            pblock = a_recent_block;
        }

        auto make_raw_block_message = [&pblock, &pindex, &config, &msgMaker] {
            CSerializedNetMsg msg;
            if (pblock) {
                // pblock points to the recent block already in memory, so just use it rather than reading from disk
                msg = msgMaker.Make(NetMsgType::BLOCK, *pblock);
            } else {
                // read the raw block data from disk and send it directly to network
                msg.m_type = NetMsgType::BLOCK;
                if (!ReadRawBlockFromDisk(msg.data, pindex, config.GetChainParams(), SER_NETWORK, msgMaker.nVersion)) {
                    assert(!"cannot load raw block data from disk");
                }
            }
            return msg;
        };

        if (inv.type == MSG_BLOCK) {
            connman->PushMessage(pfrom, make_raw_block_message());
        } else {
            auto ensure_pblock = [&pblock, &pindex, &consensusParams]() -> const CBlock & {
                // Read block from disk if not already in memory and deserialize to transform it to
                // MerkleBlock or CompactBlock
                if (!pblock) {
                    std::shared_ptr<CBlock> pblockRead = std::make_shared<CBlock>();
                    if (!ReadBlockFromDisk(*pblockRead, pindex, consensusParams)) {
                        assert(!"cannot load block from disk");
                    }
                    pblock = pblockRead;
                }
                return *pblock;
            };
            if (inv.type == MSG_FILTERED_BLOCK) {
                bool sendMerkleBlock = false;
                CMerkleBlock merkleBlock;
                {
                    WAIT_LOCK(pfrom->cs_filter, lock);
                    if (pfrom->pfilter) {
                        if (!pblock) {
                            // read into pblock now with pfrom->cs_filter not held
                            REVERSE_LOCK(lock);
                            ensure_pblock();
                        }
                        // relocked; check again (in case in future code another thread clears pfilter)
                        if (pfrom->pfilter) {
                            sendMerkleBlock = true;
                            merkleBlock = CMerkleBlock(*pblock, *pfrom->pfilter);
                        }
                    }
                }
                if (sendMerkleBlock) {
                    connman->PushMessage(
                        pfrom, msgMaker.Make(NetMsgType::MERKLEBLOCK, merkleBlock));
                    // CMerkleBlock just contains hashes, so also push any
                    // transactions in the block the client did not see. This avoids
                    // hurting performance by pointlessly requiring a round-trip.
                    // Note that there is currently no way for a node to request any
                    // single transactions we didn't send here - they must either
                    // disconnect and retry or request the full block. Thus, the
                    // protocol spec specified allows for us to provide duplicate
                    // txn here, however we MUST always provide at least what the
                    // remote peer needs.
                    for (const auto &pair : merkleBlock.vMatchedTxn) {
                        connman->PushMessage(
                            pfrom, msgMaker.Make(NetMsgType::TX,
                                                *pblock->vtx[pair.first]));
                    }
                }
                // else
                // no response
            } else if (inv.type == MSG_CMPCT_BLOCK) {
                // If a peer is asking for old blocks, we're almost guaranteed they
                // won't have a useful mempool to match against a compact block, and
                // we don't feel like constructing the object for them, so instead
                // we respond with the full, non-compact block.
                int nSendFlags = 0;
                if (CanDirectFetch(consensusParams) &&
                    pindex->nHeight >=
                        ::ChainActive().Height() - MAX_CMPCTBLOCK_DEPTH) {
                    CBlockHeaderAndShortTxIDs cmpctblock(ensure_pblock());
                    connman->PushMessage(
                        pfrom, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK,
                                            cmpctblock));
                } else {
                    connman->PushMessage(pfrom, make_raw_block_message());
                }
            }
        }

        // Trigger the peer node to send a getblocks request for the next batch
        // of inventory.
        if (hash == pfrom->hashContinue) {
            // Bypass PushInventory, this must send even if redundant, and we
            // want it right after the last block so they don't wait for other
            // stuff first.
            std::vector<CInv> vInv;
            vInv.emplace_back(
                MSG_BLOCK, ::ChainActive().Tip()->GetBlockHash());
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::INV, vInv));
            pfrom->hashContinue = BlockHash();
        }
    }
}

void PeerLogicValidation::ProcessGetData(const Config &config, const NodeRef &pfrom,
                                         const std::atomic<bool> &interruptMsgProc) const LOCKS_EXCLUDED(cs_main) {
    AssertLockNotHeld(cs_main);

    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();
    std::vector<CInv> vNotFound;
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    {
        LOCK(cs_main);

        while (it != pfrom->vRecvGetData.end() &&
               (it->type == MSG_TX || it->type == MSG_DOUBLESPENDPROOF) &&
               !pfrom->fPauseSend) {

            if (interruptMsgProc) {
                return;
            }

            const CInv &inv = *it;
            bool found = false;
            constexpr int nSendFlags = 0;

            switch (inv.type) {
                case MSG_TX:
                    // Send stream from relay memory
                    if (auto mi = mapRelay.find(inv.hash); mi != mapRelay.end()) {
                        connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::TX, *mi->second));
                        found = true;
                    } else if (pfrom->timeLastMempoolReq) {
                        auto txinfo = g_mempool.info(TxId(inv.hash));
                        // To protect privacy, do not answer getdata using the mempool
                        // when that TX couldn't have been INVed in reply to a MEMPOOL
                        // request.
                        if (txinfo.tx && txinfo.nTime <= pfrom->timeLastMempoolReq) {
                            connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::TX, *txinfo.tx));
                            found = true;
                        }
                    }
                    break;
                case MSG_DOUBLESPENDPROOF:
                    if (DoubleSpendProof::IsEnabled()) {
                        DoubleSpendProof dsp = g_mempool.doubleSpendProofStorage()->lookup(inv.hash);
                        if (!dsp.isEmpty()) {
                            connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::DSPROOF, dsp));
                            found = true;
                        }
                    }
                    break;
                default:
                    // Not reached. Here to prevent compile-time warnings.
                    break;
            }

            if (!found) {
                vNotFound.push_back(inv);
            }

            it = pfrom->vRecvGetData.erase(it);
        }
    } // release cs_main, it may not be held when calling ProcessGetBlockData

    if (it != pfrom->vRecvGetData.end() && !pfrom->fPauseSend) {
        const CInv &inv = *it;
        // if there is still at least one item in the queue, and it is of type
        // BLOCK/FILTERED_BLOCK/CMPCT_BLOCK, then process it as such
        if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK ||
            inv.type == MSG_CMPCT_BLOCK) {
            ProcessGetBlockData(config, pfrom, inv, interruptMsgProc);
        }
        // else, if the first item on the queue is an unknown type, we ignore it.
        // In either case we erase this item and continue processing the queue on
        // the next call.
        it = pfrom->vRecvGetData.erase(it);
    }

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it
        // doesn't have to wait around forever. SPV clients care about this
        // message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want
        // to do that because they want to know about (and store and rebroadcast
        // and risk analyze) the dependencies of transactions relevant to them,
        // without having to download the entire memory pool. Also, other nodes
        // can use these messages to automatically request a transaction from
        // some other peer that annnounced it, and stop waiting for us to
        // respond. In normal operation, we often send NOTFOUND messages for
        // parents of transactions that we relay; if a peer is missing a parent,
        // they may assume we have them and request the parents from us.
        connman->PushMessage(pfrom,
                             msgMaker.Make(NetMsgType::NOTFOUND, vNotFound));
    }
}

void PeerLogicValidation::SendBlockTransactions(const CBlock &block, const BlockTransactionsRequest &req, const NodeRef &pfrom) const {
    BlockTransactions resp(req);
    for (size_t i = 0; i < req.indices.size(); i++) {
        if (req.indices[i] >= block.vtx.size()) {
            LOCK(cs_main);
            Misbehaving(pfrom, 100, "out-of-bound-tx-index");
            LogPrintf(
                "Peer %d sent us a getblocktxn with out-of-bounds tx indices\n",
                pfrom->GetId());
            return;
        }
        resp.txn[i] = block.vtx[req.indices[i]];
    }
    LOCK(cs_main);
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    int nSendFlags = 0;
    connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::BLOCKTXN, resp));
}

bool PeerLogicValidation::ProcessHeadersMessage(const Config &config, const NodeRef &pfrom,
                                                const std::vector<CBlockHeader> &headers,
                                                const bool punish_duplicate_invalid) const {
    const CChainParams &chainparams = config.GetChainParams();
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    size_t nCount = headers.size();

    if (nCount == 0) {
        // Nothing interesting. Stop asking this peers for more headers.
        return true;
    }

    bool received_new_header = false;
    const CBlockIndex *pindexLast = nullptr;
    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());

        // If this looks like it could be a block announcement (nCount <
        // MAX_BLOCKS_TO_ANNOUNCE), use special logic for handling headers that
        // don't connect:
        // - Send a getheaders message in response to try to connect the chain.
        // - The peer can send up to MAX_UNCONNECTING_HEADERS in a row that
        // don't connect before giving DoS points
        // - Once a headers message is received that is valid and does connect,
        // nUnconnectingHeaders gets reset back to 0.
        if (!LookupBlockIndex(headers[0].hashPrevBlock) &&
            nCount < MAX_BLOCKS_TO_ANNOUNCE) {
            nodestate->nUnconnectingHeaders++;
            connman->PushMessage(
                pfrom,
                msgMaker.Make(NetMsgType::GETHEADERS,
                              ::ChainActive().GetLocator(pindexBestHeader),
                              uint256()));
            LogPrint(
                BCLog::NET,
                "received header %s: missing prev block %s, sending getheaders "
                "(%d) to end (peer=%d, nUnconnectingHeaders=%d)\n",
                headers[0].GetHash().ToString(),
                headers[0].hashPrevBlock.ToString(), pindexBestHeader->nHeight,
                pfrom->GetId(), nodestate->nUnconnectingHeaders);
            // Set hashLastUnknownBlock for this peer, so that if we eventually
            // get the headers - even from a different peer - we can use this
            // peer to download.
            UpdateBlockAvailability(pfrom->GetId(), headers.back().GetHash());

            if (nodestate->nUnconnectingHeaders % MAX_UNCONNECTING_HEADERS ==
                0) {
                // The peer is sending us many headers we can't connect.
                Misbehaving(pfrom, 20, "too-many-unconnected-headers");
            }
            return true;
        }

        // Check for non-contiguous header sequence
        BlockHash hashLastBlock;
        for (const CBlockHeader &header : headers) {
            if (!hashLastBlock.IsNull() &&
                header.hashPrevBlock != hashLastBlock) {
                Misbehaving(pfrom, 20, "disconnected-header");
                return error("non-continuous headers sequence");
            }
            hashLastBlock = header.GetHash();
        }

        // If we don't have the last header, then they'll have given us
        // something new (if these headers are valid).
        if (!LookupBlockIndex(hashLastBlock)) {
            received_new_header = true;
        }
    }

    CValidationState state;
    CBlockHeader first_invalid_header;
    if (!ProcessNewBlockHeaders(config, headers, state, &pindexLast,
                                &first_invalid_header)) {
        int nDoS;
        if (state.IsInvalid(nDoS)) {
            LOCK(cs_main);
            if (nDoS > 0) {
                Misbehaving(pfrom, nDoS, state.GetRejectReason());
            }
            if (punish_duplicate_invalid &&
                LookupBlockIndex(first_invalid_header.GetHash())) {
                // Goal: don't allow outbound peers to use up our outbound
                // connection slots if they are on incompatible chains.
                //
                // We ask the caller to set punish_invalid appropriately based
                // on the peer and the method of header delivery (compact blocks
                // are allowed to be invalid in some circumstances, under BIP
                // 152).
                // Here, we try to detect the narrow situation that we have a
                // valid block header (ie it was valid at the time the header
                // was received, and hence stored in mapBlockIndex) but know the
                // block is invalid, and that a peer has announced that same
                // block as being on its active chain. Disconnect the peer in
                // such a situation.
                //
                // Note: if the header that is invalid was not accepted to our
                // mapBlockIndex at all, that may also be grounds for
                // disconnecting the peer, as the chain they are on is likely to
                // be incompatible. However, there is a circumstance where that
                // does not hold: if the header's timestamp is more than 2 hours
                // ahead of our current time. In that case, the header may
                // become valid in the future, and we don't want to disconnect a
                // peer merely for serving us one too-far-ahead block header, to
                // prevent an attacker from splitting the network by mining a
                // block right at the 2 hour boundary.
                //
                // TODO: update the DoS logic (or, rather, rewrite the
                // DoS-interface between validation and net_processing) so that
                // the interface is cleaner, and so that we disconnect on all
                // the reasons that a peer's headers chain is incompatible with
                // ours (eg block->nVersion softforks, MTP violations, etc), and
                // not just the duplicate-invalid case.
                pfrom->fDisconnect = true;
            }
            return error("invalid header received");
        }
    }

    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());
        if (nodestate->nUnconnectingHeaders > 0) {
            LogPrint(BCLog::NET,
                     "peer=%d: resetting nUnconnectingHeaders (%d -> 0)\n",
                     pfrom->GetId(), nodestate->nUnconnectingHeaders);
        }
        nodestate->nUnconnectingHeaders = 0;

        assert(pindexLast);
        UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        // From here, pindexBestKnownBlock should be guaranteed to be non-null,
        // because it is set in UpdateBlockAvailability. Some nullptr checks are
        // still present, however, as belt-and-suspenders.

        if (received_new_header &&
            pindexLast->nChainWork > ::ChainActive().Tip()->nChainWork) {
            nodestate->m_last_block_announcement = GetTime();
        }

        if (nCount == MAX_HEADERS_RESULTS) {
            // Headers message had its maximum size; the peer may have more
            // headers.
            // TODO: optimize: if pindexLast is an ancestor of
            // ::ChainActive().Tip or pindexBestHeader, continue from there
            // instead.
            LogPrint(
                BCLog::NET,
                "more getheaders (%d) to end to peer=%d (startheight:%d)\n",
                pindexLast->nHeight, pfrom->GetId(), pfrom->nStartingHeight);
            connman->PushMessage(
                pfrom, msgMaker.Make(NetMsgType::GETHEADERS,
                                     ::ChainActive().GetLocator(pindexLast),
                                     uint256()));
        }

        bool fCanDirectFetch = CanDirectFetch(chainparams.GetConsensus());
        // If this set of headers is valid and ends in a block with at least as
        // much work as our tip, download as much as possible.
        if (fCanDirectFetch && pindexLast->IsValid(BlockValidity::TREE) &&
            ::ChainActive().Tip()->nChainWork <= pindexLast->nChainWork) {
            std::vector<const CBlockIndex *> vToFetch;
            const CBlockIndex *pindexWalk = pindexLast;
            // Calculate all the blocks we'd need to switch to pindexLast, up to
            // a limit.
            while (pindexWalk && !::ChainActive().Contains(pindexWalk) &&
                   vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                if (!pindexWalk->nStatus.hasData() &&
                    !IsBlockRequested(pindexWalk->GetBlockHash())) {
                    // We don't have this block, and it's not yet in flight.
                    vToFetch.push_back(pindexWalk);
                }
                pindexWalk = pindexWalk->pprev;
            }
            // If pindexWalk still isn't on our main chain, we're looking at a
            // very large reorg at a time we think we're close to caught up to
            // the main chain -- this shouldn't really happen. Bail out on the
            // direct fetch and rely on parallel download instead.
            if (!::ChainActive().Contains(pindexWalk)) {
                LogPrint(
                    BCLog::NET, "Large reorg, won't direct fetch to %s (%d)\n",
                    pindexLast->GetBlockHash().ToString(), pindexLast->nHeight);
            } else {
                std::vector<CInv> vGetData;
                // Download as much as possible, from earliest to latest.
                for (const CBlockIndex *pindex : reverse_iterate(vToFetch)) {
                    if (nodestate->vBlocksInFlight.size() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                        // Can't download any more from this peer
                        break;
                    }
                    vGetData.emplace_back(MSG_BLOCK, pindex->GetBlockHash());
                    MarkBlockAsInFlight(config, pfrom->GetId(),
                                        pindex->GetBlockHash(),
                                        chainparams.GetConsensus(), pindex);
                    LogPrint(BCLog::NET, "Requesting block %s from  peer=%d\n",
                             pindex->GetBlockHash().ToString(), pfrom->GetId());
                }
                if (vGetData.size() > 1) {
                    LogPrint(BCLog::NET,
                             "Downloading blocks toward %s (%d) via headers "
                             "direct fetch\n",
                             pindexLast->GetBlockHash().ToString(),
                             pindexLast->nHeight);
                }
                if (vGetData.size() > 0) {
                    if (nodestate->fSupportsDesiredCmpctVersion &&
                        vGetData.size() == 1 && mapBlocksInFlight.size() == 1 &&
                        pindexLast->pprev->IsValid(BlockValidity::CHAIN)) {
                        // In any case, we want to download using a compact
                        // block, not a regular one.
                        vGetData[0] = CInv(MSG_CMPCT_BLOCK, vGetData[0].hash);
                    }
                    connman->PushMessage(
                        pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                }
            }
        }
        // If we're in IBD, we want outbound peers that will serve us a useful
        // chain. Disconnect peers that are on chains with insufficient work.
        if (IsInitialBlockDownload() && nCount != MAX_HEADERS_RESULTS) {
            // When nCount < MAX_HEADERS_RESULTS, we know we have no more
            // headers to fetch from this peer.
            if (nodestate->pindexBestKnownBlock &&
                nodestate->pindexBestKnownBlock->nChainWork <
                    nMinimumChainWork) {
                // This peer has too little work on their headers chain to help
                // us sync -- disconnect if using an outbound slot (unless
                // whitelisted or addnode).
                // Note: We compare their tip to nMinimumChainWork (rather than
                // ::ChainActive().Tip()) because we won't start block download
                // until we have a headers chain that has at least
                // nMinimumChainWork, even if a peer has a chain past our tip,
                // as an anti-DoS measure.
                if (IsOutboundDisconnectionCandidate(pfrom)) {
                    LogPrintf("Disconnecting outbound peer %d -- headers "
                              "chain has insufficient work\n",
                              pfrom->GetId());
                    pfrom->fDisconnect = true;
                }
            }
        }

        if (!pfrom->fDisconnect && IsOutboundDisconnectionCandidate(pfrom) &&
            nodestate->pindexBestKnownBlock != nullptr) {
            // If this is an outbound peer, check to see if we should protect it
            // from the bad/lagging chain logic.
            if (g_outbound_peers_with_protect_from_disconnect <
                    MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT &&
                nodestate->pindexBestKnownBlock->nChainWork >=
                    ::ChainActive().Tip()->nChainWork &&
                !nodestate->m_chain_sync.m_protect) {
                LogPrint(BCLog::NET,
                         "Protecting outbound peer=%d from eviction\n",
                         pfrom->GetId());
                nodestate->m_chain_sync.m_protect = true;
                ++g_outbound_peers_with_protect_from_disconnect;
            }
        }
    }

    return true;
}

//! Called from 3 places in this file; ensuring:
//! - GETADDR is not sent if !fInbound as well as some other criteria are not met
//! - GETADDR is sent precisely once after VERACK
void PeerLogicValidation::PushGetAddrOnceIfAfterVerAck(const NodeRef &pfrom) const {
    if ( !pfrom->fInbound
         && pfrom->GetBytesSentForMsgType(NetMsgType::VERACK) > 0
         && pfrom->GetBytesSentForMsgType(NetMsgType::GETADDR) == 0)
    {
        connman->PushMessage(
            pfrom,
            CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::GETADDR));
        pfrom->fGetAddr = true;
        // When requesting a getaddr, accept an additional MAX_ADDR_TO_SEND addresses in response
        // (bypassing the MAX_ADDR_PROCESSING_TOKEN_BUCKET limit).
        pfrom->m_addr_token_bucket += MAX_ADDR_TO_SEND;
    }
}

//! Called from 3 places in this file; ensuring:
//! Feature negotiation messages are sent, but only if nVersion >= FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION:
//! - SENDADDRV2
//! Finally, after any feature negotiation messages are sent:
//! - VERACK is sent
void PeerLogicValidation::PushVerACK(const NodeRef &pfrom, int nVersion /* 0 = read from pfrom */) const {
    const CNetMsgMaker msg_maker(INIT_PROTO_VERSION);

    if (nVersion == 0) nVersion = pfrom->nVersion;

    if (nVersion >= FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION) {
        // Signal ADDRv2 support (BIP155), but only if version >= FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION
        connman->PushMessage(pfrom, msg_maker.Make(NetMsgType::SENDADDRV2));
    }

    // Send VERACK handshake message
    connman->PushMessage(pfrom, msg_maker.Make(NetMsgType::VERACK));
}

void PeerLogicValidation::ProcessOrphanTx(const Config &config, const NodeId fromPeer) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);

    CTransactionRef tx;
    bool done = false;
    size_t rejectCount = 0;
    while (!done && (tx = m_orphanage.GetTxToReconsider(fromPeer))) {
        if (rejectCount > MAX_NON_STANDARD_ORPHAN_PER_NODE) {
            continue;
        }

        bool fMissingInputs = false;
        // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
        // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
        // anyone relaying LegitTxX banned)
        CValidationState stateDummy;

        MempoolAcceptExtraInfo info;
        const TxId &txid = tx->GetId();
        if (AcceptToMemoryPool(config, g_mempool, stateDummy, tx, &fMissingInputs,
                               false /* bypass_limits */, Amount::zero() /* nAbsurdFee */, false /* test_accept */,
                               &info)) {
            LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s (poolsz %u txn, %u kB)\n", txid.ToString(),
                     g_mempool.size(), g_mempool.DynamicMemoryUsage() / 1000);
            RelayTransaction(*tx, *Assert(info.entryId));
            m_orphanage.AddChildrenToWorkSet(*tx);
            m_orphanage.EraseTx(txid);
            done = true;
        } else if (!fMissingInputs) {
            int nDos = 0;
            if (stateDummy.IsInvalid(nDos)) {
                ++rejectCount;
                if (nDos > 0) {
                    // Punish peer that gave us an invalid orphan tx
                    Misbehaving(fromPeer, nDos);
                    LogPrint(BCLog::MEMPOOL, "   invalid orphan tx %s\n", txid.ToString());
                }
            }
            // Has inputs but not accepted to mempool
            // Probably non-standard or insufficient fee
            LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", txid.ToString());
            if (!stateDummy.CorruptionPossible()) {
                assert(m_recentRejects);
                m_recentRejects->insert(txid);
            }
            m_orphanage.EraseTx(txid);
            done = true;
        }
        g_mempool.check(pcoinsTip.get());
    }
}

/** Register with TxRequestTracker that an INV has been received from a peer. The announcement parameters are decided
 *  here and then passed to TxRequestTracker. */
void PeerLogicValidation::AddTxAnnouncement(const CNode& node, const TxId &txid, std::chrono::microseconds current_time) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main); // For m_txrequest
    NodeId nodeid = node.GetId();
    if (!node.HasPermission(PF_RELAY) && m_txrequest.Count(nodeid) >= MAX_PEER_TX_ANNOUNCEMENTS) {
        // Too many queued announcements from this peer
        return;
    }
    const CNodeState* state = State(nodeid);

    // Decide the TxRequestTracker parameters for this announcement:
    // - "preferred": if fPreferredDownload is set (= outbound, or PF_NOBAN permission)
    // - "reqtime": current time plus delays for:
    //   - NONPREF_PEER_TX_DELAY for announcements from non-preferred connections
    //   - OVERLOADED_PEER_TX_DELAY for announcements from peers which have at least
    //     MAX_PEER_TX_REQUEST_IN_FLIGHT requests in flight (and don't have PF_RELAY).
    auto delay = std::chrono::microseconds{0};
    const bool preferred = state->fPreferredDownload;
    if (!preferred) delay += NONPREF_PEER_TX_DELAY;
    const bool overloaded = !node.HasPermission(PF_RELAY)
                            && m_txrequest.CountInFlight(nodeid) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
    if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;
    m_txrequest.ReceivedInv(nodeid, txid, preferred, current_time + delay);
}

// Called from PrcoessMessage(), calls ProcessNewBlock() but also does some additional node accounting.
static void ProcessBlockFromNode(const Config &config, const NodeRef &pfrom, const std::shared_ptr<const CBlock> &pblock,
                                 bool force_processing) {
    bool new_block{false};
    ProcessNewBlock(config, pblock, force_processing, &new_block);
    if (new_block) {
        pfrom->nLastBlockTime = GetTime();
        // In case this block came from a different peer than we requested
        // from, we can erase the block request now anyway (as we just stored
        // this block to disk).
        LOCK(cs_main);
        MarkBlockAsReceived(pblock->GetHash(), std::nullopt);
    } else {
        LOCK(cs_main);
        mapBlockSource.erase(pblock->GetHash());
    }
}

bool PeerLogicValidation::ProcessMessage(const Config &config, const NodeRef &pfrom, const std::string &msg_type,
                                         CDataStream &vRecv, const int64_t nTimeReceived,
                                         const std::atomic<bool> &interruptMsgProc) {
    const CChainParams &chainparams = config.GetChainParams();
    LogPrint(BCLog::NET, "received: %s (%u bytes) peer=%d\n",
             SanitizeString(msg_type), vRecv.size(), pfrom->GetId());
    if (gArgs.IsArgSet("-dropmessagestest") &&
        GetRand(gArgs.GetArg("-dropmessagestest", 0)) == 0) {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
        (msg_type == NetMsgType::FILTERLOAD ||
         msg_type == NetMsgType::FILTERADD)) {
        if (pfrom->nVersion >= NO_BLOOM_VERSION) {
            LOCK(cs_main);
            Misbehaving(pfrom, 100, "no-bloom-version");
            return false;
        } else {
            pfrom->fDisconnect = true;
            return false;
        }
    }

    if (msg_type == NetMsgType::REJECT) {
        if (LogAcceptCategory(BCLog::NET)) {
            try {
                std::string strMsg;
                uint8_t ccode;
                std::string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >>
                    ccode >>
                    LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                std::ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX) {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint(BCLog::NET, "Reject %s\n", SanitizeString(ss.str()));
            } catch (const std::ios_base::failure &) {
                // Avoid feedback loops by preventing reject messages from
                // triggering a new reject message.
                LogPrint(BCLog::NET, "Unparseable reject message received\n");
            }
        }
        return true;
    }

    if (msg_type == NetMsgType::VERSION) {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0) {
            if (m_enable_bip61) {
                connman->PushMessage(
                    pfrom,
                    CNetMsgMaker(INIT_PROTO_VERSION)
                        .Make(NetMsgType::REJECT, msg_type, REJECT_DUPLICATE,
                              std::string("Duplicate version message")));
            }
            LOCK(cs_main);
            Misbehaving(pfrom, 1, "multiple-version");
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        ServiceFlags nServices;
        int nVersion;
        int nSendVersion;
        std::string cleanSubVer;
        int nStartingHeight = -1;
        bool fRelay = true;

        vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
        if (nTime < 0) {
            nTime = 0;
        }
        nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
        nServices = ServiceFlags(nServiceInt);
        if (!pfrom->fInbound) {
            connman->SetServices(pfrom->addr, nServices);
        }
        if (!pfrom->fInbound && !pfrom->fFeeler &&
            !pfrom->m_manual_connection &&
            !HasAllDesirableServiceFlags(nServices)) {
            LogPrint(BCLog::NET,
                     "peer=%d does not offer the expected services "
                     "(%08x offered, %08x expected); disconnecting\n",
                     pfrom->GetId(), nServices,
                     GetDesirableServiceFlags(nServices));
            if (m_enable_bip61) {
                connman->PushMessage(
                    pfrom,
                    CNetMsgMaker(INIT_PROTO_VERSION)
                        .Make(NetMsgType::REJECT, msg_type,
                              REJECT_NONSTANDARD,
                              strprintf("Expected to offer services %08x",
                                        GetDesirableServiceFlags(nServices))));
            }
            pfrom->fDisconnect = true;
            return false;
        }

        if (nVersion < MIN_PEER_PROTO_VERSION) {
            // disconnect from peers older than this proto version
            LogPrint(BCLog::NET,
                     "peer=%d using obsolete version %i; disconnecting\n",
                     pfrom->GetId(), nVersion);
            if (m_enable_bip61) {
                connman->PushMessage(
                    pfrom,
                    CNetMsgMaker(INIT_PROTO_VERSION)
                        .Make(NetMsgType::REJECT, msg_type, REJECT_OBSOLETE,
                              strprintf("Version must be %d or greater",
                                        MIN_PEER_PROTO_VERSION)));
            }
            pfrom->fDisconnect = true;
            return false;
        }

        if (!vRecv.empty()) {
            vRecv >> addrFrom >> nNonce;
        }
        if (!vRecv.empty()) {
            std::string strSubVer;
            vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
            cleanSubVer = SanitizeString(strSubVer);

            if (!config.GetRejectSubVersions().empty()) {
                // check that peer subversion is not in -rejectsubversion set (exact substring match)
                const auto beforeOpenParen = cleanSubVer.substr(0, cleanSubVer.find('('));
                for (const auto &reject : config.GetRejectSubVersions()) {
                    if (!reject.empty() && beforeOpenParen.find(reject) != beforeOpenParen.npos) {
                        if (pfrom->m_manual_connection) {
                            LogPrintf("not rejecting manually-added peer=%d with subversion containing \"%s\""
                                      " (-rejectsubversion)\n", pfrom->GetId(), reject);
                        } else if (pfrom->HasPermission(PF_NOBAN)) {
                            LogPrintf("not rejecting whitelisted peer=%d with subversion containing \"%s\""
                                      " (-rejectsubversion)\n", pfrom->GetId(), reject);
                        } else {
                            // reject peer
                            LogPrintf("rejecting peer=%d because its subversion contains \"%s\" (-rejectsubversion)\n",
                                      pfrom->GetId(), reject);
                            pfrom->fDisconnect = true;
                            return false;
                        }
                    }
                }
            }
        }
        if (!vRecv.empty()) {
            vRecv >> nStartingHeight;
        }
        if (!vRecv.empty()) {
            vRecv >> fRelay;
        }
        // Disconnect if we connected to ourself
        if (pfrom->fInbound && !connman->CheckIncomingNonce(nNonce)) {
            LogPrintf("connected to self at %s, disconnecting\n",
                      pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->fInbound && addrMe.IsRoutable()) {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound) {
            PushNodeVersion(config, pfrom, GetAdjustedTime());
        }

        pfrom->nServices = nServices;

        const CNetMsgMaker msg_maker(INIT_PROTO_VERSION);

        if (nServices & NODE_EXTVERSION && connman->GetLocalServices() & NODE_EXTVERSION) {
            // This node + peer both support extversion, so use that handshake.
            // Prepare extversion message. This must be sent before we send a verack message if extversion is enabled
            extversion::Message xver;
            xver.SetVersion(); // called with no args = set it to our version defined at compile-time.

            // Note: Some types, like CAddress (see protocol.h), are sensitive to serialization version and serialize
            // differently if serializing with INIT_PROTO_VERSION versus PROTOCOL_VERSION. We would need to take that
            // into account here if we were to ever send things like CAddress instances or other such objects in our
            // extversion message.

            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::EXTVERSION, xver));
            pfrom->extversionExpected = true;
        } else {
            // Send VERACK handshake message (regular non-extversion peer)
            PushVerACK(pfrom, nVersion);
        }

        pfrom->SetAddrLocal(addrMe);
        {
            LOCK(pfrom->cs_SubVer);
            pfrom->cleanSubVer = cleanSubVer;
        }
        pfrom->nStartingHeight = nStartingHeight;

        // set nodes not relaying blocks and tx and not serving (parts) of the
        // historical blockchain as "clients"
        pfrom->fClient = (!(nServices & NODE_NETWORK) &&
                          !(nServices & NODE_NETWORK_LIMITED));

        // set nodes not capable of serving the complete blockchain history as
        // "limited nodes"
        pfrom->m_limited_node =
            (!(nServices & NODE_NETWORK) && (nServices & NODE_NETWORK_LIMITED));

        {
            LOCK(pfrom->cs_filter);
            // set to true after we get the first filter* message
            pfrom->fRelayTxes = fRelay;
        }

        // Change version
        pfrom->SetSendVersion(nSendVersion);
        pfrom->nVersion = nVersion;

        // Potentially mark this peer as a preferred download peer.
        {
            LOCK(cs_main);
            UpdatePreferredDownload(pfrom, State(pfrom->GetId()));
        }

        if (!pfrom->fInbound) {
            // Advertise our address
            if (fListen && !IsInitialBlockDownload()) {
                CAddress addr =
                    GetLocalAddress(&pfrom->addr, pfrom->GetLocalServices());
                FastRandomContext insecure_rand;
                if (addr.IsRoutable()) {
                    LogPrint(BCLog::NET,
                             "ProcessMessages: advertising address %s\n",
                             addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                } else if (IsPeerAddrLocalGood(pfrom)) {
                    addr.SetIP(addrMe);
                    LogPrint(BCLog::NET,
                             "ProcessMessages: advertising address %s\n",
                             addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                }
            }

            // Get recent addresses - unless we're doing the extversion handshake in which case we
            // do this after sending our VERACK
            PushGetAddrOnceIfAfterVerAck(pfrom);
            connman->MarkAddressGood(pfrom->addr);
        }

        std::string remoteAddr;
        if (fLogIPs) {
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();
        }

        LogPrint(BCLog::NET,
                 "receive version message: [%s] %s: version %d, blocks=%d, "
                 "us=%s, peer=%d%s\n",
                 pfrom->addr.ToString().c_str(), cleanSubVer, pfrom->nVersion,
                 pfrom->nStartingHeight, addrMe.ToString(), pfrom->GetId(),
                 remoteAddr);

        int64_t currentTime = GetTime();
        int64_t nTimeOffset = nTime - currentTime;
        pfrom->nTimeOffset = nTimeOffset;
        if (nTime < int64_t(chainparams.GenesisBlock().nTime)) {
            // Ignore time offsets that are improbable (before the Genesis
            // block) and may underflow our adjusted time.
            LOCK(cs_main);
            Misbehaving(pfrom, 20,
                        "Ignoring invalid timestamp in version message");
        } else if (!pfrom->fInbound) {
            // Don't use timedata samples from inbound peers to make it
            // harder for others to tamper with our adjusted time.
            AddTimeData(pfrom->addr, nTimeOffset);
        }

        // Feeler connections exist only to verify if address is online.
        if (pfrom->fFeeler) {
            assert(pfrom->fInbound == false);
            pfrom->fDisconnect = true;
        }
        return true;
    }

    if (pfrom->nVersion == 0) {
        // Must have a version message before anything else
        LOCK(cs_main);
        Misbehaving(pfrom, 10, "missing-version");
        return false;
    }

    if (msg_type == NetMsgType::EXTVERSION) {
        // set expected to false, we got the message
        pfrom->extversionExpected = false;
        if (pfrom->fSuccessfullyConnected) {
            pfrom->fDisconnect = true;
            return error("peer=%d received extversion message after verack, disconnecting", pfrom->GetId());
        }

        // Throws if message size limit of 100kB is exceeded
        extversion::Message::CheckSize(vRecv.in_avail());

        {
            // Unserialize and process; lock must be held
            LOCK(pfrom->cs_extversion);
            vRecv >> pfrom->extversion;
            pfrom->extversionEnabled = true;
            pfrom->ReadConfigFromExtversion();
        }

        const CNetMsgMaker msg_maker(INIT_PROTO_VERSION);
        // Finish EXTVERSION handshake with a regular VERACK
        PushVerACK(pfrom);
        // Finish by (maybe) sending GETADDR
        PushGetAddrOnceIfAfterVerAck(pfrom);

        return true;
    }

    // At this point, the outgoing message serialization version can't change.
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());

    if (msg_type == NetMsgType::VERACK) {
        pfrom->SetRecvVersion(
            std::min(pfrom->nVersion.load(), PROTOCOL_VERSION));

        if (!pfrom->fInbound) {
            // Mark this node as currently connected, so we update its timestamp
            // later.
            LOCK(cs_main);
            State(pfrom->GetId())->fCurrentlyConnected = true;
            LogPrintf(
                "New outbound peer connected: version: %d, blocks=%d, "
                "peer=%d%s\n",
                pfrom->nVersion.load(), pfrom->nStartingHeight, pfrom->GetId(),
                (fLogIPs ? strprintf(", peeraddr=%s", pfrom->addr.ToString())
                         : ""));
        }

        if (pfrom->extversionExpected) {
            // If we expected extversion but got a verack it is possible there is a service bit
            // mismatch so we should send a verack response because the peer might not
            // support extversion
            PushVerACK(pfrom);
            // Finish by (maybe) sending GETADDR
            PushGetAddrOnceIfAfterVerAck(pfrom);
        }

        if (pfrom->nVersion >= SENDHEADERS_VERSION) {
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce blocks (such as pruning
            // nodes)
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDHEADERS));
        }
        if (pfrom->nVersion >= SHORT_IDS_BLOCKS_VERSION) {
            // Tell our peer we are willing to provide version 1 or 2
            // cmpctblocks. However, we do not request new block announcements
            // using cmpctblock messages. We send this to non-NODE NETWORK peers
            // as well, because they may wish to request compact blocks from us.
            bool fAnnounceUsingCMPCTBLOCK = false;
            uint64_t nCMPCTBLOCKVersion = 1;
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDCMPCT,
                                                      fAnnounceUsingCMPCTBLOCK,
                                                      nCMPCTBLOCKVersion));
        }
        pfrom->fSuccessfullyConnected = true;
        return true;
    }

    if (msg_type == NetMsgType::SENDADDRV2) {
        if (pfrom->fSuccessfullyConnected) {
            // Disconnect peers that send SENDADDRV2 message after VERACK; this
            // must be negotiated between VERSION and VERACK.
            pfrom->fDisconnect = true;
            return false;
        }
        pfrom->m_wants_addrv2 = true;
        return true;
    }

    if (!pfrom->fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "Unsupported message \"%s\" prior to verack from peer=%d\n", SanitizeString(msg_type),
                 pfrom->GetId());
        return true;
    }

    if (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2) {
        int stream_version = vRecv.GetVersion();
        if (msg_type == NetMsgType::ADDRV2) {
            // Add ADDRV2_FORMAT to the version so that the CNetAddr and CAddress
            // unserialize methods know that an address in v2 format is coming.
            stream_version |= ADDRV2_FORMAT;
        }

        OverrideStream<CDataStream> s(&vRecv, vRecv.GetType(), stream_version);
        std::vector<CAddress> vAddr;

        s >> vAddr;

        if (vAddr.size() > MAX_ADDR_TO_SEND) {
            LOCK(cs_main);
            Misbehaving(pfrom, 20, "oversized-addr");
            return error("%s message size = %u", msg_type, vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;

        // Update/increment addr rate limiting bucket.
        const auto current_time = GetTime<std::chrono::microseconds>();
        if (pfrom->m_addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
            // Don't increment bucket if it's already full
            const auto time_diff = std::max(current_time - pfrom->m_addr_token_timestamp, std::chrono::microseconds{0});
            const double time_diff_secs = time_diff.count() / 1e6;
            const double increment = time_diff_secs * MAX_ADDR_RATE_PER_SECOND;
            pfrom->m_addr_token_bucket = std::min<double>(pfrom->m_addr_token_bucket + increment,
                                                          MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        pfrom->m_addr_token_timestamp = current_time;
        const bool rate_limited = !pfrom->HasPermission(NetPermissionFlags::PF_ADDR);
        uint64_t num_proc = 0;
        uint64_t num_rate_limit = 0;
        if (rate_limited && size_t(pfrom->m_addr_token_bucket) < vAddr.size() && pfrom->m_addr_token_bucket >= 1.0) {
            // If we anticipate dropping some addresses due to rate-limiting,
            // ensure the ones we keep are randomly selected.
            Shuffle(vAddr.begin(), vAddr.end(), FastRandomContext());
        }

        for (CAddress &addr : vAddr) {
            if (interruptMsgProc) {
                return true;
            }

            // Apply rate limiting.
            if (pfrom->m_addr_token_bucket < 1.0) {
                if (rate_limited) {
                    ++num_rate_limit;
                    continue;
                }
            } else {
                pfrom->m_addr_token_bucket -= 1.0;
            }

            // We only bother storing full nodes, though this may include things
            // which we would not make an outbound connection to, in part
            // because we may make feeler connections to them.
            if (!MayHaveUsefulAddressDB(addr.nServices) &&
                !HasAllDesirableServiceFlags(addr.nServices)) {
                continue;
            }

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60) {
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            }
            pfrom->AddAddressKnown(addr);
            if (g_banman && (g_banman->IsDiscouraged(addr) || g_banman->IsBanned(addr))) {
                // Do not process discouraged or banned addresses beyond remembering
                // we received them
                continue;
            }
            ++num_proc;
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 &&
                addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                RelayAddress(addr, fReachable);
            }
            // Do not store addresses outside our network
            if (fReachable) {
                vAddrOk.push_back(addr);
            }
        }
        pfrom->m_addr_processed += num_proc;
        pfrom->m_addr_rate_limited += num_rate_limit;
        LogPrint(BCLog::NET, "Received addr: %u addresses (%u processed, %u rate-limited) from peer=%d\n",
                 vAddr.size(), num_proc, num_rate_limit, pfrom->GetId());

        connman->AddNewAddresses(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000) {
            pfrom->fGetAddr = false;
        }
        if (pfrom->fOneShot) {
            pfrom->fDisconnect = true;
        }
        return true;
    }

    if (msg_type == NetMsgType::SENDHEADERS) {
        LOCK(cs_main);
        State(pfrom->GetId())->fPreferHeaders = true;
        return true;
    }

    if (msg_type == NetMsgType::SENDCMPCT) {
        bool sendcmpct_hb = false;
        uint64_t sendcmpct_version = 0;
        vRecv >> sendcmpct_hb >> sendcmpct_version;
        if (sendcmpct_version == 1) {
            LOCK(cs_main);
            // fProvidesHeaderAndIDs is used to "lock in" version of compact
            // blocks we send.
            CNodeState* nodestate = State(pfrom->GetId());
            nodestate->fProvidesHeaderAndIDs = true;
            nodestate->fPreferHeaderAndIDs = sendcmpct_hb;
            nodestate->fSupportsDesiredCmpctVersion = true;
            // save whether peer selects us as BIP152 high-bandwidth peer
            // (receiving sendcmpct(1) signals high-bandwidth, sendcmpct(0) low-bandwidth)
            pfrom->m_bip152_highbandwidth_from = sendcmpct_hb;
        }
        return true;
    }

    if (msg_type == NetMsgType::INV) {
        const std::vector<CInv> vInv = [&vRecv]{
            std::vector<CInv> vInvMutable;
            vRecv >> vInvMutable;
            return vInvMutable;
        }();
        if (vInv.size() > MAX_INV_SZ) {
            LOCK(cs_main);
            Misbehaving(pfrom, 20, "oversized-inv");
            return error("message inv size() = %u", vInv.size());
        }

        bool fBlocksOnly = !g_relay_txes;

        // Allow whitelisted peers to send data other than blocks in blocks only
        // mode if whitelistrelay is true
        if (pfrom->HasPermission(PF_RELAY)) {
            fBlocksOnly = false;
        }

        LOCK(cs_main);

        const auto current_time = GetTime<std::chrono::microseconds>(); // mockable time
        const uint256 *best_block = nullptr; /* may point into vInv */

        for (const CInv &inv : vInv) {
            if (interruptMsgProc) {
                return true;
            }

            const bool fAlreadyHave = AlreadyHave(inv);
            LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(),
                     fAlreadyHave ? "have" : "new", pfrom->GetId());

            if (inv.type == MSG_BLOCK) {
                UpdateBlockAvailability(pfrom->GetId(), BlockHash{inv.hash});
                if (!fAlreadyHave && !fImporting && !fReindex && !IsBlockRequested(inv.hash)) {
                    // Headers-first is the primary method of announcement on
                    // the network. If a node fell back to sending blocks by inv,
                    // it's probably for a re-org. The final block hash
                    // provided should be the highest, so send a getheaders and
                    // then fetch the blocks we need to catch up.
                    best_block = &inv.hash;
                }
            } else {
                pfrom->AddInventoryKnown(inv);
                if (fBlocksOnly) {
                    LogPrint(BCLog::NET,
                             "transaction (%s) inv sent in violation of "
                             "protocol peer=%d\n",
                             inv.hash.ToString(), pfrom->GetId());
                } else if (!fAlreadyHave && !fImporting && !fReindex &&
                           !IsInitialBlockDownload()) {
                    if (inv.type == MSG_DOUBLESPENDPROOF) {
                        if (DoubleSpendProof::IsEnabled()) {
                            // dsproof subsystem enabled, ask peer for the proof
                            LogPrint(BCLog::DSPROOF, "Got DSProof INV %s\n", inv.hash.ToString());
                            connman->PushMessage(pfrom,
                                                 msgMaker.Make(NetMsgType::GETDATA, std::vector<CInv>{inv}));
                        } else {
                            // dsproof subsystem disabled, ignore this inv
                            LogPrint(BCLog::DSPROOF, "Got DSProof INV %s (ignored, -doublespendproof=0)\n",
                                     inv.hash.ToString());
                        }
                    }
                    else if (inv.type == MSG_TX) {
                        AddTxAnnouncement(*pfrom, TxId{inv.hash}, current_time);
                    }
                }
            }
        }

        if (best_block != nullptr) {
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, ::ChainActive().GetLocator(pindexBestHeader), *best_block));
            LogPrint(BCLog::NET, "getheaders (%d) %s to peer=%d\n", pindexBestHeader->nHeight, best_block->ToString(), pfrom->GetId());
        }

        return true;
    }

    if (msg_type == NetMsgType::GETDATA) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ) {
            LOCK(cs_main);
            Misbehaving(pfrom, 20, "too-many-inv");
            return error("message getdata size() = %u", vInv.size());
        }

        LogPrint(BCLog::NET, "received getdata (%u invsz) peer=%d\n",
                 vInv.size(), pfrom->GetId());

        if (vInv.size() > 0) {
            LogPrint(BCLog::NET, "received getdata for: %s peer=%d\n",
                     vInv[0].ToString(), pfrom->GetId());
        }

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(),
                                   vInv.end());
        ProcessGetData(config, pfrom, interruptMsgProc);
        return true;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        if (locator.vHave.size() > MAX_LOCATOR_SZ) {
            LogPrint(BCLog::NET,
                     "getblocks locator size %lld > %d, disconnect peer=%d\n",
                     locator.vHave.size(), MAX_LOCATOR_SZ, pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        // We might have announced the currently-being-connected tip using a
        // compact block, which resulted in the peer sending a getblocks
        // request, which we would otherwise respond to without the new block.
        // To avoid this situation we simply verify that we are on our best
        // known chain now. This is super overkill, but we handle it better
        // for getheaders requests, and there are no known nodes which support
        // compact blocks but still use getblocks to request blocks.
        {
            std::shared_ptr<const CBlock> a_recent_block;
            {
                LOCK(cs_most_recent_block);
                a_recent_block = most_recent_block;
            }
            CValidationState state;
            if (!ActivateBestChain(config, state, a_recent_block)) {
                LogPrint(BCLog::NET, "failed to activate chain (%s)\n",
                         FormatStateMessage(state));
            }
        }

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        const CBlockIndex *pindex =
            FindForkInGlobalIndex(::ChainActive(), locator);

        // Send the rest of the chain
        if (pindex) {
            pindex = ::ChainActive().Next(pindex);
        }
        int nLimit = 500;
        LogPrint(BCLog::NET, "getblocks %d to %s limit %d from peer=%d\n",
                 (pindex ? pindex->nHeight : -1),
                 hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit,
                 pfrom->GetId());
        for (; pindex; pindex = ::ChainActive().Next(pindex)) {
            if (pindex->GetBlockHash() == hashStop) {
                LogPrint(BCLog::NET, "  getblocks stopping at %d %s\n",
                         pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            // If pruning, don't inv blocks unless we have on disk and are
            // likely to still have for some reasonable time window (1 hour)
            // that block relay might require.
            const int nPrunedBlocksLikelyToHave =
                MIN_BLOCKS_TO_KEEP -
                3600 / chainparams.GetConsensus().nPowTargetSpacing;
            if (fPruneMode &&
                (!pindex->nStatus.hasData() ||
                 pindex->nHeight <= ::ChainActive().Tip()->nHeight -
                                        nPrunedBlocksLikelyToHave)) {
                LogPrint(
                    BCLog::NET,
                    " getblocks stopping, pruned or too old block at %d %s\n",
                    pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0) {
                // When this block is requested, we'll send an inv that'll
                // trigger the peer to getblocks the next batch of inventory.
                LogPrint(BCLog::NET, "  getblocks stopping at limit %d %s\n",
                         pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
        return true;
    }

    if (msg_type == NetMsgType::GETBLOCKTXN) {
        BlockTransactionsRequest req;
        vRecv >> req;

        std::shared_ptr<const CBlock> recent_block;
        {
            LOCK(cs_most_recent_block);
            if (most_recent_block_hash == req.blockhash) {
                recent_block = most_recent_block;
            }
            // Unlock cs_most_recent_block to avoid cs_main lock inversion
        }
        if (recent_block) {
            SendBlockTransactions(*recent_block, req, pfrom);
            return true;
        }

        LOCK(cs_main);

        const CBlockIndex *pindex = LookupBlockIndex(req.blockhash);
        if (!pindex || !pindex->nStatus.hasData()) {
            LogPrint(
                BCLog::NET,
                "Peer %d sent us a getblocktxn for a block we don't have\n",
                pfrom->GetId());
            return true;
        }

        if (pindex->nHeight < ::ChainActive().Height() - MAX_BLOCKTXN_DEPTH) {
            // If an older block is requested (should never happen in practice,
            // but can happen in tests) send a block response instead of a
            // blocktxn response. Sending a full block response instead of a
            // small blocktxn response is preferable in the case where a peer
            // might maliciously send lots of getblocktxn requests to trigger
            // expensive disk reads, because it will require the peer to
            // actually receive all the data read from disk over the network.
            LogPrint(BCLog::NET,
                     "Peer %d sent us a getblocktxn for a block > %i deep\n",
                     pfrom->GetId(), MAX_BLOCKTXN_DEPTH);
            pfrom->vRecvGetData.emplace_back(MSG_BLOCK, req.blockhash);
            // The message processing loop will go around again (without
            // pausing) and we'll respond then (without cs_main)
            return true;
        }

        CBlock block;
        bool ret = ReadBlockFromDisk(block, pindex, chainparams.GetConsensus());
        assert(ret);

        SendBlockTransactions(block, req, pfrom);
        return true;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        CBlockLocator locator;
        BlockHash hashStop;
        vRecv >> locator >> hashStop;

        if (locator.vHave.size() > MAX_LOCATOR_SZ) {
            LogPrint(BCLog::NET,
                     "getheaders locator size %lld > %d, disconnect peer=%d\n",
                     locator.vHave.size(), MAX_LOCATOR_SZ, pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        LOCK(cs_main);
        if (IsInitialBlockDownload() && !pfrom->HasPermission(PF_NOBAN)) {
            LogPrint(BCLog::NET,
                     "Ignoring getheaders from peer=%d because node is in "
                     "initial block download\n",
                     pfrom->GetId());
            return true;
        }

        CNodeState *nodestate = State(pfrom->GetId());
        const CBlockIndex *pindex = nullptr;
        if (locator.IsNull()) {
            // If locator is null, return the hashStop block
            pindex = LookupBlockIndex(hashStop);
            if (!pindex) {
                return true;
            }

            if (!BlockRequestAllowed(pindex, chainparams.GetConsensus())) {
                LogPrint(BCLog::NET,
                         "%s: ignoring request from peer=%i for old block "
                         "header that isn't in the main chain\n",
                         __func__, pfrom->GetId());
                return true;
            }
        } else {
            // Find the last block the caller has in the main chain
            pindex = FindForkInGlobalIndex(::ChainActive(), locator);
            if (pindex) {
                pindex = ::ChainActive().Next(pindex);
            }
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx
        // count at the end
        std::vector<CBlock> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        LogPrint(BCLog::NET, "getheaders %d to %s from peer=%d\n",
                 (pindex ? pindex->nHeight : -1),
                 hashStop.IsNull() ? "end" : hashStop.ToString(),
                 pfrom->GetId());
        for (; pindex; pindex = ::ChainActive().Next(pindex)) {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop) {
                break;
            }
        }
        // pindex can be nullptr either if we sent ::ChainActive().Tip() OR
        // if our peer has ::ChainActive().Tip() (and thus we are sending an
        // empty headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        //
        // It is important that we simply reset the BestHeaderSent value here,
        // and not max(BestHeaderSent, newHeaderSent). We might have announced
        // the currently-being-connected tip using a compact block, which
        // resulted in the peer sending a headers request, which we respond to
        // without the new block. By resetting the BestHeaderSent, we ensure we
        // will re-announce the new block via headers (or compact blocks again)
        // in the SendMessages logic.
        nodestate->pindexBestHeaderSent =
            pindex ? pindex : ::ChainActive().Tip();
        connman->PushMessage(pfrom,
                             msgMaker.Make(NetMsgType::HEADERS, vHeaders));
        return true;
    }

    if (msg_type == NetMsgType::TX) {
        // Stop processing the transaction early if
        // We are in blocks only mode and peer is either not whitelisted or
        // whitelistrelay is off
        if (!g_relay_txes && !pfrom->HasPermission(PF_RELAY)) {
            LogPrint(BCLog::NET,
                     "transaction sent in violation of protocol peer=%d\n",
                     pfrom->GetId());
            return true;
        }

        CTransactionRef ptx;
        vRecv >> ptx;
        const CTransaction &tx = *ptx;
        const TxId &txid = tx.GetId();

        const CInv inv(MSG_TX, txid);
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        CValidationState state;

        m_txrequest.ReceivedResponse(pfrom->GetId(), txid);

        MempoolAcceptExtraInfo info;
        if (!AlreadyHave(inv) &&
            AcceptToMemoryPool(config, g_mempool, state, ptx, &fMissingInputs,
                               false /* bypass_limits */,
                               Amount::zero() /* nAbsurdFee */, false /* test_accept */, &info)) {
            g_mempool.check(pcoinsTip.get());
            // As this version of the transaction was acceptable, we can forget about any
            // requests for it.
            m_txrequest.ForgetTxId(tx.GetId());
            RelayTransaction(tx, *Assert(info.entryId));
            m_orphanage.AddChildrenToWorkSet(tx);

            pfrom->nLastTXTime = GetTime();

            LogPrint(BCLog::MEMPOOL,
                     "AcceptToMemoryPool: peer=%d: accepted %s "
                     "(poolsz %u txn, %u kB)\n",
                     pfrom->GetId(), tx.GetId().ToString(), g_mempool.size(),
                     g_mempool.DynamicMemoryUsage() / 1000);

            // Recursively process any orphan transactions that depended on this one
            ProcessOrphanTx(config, pfrom->GetId());

        } else if (fMissingInputs) {
            // It may be the case that the orphans parents have all been
            // rejected.
            bool fRejectedParents = false;
            for (const CTxIn &txin : tx.vin) {
                if (m_recentRejects->contains(txin.prevout.GetTxId())) {
                    fRejectedParents = true;
                    break;
                }
            }
            if (!fRejectedParents) {
                const auto current_time = GetTime<std::chrono::microseconds>();

                for (const CTxIn &txin : tx.vin) {
                    // FIXME: MSG_TX should use a TxHash, not a TxId.
                    const TxId _txid = txin.prevout.GetTxId();
                    CInv _inv(MSG_TX, _txid);
                    pfrom->AddInventoryKnown(_inv);
                    if (!AlreadyHave(_inv)) {
                        AddTxAnnouncement(*pfrom, _txid, current_time);
                    }
                }

                if (m_orphanage.AddTx(ptx, pfrom->GetId())) {
                    AddToCompactExtraTransactions(ptx);
                }

                // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it anymore.
                m_txrequest.ForgetTxId(tx.GetId());

                // DoS prevention: do not allow mapOrphanTransactions to grow
                // unbounded
                const size_t nMaxOrphanTx = std::max(int64_t{0}, gArgs.GetArg("-maxorphantx",
                                                                              DEFAULT_MAX_ORPHAN_TRANSACTIONS));
                m_orphanage.LimitOrphans(nMaxOrphanTx);
            } else {
                LogPrint(BCLog::MEMPOOL,
                         "not keeping orphan with rejected parents %s\n",
                         tx.GetId().ToString());
                // We will continue to reject this tx since it has rejected
                // parents so avoid re-requesting it from other peers.
                m_recentRejects->insert(tx.GetId());
                m_txrequest.ForgetTxId(tx.GetId());
            }
        } else {
            if (!state.CorruptionPossible()) {
                assert(m_recentRejects);
                m_recentRejects->insert(tx.GetId());
                m_txrequest.ForgetTxId(tx.GetId());
                if (RecursiveDynamicUsage(*ptx) < 100000) {
                    AddToCompactExtraTransactions(ptx);
                }
            }

            if (pfrom->HasPermission(PF_FORCERELAY)) {
                // Always relay transactions received from whitelisted peers,
                // even if they were already in the mempool or rejected from it
                // due to policy, allowing the node to function as a gateway for
                // nodes hidden behind it.
                //
                // Never relay transactions that we would assign a non-zero DoS
                // score for, as we expect peers to do the same with us in that
                // case.
                int nDoS = 0;
                if (!state.IsInvalid(nDoS) || nDoS == 0) {
                    LogPrintf("Force relaying tx %s from whitelisted peer=%d\n",
                              tx.GetId().ToString(), pfrom->GetId());
                    RelayTransaction(tx, info.entryId.value_or(0));
                } else {
                    LogPrintf("Not relaying invalid transaction %s from "
                              "whitelisted peer=%d (%s)\n",
                              tx.GetId().ToString(), pfrom->GetId(),
                              FormatStateMessage(state));
                }
            }
        }

        // If a tx has been detected by recentRejects, we will have reached
        // this point and the tx will have been ignored. Because we haven't run
        // the tx through AcceptToMemoryPool, we won't have computed a DoS
        // score for it or determined exactly why we consider it invalid.
        //
        // This means we won't penalize any peer subsequently relaying a DoSy
        // tx (even if we penalized the first peer who gave it to us) because
        // we have to account for recentRejects showing false positives. In
        // other words, we shouldn't penalize a peer if we aren't *sure* they
        // submitted a DoSy tx.
        //
        // Note that recentRejects doesn't just record DoSy or invalid
        // transactions, but any tx not accepted by the mempool, which may be
        // due to node policy (vs. consensus). So we can't blanket penalize a
        // peer simply for relaying a tx that our recentRejects has caught,
        // regardless of false positives.

        int nDoS = 0;
        if (state.IsInvalid(nDoS)) {
            LogPrint(BCLog::MEMPOOLREJ,
                     "%s from peer=%d was not accepted: %s\n",
                     tx.GetHash().ToString(), pfrom->GetId(),
                     FormatStateMessage(state));
            // Never send AcceptToMemoryPool's internal codes over P2P.
            if (m_enable_bip61 && state.GetRejectCode() > 0 &&
                state.GetRejectCode() < REJECT_INTERNAL) {
                connman->PushMessage(
                    pfrom, msgMaker.Make(NetMsgType::REJECT, msg_type,
                                         uint8_t(state.GetRejectCode()),
                                         state.GetRejectReason().substr(
                                             0, MAX_REJECT_MESSAGE_LENGTH),
                                         inv.hash));
            }
            if (nDoS > 0) {
                Misbehaving(pfrom, nDoS, state.GetRejectReason());
            }
        }
        return true;
    }

    if (msg_type == NetMsgType::CMPCTBLOCK) {
        // Ignore cmpctblock received while importing
        if (fImporting || fReindex) {
            LogPrint(BCLog::NET,
                     "Unexpected cmpctblock message received from peer %d\n",
                     pfrom->GetId());
            return true;
        }

        CBlockHeaderAndShortTxIDs cmpctblock;
        vRecv >> cmpctblock;

        bool received_new_header = false;

        {
            LOCK(cs_main);

            if (!LookupBlockIndex(cmpctblock.header.hashPrevBlock)) {
                // Doesn't connect (or is genesis), instead of DoSing in
                // AcceptBlockHeader, request deeper headers
                if (!IsInitialBlockDownload()) {
                    connman->PushMessage(
                        pfrom, msgMaker.Make(
                                   NetMsgType::GETHEADERS,
                                   ::ChainActive().GetLocator(pindexBestHeader),
                                   uint256()));
                }
                return true;
            }

            if (!LookupBlockIndex(cmpctblock.header.GetHash())) {
                received_new_header = true;
            }
        }

        const CBlockIndex *pindex = nullptr;
        CValidationState state;
        if (!ProcessNewBlockHeaders(config, {cmpctblock.header}, state,
                                    &pindex)) {
            int nDoS;
            if (state.IsInvalid(nDoS)) {
                if (nDoS > 0) {
                    LogPrintf("Peer %d sent us invalid header via cmpctblock\n",
                              pfrom->GetId());
                    LOCK(cs_main);
                    Misbehaving(pfrom, nDoS, state.GetRejectReason());
                } else {
                    LogPrint(BCLog::NET,
                             "Peer %d sent us invalid header via cmpctblock\n",
                             pfrom->GetId());
                }
                return true;
            }
        }

        // When we succeed in decoding a block's txids from a cmpctblock
        // message we typically jump to the BLOCKTXN handling code, with a
        // dummy (empty) BLOCKTXN message, to re-use the logic there in
        // completing processing of the putative block (without cs_main).
        bool fProcessBLOCKTXN = false;
        CDataStream blockTxnMsg(SER_NETWORK, PROTOCOL_VERSION);

        // If we end up treating this as a plain headers message, call that as
        // well
        // without cs_main.
        bool fRevertToHeaderProcessing = false;

        // Keep a CBlock for "optimistic" compactblock reconstructions (see
        // below)
        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        bool fBlockReconstructed = false;

        {
            LOCK(cs_main);
            // If AcceptBlockHeader returned true, it set pindex
            assert(pindex);
            UpdateBlockAvailability(pfrom->GetId(), pindex->GetBlockHash());

            CNodeState *nodestate = State(pfrom->GetId());

            // If this was a new header with more work than our tip, update the
            // peer's last block announcement time
            if (received_new_header &&
                pindex->nChainWork > ::ChainActive().Tip()->nChainWork) {
                nodestate->m_last_block_announcement = GetTime();
            }

            if (pindex->nStatus.hasData()) {
                // Nothing to do here
                return true;
            }

            const auto nbrs = GetNodeBlockRequestStatus(pfrom->GetId(), pindex->GetBlockHash());

            if (pindex->nChainWork <=
                    ::ChainActive()
                        .Tip()
                        ->nChainWork || // We know something better
                pindex->nTx != 0) {
                // We had this block at some point, but pruned it
                if (nbrs.requested_block_from_this_peer) {
                    // We requested this block for some reason, but our mempool
                    // will probably be useless so we just grab the block via
                    // normal getdata.
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BLOCK, cmpctblock.header.GetHash());
                    connman->PushMessage(
                        pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                }
                return true;
            }

            // If we're not close to tip yet, give up and let parallel block
            // fetch work its magic.
            if (!nbrs.already_in_flight && !CanDirectFetch(chainparams.GetConsensus())) {
                return true;
            }

            // We want to be a bit conservative just to be extra careful about
            // DoS possibilities in compact block processing...
            if (pindex->nHeight <= ::ChainActive().Height() + 2) {
                if ((nbrs.already_in_flight < MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK
                     && nodestate->vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER)
                    || nbrs.requested_block_from_this_peer) {
                    std::list<QueuedBlock>::iterator *queuedBlockIt = nullptr;
                    if (!MarkBlockAsInFlight(config, pfrom->GetId(),
                                             pindex->GetBlockHash(),
                                             chainparams.GetConsensus(), pindex,
                                             &queuedBlockIt)) {
                        if (!(*queuedBlockIt)->partialBlock) {
                            (*queuedBlockIt)
                                ->partialBlock.reset(
                                    new PartiallyDownloadedBlock(config,
                                                                 &g_mempool));
                        } else {
                            // The block was already in flight using compact
                            // blocks from the same peer.
                            LogPrint(BCLog::NET, "Peer sent us compact block "
                                                 "we were already syncing!\n");
                            return true;
                        }
                    }

                    PartiallyDownloadedBlock &partialBlock = *(*queuedBlockIt)->partialBlock;
                    ReadStatus status = partialBlock.InitData(cmpctblock, m_vExtraTxnForCompact);
                    if (status == READ_STATUS_INVALID) {
                        // Reset in-flight state in case of whitelist
                        MarkBlockAsReceived(pindex->GetBlockHash(), pfrom->GetId());
                        Misbehaving(pfrom, 100, "invalid-cmpctblk");
                        LogPrintf("Peer %d sent us invalid compact block\n",
                                  pfrom->GetId());
                        return true;
                    } else if (status == READ_STATUS_FAILED) {
                        if (nbrs.first_in_flight) {
                            // Duplicate txindices, the block is now in-flight, so just request it.
                            std::vector<CInv> vInv(1);
                            vInv[0] = CInv(MSG_BLOCK, cmpctblock.header.GetHash());
                            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                        } else {
                            // Give up for this peer and wait for other peer(s)
                            MarkBlockAsReceived(pindex->GetBlockHash(), pfrom->GetId());
                        }
                        return true;
                    }

                    BlockTransactionsRequest req;
                    for (size_t i = 0; i < cmpctblock.BlockTxCount(); i++) {
                        if (!partialBlock.IsTxAvailable(i)) {
                            req.indices.push_back(i);
                        }
                    }
                    if (req.indices.empty()) {
                        // Dirty hack to jump to BLOCKTXN code (TODO: move
                        // message handling into their own functions)
                        BlockTransactions txn;
                        txn.blockhash = cmpctblock.header.GetHash();
                        blockTxnMsg << txn;
                        fProcessBLOCKTXN = true;
                    } else if (nbrs.first_in_flight
                               || (pfrom->m_bip152_highbandwidth_to
                                   && (!pfrom->fInbound
                                       || IsBlockRequestedFromOutbound(connman, cmpctblock.header.GetHash())
                                       || nbrs.already_in_flight < MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK - 1))) {
                        // We will try to round-trip any compact blocks we get on failure,
                        // as long as it's:
                        // - first, or
                        // - it's a hb relay peer, and:
                        //   - peer is outbound, or
                        //   - we already have an outbound attempt in flight (so we'll take what we can get), or
                        //   - it's not the final parallel download slot (which we may reserve for first outbound)
                        req.blockhash = pindex->GetBlockHash();
                        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETBLOCKTXN, req));
                    } else {
                        // Give up for this peer and wait for other peer(s)
                        MarkBlockAsReceived(pindex->GetBlockHash(), pfrom->GetId());
                    }
                } else {
                    // This block is either already in flight from a different
                    // peer, or this peer has too many blocks outstanding to
                    // download from. Optimistically try to reconstruct anyway
                    // since we might be able to without any round trips.
                    PartiallyDownloadedBlock tempBlock(config, &g_mempool);
                    ReadStatus status = tempBlock.InitData(cmpctblock, m_vExtraTxnForCompact);
                    if (status != READ_STATUS_OK) {
                        // TODO: don't ignore failures
                        return true;
                    }
                    std::vector<CTransactionRef> dummy;
                    status = tempBlock.FillBlock(*pblock, dummy);
                    if (status == READ_STATUS_OK) {
                        fBlockReconstructed = true;
                    }
                }
            } else {
                if (nbrs.requested_block_from_this_peer) {
                    // We requested this block, but its far into the future, so
                    // our mempool will probably be useless - request the block
                    // normally.
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BLOCK, cmpctblock.header.GetHash());
                    connman->PushMessage(
                        pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                    return true;
                } else {
                    // If this was an announce-cmpctblock, we want the same
                    // treatment as a header message.
                    fRevertToHeaderProcessing = true;
                }
            }
        } // cs_main

        if (fProcessBLOCKTXN) {
            return ProcessMessage(config, pfrom, NetMsgType::BLOCKTXN, blockTxnMsg, nTimeReceived, interruptMsgProc);
        }

        if (fRevertToHeaderProcessing) {
            // Headers received from HB compact block peers are permitted to be
            // relayed before full validation (see BIP 152), so we don't want to
            // disconnect the peer if the header turns out to be for an invalid
            // block.
            // Note that if a peer tries to build on an invalid chain, that will
            // be detected and the peer will be discouraged.
            return ProcessHeadersMessage(config, pfrom, {cmpctblock.header},
                                         /*punish_duplicate_invalid=*/false);
        }

        if (fBlockReconstructed) {
            // If we got here, we were able to optimistically reconstruct a
            // block that is in flight from some other peer.
            {
                LOCK(cs_main);
                mapBlockSource.emplace(pblock->GetHash(),
                                       std::make_pair(pfrom->GetId(), false));
            }
            // Setting fForceProcessing to true means that we bypass some of
            // our anti-DoS protections in AcceptBlock, which filters
            // unrequested blocks that might be trying to waste our resources
            // (eg disk space). Because we only try to reconstruct blocks when
            // we're close to caught up (via the CanDirectFetch() requirement
            // above, combined with the behavior of not requesting blocks until
            // we have a chain with at least nMinimumChainWork), and we ignore
            // compact blocks with less work than our tip, it is safe to treat
            // reconstructed compact blocks as having been requested.
            ProcessBlockFromNode(config, pfrom, pblock, /*fForceProcessing=*/true);

            // hold cs_main for CBlockIndex::IsValid()
            LOCK(cs_main);
            if (pindex->IsValid(BlockValidity::TRANSACTIONS)) {
                // Clear download state for this block, which is in process from
                // some other peer. We do this after calling. ProcessNewBlock so
                // that a malleated cmpctblock announcement can't be used to
                // interfere with block relay.
                MarkBlockAsReceived(pblock->GetHash(), std::nullopt);
            }
        }
        return true;
    }

    if (msg_type == NetMsgType::BLOCKTXN) {
        // Ignore blocktxn received while importing
        if (fImporting || fReindex) {
            LogPrint(BCLog::NET,
                     "Unexpected blocktxn message received from peer %d\n",
                     pfrom->GetId());
            return true;
        }

        BlockTransactions resp;
        vRecv >> resp;

        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        bool fBlockRead = false;
        {
            LOCK(cs_main);

            const auto nbrs = GetNodeBlockRequestStatus(pfrom->GetId(), resp.blockhash);

            if (!nbrs.requested_block_from_this_peer || !nbrs.requested_block_from_this_peer->partialBlock) {
                LogPrint(BCLog::NET,
                         "Peer %d sent us block transactions for block "
                         "we weren't expecting\n",
                         pfrom->GetId());
                return true;
            }

            PartiallyDownloadedBlock &partialBlock = *nbrs.requested_block_from_this_peer->partialBlock;
            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
            if (status == READ_STATUS_INVALID) {
                // Reset in-flight state in case of whitelist.
                MarkBlockAsReceived(resp.blockhash, pfrom->GetId());
                Misbehaving(pfrom, 100, "invalid-cmpctblk-txns");
                LogPrintf("Peer %d sent us invalid compact block/non-matching "
                          "block transactions\n",
                          pfrom->GetId());
                return true;
            } else if (status == READ_STATUS_FAILED) {
                if (nbrs.first_in_flight) {
                    // Might have collided, fall back to getdata now :(
                    std::vector<CInv> invs;
                    invs.emplace_back(MSG_BLOCK, resp.blockhash);
                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, invs));
                } else {
                    MarkBlockAsReceived(resp.blockhash, pfrom->GetId());
                    LogPrint(BCLog::NET, "Peer %d sent us a compact block but it failed to reconstruct, waiting on"
                                         " first download to complete\n", pfrom->GetId());
                    return true;
                }
            } else {
                // Block is either okay, or possibly we received
                // READ_STATUS_CHECKBLOCK_FAILED.
                // Note that CheckBlock can only fail for one of a few reasons:
                // 1. bad-proof-of-work (impossible here, because we've already
                //    accepted the header)
                // 2. merkleroot doesn't match the transactions given (already
                //    caught in FillBlock with READ_STATUS_FAILED, so
                //    impossible here)
                // 3. the block is otherwise invalid (eg invalid coinbase,
                //    block is too big, etc).
                // So if CheckBlock failed, #3 is the only possibility.
                // Under BIP 152, we don't DoS-discourage unless proof of work is
                // invalid (we don't require all the stateless checks to have
                // been run). This is handled below, so just treat this as
                // though the block was successfully read, and rely on the
                // handling in ProcessNewBlock to ensure the block index is
                // updated, reject messages go out, etc.

                // `partialBlock` will now be a dangling reference
                MarkBlockAsReceived(resp.blockhash, pfrom->GetId());
                fBlockRead = true;
                // mapBlockSource is only used for sending reject messages and
                // DoS scores, so the race between here and cs_main in
                // ProcessNewBlock is fine. BIP 152 permits peers to relay
                // compact blocks after validating the header only; we should
                // not punish peers if the block turns out to be invalid.
                mapBlockSource.emplace(resp.blockhash,
                                       std::make_pair(pfrom->GetId(), false));
            }
        } // Don't hold cs_main when we call into ProcessNewBlock
        if (fBlockRead) {
            // Since we requested this block (it was in mapBlocksInFlight),
            // force it to be processed, even if it would not be a candidate for
            // new tip (missing previous block, chain not long enough, etc)
            // This bypasses some anti-DoS logic in AcceptBlock (eg to prevent
            // disk-space attacks), but this should be safe due to the
            // protections in the compact block handler -- see related comment
            // in compact block optimistic reconstruction handling.
            ProcessBlockFromNode(config, pfrom, pblock, /*fForceProcessing=*/true);
        }
        return true;
    }

    if (msg_type == NetMsgType::HEADERS) {
        // Ignore headers received while importing
        if (fImporting || fReindex) {
            LogPrint(BCLog::NET,
                     "Unexpected headers message received from peer %d\n",
                     pfrom->GetId());
            return true;
        }

        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk
        // deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            LOCK(cs_main);
            Misbehaving(pfrom, 20, "too-many-headers");
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) {
            vRecv >> headers[n];
            // Ignore tx count; assume it is 0.
            ReadCompactSize(vRecv);
        }

        // Headers received via a HEADERS message should be valid, and reflect
        // the chain the peer is on. If we receive a known-invalid header,
        // disconnect the peer if it is using one of our outbound connection
        // slots.
        bool should_punish = !pfrom->fInbound && !pfrom->m_manual_connection;
        return ProcessHeadersMessage(config, pfrom, headers, should_punish);
    }

    if (msg_type == NetMsgType::BLOCK) {
        // Ignore block received while importing
        if (fImporting || fReindex) {
            LogPrint(BCLog::NET,
                     "Unexpected block message received from peer %d\n",
                     pfrom->GetId());
            return true;
        }

        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        vRecv >> *pblock;

        LogPrint(BCLog::NET, "received block %s peer=%d\n",
                 pblock->GetHash().ToString(), pfrom->GetId());

        // Process all blocks from whitelisted peers, even if not requested,
        // unless we're still syncing with the network. Such an unrequested
        // block may still be processed, subject to the conditions in
        // AcceptBlock().
        bool forceProcessing =
            pfrom->HasPermission(PF_NOBAN) && !IsInitialBlockDownload();
        const uint256 hash(pblock->GetHash());
        {
            LOCK(cs_main);
            // Also always process if we requested the block explicitly, as we
            // may need it even though it is not a candidate for a new best tip.
            forceProcessing |= MarkBlockAsReceived(hash, pfrom->GetId());
            // mapBlockSource is only used for sending reject messages and DoS
            // scores, so the race between here and cs_main in ProcessNewBlock
            // is fine.
            mapBlockSource.emplace(hash, std::make_pair(pfrom->GetId(), true));
        }
        ProcessBlockFromNode(config, pfrom, pblock, forceProcessing);
        return true;
    }

    if (msg_type == NetMsgType::GETADDR) {
        // This asymmetric behavior for inbound and outbound connections was
        // introduced to prevent a fingerprinting attack: an attacker can send
        // specific fake addresses to users' AddrMan and later request them by
        // sending getaddr messages. Making nodes which are behind NAT and can
        // only make outgoing connections ignore the getaddr message mitigates
        // the attack.
        if (!pfrom->fInbound) {
            LogPrint(BCLog::NET,
                     "Ignoring \"getaddr\" from outbound connection. peer=%d\n",
                     pfrom->GetId());
            return true;
        }

        // Only send one GetAddr response per connection to reduce resource
        // waste and discourage addr stamping of INV announcements.
        if (pfrom->fSentAddr) {
            LogPrint(BCLog::NET, "Ignoring repeated \"getaddr\". peer=%d\n",
                     pfrom->GetId());
            return true;
        }
        pfrom->fSentAddr = true;

        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr;
        if (pfrom->HasPermission(PF_ADDR)) {
            vAddr = connman->GetAddresses(MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND);
        } else {
            // send a cached set of addresses so as to prevent topology leaks
            vAddr = connman->GetAddressesUntrusted(*pfrom, MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND);
        }
        FastRandomContext insecure_rand;
        for (const CAddress &addr : vAddr) {
            pfrom->PushAddress(addr, insecure_rand);
        }
        return true;
    }

    if (msg_type == NetMsgType::MEMPOOL) {
        if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
            !pfrom->HasPermission(PF_MEMPOOL)) {
            if (!pfrom->HasPermission(PF_NOBAN)) {
                LogPrint(BCLog::NET,
                         "mempool request with bloom filters disabled, "
                         "disconnect peer=%d\n",
                         pfrom->GetId());
                pfrom->fDisconnect = true;
            }
            return true;
        }

        if (connman->OutboundTargetReached(false) &&
            !pfrom->HasPermission(PF_MEMPOOL)) {
            if (!pfrom->HasPermission(PF_NOBAN)) {
                LogPrint(BCLog::NET,
                         "mempool request with bandwidth limit reached, "
                         "disconnect peer=%d\n",
                         pfrom->GetId());
                pfrom->fDisconnect = true;
            }
            return true;
        }

        LOCK(pfrom->cs_inventory);
        pfrom->fSendMempool = true;
        return true;
    }

    if (msg_type == NetMsgType::PING) {
        if (pfrom->nVersion > BIP0031_VERSION) {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful
            // features:
            //
            // 1) A remote node can quickly check if the connection is
            // operational.
            // 2) Remote nodes can measure the latency of the network thread. If
            // this node is overloaded it won't respond to pings quickly and the
            // remote node can avoid sending us more work, like chain download
            // requests.
            //
            // The nonce stops the remote getting confused between different
            // pings: without it, if the remote node sends a ping once per
            // second and this node takes 5 seconds to respond to each, the 5th
            // ping the remote sends would appear to return very quickly.
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PONG, nonce));
        }
        return true;
    }

    if (msg_type == NetMsgType::PONG) {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old
            // ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer
                    // outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        pfrom->nMinPingUsecTime = std::min(
                            pfrom->nMinPingUsecTime.load(), pingUsecTime);
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation
                        // somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere;
            // cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint(BCLog::NET,
                     "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                     pfrom->GetId(), sProblem, pfrom->nPingNonceSent, nonce,
                     nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
        return true;
    }

    if (msg_type == NetMsgType::FILTERLOAD) {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints()) {
            // There is no excuse for sending a too-large filter
            LOCK(cs_main);
            Misbehaving(pfrom, 100, "oversized-bloom-filter");
        } else {
            LOCK(pfrom->cs_filter);
            pfrom->pfilter.reset(new CBloomFilter(filter));
            pfrom->fRelayTxes = true;
        }
        return true;
    }

    if (msg_type == NetMsgType::FILTERADD) {
        std::vector<uint8_t> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a
        // script data object, and thus, the maximum size any matched object can
        // have) in a filteradd message.
        bool bad = false;
        // NOTE: We use MAX_SCRIPT_ELEMENT_SIZE_LEGACY here even if the more geneous VM limits are enabled because of
        // the current p2p protocol spec. Add a FILTERADD2 message to support larger scripts, if the need arises.
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE_LEGACY) {
            bad = true;
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter) {
                pfrom->pfilter->insert(vData);
            } else {
                bad = true;
            }
        }
        if (bad) {
            LOCK(cs_main);
            // The structure of this code doesn't really allow for a good error
            // code. We'll go generic.
            Misbehaving(pfrom, 100, "invalid-filteradd");
        }
        return true;
    }

    if (msg_type == NetMsgType::FILTERCLEAR) {
        LOCK(pfrom->cs_filter);
        if (pfrom->GetLocalServices() & NODE_BLOOM) {
            pfrom->pfilter.reset(new CBloomFilter());
        }
        pfrom->fRelayTxes = true;
        return true;
    }

    if (msg_type == NetMsgType::FEEFILTER) {
        Amount newFeeFilter = Amount::zero();
        vRecv >> newFeeFilter;
        if (MoneyRange(newFeeFilter)) {
            {
                LOCK(pfrom->cs_feeFilter);
                pfrom->minFeeFilter = newFeeFilter;
            }
            LogPrint(BCLog::NET, "received: feefilter of %s from peer=%d\n",
                     CFeeRate(newFeeFilter).ToString(), pfrom->GetId());
        }
        return true;
    }

    if (msg_type == NetMsgType::DSPROOF) {
        LogPrint(BCLog::DSPROOF, "Received a Double Spend Proof from peer %d\n", pfrom->GetId());
        if (!DoubleSpendProof::IsEnabled()) {
            // -doublespendproof=0; dsproof subsystem disabled. Accept the message, but don't act on it.
            //
            // Note: this branch should not normally be taken, since we would never GETDATA on an inv of type
            // MSG_DOUBLESPENDPROOF if the dsproof subsystem is disabled. However, if we ever enable dynamic runtime
            // tweaks to enable/disable dsproofs in the future, then this branch could potentially be taken then.
            LogPrint(BCLog::DSPROOF, "  dsproof subsystem is disabled, ignoring message\n");
            return true;
        }
        DoubleSpendProof dsp;
        CTransactionRef addedForTx; // if !nullptr, the proof validated and we should broadcast the inv
        // whitelisted peers are marked with -1 so they do not get punished for invalid proofs
        const auto bannablePeerId = pfrom->HasPermission(PF_NOBAN) ? -1 : pfrom->GetId();
        try {
            vRecv >> dsp;
            // NOTE: We must hold cs_main and pool.cs here to get a "transactional"
            // and consistent view of the mempool while we perform the validation
            // operation & add operations.
            // See: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/merge_requests/700#note_417716740
            // Also see: The comments in txmempool.h about mempool consistency guarantees.
            LOCK2(cs_main, g_mempool.cs);
            switch ( dsp.validate(g_mempool) ) {
            case DoubleSpendProof::Valid:
                addedForTx = g_mempool.addDoubleSpendProof(dsp);
                break;
            case DoubleSpendProof::MissingUTXO:
            case DoubleSpendProof::MissingTransaction:
                LogPrint(BCLog::DSPROOF, "DoubleSpend Proof postponed: is orphan (outpoint: %s)\n", dsp.outPoint().ToString());
                g_mempool.doubleSpendProofStorage()->addOrphan(dsp, bannablePeerId);
                break;
            case DoubleSpendProof::Invalid:
            default:
                throw std::runtime_error(strprintf("Proof didn't validate (%s)", dsp.GetId().ToString()));
            }
        } catch (const std::exception &e) {
            LogPrint(BCLog::DSPROOF, "Failure handling double spend proof. Peer: %d Reason: %s\n", pfrom->GetId(), e.what());
            if (!dsp.GetId().IsNull())
                g_mempool.doubleSpendProofStorage()->markProofRejected(dsp.GetId());
            if (bannablePeerId > -1) {
                // signal that a bad proof was seen & punish peer
                GetMainSignals().BadDSProofsDetectedFromNodeIds(std::vector<NodeId>(1, bannablePeerId));
            }
            return false;
        }
        if (addedForTx && !dsp.GetId().IsNull()) { // added to mempool correctly, forward to nodes.
            const auto &dspId = dsp.GetId();
            LogPrint(BCLog::DSPROOF, "  Good DSP (tx: %s  dspId: %s  outpoint: %s)\n",
                                     addedForTx->GetId().ToString(), dspId.ToString(), dsp.outPoint().ToString());
            // broadcast inv to peers and/or tell other subsystems about this dsp<->tx association
            GetMainSignals().TransactionDoubleSpent(addedForTx, dspId);
        }

        return true;
    }

    if (msg_type == NetMsgType::NOTFOUND) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() <= MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            LOCK(cs_main);
            for (const CInv &inv : vInv) {
                if (inv.type == MSG_TX) {
                    // completed in TxRequestTracker.
                    m_txrequest.ReceivedResponse(pfrom->GetId(), TxId{inv.hash});
                }
            }
        }
        return true;
    }

    // Ignore unknown commands for extensibility
    LogPrint(BCLog::NET, "Unknown command \"%s\" from peer=%d\n",
             SanitizeString(msg_type), pfrom->GetId());
    return true;
}

bool PeerLogicValidation::SendRejectsAndCheckIfShouldDiscourage(const NodeRef &pnode) const EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    AssertLockHeld(cs_main);
    CNodeState &state = *State(pnode->GetId());

    if (m_enable_bip61) {
        for (const CBlockReject &reject : state.rejects) {
            connman->PushMessage(
                pnode,
                CNetMsgMaker(INIT_PROTO_VERSION)
                    .Make(NetMsgType::REJECT, std::string(NetMsgType::BLOCK),
                          reject.chRejectCode, reject.strRejectReason,
                          reject.hashBlock));
        }
    }
    state.rejects.clear();

    if (state.fShouldDiscourage) {
        state.fShouldDiscourage = false;
        if (pnode->HasPermission(PF_NOBAN)) {
            LogPrintf("Warning: not punishing whitelisted peer %s!\n",
                      pnode->addr.ToString());
        } else if (pnode->m_manual_connection) {
            LogPrintf("Warning: not punishing manually-connected peer %s!\n",
                      pnode->addr.ToString());
        } else if (pnode->addr.IsLocal()) {
            // Disconnect but don't discourage _this_ local node
            LogPrintf("Warning: disconnecting but not discouraging local peer %s!\n",
                      pnode->addr.ToString());
            pnode->fDisconnect = true;
        } else {
            // Disconnect and discourage all nodes sharing the address
            if (m_banman) {
                m_banman->Discourage(pnode->addr);
            }
            connman->DisconnectNode(pnode->addr);
        }
        return true;
    }
    return false;
}

bool PeerLogicValidation::ProcessMessages(const Config &config, NodeRef pfrom, std::atomic<bool> &interruptMsgProc) {
    const CChainParams &chainparams = config.GetChainParams();
    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fMoreWork = false;

    if (!pfrom->vRecvGetData.empty()) {
        ProcessGetData(config, pfrom, interruptMsgProc);
    }

    {
        LOCK(cs_main);
        if (m_orphanage.HaveTxToReconsider(pfrom->GetId())) {
            ProcessOrphanTx(config, pfrom->GetId());
        }

    }

    if (pfrom->fDisconnect) {
        return false;
    }

    // this maintains the order of responses and prevents vRecvGetData from
    // growing unbounded
    if (!pfrom->vRecvGetData.empty()) {
        return true;
    }

    {
        LOCK(cs_main);
        if (m_orphanage.HaveTxToReconsider(pfrom->GetId())) {
            return true;
        }
    }

    // Don't bother if send buffer is too full to respond anyway
    if (pfrom->fPauseSend) {
        return false;
    }

    std::list<CNetMessage> msgs;
    {
        LOCK(pfrom->cs_vProcessMsg);
        if (pfrom->vProcessMsg.empty()) {
            return false;
        }
        // Just take one message
        msgs.splice(msgs.begin(), pfrom->vProcessMsg,
                    pfrom->vProcessMsg.begin());
        pfrom->nProcessQueueSize -=
            msgs.front().vRecv.size() + CMessageHeader::HEADER_SIZE;
        pfrom->fPauseRecv =
            pfrom->nProcessQueueSize > connman->GetReceiveFloodSize();
        fMoreWork = !pfrom->vProcessMsg.empty();
    }
    CNetMessage &msg(msgs.front());

    msg.SetVersion(pfrom->GetRecvVersion());

    // Scan for message start
    if (memcmp(std::begin(msg.hdr.pchMessageStart),
               std::begin(chainparams.NetMagic()),
               CMessageHeader::MESSAGE_START_SIZE) != 0) {
        LogPrint(BCLog::NET,
                 "PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n",
                 SanitizeString(msg.hdr.GetCommand()), pfrom->GetId());

        // Make sure we discourage and disconnect where that come from
        if (m_banman) {
            m_banman->Discourage(pfrom->addr);
        }
        connman->DisconnectNode(pfrom->addr);

        pfrom->fDisconnect = true;
        return false;
    }

    // Read header
    CMessageHeader &hdr = msg.hdr;
    if (!hdr.IsValid(config)) {
        LogPrint(BCLog::NET, "PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n",
                 SanitizeString(hdr.GetCommand()), pfrom->GetId());
        return fMoreWork;
    }
    std::string msg_type = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;

    // Checksum
    CDataStream &vRecv = msg.vRecv;
    const uint256 &hash = msg.GetMessageHash();
    if (std::memcmp(hash.data(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): CHECKSUM ERROR expected %s was %s from peer=%d\n", __func__,
                 SanitizeString(msg_type), nMessageSize, HexStr(Span{hash}.first(CMessageHeader::CHECKSUM_SIZE)),
                 HexStr(hdr.pchChecksum), pfrom->GetId());
        if (m_banman) {
            m_banman->Discourage(pfrom->addr);
        }
        connman->DisconnectNode(pfrom->addr);
        return fMoreWork;
    }

    // Process message
    bool fRet = false;
    try {
        fRet = ProcessMessage(config, pfrom, msg_type, vRecv, msg.nTime, interruptMsgProc);
        if (interruptMsgProc) {
            return false;
        }

        if (!pfrom->vRecvGetData.empty()) {
            fMoreWork = true;
        }
    } catch (const std::exception& e) {
        if (m_enable_bip61) {
            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION)
                                            .Make(NetMsgType::REJECT, msg_type, REJECT_MALFORMED,
                                                  std::string("error parsing message")));
        }
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Exception '%s' (%s) caught\n", __func__, SanitizeString(msg_type),
                 nMessageSize, e.what(), typeid(e).name());
    } catch (...) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Unknown exception caught\n", __func__, SanitizeString(msg_type),
                 nMessageSize);
    }

    if (!fRet) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes) FAILED peer=%d\n", __func__,
                 SanitizeString(msg_type), nMessageSize, pfrom->GetId());
    }

    LOCK(cs_main);
    SendRejectsAndCheckIfShouldDiscourage(pfrom);

    return fMoreWork;
}

void PeerLogicValidation::ConsiderEviction(const NodeRef &pto, int64_t time_in_seconds) {
    AssertLockHeld(cs_main);

    auto *pstate = State(pto->GetId());
    assert(pstate != nullptr);
    CNodeState &state = *pstate;
    const CNetMsgMaker msgMaker(pto->GetSendVersion());

    if (!state.m_chain_sync.m_protect &&
        IsOutboundDisconnectionCandidate(pto) && state.fSyncStarted) {
        // This is an outbound peer subject to disconnection if they don't
        // announce a block with as much work as the current tip within
        // CHAIN_SYNC_TIMEOUT + HEADERS_RESPONSE_TIME seconds (note: if their
        // chain has more work than ours, we should sync to it, unless it's
        // invalid, in which case we should find that out and disconnect from
        // them elsewhere).
        if (state.pindexBestKnownBlock != nullptr &&
            state.pindexBestKnownBlock->nChainWork >=
                ::ChainActive().Tip()->nChainWork) {
            if (state.m_chain_sync.m_timeout != 0) {
                state.m_chain_sync.m_timeout = 0;
                state.m_chain_sync.m_work_header = nullptr;
                state.m_chain_sync.m_sent_getheaders = false;
            }
        } else if (state.m_chain_sync.m_timeout == 0 ||
                   (state.m_chain_sync.m_work_header != nullptr &&
                    state.pindexBestKnownBlock != nullptr &&
                    state.pindexBestKnownBlock->nChainWork >=
                        state.m_chain_sync.m_work_header->nChainWork)) {
            // Our best block known by this peer is behind our tip, and we're
            // either noticing that for the first time, OR this peer was able to
            // catch up to some earlier point where we checked against our tip.
            // Either way, set a new timeout based on current tip.
            state.m_chain_sync.m_timeout = time_in_seconds + CHAIN_SYNC_TIMEOUT;
            state.m_chain_sync.m_work_header = ::ChainActive().Tip();
            state.m_chain_sync.m_sent_getheaders = false;
        } else if (state.m_chain_sync.m_timeout > 0 &&
                   time_in_seconds > state.m_chain_sync.m_timeout) {
            // No evidence yet that our peer has synced to a chain with work
            // equal to that of our tip, when we first detected it was behind.
            // Send a single getheaders message to give the peer a chance to
            // update us.
            if (state.m_chain_sync.m_sent_getheaders) {
                // They've run out of time to catch up!
                LogPrintf(
                    "Disconnecting outbound peer %d for old chain, best known "
                    "block = %s\n",
                    pto->GetId(),
                    state.pindexBestKnownBlock != nullptr
                        ? state.pindexBestKnownBlock->GetBlockHash().ToString()
                        : "<none>");
                pto->fDisconnect = true;
            } else {
                assert(state.m_chain_sync.m_work_header);
                LogPrint(
                    BCLog::NET,
                    "sending getheaders to outbound peer=%d to verify chain "
                    "work (current best known block:%s, benchmark blockhash: "
                    "%s)\n",
                    pto->GetId(),
                    state.pindexBestKnownBlock != nullptr
                        ? state.pindexBestKnownBlock->GetBlockHash().ToString()
                        : "<none>",
                    state.m_chain_sync.m_work_header->GetBlockHash()
                        .ToString());
                connman->PushMessage(
                    pto,
                    msgMaker.Make(NetMsgType::GETHEADERS,
                                  ::ChainActive().GetLocator(
                                      state.m_chain_sync.m_work_header->pprev),
                                  uint256()));
                state.m_chain_sync.m_sent_getheaders = true;
                // 2 minutes
                constexpr int64_t HEADERS_RESPONSE_TIME = 120;
                // Bump the timeout to allow a response, which could clear the
                // timeout (if the response shows the peer has synced), reset
                // the timeout (if the peer syncs to the required work but not
                // to our tip), or result in disconnect (if we advance to the
                // timeout and pindexBestKnownBlock has not sufficiently
                // progressed)
                state.m_chain_sync.m_timeout =
                    time_in_seconds + HEADERS_RESPONSE_TIME;
            }
        }
    }
}

void PeerLogicValidation::EvictExtraOutboundPeers(int64_t time_in_seconds) {
    // Check whether we have too many outbound peers
    int extra_peers = connman->GetExtraOutboundCount();
    if (extra_peers <= 0) {
        return;
    }

    // If we have more outbound peers than we target, disconnect one.
    // Pick the outbound peer that least recently announced us a new block, with
    // ties broken by choosing the more recent connection (higher node id)
    NodeId worst_peer = -1;
    int64_t oldest_block_announcement = std::numeric_limits<int64_t>::max();

    connman->ForEachNode([&](const NodeRef &pnode) {
        AssertLockHeld(cs_main);

        // Ignore non-outbound peers, or nodes marked for disconnect already
        if (!IsOutboundDisconnectionCandidate(pnode) || pnode->fDisconnect) {
            return;
        }
        CNodeState *state = State(pnode->GetId());
        if (state == nullptr) {
            // shouldn't be possible, but just in case
            return;
        }
        // Don't evict our protected peers
        if (state->m_chain_sync.m_protect) {
            return;
        }
        if (state->m_last_block_announcement < oldest_block_announcement ||
            (state->m_last_block_announcement == oldest_block_announcement &&
             pnode->GetId() > worst_peer)) {
            worst_peer = pnode->GetId();
            oldest_block_announcement = state->m_last_block_announcement;
        }
    });

    if (worst_peer == -1) {
        return;
    }

    bool disconnected = connman->ForNode(worst_peer, [&](const NodeRef &pnode) {
        AssertLockHeld(cs_main);

        // Only disconnect a peer that has been connected to us for some
        // reasonable fraction of our check-frequency, to give it time for new
        // information to have arrived.
        // Also don't disconnect any peer we're trying to download a block from.
        CNodeState &state = *State(pnode->GetId());
        if (time_in_seconds - pnode->nTimeConnected > MINIMUM_CONNECT_TIME && state.vBlocksInFlight.empty()) {
            LogPrint(BCLog::NET,
                     "disconnecting extra outbound peer=%d (last block "
                     "announcement received at time %d)\n",
                     pnode->GetId(), oldest_block_announcement);
            pnode->fDisconnect = true;
            return true;
        } else {
            LogPrint(BCLog::NET,
                     "keeping outbound peer=%d chosen for eviction "
                     "(connect time: %d, blocks_in_flight: %d)\n",
                     pnode->GetId(), pnode->nTimeConnected,
                     state.vBlocksInFlight.size());
            return false;
        }
    });

    if (disconnected) {
        // If we disconnected an extra peer, that means we successfully
        // connected to at least one peer after the last time we detected a
        // stale tip. Don't try any more extra peers until we next detect a
        // stale tip, to limit the load we put on the network from these extra
        // connections.
        connman->SetTryNewOutboundPeer(false);
    }
}

void PeerLogicValidation::CheckForStaleTipAndEvictPeers(
    const Consensus::Params &consensusParams) {
    LOCK(cs_main);

    if (connman == nullptr) {
        return;
    }

    int64_t time_in_seconds = GetTime();

    EvictExtraOutboundPeers(time_in_seconds);

    if (time_in_seconds <= m_stale_tip_check_time) {
        return;
    }

    // Check whether our tip is stale, and if so, allow using an extra outbound
    // peer.
    if (!fImporting && !fReindex && connman->GetNetworkActive() &&
        connman->GetUseAddrmanOutgoing() && TipMayBeStale(consensusParams)) {
        LogPrintf("Potential stale tip detected, will try using extra outbound "
                  "peer (last tip update: %d seconds ago)\n",
                  time_in_seconds - g_last_tip_update);
        connman->SetTryNewOutboundPeer(true);
    } else if (connman->GetTryNewOutboundPeer()) {
        connman->SetTryNewOutboundPeer(false);
    }
    m_stale_tip_check_time = time_in_seconds + STALE_CHECK_INTERVAL;
}

bool PeerLogicValidation::SendMessages(const Config &config, NodeRef pto,
                                       std::atomic<bool> &interruptMsgProc [[maybe_unused]]) {
    const Consensus::Params &consensusParams =
        config.GetChainParams().GetConsensus();

    // Don't send anything until the version handshake is complete
    if (!pto->fSuccessfullyConnected || pto->fDisconnect) {
        return true;
    }

    // If we get here, the outgoing message serialization version is set and
    // can't change.
    const CNetMsgMaker msgMaker(pto->GetSendVersion());

    const int64_t nNow = GetTimeMicros(); // non-mockable time
    const auto current_time = GetTime<std::chrono::microseconds>(); // mockable time
    const int64_t current_time_secs = std::chrono::duration_cast<std::chrono::seconds>(current_time).count();

    //
    // Message: ping
    //
    bool pingSend = false;
    if (pto->fPingQueued) {
        // RPC ping request by user
        pingSend = true;
    }
    if (pto->nPingNonceSent == 0 &&
        pto->nPingUsecStart + PING_INTERVAL * 1000000 < nNow) {
        // Ping automatically sent as a latency probe & keepalive.
        pingSend = true;
    }
    if (pingSend) {
        uint64_t nonce = 0;
        while (nonce == 0) {
            GetRandBytes((uint8_t *)&nonce, sizeof(nonce));
        }
        pto->fPingQueued = false;
        pto->nPingUsecStart = nNow;
        if (pto->nVersion > BIP0031_VERSION) {
            pto->nPingNonceSent = nonce;
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce));
        } else {
            // Peer is too old to support ping command with nonce, pong will
            // never arrive.
            pto->nPingNonceSent = 0;
            connman->PushMessage(pto, msgMaker.Make(NetMsgType::PING));
        }
    }

    // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain) {
        return true;
    }

    if (SendRejectsAndCheckIfShouldDiscourage(pto)) {
        return true;
    }
    CNodeState &state = *State(pto->GetId());

    // Address refresh broadcast
    if (!IsInitialBlockDownload() && pto->m_next_local_addr_send < current_time) {
        AdvertiseLocal(pto);
        pto->m_next_local_addr_send = PoissonNextSend(current_time, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
    }

    //
    // Message: addr
    //
    if (pto->m_next_addr_send < current_time) {
        pto->m_next_addr_send = PoissonNextSend(current_time, AVG_ADDRESS_BROADCAST_INTERVAL);
        std::vector<CAddress> vAddr;
        vAddr.reserve(pto->vAddrToSend.size());

        const char *msg_type;
        int make_flags;
        if (pto->m_wants_addrv2) {
            msg_type = NetMsgType::ADDRV2;
            make_flags = ADDRV2_FORMAT;
        } else {
            msg_type = NetMsgType::ADDR;
            make_flags = 0;
        }

        for (const CAddress &addr : pto->vAddrToSend) {
            if (!pto->addrKnown.contains(addr.GetKey())) {
                pto->addrKnown.insert(addr.GetKey());
                vAddr.push_back(addr);
                // receiver rejects addr messages larger than MAX_ADDR_TO_SEND
                if (vAddr.size() >= MAX_ADDR_TO_SEND) {
                    connman->PushMessage(pto, msgMaker.Make(make_flags, msg_type, vAddr));
                    vAddr.clear();
                }
            }
        }
        pto->vAddrToSend.clear();
        if (!vAddr.empty()) {
            connman->PushMessage(pto, msgMaker.Make(make_flags, msg_type, vAddr));
        }

        // we only send the big addr message once
        if (pto->vAddrToSend.capacity() > 40) {
            pto->vAddrToSend.shrink_to_fit();
        }
    }

    // Start block sync
    if (pindexBestHeader == nullptr) {
        pindexBestHeader = ::ChainActive().Tip();
    }

    // Download if this is a nice peer, or we have no nice peers and this one
    // might do.
    bool fFetch = state.fPreferredDownload ||
                  (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot);

    if (!state.fSyncStarted && !pto->fClient && !fImporting && !fReindex) {
        // Only actively request headers from a single peer, unless we're close
        // to today.
        if ((nSyncStarted == 0 && fFetch) ||
            pindexBestHeader->GetBlockTime() >
                GetAdjustedTime() - 24 * 60 * 60) {
            state.fSyncStarted = true;
            state.nHeadersSyncTimeout =
                nNow + HEADERS_DOWNLOAD_TIMEOUT_BASE +
                HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER *
                    (GetAdjustedTime() - pindexBestHeader->GetBlockTime()) /
                    (consensusParams.nPowTargetSpacing);
            nSyncStarted++;
            const CBlockIndex *pindexStart = pindexBestHeader;
            /**
             * If possible, start at the block preceding the currently best
             * known header. This ensures that we always get a non-empty list of
             * headers back as long as the peer is up-to-date. With a non-empty
             * response, we can initialise the peer's known best block. This
             * wouldn't be possible if we requested starting at pindexBestHeader
             * and got back an empty response.
             */
            if (pindexStart->pprev) {
                pindexStart = pindexStart->pprev;
            }

            LogPrint(BCLog::NET,
                     "initial getheaders (%d) to peer=%d (startheight:%d)\n",
                     pindexStart->nHeight, pto->GetId(), pto->nStartingHeight);
            connman->PushMessage(
                pto, msgMaker.Make(NetMsgType::GETHEADERS,
                                   ::ChainActive().GetLocator(pindexStart),
                                   uint256()));
        }
    }

    // Resend wallet transactions that haven't gotten in a block yet
    // Except during reindex, importing and IBD, when old wallet transactions
    // become unconfirmed and spams other nodes.
    //
    // Additionally, we rate limit this signal to at most once per second,
    // since spamming this signal too often can waste cycles, and the wallet
    // doesn't need this to fire more frequently than once per second anyway.
    if (std::abs(nNow - m_last_bcast_sig_time) >= 1'000'000 && !fReindex && !fImporting && !IsInitialBlockDownload()) {
        m_last_bcast_sig_time = nNow;
        GetMainSignals().Broadcast(nTimeBestReceived, connman);
    }

    //
    // Try sending block announcements via headers
    //
    {
        // If we have less than MAX_BLOCKS_TO_ANNOUNCE in our list of block
        // hashes we're relaying, and our peer wants headers announcements, then
        // find the first header not yet known to our peer but would connect,
        // and send. If no header would connect, or if we have too many blocks,
        // or if the peer doesn't want headers, just add all to the inv queue.
        LOCK(pto->cs_inventory);
        std::vector<CBlock> vHeaders;
        bool fRevertToInv =
            ((!state.fPreferHeaders &&
              (!state.fPreferHeaderAndIDs ||
               pto->vBlockHashesToAnnounce.size() > 1)) ||
             pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
        // last header queued for delivery
        const CBlockIndex *pBestIndex = nullptr;
        // ensure pindexBestKnownBlock is up-to-date
        ProcessBlockAvailability(pto->GetId());

        if (!fRevertToInv) {
            bool fFoundStartingHeader = false;
            // Try to find first header that our peer doesn't have, and then
            // send all headers past that one. If we come across an headers that
            // aren't on ::ChainActive(), give up.
            for (const BlockHash &hash : pto->vBlockHashesToAnnounce) {
                const CBlockIndex *pindex = LookupBlockIndex(hash);
                assert(pindex);
                if (::ChainActive()[pindex->nHeight] != pindex) {
                    // Bail out if we reorged away from this block
                    fRevertToInv = true;
                    break;
                }
                if (pBestIndex != nullptr && pindex->pprev != pBestIndex) {
                    // This means that the list of blocks to announce don't
                    // connect to each other. This shouldn't really be possible
                    // to hit during regular operation (because reorgs should
                    // take us to a chain that has some block not on the prior
                    // chain, which should be caught by the prior check), but
                    // one way this could happen is by using invalidateblock /
                    // reconsiderblock repeatedly on the tip, causing it to be
                    // added multiple times to vBlockHashesToAnnounce. Robustly
                    // deal with this rare situation by reverting to an inv.
                    fRevertToInv = true;
                    break;
                }
                pBestIndex = pindex;
                if (fFoundStartingHeader) {
                    // add this to the headers message
                    vHeaders.push_back(pindex->GetBlockHeader());
                } else if (PeerHasHeader(&state, pindex)) {
                    // Keep looking for the first new block.
                    continue;
                } else if (pindex->pprev == nullptr ||
                           PeerHasHeader(&state, pindex->pprev)) {
                    // Peer doesn't have this header but they do have the prior
                    // one.
                    // Start sending headers.
                    fFoundStartingHeader = true;
                    vHeaders.push_back(pindex->GetBlockHeader());
                } else {
                    // Peer doesn't have this header or the prior one --
                    // nothing will connect, so bail out.
                    fRevertToInv = true;
                    break;
                }
            }
        }
        if (!fRevertToInv && !vHeaders.empty()) {
            if (vHeaders.size() == 1 && state.fPreferHeaderAndIDs) {
                // We only send up to 1 block as header-and-ids, as otherwise
                // probably means we're doing an initial-ish-sync or they're
                // slow.
                LogPrint(BCLog::NET,
                         "%s sending header-and-ids %s to peer=%d\n", __func__,
                         vHeaders.front().GetHash().ToString(), pto->GetId());

                int nSendFlags = 0;

                bool fGotBlockFromCache = false;
                {
                    LOCK(cs_most_recent_block);
                    if (most_recent_block_hash == pBestIndex->GetBlockHash()) {
                        CBlockHeaderAndShortTxIDs cmpctblock(
                            *most_recent_block);
                        connman->PushMessage(
                            pto,
                            msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK,
                                          cmpctblock));
                        fGotBlockFromCache = true;
                    }
                }
                if (!fGotBlockFromCache) {
                    CBlock block;
                    bool ret =
                        ReadBlockFromDisk(block, pBestIndex, consensusParams);
                    assert(ret);
                    CBlockHeaderAndShortTxIDs cmpctblock(block);
                    connman->PushMessage(
                        pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK,
                                           cmpctblock));
                }
                state.pindexBestHeaderSent = pBestIndex;
            } else if (state.fPreferHeaders) {
                if (vHeaders.size() > 1) {
                    LogPrint(BCLog::NET,
                             "%s: %u headers, range (%s, %s), to peer=%d\n",
                             __func__, vHeaders.size(),
                             vHeaders.front().GetHash().ToString(),
                             vHeaders.back().GetHash().ToString(),
                             pto->GetId());
                } else {
                    LogPrint(BCLog::NET, "%s: sending header %s to peer=%d\n",
                             __func__, vHeaders.front().GetHash().ToString(),
                             pto->GetId());
                }
                connman->PushMessage(
                    pto, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
                state.pindexBestHeaderSent = pBestIndex;
            } else {
                fRevertToInv = true;
            }
        }
        if (fRevertToInv) {
            // If falling back to using an inv, just try to inv the tip. The
            // last entry in vBlockHashesToAnnounce was our tip at some point in
            // the past.
            if (!pto->vBlockHashesToAnnounce.empty()) {
                const BlockHash &hashToAnnounce =
                    pto->vBlockHashesToAnnounce.back();
                const CBlockIndex *pindex = LookupBlockIndex(hashToAnnounce);
                assert(pindex);

                // Warn if we're announcing a block that is not on the main
                // chain. This should be very rare and could be optimized out.
                // Just log for now.
                if (::ChainActive()[pindex->nHeight] != pindex) {
                    LogPrint(BCLog::NET,
                             "Announcing block %s not on main chain (tip=%s)\n",
                             hashToAnnounce.ToString(),
                             ::ChainActive().Tip()->GetBlockHash().ToString());
                }

                // If the peer's chain has this block, don't inv it back.
                if (!PeerHasHeader(&state, pindex)) {
                    pto->PushInventory(CInv(MSG_BLOCK, hashToAnnounce));
                    LogPrint(BCLog::NET, "%s: sending inv peer=%d hash=%s\n",
                             __func__, pto->GetId(), hashToAnnounce.ToString());
                }
            }
        }
        pto->vBlockHashesToAnnounce.clear();
    }

    //
    // Message: inventory
    //
    std::vector<CInv> vInv;
    {
        LOCK(pto->cs_inventory);

        const uint64_t invBroadcastInterval = config.GetInvBroadcastInterval();
        // effective max number of transactions per inventory is
        // rawRatePerSecond * blockSizeInMB * broadcastIntervalInSeconds (rounded up)
        const uint64_t nMaxBroadcasts = std::ceil(
                                            config.GetInvBroadcastRate()
                                          * (GetNextBlockSizeLimit(config, ::ChainActive().Tip()) / 1000000.0)
                                          * (std::max<uint64_t>(invBroadcastInterval, 1) / 1000.0));

        {
            // reserve memory, limiting it to what we anticipate to send, up to a cap of MAX_INV_SZ
            const uint64_t nTxsToSend = [&]() EXCLUSIVE_LOCKS_REQUIRED(pto->cs_inventory) {
                LOCK(pto->cs_filter);
                return pto->fRelayTxes ? pto->setInventoryTxToSendTopoSorted.size() : 0;
            }();
            const uint64_t nBlocksToSend = pto->vInventoryBlockToSend.size();
            /* we never send more that MAX_INV_SZ items at a time */
            vInv.reserve(std::min<uint64_t>(MAX_INV_SZ, std::min<uint64_t>(nMaxBroadcasts, nTxsToSend) + nBlocksToSend));
        }

        // Add blocks
        for (const BlockHash &hash : pto->vInventoryBlockToSend) {
            vInv.emplace_back(MSG_BLOCK, hash);
            if (vInv.size() == MAX_INV_SZ) {
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, std::move(vInv)));
                vInv.clear();
            }
        }
        pto->vInventoryBlockToSend.clear();

        // add generic INVs (such as DSProofs, which will be sent immediately without delay)
        for (const CInv &inv : pto->vInventoryToSend) {
            vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ) {
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, std::move(vInv)));
                vInv.clear();
            }
        }
        pto->vInventoryToSend.clear();

        // Check whether periodic sends should happen
        bool fSendTrickle = pto->HasPermission(PF_NOBAN);
        if (!invBroadcastInterval || pto->nNextInvSend < current_time) {
            fSendTrickle = true;
            if (pto->fInbound) {
                pto->nNextInvSend = std::chrono::microseconds{connman->PoissonNextSendInbound(nNow, invBroadcastInterval)};
            } else {
                // Use half the delay for outbound peers, as there is less
                // privacy concern for them.
                pto->nNextInvSend = PoissonNextSend(current_time, std::chrono::milliseconds{invBroadcastInterval >> 1});
            }
        }

        // Time to send but the peer has requested we not relay transactions.
        if (fSendTrickle) {
            LOCK(pto->cs_filter);
            if (!pto->fRelayTxes) {
                pto->setInventoryTxToSendTopoSorted.clear();
            }
        }

        // Respond to BIP35 mempool requests
        if (fSendTrickle && pto->fSendMempool) {
            auto vtxinfo = g_mempool.infoAll();
            pto->fSendMempool = false;
            Amount filterrate = Amount::zero();
            {
                LOCK(pto->cs_feeFilter);
                filterrate = pto->minFeeFilter;
            }

            LOCK(pto->cs_filter);

            for (const auto &txinfo : vtxinfo) {
                const TxId &txid = txinfo.tx->GetId();
                // erase this txid from the set since we are relaying it now
                std::pair eraseItem(txinfo.entryId, txid);
                pto->setInventoryTxToSendTopoSorted.erase(eraseItem);
                // also erase any "unknown" entryId==0 entries from the set for this txid
                eraseItem.first = 0;
                pto->setInventoryTxToSendTopoSorted.erase(eraseItem);
                if (filterrate != Amount::zero() &&
                    txinfo.feeRate.GetFeePerK() < filterrate) {
                    continue;
                }
                if (pto->pfilter &&
                    !pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) {
                    continue;
                }
                pto->filterInventoryKnown.insert(txid);
                vInv.emplace_back(MSG_TX, txid);
                if (vInv.size() == MAX_INV_SZ) {
                    connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, std::move(vInv)));
                    vInv.clear();
                }
            }
            pto->timeLastMempoolReq = current_time_secs;
        }

        // Determine transactions to relay
        if (fSendTrickle) {
            // First, resolve all `entryId == 0` entries in `setInventoryTxToSendTopoSorted`. These unresolved entries
            // live in the beginning of the map. `entryId == 0` entries may occur if some code requested to relay a txn
            // for which it didn't necessarily know the mempool acceptance order (wallet & RPC code may do this). We
            // resolve these first so that the loop later down in this code block is iterating over txns in topological
            // order (so that we always relay in topological order).
            auto IsUnresolvedEntryId = [&pto](const auto &it) EXCLUSIVE_LOCKS_REQUIRED(pto->cs_inventory) {
                return it != pto->setInventoryTxToSendTopoSorted.end() && it->first == 0;
            };
            if (auto it = pto->setInventoryTxToSendTopoSorted.begin(); IsUnresolvedEntryId(it)) {
                LOCK(g_mempool.cs);
                do {
                    const TxId txid = it->second;
                    // Erase first, re-add with correct ordering if still in mempool.
                    pto->setInventoryTxToSendTopoSorted.erase(it);
                    if (const auto itmp = g_mempool.GetIter(txid)) {
                        if (const auto entryId = (*itmp)->GetEntryId()) {
                            // Re-add with mempool admission order sorting (topological sorting).
                            pto->setInventoryTxToSendTopoSorted.emplace(entryId, txid);
                        }
                    }
                } while (IsUnresolvedEntryId(it = pto->setInventoryTxToSendTopoSorted.begin()));
            }
            Amount filterrate = Amount::zero();
            {
                LOCK(pto->cs_feeFilter);
                filterrate = pto->minFeeFilter;
            }
            // Send out the inventory in the order of admission to our mempool,
            // which is guaranteed to be a topological sort order.

            // No reason to drain out at many times the network's capacity,
            // especially since we have many peers and some will draw much
            // shorter delays.
            size_t nRelayedTransactions = 0;
            LOCK(pto->cs_filter);
            while (!pto->setInventoryTxToSendTopoSorted.empty() && nRelayedTransactions < nMaxBroadcasts) {
                // Fetch the top element from the set (earliest txn)
                TxId txid{TxId::Uninitialized};
                {
                    auto it = pto->setInventoryTxToSendTopoSorted.begin();
                    txid = it->second;

                    // Remove it from the to-be-sent set
                    pto->setInventoryTxToSendTopoSorted.erase(it);
                }
                // Check if not in the filter already
                if (pto->filterInventoryKnown.contains(txid)) {
                    continue;
                }
                // Not in the mempool anymore? Don't bother sending it.
                auto txinfo = g_mempool.info(txid);
                if (!txinfo.tx) {
                    continue;
                }
                if (filterrate != Amount::zero() && txinfo.feeRate.GetFeePerK() < filterrate) {
                    continue;
                }
                if (pto->pfilter && !pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) {
                    continue;
                }
                // Send
                vInv.emplace_back(MSG_TX, txid);
                ++nRelayedTransactions;
                {
                    // Expire old relay messages
                    while (!vRelayExpiration.empty() &&
                           vRelayExpiration.front().first < nNow) {
                        mapRelay.erase(vRelayExpiration.front().second);
                        vRelayExpiration.pop_front();
                    }

                    auto ret = mapRelay.emplace(txid, txinfo.tx);
                    if (ret.second) {
                        vRelayExpiration.emplace_back(nNow + 15 * 60 * 1000000, ret.first);
                    }
                }
                if (vInv.size() == MAX_INV_SZ) {
                    connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, std::move(vInv)));
                    vInv.clear();
                }
                pto->filterInventoryKnown.insert(txid);
            }
        }
    }
    if (!vInv.empty()) {
        connman->PushMessage(pto, msgMaker.Make(NetMsgType::INV, std::move(vInv)));
        vInv.clear();
    }

    // Detect whether we're stalling
    if (state.nStallingSince &&
        state.nStallingSince < nNow - 1000000 * BLOCK_STALLING_TIMEOUT) {
        // Stalling only triggers when the block download window cannot move.
        // During normal steady state, the download window should be much larger
        // than the to-be-downloaded set of blocks, so disconnection should only
        // happen during initial block download.
        LogPrintf("Peer=%d is stalling block download, disconnecting\n",
                  pto->GetId());
        pto->fDisconnect = true;
        return true;
    }
    // In case there is a block that has been in flight from this peer for 2 +
    // 0.5 * N times the block interval (with N the number of peers from which
    // we're downloading validated blocks), disconnect due to timeout. We
    // compensate for other peers to prevent killing off peers due to our own
    // downstream link being saturated. We only count validated in-flight blocks
    // so peers can't advertise non-existing block hashes to unreasonably
    // increase our timeout.
    if (state.vBlocksInFlight.size() > 0) {
        QueuedBlock &queuedBlock = state.vBlocksInFlight.front();
        int nOtherPeersWithValidatedDownloads =
            nPeersWithValidatedDownloads -
            (state.nBlocksInFlightValidHeaders > 0);
        if (nNow > state.nDownloadingSince +
                       consensusParams.nPowTargetSpacing *
                           (BLOCK_DOWNLOAD_TIMEOUT_BASE +
                            BLOCK_DOWNLOAD_TIMEOUT_PER_PEER *
                                nOtherPeersWithValidatedDownloads)) {
            LogPrintf("Timeout downloading block %s from peer=%d, "
                      "disconnecting\n",
                      queuedBlock.hash.ToString(), pto->GetId());
            pto->fDisconnect = true;
            return true;
        }
    }

    // Check for headers sync timeouts
    if (state.fSyncStarted &&
        state.nHeadersSyncTimeout < std::numeric_limits<int64_t>::max()) {
        // Detect whether this is a stalling initial-headers-sync peer
        if (pindexBestHeader->GetBlockTime() <=
            GetAdjustedTime() - 24 * 60 * 60) {
            if (nNow > state.nHeadersSyncTimeout && nSyncStarted == 1 &&
                (nPreferredDownload - state.fPreferredDownload >= 1)) {
                // Disconnect a (non-whitelisted) peer if it is our only sync
                // peer, and we have others we could be using instead.
                // Note: If all our peers are inbound, then we won't disconnect
                // our sync peer for stalling; we have bigger problems if we
                // can't get any outbound peers.
                if (!pto->HasPermission(PF_NOBAN)) {
                    LogPrintf("Timeout downloading headers from peer=%d, "
                              "disconnecting\n",
                              pto->GetId());
                    pto->fDisconnect = true;
                    return true;
                } else {
                    LogPrintf("Timeout downloading headers from whitelisted "
                              "peer=%d, not disconnecting\n",
                              pto->GetId());
                    // Reset the headers sync state so that we have a chance to
                    // try downloading from a different peer.
                    // Note: this will also result in at least one more
                    // getheaders message to be sent to this peer (eventually).
                    state.fSyncStarted = false;
                    nSyncStarted--;
                    state.nHeadersSyncTimeout = 0;
                }
            }
        } else {
            // After we've caught up once, reset the timeout so we can't trigger
            // disconnect later.
            state.nHeadersSyncTimeout = std::numeric_limits<int64_t>::max();
        }
    }

    // Check that outbound peers have reasonable chains. `current_time_secs`
    // (which comes from GetTime()) is used by this anti-DoS logic so we can
    // test this using mocktime.
    ConsiderEviction(pto, current_time_secs);

    //
    // Message: getdata (blocks)
    //
    std::vector<CInv> vGetData;
    if (!pto->fClient && ((fFetch && !pto->m_limited_node) || !IsInitialBlockDownload())
        && state.vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        std::vector<const CBlockIndex *> vToDownload;
        NodeId staller = -1;
        FindNextBlocksToDownload(pto->GetId(),
                                 MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.vBlocksInFlight.size(),
                                 vToDownload, staller, consensusParams);
        for (const CBlockIndex *pindex : vToDownload) {
            vGetData.emplace_back(MSG_BLOCK, pindex->GetBlockHash());
            MarkBlockAsInFlight(config, pto->GetId(), pindex->GetBlockHash(),
                                consensusParams, pindex);
            LogPrint(BCLog::NET, "Requesting block %s (%d) peer=%d\n",
                     pindex->GetBlockHash().ToString(), pindex->nHeight,
                     pto->GetId());
        }
        if (state.vBlocksInFlight.empty() && staller != -1) {
            if (State(staller)->nStallingSince == 0) {
                State(staller)->nStallingSince = nNow;
                LogPrint(BCLog::NET, "Stall started peer=%d\n", staller);
            }
        }
    }

    //
    // Message: getdata (transactions)
    //
    std::vector<std::pair<NodeId, TxId>> expired;
    const auto requestable = m_txrequest.GetRequestable(pto->GetId(), current_time, &expired);
    for (const auto & [nodeid, txid] : expired) {
        LogPrint(BCLog::NET, "timeout of inflight tx %s from peer=%d\n", txid.ToString(), nodeid);
    }
    for (const TxId &txid : requestable) {
        const CInv inv(MSG_TX, txid);
        if (!AlreadyHave(inv)) {
            LogPrint(BCLog::NET, "Requesting tx %s peer=%d\n", txid.ToString(), pto->GetId());
            vGetData.push_back(inv);
            if (vGetData.size() >= MAX_GETDATA_SZ) {
                connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                vGetData.clear();
            }
            m_txrequest.RequestedTx(pto->GetId(),txid, current_time + GETDATA_TX_INTERVAL);
        } else {
            // We have already seen this transaction, no need to download. This is just a belt-and-suspenders, as
            // this should already be called whenever a transaction becomes Already().
            m_txrequest.ForgetTxId(txid);
        }
    }

    if (!vGetData.empty()) {
        connman->PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
    }

    //
    // Message: feefilter
    //
    // We don't want white listed peers to filter txs to us if we have
    // -whitelistforcerelay
    if (pto->nVersion >= FEEFILTER_VERSION && m_enable_feefilter && !pto->HasPermission(PF_FORCERELAY)) {
        Amount currentFilter = g_mempool.GetMinFee(config.GetMaxMemPoolSize()).GetFeePerK();
        if (nNow > pto->nextSendTimeFeeFilter) {
            static CFeeRate default_feerate =
                CFeeRate(DEFAULT_MIN_RELAY_TX_FEE_PER_KB);
            static FeeFilterRounder filterRounder(default_feerate);
            Amount filterToSend = filterRounder.round(currentFilter);
            filterToSend = std::max(filterToSend, ::minRelayTxFee.GetFeePerK());

            if (filterToSend != pto->lastSentFeeFilter) {
                connman->PushMessage(
                    pto, msgMaker.Make(NetMsgType::FEEFILTER, filterToSend));
                pto->lastSentFeeFilter = filterToSend;
            }
            pto->nextSendTimeFeeFilter =
                PoissonNextSend(nNow, AVG_FEEFILTER_BROADCAST_INTERVAL);
        }
        // If the fee filter has changed substantially and it's still more than
        // MAX_FEEFILTER_CHANGE_DELAY until scheduled broadcast, then move the
        // broadcast to within MAX_FEEFILTER_CHANGE_DELAY.
        else if (nNow + MAX_FEEFILTER_CHANGE_DELAY * 1000000 <
                     pto->nextSendTimeFeeFilter &&
                 (currentFilter < 3 * pto->lastSentFeeFilter / 4 ||
                  currentFilter > 4 * pto->lastSentFeeFilter / 3)) {
            pto->nextSendTimeFeeFilter =
                nNow + GetRandInt(MAX_FEEFILTER_CHANGE_DELAY) * 1000000;
        }
    }
    return true;
}

void PeerLogicValidation::TransactionDoubleSpent(const CTransactionRef &ptx, const DspId &dspId) {
    // NB: This will not be called if dsproofs are globally disabled (-doublespendproof=0).
    LogPrint(BCLog::DSPROOF, "  DSP broadcasting an INV for dspId: %s txId: %s\n", dspId.ToString(), ptx->GetId().ToString());
    connman->ForEachNode([ptx, inv = CInv(MSG_DOUBLESPENDPROOF, dspId)](const NodeRef &pnode) {
        {
            LOCK(pnode->cs_filter);
            if (!pnode->fRelayTxes)
                return;
            if (pnode->pfilter && !pnode->pfilter->IsRelevantAndUpdate(*ptx))
                return;
        }
        pnode->PushInventory(inv);
    });
}

void PeerLogicValidation::BadDSProofsDetectedFromNodeIds(const std::vector<NodeId> &nodeIds) {
    // NB: This will not be called if dsproofs are globally disabled (-doublespendproof=0).
    LOCK(cs_main);
    for (const auto &nodeId : nodeIds) {
        // Punish peer that gave us an invalid proof (if they are still connected)
        Misbehaving(nodeId, 10, "bad-dsproof");
    }
}

std::vector<TxOrphanage::OrphanTxBase> PeerLogicValidation::GetOrphanTransactions() const {
    LOCK(cs_main);
    return m_orphanage.GetOrphanTransactions();
}
