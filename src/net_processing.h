// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020-2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <consensus/params.h>
#include <net.h>
#include <peerratelimiter.h>
#include <sync.h>
#include <txorphanage.h>
#include <txrequest.h>
#include <validationinterface.h>

#include <atomic>
#include <memory>

extern RecursiveMutex cs_main;

/**
 * Default average delay between trickled inventory transmissions in millisec.
 * Blocks and whitelisted receivers bypass this, outbound peers get half this
 * delay. Note: this ends up capped at MAX_INV_BROADCAST_INTERVAL (defined in
 * policy/policy.h).
 */
static constexpr unsigned int DEFAULT_INV_BROADCAST_INTERVAL = 500;
/**
 * Maximum number of inventory items to send per transmission.
 * Limits the impact of low-fee transaction floods. Note: this ends up capped
 * at MAX_INV_BROADCAST_RATE (defined in policy/policy.h).
 */
static constexpr unsigned int DEFAULT_INV_BROADCAST_RATE = 7;


class Config;

/**
 * Default for -maxorphantx, maximum number of orphan transactions kept in
 * memory.
 */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/**
 * Default number of orphan+recently-replaced txn to keep around for block
 * reconstruction.
 */
static const unsigned int DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;

/** Default for BIP61 (sending reject messages) */
static constexpr bool DEFAULT_ENABLE_BIP61 = true;

/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static constexpr unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

class PeerLogicValidation final : public CValidationInterface,
                                  public NetEventsInterface {
private:
    CConnman *const connman;
    BanMan *const m_banman;
    std::shared_ptr<std::atomic_bool> deleted; ///< Used to suppress further scheduler tasks if this instance is gone.
    TxRequestTracker m_txrequest GUARDED_BY(cs_main);
    TxOrphanage m_orphanage GUARDED_BY(cs_main);

    bool SendRejectsAndCheckIfShouldDiscourage(const NodeRef &pnode, bool enable_bip61)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

public:
    PeerLogicValidation(CConnman *connman, BanMan *banman,
                        CScheduler &scheduler, bool enable_bip61, bool enable_feefilter);

    ~PeerLogicValidation();

    /**
     * Overridden from CValidationInterface.
     */
    void
    BlockConnected(const std::shared_ptr<const CBlock> &pblock,
                   const CBlockIndex *pindexConnected,
                   const std::vector<CTransactionRef> &vtxConflicted) override;
    /**
     * Overridden from CValidationInterface.
     */
    void UpdatedBlockTip(const CBlockIndex *pindexNew,
                         const CBlockIndex *pindexFork,
                         bool fInitialDownload) override;
    /**
     * Overridden from CValidationInterface.
     */
    void BlockChecked(const CBlock &block,
                      const CValidationState &state) override;
    /**
     * Overridden from CValidationInterface.
     */
    void NewPoWValidBlock(const CBlockIndex *pindex,
                          const std::shared_ptr<const CBlock> &pblock) override;

    /**
     * Initialize a peer by adding it to mapNodeState and pushing a message
     * requesting its version.
     */
    void InitializeNode(const Config &config, NodeRef pnode) override;
    /**
     * Handle removal of a peer by updating various state and removing it from
     * mapNodeState.
     */
    void FinalizeNode(const Config &config, NodeId nodeid, bool &fUpdateConnectionTime) override;
    /**
     * Process protocol messages received from a given node.
     */
    bool ProcessMessages(const Config &config, NodeRef pfrom, std::atomic<bool> &interrupt) override;
    /**
     * Send queued protocol messages to be sent to a give node.
     *
     * @param[in]   pto             The node which we are sending messages to.
     * @param[in]   interrupt       Interrupt condition for processing threads
     * @return                      True if there is more work to be done
     */
    bool SendMessages(const Config &config, NodeRef pto, std::atomic<bool> &interrupt) override
        EXCLUSIVE_LOCKS_REQUIRED(pto->cs_sendProcessing);

    /**
     * Consider evicting an outbound peer based on the amount of time they've
     * been behind our tip.
     */
    void ConsiderEviction(const NodeRef &pto, int64_t time_in_seconds)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to
     * an extra outbound.
     */
    void
    CheckForStaleTipAndEvictPeers(const Consensus::Params &consensusParams);
    /**
     * If we have extra outbound peers, try to disconnect the one with the
     * oldest block announcement.
     */
    void EvictExtraOutboundPeers(int64_t time_in_seconds)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /// Called when AcceptToMemoryPool creates a double-spend proof for a tx
    /// and associates it with said tx. Only ever called at most once per
    /// proof. Notifies all peers of the new dsproof inv.
    void TransactionDoubleSpent(const CTransactionRef &ptx, const DspId &dspId) override;

    /// Called when a double-spend proof turns out to be bad either because it
    /// was a rescued orphan that was bad, or because a peer sent us a bad proof.
    /// We punish the nodeid(s) in question in that case (if they are still connected).
    void BadDSProofsDetectedFromNodeIds(const std::vector<NodeId> &nodeIds) override;

    /**
     * Apply the specified peer rate limit rules.
     */
    void SetPeerRateLimitRules(const std::vector<PeerRateLimitRule> &rules);

    /**
     * @brief IsPerPeerRateLimitingTemporarilySuppressed (from NetEventsInterface)
     * @return true if we are in IBD, false otherwise
     */
    bool IsPerPeerRateLimitingTemporarilySuppressed() const override;

    /// Retrieve all of the orphan transactions currently in the TxOrphanage (used by RPC interface)
    std::vector<TxOrphanage::OrphanTxBase> GetOrphanTransactions() const;

private:
    //! Next time to check for stale tip
    int64_t m_stale_tip_check_time;

    //! Last time we spammed the "Broadcast" app-wide signal (in non-mockable microseconds)
    int64_t m_last_bcast_sig_time GUARDED_BY(cs_main) = 0;

    /** Enable BIP61 (sending reject messages) */
    const bool m_enable_bip61;

    /** Enable sending feefilter messages to peers. */
    const bool m_enable_feefilter;

    const bool m_is_regtest; ///< True if we are a regtest node
    std::vector<PeerRateLimitRule> m_peerRateLimitRules; ///< If not empty, per-peer traffic rate limiting is active
     //! Cached value from the last time this->UpdatedBlockTip() was called: the last fInitialDownload param seen.
     //! If negative: is unset (UpdatedBlockTip() was never called). If non-negative, interpreted as a boolean as the
     //! last fInitialDownload flag seen.
    std::atomic_int m_cachedLastIBDFlagSeen{-1};
};

struct CNodeStateStats {
    int nMisbehavior = 0;
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    std::vector<int> vHeightInFlight;
};

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch, const std::string &reason = "");
