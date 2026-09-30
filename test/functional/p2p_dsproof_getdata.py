#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash Node developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test batching of double-spend-proof getdata requests."""

from test_framework.messages import CInv, MSG_DSPROOF, msg_inv
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Must match MAX_DSPROOF_GET_DATAS_TO_BATCH and MAX_GETDATA_SZ in src/net_processing.cpp
MAX_DSPROOF_GET_DATAS_TO_BATCH = 5000
MAX_GETDATA_SZ = 1000


class GetDataCollector(P2PInterface):
    """Records every getdata, so we can assert on how the requests were split."""

    def __init__(self):
        super().__init__()
        self.getdata_batches = []

    def on_getdata(self, message):
        self.getdata_batches.append([(inv.type, inv.hash) for inv in message.inv])

    def take_batches(self):
        with p2p_lock:
            batches = self.getdata_batches
            self.getdata_batches = []
        return batches


class DSProofGetDataTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        # Leave IBD; dsproof invs are ignored while in IBD.
        self.nodes[0].generatetoaddress(1, self.nodes[0].get_deterministic_priv_key().address)
        peer = self.nodes[0].add_p2p_connection(GetDataCollector())

        self.log.info("A single inv of several dsproofs is requested in one getdata, in inv order")
        announced = [CInv(MSG_DSPROOF, dspid) for dspid in range(1, 4)]
        expected = [(inv.type, inv.hash) for inv in announced]
        peer.send_message(msg_inv(announced))
        peer.wait_for_getdata(timeout=30)
        peer.sync_with_ping()
        assert_equal(peer.take_batches(), [expected])

        # A second pass must not re-request: the queue is drained, not copied.
        peer.sync_with_ping()
        assert_equal(peer.take_batches(), [])

        self.log.info("A queue-filling inv is split at MAX_GETDATA_SZ and truncated at the batch cap")
        first = 100
        # One more than the cap, so the last announced dspid must be dropped.
        announced = [CInv(MSG_DSPROOF, dspid)
                     for dspid in range(first, first + MAX_DSPROOF_GET_DATAS_TO_BATCH + 1)]
        peer.send_message(msg_inv(announced))
        peer.sync_with_ping()
        batches = peer.take_batches()

        assert_equal([len(batch) for batch in batches],
                     [MAX_GETDATA_SZ] * (MAX_DSPROOF_GET_DATAS_TO_BATCH // MAX_GETDATA_SZ))
        requested = [inv for batch in batches for inv in batch]
        assert_equal(requested, [(inv.type, inv.hash) for inv in announced[:-1]])


if __name__ == "__main__":
    DSProofGetDataTest().main()
