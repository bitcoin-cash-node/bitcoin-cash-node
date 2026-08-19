#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Cash Node developers
# Author matricz
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test that inv messages are sent according to
an exponential distribution with scale -txbroadcastinterval
The outbound interval should be half of the inbound
"""
import time

from test_framework.cdefs import MAX_INV_BROADCAST_INTERVAL
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import wait_until, connect_nodes, disconnect_nodes
from scipy import stats


class InvReceiver(P2PInterface):

    def __init__(self):
        super().__init__()
        self.invTimes = []
        self.invDelays = []

    def on_inv(self, message):

        timeArrived = time.time()
        # If an inv contains more then one transaction, then the number of invs (==samplesize)
        # will be non-deterministic. This would be an error.
        assert len(message.inv) == 1
        self.invTimes.append(timeArrived)
        if len(self.invTimes) > 1:
            timediff = self.invTimes[-1] - self.invTimes[-2]
            self.invDelays.append(timediff)


class TxBroadcastIntervalTest(BitcoinTestFramework):

    # This test will have a node create a number of transactions and relay them
    # to the P2P InvReceivers (one inbound and one outbound) according to test
    # parameters.
    # A third disconnected node is used only to create signed transactions

    # The nodes are configured with "-txbroadcastrate=1" and
    # "-forceblocksize=2000000" so that they relay at most one tx per inv
    # It's convenient, because we can now define the exact number of invs
    # (== sample size -1) that we want to send
    # This holds true only for interval values <= 500 ms

    # The P2P InvReceiver just listens and registers the delays between invs and
    # constructs a sample array from these delays
    # This sample is tested against a reference exponential distribution
    # density with the same parameters with scipy.stats.kstest
    # (See https://en.wikipedia.org/wiki/Kolmogorov%E2%80%93Smirnov_test)
    # The test is accepted if the delays sample resembles the reference
    # distribution -- or, more specifically, if the probability that the
    # observed distribution would have occurred as a sampling of the theoretical
    # exponential distribution with a probability of at least alpha
    # (pvalue > alpha, default 0.001)

    # There is one P2P interface that connects directly to the node that
    # generates transactions.
    # This tests the *inbound* connection interval.
    # The first node creates an outbound connection to the second node,
    # which relays the transactions instantly (-txbroadcastinterval=1)
    # to the second P2P interface, which tests the *outbound* connection
    # interval (= 1/2 of the inbound).
    # (but is less reliable for small values of the -txbroadcastinterval)

    def add_options(self, parser):
        parser.add_argument("--interval", dest="interval", type=int, default=500,
                            help="Set the average send interval in ms")
        parser.add_argument("--samplesize", dest="samplesize", type=int, default=50,
                            help="Set the samplesize (number of inv message delays) for testing")
        parser.add_argument("--alpha", dest="alpha", type=float, default="0.001",
                            help="Set a confidence threshold for the kstest")

    def set_test_params(self):
        assert self.options.interval <= MAX_INV_BROADCAST_INTERVAL
        self.scale = self.options.interval / 1000
        self.num_nodes = 3
        self.setup_clean_chain = True
        # Note that -forceblocksize also disables ABLA
        args = [
            ["-txbroadcastinterval={}".format(self.options.interval),
                "-txbroadcastrate=1", "-forceblocksize=2000000", "-blockmaxsize=2000000"],
            ["-txbroadcastinterval=1",
                "-txbroadcastrate=1", "-forceblocksize=2000000", "-blockmaxsize=2000000"],
            ["-persistmempool=0"],
        ]
        self.extra_args = args

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], self.nodes[1])
        connect_nodes(self.nodes[1], self.nodes[2])
        self.nodes[2].generatetoaddress(1, self.nodes[2].get_deterministic_priv_key().address)
        self.sync_all()

        # Generate self.options.samplesize txns using "fillmempool". However, we must disconnect
        # node 2 so that it doesn't broadcast the txs it creates for "fillmempool".
        disconnect_nodes(self.nodes[1], self.nodes[2])
        mbytes = 0
        while len(self.nodes[2].getrawmempool(False)) < self.options.samplesize:
            mbytes += 1
            self.nodes[2].fillmempool(mbytes)

        self.signedtxs = []
        for txid in self.nodes[2].getrawmempool(False)[:self.options.samplesize]:
            self.signedtxs.append(self.nodes[2].getrawtransaction(txid, False))

        assert len(self.signedtxs) == self.options.samplesize

        # Now restart node 2 so that it drops its mempool (it has -persistmempool=0).
        self.restart_node(2)
        # Reconnect node 2 so that it synchs up all the previous coinbase TXOs for the txns we have in `self.signedtxs`
        connect_nodes(self.nodes[2], self.nodes[0])
        self.sync_blocks()
        # Now keep node 2 disconnected to minimize CPU load for the remainder of the test.
        disconnect_nodes(self.nodes[2], self.nodes[0])

    def run_test(self):
        inbound_receiver, outbound_receiver = InvReceiver(), InvReceiver()
        self.nodes[0].add_p2p_connection(inbound_receiver)
        self.nodes[1].add_p2p_connection(outbound_receiver)

        for tx in self.signedtxs:
            self.nodes[0].sendrawtransaction(tx, True)

        wait_until(
            lambda: len(inbound_receiver.invTimes) == self.options.samplesize,
            lock=p2p_lock,
            timeout=self.options.samplesize * self.options.interval / 1000 * 2)
        wait_until(
            lambda: len(outbound_receiver.invTimes) == self.options.samplesize,
            lock=p2p_lock,
            timeout=self.options.samplesize * self.options.interval / 1000)

        inbound_result = stats.kstest(inbound_receiver.invDelays, stats.expon(scale=self.scale).cdf)
        outbound_result = stats.kstest(outbound_receiver.invDelays, stats.expon(scale=self.scale / 2).cdf)
        self.log.info("kstestresults for interval {}: inbound {}, outbound {}".format(
            self.options.interval,
            inbound_result,
            outbound_result))
        assert inbound_result.pvalue > self.options.alpha, (inbound_result.pvalue, inbound_receiver.invDelays)
        assert outbound_result.pvalue > self.options.alpha, (outbound_result.pvalue, outbound_receiver.invDelays)


if __name__ == '__main__':
    TxBroadcastIntervalTest().main()
