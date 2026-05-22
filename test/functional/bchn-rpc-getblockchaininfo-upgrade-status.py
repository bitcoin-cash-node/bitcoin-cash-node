#!/usr/bin/env python3
# Copyright (c) 2025-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Verify getblockchaininfo.upgrade_status fields.

Covers:
- Presence and types of fields pre-activation (future activation time):
  mempool_activated = false; block_preactivation_{height,hash} = null; block_postactivation_{height,hash} = null
- Correct mempool_activation_mtp equals CLI override
- software_expiration_time present (numeric or null)
- Post-activation (past activation time):
  mempool_activated = true; preactivation populated and consistent;
  postactivation is null until the first post-activation block exists, and populated thereafter
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

UPGRADE_ACTIVATION_ARG = 'upgrade2027activationtime'

class GetBlockchainInfoUpgradeStatusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # Start with upgrade well in the future
        self.future_time = int(time.time()) + 10_000_000
        self.extra_args = [[f'-{UPGRADE_ACTIVATION_ARG}={self.future_time}']]

    def run_test(self):
        node = self.nodes[0]

        # Pre-activation: far-future activation time => mempool_activated = false
        info = node.getblockchaininfo()
        us = info['upgrade_status']
        assert_equal(us['name'], "May 2027 Upgrade (regtestnet)")
        assert_equal(us['mempool_activation_mtp'], self.future_time)
        assert_equal(us['mempool_activated'], False)
        # Not yet known, but expected to always be present as `null`
        assert us['block_preactivation_height'] is None
        assert us['block_preactivation_hash'] is None
        assert us['block_postactivation_height'] is None
        assert us['block_postactivation_hash'] is None
        # On regtest, expiration may be unset (null). Just ensure the field exists and is numeric or NoneType.
        assert isinstance(us['software_expiration_time'], (int, type(None)))

        # Move activation time to the past and restart; mine a block to advance MTP and ensure activation reached
        # Ensure activation is definitely reached by using an activation time in the distant past
        past_time = 0
        self.restart_node(0, extra_args=[f'-{UPGRADE_ACTIVATION_ARG}={past_time}'])
        # At this point mempool activation should become true, but postactivation
        # block may not exist until we mine one. Check both cases.

        info = node.getblockchaininfo()
        us = info['upgrade_status']
        assert_equal(us['mempool_activation_mtp'], past_time)
        assert_equal(us['mempool_activated'], True)

        # Preactivation block details should be available
        act_h = us['block_preactivation_height']
        act_hash = us['block_preactivation_hash']
        assert act_h is not None
        assert isinstance(act_h, int)
        assert act_hash is not None and isinstance(act_hash, str)
        # Hash is a valid 64-hex string and matches getblockhash(height)
        assert_equal(len(act_hash), 64)
        assert_equal(node.getblockhash(act_h), act_hash)

        # Before mining a block, postactivation may be null on fresh activation
        post_h = us['block_postactivation_height']
        post_hash = us['block_postactivation_hash']
        if post_h is None:
            # Mine one block so the first post-activation block exists
            address = node.get_deterministic_priv_key().address
            self.generatetoaddress(node, 1, address)
            info = node.getblockchaininfo()
            us = info['upgrade_status']
            post_h = us['block_postactivation_height']
            post_hash = us['block_postactivation_hash']
        assert post_h is not None
        assert isinstance(post_h, int)
        assert post_hash is not None and isinstance(post_hash, str)
        assert_equal(len(post_hash), 64)
        assert_equal(node.getblockhash(post_h), post_hash)
        # And the postactivation block is exactly one after preactivation
        assert_equal(post_h, act_h + 1)

        self.restart_node(
            0,
            extra_args=[
                f'-{UPGRADE_ACTIVATION_ARG}={self.future_time}',
                '-expire=0',
            ],
        )
        info = node.getblockchaininfo()
        us = info['upgrade_status']
        assert_equal(us['mempool_activated'], False)
        assert us['software_expiration_time'] is None


if __name__ == '__main__':
    GetBlockchainInfoUpgradeStatusTest().main()
