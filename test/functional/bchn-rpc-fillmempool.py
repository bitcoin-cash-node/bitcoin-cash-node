#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests the `fillmempool` RPC."""

from test_framework.cdefs import DEFAULT_CONSENSUS_BLOCK_SIZE, ONE_MEGABYTE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

DEFAULT_MAX_MEMPOOL_SIZE_PER_MB = 10
MAX_MEMPOOL_MB = DEFAULT_MAX_MEMPOOL_SIZE_PER_MB * DEFAULT_CONSENSUS_BLOCK_SIZE // ONE_MEGABYTE


class FillMempoolTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_extra_args = ['-percentblockmaxsize=100']
        self.extra_args = [self.base_extra_args] * self.num_nodes
        # We need a long timeout for this test because the sanitizer-undefined CI job is very slow for `fillmempool`
        self.rpc_timeout = 600

    def run_test(self):
        node = self.nodes[0]
        mpi = node.getmempoolinfo()
        assert_equal(mpi['size'], 0)

        # Check error conditions
        assert_raises_rpc_error(-8, "megabytes argument must be greater than 0", node.fillmempool, 0)
        assert_raises_rpc_error(-8, "megabytes argument must be greater than 0", node.fillmempool, -1)
        assert_raises_rpc_error(-8, "Max mempool size is", node.fillmempool, MAX_MEMPOOL_MB + 1)

        assert MAX_MEMPOOL_MB > 100  # Required by below loop

        fuzziness = 500  # fuzziness about how well fillmempool can meet the requirement -> +/- 500 bytes
        prev_size = 0
        for size_mb in [1, 10, 64, 100]:
            res = node.fillmempool(size_mb)
            assert_greater_than_or_equal(res['mempool_dynamic_usage'] + fuzziness, size_mb * ONE_MEGABYTE)
            mpi = node.getmempoolinfo()
            assert_greater_than_or_equal(mpi['usage'] + fuzziness, size_mb * ONE_MEGABYTE)
            # Check some getmempoolinfo keys while we are here
            new_size = mpi['size']
            assert_greater_than(new_size, prev_size)
            prev_size = new_size
            assert_equal(sum(mp['fees']['base'] for mp in node.getrawmempool(True).values()), mpi['total_fee'])


if __name__ == '__main__':
    FillMempoolTest().main()
