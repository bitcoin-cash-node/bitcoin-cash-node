#!/usr/bin/env python3
# Copyright (c) 2022-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deserialization of banlist.dat using the listbanned RPC call."""

import json
import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

TESTSDIR = os.path.dirname(os.path.realpath(__file__))

# Ban list and JSON file were generated with:
# bitcoind -regtest -debug=net
# bitcoin-cli -regtest setmocktime 1643252767
# bitcoin-cli -regtest setban 28.0.0.0/8 add
# bitcoin-cli -regtest setban 188.162.251.56/32 add
# bitcoin-cli -regtest setban 189.7.128.0/24 add
# bitcoin-cli -regtest setban 9908:8554:2487:5277::/64 add
# bitcoin-cli -regtest setban de41:b9a8:b178:52f:f639:e9bf:4ae3:dca8 add
# bitcoin-cli -regtest listbanned
# bitcoin-cli -regtest stop


class DeserializeBanlistTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)

        chain_data_dir = os.path.join(self.nodes[0].datadir, self.chain)
        self.node_banlist_dat = os.path.join(chain_data_dir, 'banlist.dat')
        os.makedirs(chain_data_dir, exist_ok=False)

    def check_banlist(self, banlist_name, empty=False, time_elapsed=0):
        test_banlist_dat = os.path.join(TESTSDIR, 'data', f'{banlist_name}.dat')
        test_banlist_json = os.path.join(TESTSDIR, 'data', f'{banlist_name}.json')

        with open(test_banlist_json, encoding='utf8') as jsonbans:
            test_banned = json.load(jsonbans)

        # In order to properly test the "time_remaining" key, apply time_elapsed to each dict in the list
        if time_elapsed:
            for item in test_banned:
                tr = item["time_remaining"]
                tr -= time_elapsed
                item["time_remaining"] = tr

        shutil.copyfile(test_banlist_dat, self.node_banlist_dat)

        self.start_nodes(extra_args=self.extra_args)

        banned = self.nodes[0].listbanned()

        assert_equal([] if empty else test_banned, banned)

        self.stop_nodes()

        os.remove(self.node_banlist_dat)

    def run_test(self):
        banlists = ['banlist_old', 'banlist_broken', 'banlist_new']

        # Ban is not expired
        self.extra_args = [['-mocktime=1643252767']]
        for banlist in banlists:
            self.check_banlist(banlist)

        # Just before the ban expires
        self.extra_args = [['-mocktime=1643339167']]
        for banlist in banlists:
            self.check_banlist(banlist, time_elapsed=86400)

        # Just when the ban expired, check the list is empty
        self.extra_args = [['-mocktime=1643339168']]
        for banlist in banlists:
            self.check_banlist(banlist, empty=True)

if __name__ == '__main__':
    DeserializeBanlistTest().main()
