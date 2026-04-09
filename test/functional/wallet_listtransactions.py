#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listtransactions API."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_array_result


class ListTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Leave IBD
        self.generate(self.nodes[0], 1)
        # Simple send, 0 to 1:
        txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.1)
        self.sync_all()
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-0.1"), "confirmations": 0})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"txid": txid},
                            {"category": "receive", "amount": Decimal("0.1"), "confirmations": 0})
        # mine a block, confirmations should change:
        blockhash = self.nodes[0].generate(1)[0]
        blockheight = self.nodes[0].getblockheader(blockhash)['height']
        self.sync_all()
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txid": txid},
                            {"category": "send", "amount": Decimal("-0.1"), "confirmations": 1,
                             "blockhash": blockhash, "blockheight": blockheight})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"txid": txid},
                            {"category": "receive", "amount": Decimal("0.1"), "confirmations": 1,
                             "blockhash": blockhash, "blockheight": blockheight})

        # send-to-self:
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 0.2)
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txid": txid, "category": "send"},
                            {"amount": Decimal("-0.2")})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"txid": txid, "category": "receive"},
                            {"amount": Decimal("0.2")})

        # sendmany from node1: twice to self, twice to node2:
        send_to = {self.nodes[0].getnewaddress(): 0.11,
                   self.nodes[1].getnewaddress(): 0.22,
                   self.nodes[0].getnewaddress(): 0.33,
                   self.nodes[1].getnewaddress(): 0.44}
        txid = self.nodes[1].sendmany("", send_to)
        self.sync_all()
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-0.11")},
                            {"txid": txid})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"category": "receive", "amount": Decimal("0.11")},
                            {"txid": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-0.22")},
                            {"txid": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "receive", "amount": Decimal("0.22")},
                            {"txid": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-0.33")},
                            {"txid": txid})
        assert_array_result(self.nodes[0].listtransactions(),
                            {"category": "receive", "amount": Decimal("0.33")},
                            {"txid": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "send", "amount": Decimal("-0.44")},
                            {"txid": txid})
        assert_array_result(self.nodes[1].listtransactions(),
                            {"category": "receive", "amount": Decimal("0.44")},
                            {"txid": txid})

        pubkey_A = self.nodes[1].getaddressinfo(
            self.nodes[1].getnewaddress())['pubkey']
        multisig_A = self.nodes[1].createmultisig(1, [pubkey_A])
        self.nodes[0].importaddress(
            multisig_A["redeemScript"], "label_A_watchonly", False, True)

        pubkey_B = self.nodes[1].getaddressinfo(
            self.nodes[1].getnewaddress())['pubkey']
        multisig_B = self.nodes[1].createmultisig(1, [pubkey_B])
        self.nodes[0].importaddress(
            multisig_B["redeemScript"], "label_B_watchonly", False, True)

        plain_addr_C = self.nodes[1].getnewaddress()
        pubkey_C = self.nodes[1].getaddressinfo(plain_addr_C)['pubkey']
        self.nodes[0].importpubkey(pubkey_C, "label_C", False)

        num_wildcard_label_results_before_txs = len(self.nodes[0].listtransactions(label="*",
                                                                                   count=100,
                                                                                   include_watchonly=True))

        txid_A = self.nodes[1].sendtoaddress(multisig_A["address"], 0.01)
        txid_B = self.nodes[1].sendtoaddress(multisig_B["address"], 0.01)
        txid_C = self.nodes[1].sendtoaddress(plain_addr_C, 0.01)

        self.generate(self.nodes[1], 1)
        self.sync_all()

        # check label_A_watchonly results
        assert len(
            self.nodes[0].listtransactions(
                label="label_A_watchonly",
                count=100,
                include_watchonly=False)) == 0
        assert len(
            self.nodes[0].listtransactions(
                label="label_A_watchonly",
                count=100,
                include_watchonly=True)) == 1

        # check label_B_watchonly results
        assert len(
            self.nodes[0].listtransactions(
                label="label_B_watchonly",
                count=100,
                include_watchonly=False)) == 0
        assert len(
            self.nodes[0].listtransactions(
                label="label_B_watchonly",
                count=100,
                include_watchonly=True)) == 1

        # check label_C results
        assert len(
            self.nodes[0].listtransactions(
                label="label_C",
                count=100,
                include_watchonly=False)) == 0
        assert len(
            self.nodes[0].listtransactions(
                label="label_C",
                count=100,
                include_watchonly=True)) == 1

        # check no results returned for unknown label
        assert len(
            self.nodes[0].listtransactions(
                label="no_such_label",
                count=100,
                include_watchonly=True)) == 0

        # wildcard labels : 3 new txs added (A, B & C)
        assert len(
            self.nodes[0].listtransactions(
                label='*',
                count=100,
                include_watchonly=True)) - num_wildcard_label_results_before_txs == 3

        # check wildcard returns all labeled txs
        assert_array_result(self.nodes[0].listtransactions(label="*", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_A_watchonly", "amount": Decimal("0.01")},
                            {"txid": txid_A, "label": "label_A_watchonly"},
                            should_not_find=False)
        assert_array_result(self.nodes[0].listtransactions(label="*", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_B_watchonly", "amount": Decimal("0.01")},
                            {"txid": txid_B, "label": "label_B_watchonly"},
                            should_not_find=False)
        assert_array_result(self.nodes[0].listtransactions(label="*", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_C", "amount": Decimal("0.01")},
                            {"txid": txid_C, "label": "label_C"},
                            should_not_find=False)

        # check label A returns only label A, not B or C
        assert_array_result(self.nodes[0].listtransactions(label="label_A_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_A_watchonly", "amount": Decimal("0.01")},
                            {"txid": txid_A, "label": "label_A_watchonly"})
        assert_array_result(self.nodes[0].listtransactions(label="label_A_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_B_watchonly", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)
        assert_array_result(self.nodes[0].listtransactions(label="label_A_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_C", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)

        # check label B returns only label B, not A or C
        assert_array_result(self.nodes[0].listtransactions(label="label_B_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_B_watchonly", "amount": Decimal("0.01")},
                            {"txid": txid_B, "label": "label_B_watchonly"})
        assert_array_result(self.nodes[0].listtransactions(label="label_B_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_A_watchonly", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)
        assert_array_result(self.nodes[0].listtransactions(label="label_B_watchonly", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_C", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)

        # check label C returns only label C, not A or B
        assert_array_result(self.nodes[0].listtransactions(label="label_C", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_C", "amount": Decimal("0.01")},
                            {"txid": txid_C, "label": "label_C"})
        assert_array_result(self.nodes[0].listtransactions(label="label_C", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_A_watchonly", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)
        assert_array_result(self.nodes[0].listtransactions(label="label_C", count=100, include_watchonly=True),
                            {"category": "receive", "label": "label_B_watchonly", "amount": Decimal("0.01")},
                            {},
                            should_not_find=True)


if __name__ == '__main__':
    ListTransactionsTest().main()
