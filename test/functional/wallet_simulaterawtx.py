#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Copyright (c) 2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test simulaterawtransaction.
"""

from decimal import Decimal
from test_framework.cdefs import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_raises_rpc_error,
)


class SimulateTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        an_address = node.getnewaddress()

        node.generatetoaddress(1, an_address) # Leave IBD

        node.createwallet(wallet_name='w0')
        node.createwallet(wallet_name='w1')
        node.createwallet(wallet_name='w2', disable_private_keys=True)
        w0 = node.get_wallet_rpc('w0')
        w1 = node.get_wallet_rpc('w1')
        w2 = node.get_wallet_rpc('w2')

        self.generatetoaddress(node, COINBASE_MATURITY + 1, w0.getnewaddress())
        assert_equal(w0.getbalance(), 50.0)
        assert_equal(w1.getbalance(), 0.0)

        address1 = w1.getnewaddress()
        address2 = w1.getnewaddress()

        # Add address1 as watch-only to w2
        w2.importpubkey(pubkey=w1.getaddressinfo(address1)["pubkey"])

        tx1 = node.createrawtransaction([], [{address1: 5.0}])
        tx2 = node.createrawtransaction([], [{address2: 10.0}])

        # w0 should be unaffected, w2 should see +5 for tx1 (but only if we include_watchonly for w2)
        include_watchonly = {"include_watchonly": True}
        assert_equal(w0.simulaterawtransaction([tx1])["balance_change"], 0.0)
        assert_equal(w2.simulaterawtransaction([tx1])["balance_change"], 0.0)
        assert_equal(w2.simulaterawtransaction([tx1], include_watchonly)["balance_change"], 5.0)
        # Also test that unknown keys are rejected
        assert_raises_rpc_error(-3, "Unexpected key a_bad_key",
                                w2.simulaterawtransaction, [tx1], {"a_bad_key": 1})
        # Also test the undocumented support for a single raw tx as a string works
        assert_equal(w2.simulaterawtransaction(tx1, include_watchonly)["balance_change"], 5.0)

        # w1 should see +5 balance for tx1
        assert_equal(w1.simulaterawtransaction([tx1])["balance_change"], 5.0)

        # w0 should be unaffected, w2 should see +5 for both transactions
        assert_equal(w0.simulaterawtransaction([tx1, tx2])["balance_change"], 0.0)
        assert_equal(w2.simulaterawtransaction([tx1, tx2])["balance_change"], 0.0)  # No watch_only, no change
        assert_equal(w2.simulaterawtransaction([tx1, tx2], include_watchonly)["balance_change"], 5.0)

        # w1 should see +15 balance for both transactions
        assert_equal(w1.simulaterawtransaction([tx1, tx2])["balance_change"], 15.0)

        # w0 funds transaction; it should now see a decrease in (tx fee and payment), and w1 should see the same as above
        funding = w0.fundrawtransaction(tx1)
        tx1 = funding["hex"]
        tx1changepos = funding["changepos"]
        bitcoin_fee = Decimal(funding["fee"])

        # w0 sees fee + 5 btc decrease, w2 sees + 5 btc
        assert_approx(w0.simulaterawtransaction([tx1])["balance_change"], -(Decimal("5") + bitcoin_fee))
        assert_approx(w2.simulaterawtransaction([tx1], include_watchonly)["balance_change"], Decimal("5"))

        # w1 sees same as before
        assert_equal(w1.simulaterawtransaction([tx1])["balance_change"], 5.0)

        # same inputs (tx) more than once should error
        assert_raises_rpc_error(-8, "Transaction(s) are spending the same output more than once",
                                w0.simulaterawtransaction, [tx1, tx1])

        tx1ob = node.decoderawtransaction(tx1)
        tx1hex = tx1ob["txid"]
        tx1vout = 1 - tx1changepos
        # tx3 spends new w1 UTXO paying to w0
        tx3 = node.createrawtransaction([{"txid": tx1hex, "vout": tx1vout}], {w0.getnewaddress(): 4.9999})
        # tx4 spends new w1 UTXO paying to w1
        tx4 = node.createrawtransaction([{"txid": tx1hex, "vout": tx1vout}], {w1.getnewaddress(): 4.9999})

        # on their own, both should fail due to missing input(s)
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already",
                                w0.simulaterawtransaction, [tx3])
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already",
                                w1.simulaterawtransaction, [tx3])
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already",
                                w0.simulaterawtransaction, [tx4])
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already",
                                w1.simulaterawtransaction, [tx4])

        # they should succeed when including tx1:
        #       wallet                  tx3                             tx4
        #       w0                      -5 - bitcoin_fee + 4.9999       -5 - bitcoin_fee
        #       w1                      0                               +4.9999
        assert_approx(w0.simulaterawtransaction([tx1, tx3])["balance_change"],
                      -Decimal("5") - bitcoin_fee + Decimal("4.9999"))
        assert_approx(w1.simulaterawtransaction([tx1, tx3])["balance_change"], 0)
        assert_approx(w0.simulaterawtransaction([tx1, tx4])["balance_change"], -Decimal("5") - bitcoin_fee)
        assert_approx(w1.simulaterawtransaction([tx1, tx4])["balance_change"], Decimal("4.9999"))

        # they should fail if attempting to include both tx3 and tx4
        assert_raises_rpc_error(-8, "Transaction(s) are spending the same output more than once",
                                w0.simulaterawtransaction, [tx1, tx3, tx4])
        assert_raises_rpc_error(-8, "Transaction(s) are spending the same output more than once",
                                w1.simulaterawtransaction, [tx1, tx3, tx4])

        # send tx1 to avoid reusing same UTXO below
        node.sendrawtransaction(w0.signrawtransactionwithwallet(tx1)["hex"])
        node.generatetoaddress(1, an_address)  # Confirm tx to trigger error below

        # w0 funds transaction 2; it should now see a decrease in (tx fee and payment), and w1 should see the same as above
        funding = w0.fundrawtransaction(tx2)
        tx2 = funding["hex"]
        bitcoin_fee2 = Decimal(funding["fee"])
        assert_approx(w0.simulaterawtransaction([tx2])["balance_change"], -(Decimal("10") + bitcoin_fee2))
        assert_approx(w1.simulaterawtransaction([tx2])["balance_change"], +(Decimal("10")))
        assert_approx(w2.simulaterawtransaction([tx2])["balance_change"], 0)
        assert_approx(w2.simulaterawtransaction([tx2], include_watchonly)["balance_change"], 0)

        # w0-w2 error due to tx1 already being mined
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already", w0.simulaterawtransaction, [tx1, tx2])
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already", w1.simulaterawtransaction, [tx1, tx2])
        assert_raises_rpc_error(-8, "One or more transaction inputs are missing or have been spent already", w2.simulaterawtransaction, [tx1, tx2])


if __name__ == '__main__':
    SimulateTxTest().main()
