#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Cash Node developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Preset + includeWatching: the second fAllowWatchOnly disjunct.

wallet.cpp CWallet::SelectCoins() at or about line 2932 ORs
coin_control.fAllowWatchOnly into the preset-coin use_max_sig. Nothing
covers that term: the existing preset test uses a watch-only coin, for
which the IsMine half is already true. Name a coin the wallet CAN sign
and set includeWatching, and only the new term keeps the estimate at
the foreign-signer size.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, find_output


class PresetIncludeWatchingFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], ["-signschnorr=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0, node1 = self.nodes
        self.generate(node0, 101)
        self.sync_all()

        # A coin node0 can spend itself, named explicitly as a preset input.
        addr = node0.getnewaddress()
        privkey = node0.dumpprivkey(addr)
        txid = node0.sendtoaddress(addr, Decimal("1.0"))
        self.generate(node0, 1)
        self.sync_all()
        vout = find_output(node0, txid, Decimal("1.0"))

        unsigned = node0.createrawtransaction(
            [{"txid": txid, "vout": vout}], {node0.getnewaddress(): Decimal("0.5")})
        funded = node0.fundrawtransaction(unsigned, {"includeWatching": True})

        signed = node1.signrawtransactionwithkey(funded["hex"], [privkey])
        assert_equal(signed["complete"], True)

        est = len(funded["hex"]) // 2
        real = len(signed["hex"]) // 2
        fee_sat = int(funded["fee"] * Decimal("1e8"))
        self.log.info("unsigned {} B, signed {} B, fee {} sat, min relay needs {} sat"
                      .format(est, real, fee_sat, real))

        node0.sendrawtransaction(signed["hex"])
        self.log.info("accepted")


if __name__ == '__main__':
    PresetIncludeWatchingFeeTest().main()
