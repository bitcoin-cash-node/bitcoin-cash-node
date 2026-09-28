#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Cash Node developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Does fundrawtransaction; sizing a preset watch-only input for a possibly
external signer

Failure path: the user specifies a watch-only UTXO explicitly in
createrawtransaction and then funds it, leaving includeWatching at its default
false (they are not asking the wallet to *find* watch-only coins). If the
wallet sizes that input as if it would sign it itself with Schnorr, the fee is
6-7 sat/input short of what an ECDSA signer actually produces.

This test catches that potential regression -- the wallet *must* correctly
determine that the inputs it is signing for are external even if
inlcudeWatching is set to false for the tx creation RPCs."""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, find_output


class PresetInputFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0 signs Schnorr (default); node1 is the external ECDSA signer.
        self.extra_args = [[], ["-signschnorr=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node0, node1 = self.nodes
        self.generate(node0, 101)
        self.sync_all()

        # A key that lives only on node1. node0 merely watches it.
        ext_addr = node1.getnewaddress()
        ext_privkey = node1.dumpprivkey(ext_addr)
        ext_pubkey = node1.getaddressinfo(ext_addr)["pubkey"]
        node0.importpubkey(ext_pubkey, "", True)

        # Fund it and confirm.
        txid = node0.sendtoaddress(ext_addr, Decimal("1.0"))
        self.generate(node0, 1)
        self.sync_all()
        vout = find_output(node0, txid, Decimal("1.0"))
        raw = node0.getrawtransaction(txid, True)
        spk = raw["vout"][vout]["scriptPubKey"]["hex"]

        # Name the watch-only UTXO explicitly, then fund. includeWatching is
        # left false on purpose: we are not asking the wallet to find coins.
        unsigned = node0.createrawtransaction(
            [{"txid": txid, "vout": vout}], {node0.getnewaddress(): Decimal("0.5")})
        funded = node0.fundrawtransaction(unsigned)
        self.log.info("fundrawtransaction fee: {}".format(funded["fee"]))

        # The real signer is external and uses ECDSA.
        prevtxs = [{"txid": txid, "vout": vout, "scriptPubKey": spk, "amount": Decimal("1.0")}]
        signed = node1.signrawtransactionwithkey(funded["hex"], [ext_privkey], prevtxs)
        assert_equal(signed["complete"], True)

        est_size = len(funded["hex"]) // 2
        real_size = len(signed["hex"]) // 2
        fee_sat = int(funded["fee"] * Decimal("1e8"))
        self.log.info("estimated-unsigned {} B, signed {} B, fee {} sat, "
                      "min relay needs {} sat".format(est_size, real_size, fee_sat, real_size))

        # Fee was computed for the wallet's size estimate; if that estimate was
        # made with a 65-byte Schnorr signature, it is short of what the ECDSA
        # signer produced and the network will reject it at 1 sat/byte.
        txid2 = node0.sendrawtransaction(signed["hex"])
        self.log.info("accepted: {}".format(txid2))


if __name__ == '__main__':
    PresetInputFeeTest().main()
