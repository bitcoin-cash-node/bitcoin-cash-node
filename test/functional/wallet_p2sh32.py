#!/usr/bin/env python3
# Copyright (c) 2022-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet sending to p2sh32 addresses.  This should fail as non-standard pre-activation, and work ok
post-activation"""
import time

from test_framework import cashaddr
from test_framework.key import ECKey
from test_framework.messages import FromHex, CTransaction
from test_framework.script import (
    CScript,
    hash160, hash256,
    OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_HASH256,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes_bi, wait_until


class WalletP2SH32Test(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 2
        # Need to force-disable upgrade12 as it interferes with the pre-activation portion of this test
        no_upgrade12 = '-upgrade12activationheight=999999999'
        # node 0 does not accept non-std txns, node 1 does accept non-std txns
        self.extra_args = [['-upgrade9activationheight=999999999', '-acceptnonstdtxn=0', '-expire=0',
                            '-whitelist=127.0.0.1', '-txbroadcastinterval=1', no_upgrade12],
                           ['-upgrade9activationheight=999999999', '-acceptnonstdtxn=1', '-expire=0',
                            '-whitelist=127.0.0.1', '-txbroadcastinterval=1', no_upgrade12]]
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.log.info("Mining blocks...")

        addr0 = self.nodes[0].getnewaddress()
        addr1 = self.nodes[1].getnewaddress()

        # Ensure both node0 and node1 have funds
        self.nodes[0].generatetoaddress(10, addr0)
        self.sync_all()
        self.nodes[1].generatetoaddress(10, addr1)
        self.sync_all()
        # Mature the above 2 sets of coins
        self.nodes[0].generatetoaddress(51, addr0)
        self.sync_all()
        self.nodes[1].generatetoaddress(50, addr1)
        self.sync_all()

        priv_key = ECKey()
        priv_key.set(secret=b'WalletP2SH32_WalletP2SH32_Wallet', compressed=True)
        # Make p2sh32 wrapping p2pkh
        pub_key = priv_key.get_pubkey().get_bytes()
        redeem_script = CScript([OP_DUP, OP_HASH160, hash160(pub_key), OP_EQUALVERIFY, OP_CHECKSIG])
        # scriptPubKey for p2sh32
        spk_p2sh32 = CScript([OP_HASH256, hash256(redeem_script), OP_EQUAL])
        addr_p2sh32 = cashaddr.encode("bchreg", cashaddr.SCRIPT_TYPE, hash256(redeem_script))

        self.log.info(f"Sending to p2sh32 {addr_p2sh32} via node0 ...")
        # First, send funds to a p2sh_32.. this should fail as non-standard but note that sadly `sendtoaddress`
        # pretends like nothing bad has happened even if AcceptToMemoryPool fails, so we must manually check
        # mempool to test whether it was accepted or not.
        with self.nodes[0].assert_debug_log(['CommitTransaction(): Transaction cannot be broadcast immediately, '
                                             'scriptpubkey (code 64)']):
            txid = self.nodes[0].sendtoaddress(addr_p2sh32, 1.0)
            tx = FromHex(CTransaction(), self.nodes[0].gettransaction(txid)["hex"])
            assert_equal(tx.vout[0].scriptPubKey.hex(), spk_p2sh32.hex())  # Ensure addr_p2sh32 parsed ok
        assert txid not in self.nodes[0].getrawmempool()
        self.log.info(f"txid: {txid} NOT in mempool ...")
        # Abandon this non-standard txn in wallet to avoid problems with self.sync_all() later
        self.nodes[0].abandontransaction(txid)

        self.log.info(f"Sending to p2sh32 {addr_p2sh32} via node1 ...")
        # This one accepts non-std so it should succeed
        txid = self.nodes[1].sendtoaddress(addr_p2sh32, 1.0)
        tx = FromHex(CTransaction(), self.nodes[1].gettransaction(txid)["hex"])
        assert_equal(tx.vout[0].scriptPubKey.hex(), spk_p2sh32.hex())  # Ensure addr_p2sh32 parsed ok
        assert txid in self.nodes[1].getrawmempool()
        self.log.info(f"txid: {txid} in mempool")
        time.sleep(1.0)  # Give txn some time to propagate for below check
        assert txid not in self.nodes[0].getrawmempool()

        # Confirm the mempool for node1
        self.nodes[1].generatetoaddress(1, addr1)
        self.sync_all()

        # Activate Upgrade9
        self.log.info("Activating Upgrade9 ...")

        # Get the current height
        activation_height = self.nodes[0].getblockchaininfo()["blocks"]
        for node_num, args in enumerate(self.extra_args):
            args = args.copy()
            assert_equal(args[0], '-upgrade9activationheight=999999999')
            args[0] = f"-upgrade9activationheight={activation_height}"
            self.restart_node(node_num, extra_args=args)
        connect_nodes_bi(self.nodes[0], self.nodes[1])
        self.sync_all()

        self.log.info(f"Sending to p2sh32 {addr_p2sh32} via node0 ...")
        txid = self.nodes[0].sendtoaddress(addr_p2sh32, 1.0)
        tx = FromHex(CTransaction(), self.nodes[0].gettransaction(txid)["hex"])
        assert_equal(tx.vout[0].scriptPubKey.hex(), spk_p2sh32.hex())  # Ensure addr_p2sh32 parsed ok
        assert txid in self.nodes[0].getrawmempool()
        self.sync_all()
        assert txid in self.nodes[1].getrawmempool()
        self.log.info(f"txid: {txid} in mempool")

        self.log.info(f"Sending to p2sh32 {addr_p2sh32} via node1 ...")
        txid = self.nodes[1].sendtoaddress(addr_p2sh32, 1.0)
        tx = FromHex(CTransaction(), self.nodes[1].gettransaction(txid)["hex"])
        assert_equal(tx.vout[0].scriptPubKey.hex(), spk_p2sh32.hex())  # Ensure addr_p2sh32 parsed ok
        assert txid in self.nodes[1].getrawmempool()
        self.sync_all()
        assert txid in self.nodes[0].getrawmempool()
        self.log.info(f"txid: {txid} in mempool")

        # Ensure that wallet supports managing p2sh_32 addresses as watching-only
        bal = self.nodes[0].getbalance()
        self.nodes[0].importaddress(addr_p2sh32, "My P2SH32 Watching-Only", True)
        wait_until(lambda: self.nodes[0].getbalance("*", 0, True) > bal)

        # However, importing p2sh_32 as non-watching-only doesn't work
        res = self.nodes[1].importmulti(
            # Requests
            [{
                "scriptPubKey": {"address": addr_p2sh32},
                "timestamp": "now",
                "redeemscript": redeem_script.hex(),
                "pubkeys": [pub_key.hex()],
                "keys": [priv_key.get_bytes().hex()],
                "watchonly": False,
                "label": "My P2SH32"
            }],
            # Options
            {
                "rescan": True,
            }
        )
        self.log.info("importmulti result: " + str(res))
        assert_equal(res[0]["success"], False)
        assert_equal(res[0]["error"]["code"], -5)
        assert_equal(res[0]["error"]["message"], "Invalid P2SH address / script")


if __name__ == '__main__':
    WalletP2SH32Test().main()
