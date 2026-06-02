#!/usr/bin/env python3
# Copyright (c) 2025-2026 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test support for new opcodes that activate with Upgrade 12 (May 2026): loops, functions, and bitwise ops."""
import random

from test_framework import address
from test_framework.messages import (
    CBlock,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import (
    CScript, CScriptNum,
    hash160,
    OP_CHECKSIG, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_TRUE, OP_0, OP_2, OP_3, OP_6, OP_1ADD, OP_EQUAL,
    OP_INVERT, OP_BEGIN, OP_UNTIL, OP_DEFINE, OP_INVOKE, OP_LSHIFTBIN, OP_RSHIFTBIN, OP_LSHIFTNUM, OP_RSHIFTNUM,
)
from test_framework.test_framework import BitcoinTestFramework


class LoopsFunctionsBitwiseTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_extra_args = ['-acceptnonstdtxn=0', '-expire=0', '-whitelist=127.0.0.1']
        self.extra_args = [['-upgrade12activationheight=999999999'] + self.base_extra_args]

    @staticmethod
    def get_rand_bytes(n_bytes: int = 32) -> bytes:
        assert n_bytes >= 0
        n_bits = n_bytes * 8
        return random.getrandbits(n_bits).to_bytes(length=n_bytes, byteorder='little')

    def run_test(self):
        node = self.nodes[0]  # convenience reference to the node
        self.bootstrap_p2p()  # add one p2p connection to the node

        # A simple anyone-can-spend script that loops 6 times
        script_loops = CScript([self.get_rand_bytes(), OP_DROP, OP_0, OP_BEGIN, OP_1ADD, OP_DUP, OP_6, OP_EQUAL,
                                OP_UNTIL])
        addr_loops = address.script_to_p2sh(script_loops)

        # A simple function definition that defines a function that pushes "true" to the stack, then invokes it
        script_functions = CScript([self.get_rand_bytes(), OP_DROP, bytes([OP_TRUE]), bytes(b'AFuncId'), OP_DEFINE,
                                    bytes(b'AFuncId'), OP_INVOKE])
        addr_functions = address.script_to_p2sh(script_functions)

        # One of each script for: OP_INVERT, OP_LSHIFTNUM, OP_RSHIFTNUM, OP_LSHIFTBIN, OP_RSHIFTBIN
        scripts_bitwise = []
        addrs_bitwise = []
        scripts_bitwise.append(CScript([self.get_rand_bytes(), OP_DROP, bytes([0b1010_1101, 0b0000_0000, 0b1111_1111]),
                                        OP_INVERT, bytes([0b0101_0010, 0b1111_1111, 0b0000_0000]), OP_EQUAL]))
        addrs_bitwise.append(address.script_to_p2sh(scripts_bitwise[-1]))
        scripts_bitwise.append(CScript([self.get_rand_bytes(), OP_DROP, CScriptNum(12345),
                                        OP_3, OP_LSHIFTNUM, CScriptNum(12345 * 8), OP_EQUAL]))
        addrs_bitwise.append(address.script_to_p2sh(scripts_bitwise[-1]))
        scripts_bitwise.append(CScript([self.get_rand_bytes(), OP_DROP, CScriptNum(12345),
                                        OP_3, OP_RSHIFTNUM, CScriptNum(12345 // 8), OP_EQUAL]))
        addrs_bitwise.append(address.script_to_p2sh(scripts_bitwise[-1]))
        scripts_bitwise.append(CScript([self.get_rand_bytes(), OP_DROP, bytes([0b1010_1101, 0b0000_0000, 0b1111_1111]),
                                        OP_2, OP_LSHIFTBIN, bytes([0b1011_0100, 0b0000_0011, 0b1111_1100]), OP_EQUAL]))
        addrs_bitwise.append(address.script_to_p2sh(scripts_bitwise[-1]))
        scripts_bitwise.append(CScript([self.get_rand_bytes(), OP_DROP, bytes([0b1010_1101, 0b0000_0000, 0b1111_1111]),
                                        OP_2, OP_RSHIFTBIN, bytes([0b0010_1011, 0b0100_0000, 0b0011_1111]), OP_EQUAL]))
        addrs_bitwise.append(address.script_to_p2sh(scripts_bitwise[-1]))

        # Mine to the "loops" p2sh address
        txn_payto_loops = FromHex(CBlock(), node.getblock(node.generatetoaddress(1, addr_loops)[0], 0)).vtx[0]
        # Mine to the "functions" p2sh address
        txn_payto_functions = FromHex(CBlock(), node.getblock(node.generatetoaddress(1, addr_functions)[0], 0)).vtx[0]
        # Minte to the "bitwise" p2sh addresses
        txns_payto_bitwise = []
        for addr_bitwise in addrs_bitwise:
            txns_payto_bitwise.append(FromHex(CBlock(),
                                              node.getblock(node.generatetoaddress(1, addr_bitwise)[0], 0)).vtx[0])

        # Mature the above coinbase txns
        my_addr = node.get_deterministic_priv_key().address
        my_spk = CScript([OP_DUP, OP_HASH160,  hash160(address.base58_to_byte(my_addr)[0]), OP_EQUALVERIFY, OP_CHECKSIG])
        node.generatetoaddress(100, my_addr)

        def make_tx(spend_from: CTransaction, send_to_spk: bytes, redeem_script: bytes) -> CTransaction:
            """Assumption: all spend_from outputs owned by redeem_script"""
            tx = CTransaction()
            total_value = 0
            if spend_from.sha256 is None:
                spend_from.rehash()
            spend_from_spk = CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL])
            for i, txout in enumerate(spend_from.vout):
                if txout.scriptPubKey == spend_from_spk:
                    total_value += txout.nValue
                    tx.vin.append(CTxIn(COutPoint(spend_from.sha256, i), scriptSig=CScript([redeem_script])))
            assert total_value > 1100 and len(tx.vin) > 0
            tx.vout.append(CTxOut(total_value - 500, send_to_spk))
            tx.rehash()
            return tx

        # Spending the "loops" redeem script should fail pre-activation
        tx = make_tx(txn_payto_loops, my_spk, script_loops)
        self.send_txs([tx], success=False,
                      reject_reason='mandatory-script-verify-flag-failed (Opcode missing or not understood)')
        assert tx.hash not in node.getrawmempool()

        # Spending the "functions" redeem script should fail pre-activation
        tx = make_tx(txn_payto_functions, my_spk, script_functions)
        self.send_txs([tx], success=False,
                      reject_reason='mandatory-script-verify-flag-failed (Opcode missing or not understood)')
        assert tx.hash not in node.getrawmempool()

        # Spending to the "bitwise" redeem scripts should fail pre-activation
        for i, script in enumerate(scripts_bitwise):
            spend_tx = txns_payto_bitwise[i]
            tx = make_tx(spend_tx, my_spk, script)
            self.send_txs([tx], success=False,
                          reject_reason='mandatory-script-verify-flag-failed (Attempted to use a disabled opcode)')
            assert tx.hash not in node.getrawmempool()


        # Next, activate the upgrade

        # Get the current tip height and hash
        tip_hash = node.getblockchaininfo()["bestblockhash"]
        tip_height = node.getblockheader(tip_hash)["height"]
        # Restart the node, enabling upgrade12 as of the tip
        self.restart_node(0, extra_args=[f"-upgrade12activationheight={tip_height}"] + self.base_extra_args)
        self.reconnect_p2p()


        # Spending the "loops" redeem script should succeed post-activation
        tx = make_tx(txn_payto_loops, my_spk, script_loops)
        self.send_txs([tx], success=True)
        assert tx.hash in node.getrawmempool()

        # Spending the "functions" redeem script should succeed post-activation
        tx = make_tx(txn_payto_functions, my_spk, script_functions)
        self.send_txs([tx], success=True)
        assert tx.hash in node.getrawmempool()

        # Spending to the "bitwise" redeem scripts should succeed post-activation
        for i, script in enumerate(scripts_bitwise):
            spend_tx = txns_payto_bitwise[i]
            tx = make_tx(spend_tx, my_spk, script)
            self.send_txs([tx], success=True)
            assert tx.hash in node.getrawmempool()

    def bootstrap_p2p(self):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.nodes[0].add_p2p_connection(P2PDataStore())
        # We need to wait for the initial getheaders from the peer before we
        # start populating our blockstore. If we don't, then we may run ahead
        # to the next subtest before we receive the getheaders. We'd then send
        # an INV for the next block and receive two getheaders - one for the
        # IBD and one for the INV. We'd respond to both and could get
        # unexpectedly disconnected if the DoS score for that error is 50.
        self.nodes[0].p2p.wait_for_getheaders(timeout=5)

    def reconnect_p2p(self):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        bs, lbh, ts, p2p = None, None, None, None
        if self.nodes[0].p2ps:
            p2p = self.nodes[0].p2p
            bs, lbh, ts = p2p.block_store, p2p.last_block_hash, p2p.tx_store
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p()
        if p2p and (bs or lbh or ts):
            # Set up the block store again so that p2p node can adequately send headers again for everything
            # node might want after a restart
            p2p = self.nodes[0].p2p
            p2p.block_store, p2p.last_block_hash, p2p.tx_store = bs, lbh, ts

    def send_txs(self, txs, success=True, reject_reason=None, reconnect=False):
        """Sends txns to test node. Syncs and verifies that txns are in mempool

        Call with success = False if the txns should be rejected."""
        self.nodes[0].p2p.send_txs_and_test(txs, self.nodes[0], success=success, expect_disconnect=reconnect,
                                            reject_reason=reject_reason)
        if reconnect:
            self.reconnect_p2p()


if __name__ == '__main__':
    LoopsFunctionsBitwiseTest().main()
